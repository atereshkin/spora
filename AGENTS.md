# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spora is a peer-to-peer VPN/tunnel written in Rust. It creates encrypted network tunnels between two peers using UDP hole punching for NAT traversal, with a dumb UDP relay as a fallback when direct connection fails. Primary target is Android (via FFI), with CLI support for Linux and Windows.

## Build Commands

```bash
cargo build                    # Build all workspace crates
cargo build --release          # Release build
cargo test                     # Run tests (includes the spora-lab network suites)
cargo clippy                   # Lint
./build-ffi.sh                 # Cross-compile for Android + generate Kotlin bindings
```

The FFI build requires Android NDK linkers configured in `~/.cargo/config.toml` and Android targets installed via `rustup target add`.

### e2e network lab

`cargo test -p spora-lab` runs end-to-end suites (smoke, nat_matrix, resilience,
conditions, record, connlog, ipv6, …) in Linux network namespaces with real kernel NAT (iptables) and tc
netem — no root needed (unprivileged userns; suites self-skip if unavailable;
`SPORA_LAB=skip` opts out). Architecture, NAT recipes, and the product findings
the suites encode live in `docs/lab.md`. Suites are `harness = false` binaries;
filter scenarios with e.g. `cargo test -p spora-lab --test nat_matrix -- cone`.
Protocol timings are configurable via `Config.timings` (`Timings`, prod
defaults); lifecycle events via `Config.event_hook` (`TunnelEvent`); the
machine-readable account of a whole run via `Config.record` (see "Connection
record"); the direct upgrade can be disabled via `Config.enable_direct_upgrade`
— these exist for the lab but are usable by the apps (e.g. path-state
display).

**Reading suite results reliably.** ERROR log lines interleave between a
scenario's name and its verdict, so `scenario X ... FAILED` is often NOT one
line — never line-grep for that shape. The reliable signals are the per-suite
summary line (`<suite>: ok. N passed` / `<suite>: FAILED. N passed; M failed`)
and the process exit code. Piping `cargo test` through `tail`/`grep` replaces
`$?` with the filter's status (use `pipefail`/`PIPESTATUS`, or write the full
log to a file and inspect that), and a `tail -N` window silently hides
early-suite failures under `--no-fail-fast` — check the whole log. Timing
scenarios (e.g. `conditions::latency_jitter`) are load-sensitive and can flake
at low single-digit percentages: to confirm or chase one, loop the single suite
filtered (`cargo test -p spora-lab --test conditions -- latency`) 20-30×
serially on a quiet machine rather than re-running the full suite a few times.

## Workspace Structure

Workspace members (resolver v3):

- **spora-core** — Core library. Exposes `share()` (sharer mode) and `connect(url)` (client mode). Contains all networking logic.
- **spora-cli** — CLI binary with `spora share` and `spora use <URL>` subcommands. Uses `tokio-tun` for TUN device on Unix. `spora share --os-routing` enables the privileged netstack bypass (see "Share-side exit modes"). `--relay <host:port>` (share) and `--stun <host:port>` (share/use) override the built-in endpoints.
- **spora-ffi** — Uniffi-based FFI for Android/JNI. Wraps core functions for Kotlin. Builds as `cdylib`.
- **spora-wincore**, **spora-winui** — Windows service + UI.
- **relay** — Dumb UDP relay (both `lib.rs` for use in tests and `main.rs` for the deployed binary). Forwards packets between peers by inspecting QUIC long-header DCIDs and tracking a small flow table. Speaks no QUIC, holds no TLS keys.
- **relay-client** — Tiny client of the relay protocol: the wire-protocol constants (`protocol` module) and the sharer's `register_loop` helper.
- **spora-lab** — Network-namespace e2e test lab (test-only; see `docs/lab.md`): runs the real sharer/client/relay across netns topologies with iptables NAT flavors and netem conditions, in-process (one pinned thread + current-thread tokio runtime per simulated host).

## Architecture

### High-level flow (Design 2 — dumb relay + end-to-end QUIC)

```
A (sharer) <----- end-to-end QUIC (cert pinned, secret-auth) -----> B (client)
                                  |
                                  v
                              Relay (dumb UDP forwarder)
                              - routes by inspecting QUIC DCID
                              - flow table: (B_addr -> A_addr)
                              - no QUIC, no TLS, no plaintext access
```

There is exactly one QUIC connection — between A and B — even when traffic flows through the relay. The relay is a stateless-ish UDP forwarder: it looks at QUIC long-header packets and routes them by Destination Connection ID; everything after the first match is forwarded by source-address 5-tuple. PMTUD runs end-to-end on the single connection, not per-leg.

### Identity persistence

`Identity` (cert + key + secret + routing_key) is what determines the share URL. **Platform-specific clients are responsible for persisting it** in a platform-appropriate way so the URL stays stable across launches:

- CLI: `$XDG_CONFIG_HOME/spora/identity.bin` (mode 0600), `--fresh` flag forces regeneration.
- FFI (Android): `make_identity()` returns bytes, app stores them (SharedPreferences/EncryptedSharedPreferences), passes them back to `share(identity_bytes, …)`.
- Windows wincore (gRPC): the proto's `ShareRequest.key` field is interpreted as base64url(identity bytes), or empty to generate fresh. Proto change to `bytes identity` is a follow-up.

Use `Identity::generate()` once and `Identity::from_bytes(&persisted)` thereafter. Round-trip via `to_bytes()` / `from_bytes()` is versioned and magic-checked (`b"sIDv"`, version 1).

### Sharer (A) flow — `spora_core::share(identity, config)` (rolling listener / per-port sessions)

1. Receive `Identity` from the platform layer (already persisted on disk or in the OS keystore).
2. Bind the generation-0 LISTENER socket (ephemeral port); `try_clone()` it so quinn owns one fd and the registrar uses the other. Spawn its registrar — every 30s a signed `[CTRL_MAGIC | REGISTER | routing_key]` packet to each UDP relay; the relay updates `routing_key -> A_addr`. One `RegisterSigner` (strictly-increasing timestamps) is shared across ALL generations.
3. Per accepted+authenticated session, `run_share_loop` ROLLS: the session keeps the socket/endpoint it arrived on (its own port, its own relay flow, its own quinn endpoint), and a fresh listener socket + registrar generation takes over the routing key (old listener: registrar aborted, `set_server_config(None)`). The relay's binding therefore always points at a flow-free port — no "actively-serving" lockout for dead predecessors, no same-DCID Initial swallow — and a REGISTER from the new port displaces the old binding (no relay changes needed). Demoted endpoints are tracked and closed once no session can use them.
4. `Direct` endpoints get a separate PERMANENT endpoint on the advertised port (never rolls, never registers); direct-dialing clients use random initial DCIDs (the routing-key DCID exists only for relay routing). The nz carrier rolls its dedicated socket the same way (dispatcher demotes, keeps serving its session, exits when its tables empty).
5. Per session: wrap `transport` in `UpgradableTransport → KeepAliveTransport`; spawn `try_direct_upgrade` (responder role, with the identity); spawn the netstack tunnel. New peer kicks previous (two LIVE clients on one URL will alternate at `reconnect_delay` cadence — the fixed delay is the anti-storm pacing; real multi-client is future work, structurally easy now that each session owns an endpoint).

NAT caveat: a listener's NAT mapping is kept alive only by outbound REGISTERs (relay never replies); on NATs with unreplied-UDP timeout <= register interval the mapping can lapse between REGISTERs. Planned fix: relay REGISTER-ACK (see `QuicListenerCtx` doc).

### Client (B) flow — `spora_core::connect(url)`

1. Parse URL to `Token { routing_key, secret, relay_host, relay_port }`.
2. Resolve the relay address; bind a UDP socket.
3. Build quinn client config that pins the server cert to `routing_key` (`RoutingKeyVerifier`) and sets `initial_dst_cid_provider` so B's first Initial carries `DCID = routing_key`.
4. `client_connect` to the relay address — relay routes by DCID to A — QUIC handshake completes end-to-end. B opens a bidi stream and writes the secret; A verifies and accepts.
5. Wrap the resulting `QuicPeerTransport` in `UpgradableTransport → KeepAliveTransport → ReconnectTransport`; spawn `try_direct_upgrade` (initiator role).

### Direct upgrade (`try_direct_upgrade` in `lib.rs`)

After the relay-via session is up, both sides try to establish a direct path:

- Signaling rides on the bidi QUIC stream that was opened during the auth step (the `SignalChannel` in `signal.rs`, length-framed messages).
- STUN to discover external addresses; exchange endpoints via the signal channel; punch + bidirectional verify.
- Build a fresh `e2e::client_endpoint` / `e2e::server_endpoint` over the new direct socket, using the same `Identity` / `routing_key`. New QUIC handshake completes end-to-end on the direct path.
- `UpgradeSender` swaps the inner transport from the relay-via QUIC to the direct QUIC. The old relay-via connection drains and times out.

(Note: quinn 0.11 does NOT expose client-initiated QUIC connection migration. The upgrade is a tear-down + rebuild of QUIC over a new socket, not in-place migration. Inner TCP retransmits cover the brief handshake stall.)

### Share-side exit modes (`Config::exit_mode`)

How the share side turns tunneled IP packets into real traffic:

- **`ExitMode::Netstack`** (default, unprivileged) — userland smoltcp netstack (`server::start_tunnel`): TCP/UDP flows are terminated in-process and re-originated from OS sockets. Used by FFI/Android and the CLI without flags.
- **`ExitMode::Custom(SessionHandler)`** — netstack bypass. The handler is called once per accepted session with the composed `IpTransport` and a `CancellationToken` (cancelled when a new peer replaces the session or the share stops). The core still owns accept/registration/direct-upgrade.

The CLI implements OS routing on top of `Custom` (`spora share --os-routing`, plus `--tun-addr`, `--tun-mtu`, `--no-nat`; see `spora-cli/src/os_route.rs`). Requires root/CAP_NET_ADMIN, Linux only. It creates a TUN device and pumps packets transport↔TUN; the kernel forwards/NATs. Key invariants:

- **Keepalive pings must be answered locally.** The client's keepalive layer pings a synthetic private address (10.0.0.2) and declares the tunnel dead without a response; smoltcp answers those in netstack mode, so the pump answers ICMP echo requests to blocked private destinations itself.
- **Client source addresses are learned, not assumed — but must be private.** Each platform picks its own client TUN address (e.g. wincore uses 10.0.85.1), so the pump learns inner source IPs from forwarded packets and installs a `/32` (v6: `/128`) route + scoped MASQUERADE rule per peer (cap 64, shared across families). The source is client-controlled, so it is **restricted to RFC1918/CGNAT** (`is_private_client_source`) for v4 and **ULA fc00::/7 only** (`is_ula_client_source`) for v6; a public source would otherwise install a route that hijacks the sharer's own egress to that address. A learned source that collides with a directly-connected host route (the sharer's own LAN) is also refused (route-table check, per family).
- Destinations matching `is_local_address` are dropped (parity with the netstack's `block_local`); ICMPv6 echoes to blocked v6 destinations are answered locally like the v4 ones (mandatory pseudo-header checksum). IPv6 is carried in **both** directions; the host→client pump filters frames whose v6 src/dst is link-local or multicast (the kernel's RS/NS/MLD/DAD chatter must not leak to the peer). The TUN gets a ULA from `--tun-addr6` (default `fd00:5350::1/64`).
- NAT setup at startup applies v4+v6 forwarding sysctls, FORWARD accepts, and TCP MSS clamp to the TUN MTU (v6 clamp = MTU−60) via iptables AND ip6tables; the per-peer scoped MASQUERADE is added lazily in `learn_peer` when each client source is first seen. All of it is undone on exit; `--no-nat` skips it. Cleanup runs from `OsRoute`'s `Drop`, so it fires on Ctrl+C (SIGINT), SIGTERM, error returns, and panics.

### Wire protocol — relay control & QUIC routing (see `relay_client::protocol`)

- Sharer registration: `[0x80, 's', 'p', 'R', 0x01, <20-byte routing_key>]`. The leading `0x80` has the QUIC "fixed bit" clear, so QUIC parsers will not mistake control traffic for QUIC.
- QUIC long-header packets (Initial, Handshake): the relay parses out the DCID at byte offset 6, matches against registered routing keys, and installs a bidirectional `(B_addr, A_addr)` flow.
- QUIC short-header (1-RTT) packets: routed by 5-tuple via the flow table that was installed when the first Initial arrived.

### Token / URL format

```
https://spora.to/s/<base64url(routing_key || secret)>?r=<host>:<port>[&r=<host>:<port>...]
```

`routing_key` is 20 bytes (the QUIC v1 DCID maximum); `secret` is 16 bytes. The blob is 36 bytes → 48 base64url chars. An IPv6 relay literal is bracketed (`?r=[2001:db8::1]:443`); `Token::from_url` strips the brackets, so each `RelayEndpoint::host` is a bare hostname/literal. One `?r=` per relay (`Token::relays: Vec<RelayEndpoint>`); a single-`?r=` URL is the back-compatible degenerate case.

### Multiple relays

`Config.relays` / `Token.relays` carry one or more relay endpoints (in preference order). The model is fully generic — used for dual-stack reachability AND censorship-fallback:

- **Sharer registers with ALL relays** on one socket. The socket is dual-stack (`::`, `IPV6_V6ONLY` off) when the relay set includes any v6 endpoint, so it reaches both families and accepts client Initials forwarded by any relay (v4 relays appear v4-mapped); a pure-v4 relay set keeps a plain `0.0.0.0` socket. `register_loop` takes a `Vec<SocketAddr>` and tolerates per-relay send failures (a v4-only host silently skips a v6 relay).
- **Client tries relays IPv6-first** (`resolve_relays_preferring_v6`), each with a family-matched socket, under `Timings.relay_dial_timeout` (default 8s), until one bootstraps a relay-via session. The list is re-resolved and re-ordered on every (re)dial (`resolve_for_dial`), so DNS changes and censorship failover take effect on reconnect; a lookup that fails falls back to the last addresses that resolved — a poisoned resolver must not cost the client the addresses it already had — and both the failure and the fallback land in the connection record. Regression test: `cargo test -p spora-lab --test record -- redial`. Preferring a v6 relay is the lever that drives a v6 hole punch (`path_ipv6` comes from the chosen relay's family), which succeeds far more often (firewall-only, no NAT). A dead relay, a censored one, and a relay the sharer never registered with (family mismatch) all look identical — a dropped Initial — and all fail over to the next.
- **A hostname with A+AAAA records expands to two endpoints** at resolve time (`resolve_one_relay` returns every resolved address), independently on each side — so it behaves exactly as if both IPs were listed.
- The relay itself is unchanged: each does its dumb DCID-routed forwarding; the sharer's registrations and the clients' flows are per-relay and independent.

### IPv6

Both axes are supported and lab-tested (`cargo test -p spora-lab --test ipv6`; needs ip6tables, skips cleanly without):

- **Outer transport over v6**: relay endpoints are resolved per family (see "Multiple relays" — the client tries v6 first, the sharer registers with all). STUN is queried in the relay-path family first (`pierce_keep_socket(.., prefer_ipv6)`), so punch + direct QUIC run on v6 when the session does. The endpoint exchange is one candidate per side — a cross-family pairing fails fast (`address family mismatch`, transient) instead of burning the punch timeout. The relay binary binds `::` dual-stack by default (one socket, one flow table; v4 peers appear v4-mapped; `--bind 0.0.0.0` for v4-only hosts). The deployed default relay is still a v4 literal, so v6 outer paths need a v6-capable relay host in the URL (or a dual-stack hostname).
- **Inner v6 in the tunnel**: the netstack terminates v6 TCP/UDP and re-originates from family-matched OS sockets (`Domain::for_address`); the vendored netstack walks v6 extension-header chains. Oversized inner packets fragment at the tunnel layer per family (IPv4 header fragmentation / RFC 8200 Fragment header, shared 32-bit id counter); `IpReassembler` (share side) and the lab pump reassemble both. The keepalive stays a v4 ICMP ping (10.0.0.2): injected below inner traffic, answered by every exit mode — works unchanged on v6-carrying tunnels.
- **Address hygiene**: `is_local_address` judges v4-mapped destinations by the v4 rules (a dual-stack egress socket would otherwise reach the LAN via `::ffff:192.168.x.x`) and blocks `::`, ULA, link-local, `ff00::/8`; `neg::is_valid_punch_target` and `relay::is_relayable` canonicalize v4-mapped forms before their policy checks.

### Connection log (`spora-core/src/connlog.rs`, see `docs/connection-logging.md`)

The sharer keeps a local NetFlow-style per-flow record ("which client connected to destination IP X during [T1,T2]") — the sharer's egress accountability record for abuse/LE queries. `Config.conn_log: Option<ConnLogConfig>`; core defaults to off, **platforms enable by default** (CLI: `$XDG_STATE_HOME/spora/connlog/<routing-key>/`, `--no-conn-log` to disable; FFI: `conn_log_dir` param; wincore: proto fields, `%PROGRAMDATA%\Spora\connlog\<rk>`). Key facts:

- Storage is SQLite (WAL) on a dedicated writer thread fed by a bounded channel — hooks never block the tunnel; overflow/IO trouble becomes visible `log_gap` marks (plus `clock_jump`, `share_start/stop`, `flow_throttle`), because an absence of records must be distinguishable from absence of traffic. `share()` fails loudly if the log dir is unwritable.
- Two meters, one log: the netstack exit logs flows at its re-origination points (TCP/UDP, byte counts via `CountedIo`/NAT-entry counters, and `getsockname()` as the **egress source address** — the attribution-critical field); `ExitMode::Custom` gets a passive `MeteredTransport` wrapped around the handler's transport (records marked `confirmed=false`, "offered to tunnel"); `--os-routing` enriches those with the post-MASQUERADE port via a conntrack lookup. Flow records are rate-limited per session (token bucket; suppression summarized in marks). `FlowGuard` is a Drop-guard, so abort-driven teardown still closes records.
- Session records carry four address kinds of different evidentiary weight: `reported` (client-asserted, never to be read as an observation), `punch_verified` (address-validated; captured even when the direct QUIC build fails), `verified` (direct connection), `sharer_public` (own STUN). A relay-via-only session never directly observes the client's IP — documented limitation.
- Retention default 90 days, swept in the writer; `spora log hold` pins ranges (preservation requests); logs are deliberately NOT deleted with the identity. Query via `spora log query --ip ... --from ... --to ... [--json]`.
- e2e coverage: `cargo test -p spora-lab --test connlog`.

### Connection record (`spora-core/src/record.rs`, see `docs/diagnostic-record.md`)

A structured, versioned account of ONE RUN of `connect()`/`share()`: every step
timestamped, every failure carrying a code from a **closed vocabulary** (never
free text), quality samples while the tunnel is up, and a terminal outcome.
Counting is the point — a reworded `format!` must not be able to change what a
failure counts as. `Config.record: Option<RecordConfig>`; core defaults to off
(the CLI turns it on: `$XDG_STATE_HOME/spora/records/`, `--no-record` to
disable). Read it with `spora record list|show|export [--json]`. Key facts:

- Vocabularies: `StepKind`, `Reason`, `StepOutcome` (incl. `skipped` and
  `abandoned`), `Carrier` (quic/tcp_tls/nz) x `PathKind`
  (relay/direct_advertised/direct_punched), `Outcome`, `MtuSource`. Adding a
  code does NOT bump `FORMAT_VERSION`; unknown codes degrade to `unknown` in an
  older reader instead of failing the parse.
- Classification happens where the error is BORN: `record::Fault { reason,
  detail }` is the crate-internal error type in the dial/handshake/upgrade
  paths (`e2e*.rs`, `carrier.rs`, `noise.rs`), and `impl From<Fault> for String`
  keeps the old `Result<_, String>` boundaries source-compatible. By the time an
  error reaches `io::Error::other`, its kind is gone.
- On disk: append-only JSON Lines, one file per run, flushed per entry on a
  dedicated writer thread behind a bounded channel (overflow → visible `gap`
  entries). A step is written twice — `started`, then its conclusion — and a
  LATER ENTRY SUPERSEDES AN EARLIER ONE WITH THE SAME `seq`, so a record that
  ends at a `started` entry is a record of something still running. Records
  close on Drop, so an unplanned exit still gets an ending.
- Numbers: traffic/probe counters live in `KeepAliveTransport` (`LinkCounters`)
  — the one layer on every carrier and on both sides of a path swap, so one
  series survives the upgrade; carrier stats (QUIC rtt/cwnd/lost/MTU) are added
  when available. Probe RTT and probe loss are the only carrier-agnostic
  figures. `mtu_src` distinguishes `discovered` from `declared`.
- Honest limits are part of the design, not omissions: a relay-via session
  never observes the peer's address; REGISTER is unacknowledged so `register`
  records intent, not receipt; `no_response` is used ONLY where the code can
  prove nothing arrived (nz handshake, punch) — QUIC timeouts are
  `handshake_timeout`; the two ends' records are not automatically joinable.
- e2e coverage: `cargo test -p spora-lab --test record`.

### Transport Layer (`spora-core/src/transport/`)

The `Transport` trait = `Stream<Item=io::Result<Vec<u8>>> + Sink<Vec<u8>>`. Implementations:

- `QuicPeerTransport` (in `transport/quic.rs`) — wraps a `quinn::Connection`'s datagram channel as IP packets. Uses quinn **BBR** to pace datagrams to the bottleneck (replaced `NoopCc`, which paced nothing and let the share-side smoltcp download sender burst the path into congestion collapse — see `docs/lab.md`). Used by both relay-via and direct paths.
- `UpgradableTransport` (in `transport/upgradable.rs`) — wraps any transport; can be swapped to a new inner transport via `UpgradeSender`.
- `KeepAliveTransport` (in `transport/keepalive.rs`) — injects ICMP Echo Requests at configurable intervals. This is the SINGLE, transport-agnostic keepalive of record for all carriers (QUIC/nz/TCP): quinn's own `keep_alive_interval` was removed (only `max_idle_timeout` remains, as a passive reaper) so there is one knob-honoring control point. **Client** side is `Adaptive` (atomic knob: 0 = dormant/screen-off/radio-silent, >0 = probe every N s). **Share** side is reactive `Periodic` with an `active_window`: it pings only while it has heard from the client recently, and goes quiet once the client goes dormant — so a dormant client is never forced to ACK share-side pings (true radio silence). Cooperate-with-sleep: a dormancy longer than the idle timeout drops the connection (`max_idle_timeout` reaps it) and it reconnects on wake — cheap now via per-port.
- `ReconnectTransport` (in `transport/mod.rs`) — wraps any transport; on error/close, re-dials via a closure. Parks (does not redial) while the app is dormant (keepalive knob 0), waking on `set_keepalive(N>0)` — a screen-off phone stays radio-silent instead of spinning the radio on a dead tunnel.
- `MeteredTransport` (in `transport/meter.rs`) — share side, `ExitMode::Custom` only: passive connection-log flow meter (see "Connection log").

Composition (client side): `QuicPeerTransport → UpgradableTransport → KeepAliveTransport → ReconnectTransport`. Server side omits the outermost `ReconnectTransport` (a new peer just opens a new QUIC connection at the QUIC server endpoint).

### Key Constants

- STUN server: `stun.l.google.com:19302`
- Default relay: `167.71.66.250:443` (UDP, not TLS now — the relay speaks no protocol other than the magic-prefix control packets and QUIC pass-through)
- Routing-key length: 20 bytes (fits in a QUIC v1 DCID)
- Secret length: 16 bytes
- Register interval: 30s. Relay registration timeout: 120s. Flow timeout: 60s.
- QUIC: initial_mtu=1200, PMTUD enabled, BBR, idle 30s. NO quinn keep-alive (the ICMP `KeepAliveTransport` is the single keepalive; `Timings.quic_keep_alive` now sets the SHARE-side ICMP interval, not a quinn setting).

## Conventions

- Edition 2024 across the workspace (spora-core now too).
- Async throughout using tokio with full features.
- `spora-core/build.rs` stamps the git commit + a dirty flag into the binary
  (overridable with `SPORA_BUILD_COMMIT`/`SPORA_BUILD_DIRTY` for release
  pipelines); every connection record names the build that produced it.
- Logging via `log` crate (env_logger in CLI, android_logger in FFI).
- Public API error type is currently `Result<T, String>`.
- The companion Android app lives in a sibling `../spora-android/` repo.
