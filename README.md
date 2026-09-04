# Spora 

**Spora** is a P2P VPN application and suite of protocols. It is designed for a single network topology commonly used by consumer VPN products: a "client" node and an "exit" node. Any device running **Spora** (including one behind a NAT/firewall) can act as a VPN server routing clients' traffic to/from the Internet.

### A word of caution

Spora is a tool for improving *connectivity* under adverse network conditions (censorship and Geo-IP-based discrimination) but not *privacy* or *security*. Spora's main design principle is connectivity above all else. Therefore, it contains features and design decisions commonly avoided by VPN applications, such as custom protocols and extensive connection logging.

## Project structure

This repository contains all the networking functionality, FFIs and a cross-platform CLI client. The GUI Spora applications are distributed in binary form only.

It is a Rust [workspace](Cargo.toml) (edition 2024). The crates:

- **`spora-core`** — the library everything else builds on. All of the networking lives here: NAT traversal (UDP hole punching), the relay-path and direct QUIC transports, the direct-path upgrade, the userland exit netstack, and the connection log. Its public surface is two calls — `share()` (act as an exit) and `connect(url)` (act as a client).
- **`spora-cli`** — the cross-platform command-line client; builds to the `spora-cli` binary with `share`, `use <URL>`, `log` and `record` subcommands. The reference front-end for `spora-core`.
- **`spora-ffi`** — [UniFFI](https://mozilla.github.io/uniffi-rs/) bindings that wrap `spora-core` for the Android app (built as a `cdylib` with generated Kotlin; build outputs land in `jniLibs/` and `out/uniffi/`).
- **`relay`** — the relay daemon: a "dumb" forwarder that pairs a sharer and client by routing key and splices their traffic without ever seeing inside it (it holds no keys and reads no plaintext). A public relay is built into the client, so running your own is optional. See [`relay/README.md`](relay/README.md) for its carriers, authorization, and session log.
- **`relay-client`** — the sliver shared by core and relay: the relay wire-protocol constants and the sharer's registration loop.
- **`spora-lab`** — a test-only end-to-end lab that runs a real sharer, client, and relay across Linux network-namespace topologies with kernel NAT and link emulation.
- **`vendor/netstack-smoltcp`** — a vendored fork of the userland netstack the exit uses; a path dependency of `spora-core`, not a workspace member.

## Getting started

### Build

```bash
cargo build --release
```

The client is then at `target/release/spora-cli` (symlink or alias it to `spora` if you like — it names itself `spora` in `--help`). The build also produces the `relay` daemon, which you only need if you want to run your own relay; a public one is built in.

### Share your connection — be an exit

```bash
spora-cli share
```

Prints an `https://spora.to/s/…` URL; hand it to the peer that should tunnel through you, and leave the process running (Ctrl+C stops it). No privileges needed — the default exit is a userland netstack that terminates each flow and re-originates it from ordinary OS sockets.

First run writes a persistent identity to `$XDG_CONFIG_HOME/spora/identity.bin` so the URL stays the same across restarts (`--fresh` regenerates it). It also opens a local connection log at `$XDG_STATE_HOME/spora/connlog/<routing-key>/` — your record of which client reached which destination, and when (`--no-conn-log` disables it; read it back with `spora-cli log query …`).

For a kernel-level exit — packets routed and NATed by the kernel through a TUN device instead of the userland netstack — use `spora-cli share --os-routing` (needs root / `CAP_NET_ADMIN`, Linux only).

### Relays

By default `spora-cli share` registers with a built-in public relay, so the URL works from anywhere with no extra setup. Two ways to change that:

**Run your own relay.** The build also produces the `relay` daemon; run it on any Internet-routable machine and point `share` at it (repeat `--relay` for several):

```bash
relay --port 51820                        # on a public host — 443 is the default, but binding <1024 needs privilege
spora-cli share --relay your.host:51820   # register there instead of the built-in default
```

**Skip the relay entirely.** If the exit machine is *itself* Internet-routable, you don't need a relay at all: advertise a direct endpoint and clients dial the sharer straight — no relay, no relay bandwidth.

```bash
spora-cli share --direct your.public.host:51820
```

See [`relay/README.md`](relay/README.md) for running a relay in production — its TCP/TLS and Noise-UDP carriers, capability-token authorization, and session log.

### Connect — be a client

```bash
sudo spora-cli use "https://spora.to/s/…"
```

A full VPN client on Linux, macOS and Windows: it brings up the tunnel interface (TUN / `utun` / wintun), routes your traffic through it, sends your DNS to the sharer (whose exit resolves through its own resolvers), follows the path's discovered MTU, and undoes all of it on exit (Ctrl+C / SIGTERM). It needs privileges — root on Linux/macOS, an elevated console on Windows (where `wintun.dll` from [wintun.net](https://www.wintun.net/) must sit next to the executable).

The host's own default route is never replaced: on Linux the tunnel lives in its own routing table behind two policy rules (the wg-quick model), elsewhere as the two half-default routes — and the tunnel's own sockets toward the relay, the STUN servers, and the hole-punched peer are kept on the physical uplink (`SO_MARK` / `IP_BOUND_IF` / `IP_UNICAST_IF`), so nothing loops.

Dials still leave over your normal network first; routes and DNS are only installed once the tunnel is up. Flags to shape it:

- `--route <CIDR>` (repeatable) — split tunnel: route only these prefixes; your more-specific local routes still win. `--no-routes` installs none at all (you route into the interface yourself).
- `--dns <IP>` (repeatable; default `100.64.0.53`, the sharer's DNS forwarder, which answers from the sharer's own resolvers and falls back to public ones) — the resolvers to use while connected; any other resolver must be public, because the exit drops traffic to private destinations. The sharer side has `--dns-upstream` to pick the forwarder's resolvers and `--no-dns-forwarder` to turn it off. With `--route`, the resolvers themselves are routed through the tunnel too, so split-tunnel DNS is not sent in cleartext over the uplink. `--no-dns` leaves the resolver alone.
- `--tun-addr` / `--tun-addr6` — the client's addresses inside the tunnel (defaults `10.11.0.2/24`, `fd00:5350::2/64`; must stay private/ULA). `--no-ipv6` keeps IPv6 out of the tunnel entirely — note that v6 traffic then *bypasses* it on a v6-capable host.
- `--mtu <N>` — pin the interface MTU instead of following the path's PMTUD-discovered budget (which is re-applied after a direct-path upgrade). Below 1280 requires `--no-ipv6` (IPv6's minimum link MTU).
- Only one managed `spora-cli use` runs at a time (an instance lock; `--tun-name` sessions are exempt).
- `--tun-name <name>` — attach to a pre-created TUN and only pump packets: nothing else on the host is touched; the caller owns the interface's address, MTU, routes and cleanup (Linux only; this is the automation/testing mode, and without a full-tunnel route set the tunnel's own relay endpoint must not be routed into the interface).

### What went wrong, when something does

Both `share` and `use` keep a **connection record**: a machine-readable account of one run — every step that was attempted, a reason code (from a fixed set, not free text) for every failure, quality samples while the tunnel is up, and how it ended. It lives at `$XDG_STATE_HOME/spora/records/`; `--no-record` turns it off and `--record-dir` moves it.

```bash
spora-cli record list                 # one line per run: when, how it ended, what failed first
spora-cli record show                 # the newest run, step by step
spora-cli record export -o run.json   # hand it to someone else
```

`list` and `show` take `--json`; `export` is always JSON. This is the thing to send when reporting a connection problem: it says *where* the attempt died rather than only that it did.

### Other overrides

Repeatable `--stun <host:port>` options (on `share`/`use`) replace the built-in ordered STUN fallback list used for direct-path discovery; `--tcp-relay` / `--nz-relay` (on `share`) advertise alternative-carrier relay endpoints for networks that block or fingerprint QUIC (see [`relay/README.md`](relay/README.md)).

With `--json`, `share` and `use` emit `path_activated` when a transport can
carry tunnel traffic. Its `carrier` is `quic`, `tcp_tls`, or `nz`; its `path`
is `relay`, `direct_advertised`, or `direct_punched`. The event appears for the
initial path and again after an acknowledged punched-path swap, so automation
and status UIs do not have to infer the active protocol from log prose.
