# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spora is a peer-to-peer VPN/tunnel written in Rust. It creates encrypted network tunnels between two peers using UDP hole punching for NAT traversal, with a dumb UDP relay as a fallback when direct connection fails. Primary target is Android (via FFI), with CLI support for Linux and Windows.

## Build Commands

```bash
cargo build                    # Build all workspace crates
cargo build --release          # Release build
cargo test                     # Run tests
cargo clippy                   # Lint
./build-ffi.sh                 # Cross-compile for Android + generate Kotlin bindings
```

The FFI build requires Android NDK linkers configured in `~/.cargo/config.toml` and Android targets installed via `rustup target add`.

## Workspace Structure

Workspace members (resolver v3):

- **spora-core** — Core library. Exposes `share()` (sharer mode) and `connect(url)` (client mode). Contains all networking logic.
- **spora-cli** — CLI binary with `spora share` and `spora use <URL>` subcommands. Uses `tokio-tun` for TUN device on Unix.
- **spora-ffi** — Uniffi-based FFI for Android/JNI. Wraps core functions for Kotlin. Builds as `cdylib`.
- **spora-wincore**, **spora-winui** — Windows service + UI.
- **relay** — Dumb UDP relay (both `lib.rs` for use in tests and `main.rs` for the deployed binary). Forwards packets between peers by inspecting QUIC long-header DCIDs and tracking a small flow table. Speaks no QUIC, holds no TLS keys.
- **relay-client** — Tiny client of the relay protocol: the wire-protocol constants (`protocol` module) and the sharer's `register_loop` helper.

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

### Sharer (A) flow — `spora_core::share(identity, config)`

1. Receive `Identity` from the platform layer (already persisted on disk or in the OS keystore).
2. Bind UDP socket; `try_clone()` it so quinn owns one fd and `register_loop` uses the other.
3. Spawn `relay_client::register_loop` — every 30s sends a `[CTRL_MAGIC | REGISTER | routing_key]` UDP packet to the relay; the relay updates `routing_key -> A_addr`.
4. Stand up a quinn server `Endpoint` with the identity's cert. `accept_one()` performs the QUIC handshake, accepts a bidi stream, reads B's 16-byte secret, verifies, and yields an `E2eSession { conn, transport, signal }`.
5. Per session: wrap `transport` in `UpgradableTransport → KeepAliveTransport`; spawn `try_direct_upgrade` (responder role, with the identity); spawn the netstack tunnel.

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

### Wire protocol — relay control & QUIC routing (see `relay_client::protocol`)

- Sharer registration: `[0x80, 's', 'p', 'R', 0x01, <20-byte routing_key>]`. The leading `0x80` has the QUIC "fixed bit" clear, so QUIC parsers will not mistake control traffic for QUIC.
- QUIC long-header packets (Initial, Handshake): the relay parses out the DCID at byte offset 6, matches against registered routing keys, and installs a bidirectional `(B_addr, A_addr)` flow.
- QUIC short-header (1-RTT) packets: routed by 5-tuple via the flow table that was installed when the first Initial arrived.

### Token / URL format

```
https://spora.to/s/<base64url(routing_key || secret)>?r=<relay_host>:<relay_port>
```

`routing_key` is 20 bytes (the QUIC v1 DCID maximum); `secret` is 16 bytes. The blob is 36 bytes → 48 base64url chars.

### Transport Layer (`spora-core/src/transport/`)

The `Transport` trait = `Stream<Item=io::Result<Vec<u8>>> + Sink<Vec<u8>>`. Implementations:

- `QuicPeerTransport` (in `transport/quic.rs`) — wraps a `quinn::Connection`'s datagram channel as IP packets. Uses `NoopCc` so QUIC's congestion control doesn't fight inner TCP. Used by both relay-via and direct paths.
- `UpgradableTransport` (in `transport/upgradable.rs`) — wraps any transport; can be swapped to a new inner transport via `UpgradeSender`.
- `KeepAliveTransport` (in `transport/keepalive.rs`) — injects ICMP Echo Requests at configurable intervals; supports an `Adaptive` mode driven by an atomic knob (used for Android battery-aware behavior).
- `ReconnectTransport` (in `transport/mod.rs`) — wraps any transport; on error/close, re-dials via a closure.

Composition (client side): `QuicPeerTransport → UpgradableTransport → KeepAliveTransport → ReconnectTransport`. Server side omits the outermost `ReconnectTransport` (a new peer just opens a new QUIC connection at the QUIC server endpoint).

### Key Constants

- STUN server: `stun.l.google.com:19302`
- Default relay: `188.166.74.116:443` (UDP, not TLS now — the relay speaks no protocol other than the magic-prefix control packets and QUIC pass-through)
- Routing-key length: 20 bytes (fits in a QUIC v1 DCID)
- Secret length: 16 bytes
- Register interval: 30s. Relay registration timeout: 120s. Flow timeout: 60s.
- QUIC: initial_mtu=1200, PMTUD enabled, NoopCc, idle 30s, keepalive 10s.

## Conventions

- Edition 2024 across the workspace (spora-core now too).
- Async throughout using tokio with full features.
- Logging via `log` crate (env_logger in CLI, android_logger in FFI).
- Public API error type is currently `Result<T, String>`.
- The companion Android app lives in a sibling `../spora-android/` repo.
