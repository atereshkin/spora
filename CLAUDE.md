# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spora is a peer-to-peer VPN/tunnel written in Rust. It creates encrypted network tunnels between two peers using UDP hole punching for NAT traversal. Primary target is Android (via FFI), with CLI support for Linux and Windows.

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

Five crates in the workspace (resolver v3):

- **spora-core** — Core library. Exposes `share()` (server mode) and `connect(url)` (client mode). Contains all networking logic.
- **spora-cli** — CLI binary with `spora share` and `spora use <URL>` subcommands. Uses `tokio-tun` for TUN device on Unix.
- **spora-ffi** — Uniffi-based FFI for Android/JNI. Wraps core functions for Kotlin. Builds as `cdylib`.
- **relay** — QUIC relay server for bootstrapping peer connections. Subscribers register with a key, publishers connect with the same key.
- **relay-client** — Client library for the relay server (`RelayService::sub`/`publish`).

## Architecture

### Connection Flow

**Share (server) side:**
1. Subscribe to relay with a key → wait for peer
2. Receive peer's external address via TCP negotiation (`neg.rs`)
3. STUN hole punch → create UDP socket → send initial packet
4. Build virtual IP stack (`netstack-smoltcp`) on top of UDP transport
5. Relay TCP/UDP traffic between tunnel and real internet

**Connect (client) side:**
1. STUN hole punch to discover external address
2. Publish to relay → exchange endpoints via TCP negotiation
3. Create UDP socket → wrap in `ReconnectTransport` → wrap in `KeepAliveTransport`
4. Pipe transport to/from TUN device (`tun_util.rs`)

### Transport Layer (`spora-core/src/transport/`)

The `Transport` trait = `Stream<Item=io::Result<Vec<u8>>> + Sink<Vec<u8>>`. Implementations:

- `UdpTransport` — Raw UDP with 30s inactivity timeout. Filters packets by peer address.
- `ReconnectTransport` — Wraps any transport; on error/close, re-dials via a closure. Drops packets while reconnecting.
- `KeepAliveTransport` — Injects ICMP Echo Requests at configurable intervals to keep NAT mappings alive.

Transports compose: `UdpTransport` → `ReconnectTransport` → `KeepAliveTransport`.

### Key Constants

- STUN server: `stun.l.google.com:19302`
- Relay server: `188.166.74.116:2334`
- Base UDP port: `54321` (tries up to +10)
- Reconnect delay: 5s, UDP timeout: 30s, Keepalive: 10s

## Conventions

- Edition 2024 for newer crates, 2021 for spora-core
- Async throughout using tokio with full features
- Logging via `log` crate (env_logger in CLI, android_logger in FFI)
- Error handling uses `Result<T, String>` in public API (not yet migrated to proper error types)
- The companion Android app lives in a sibling `../spora-android/` repo
