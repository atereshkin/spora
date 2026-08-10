# relay

The Spora **relay** is a rendezvous and fallback forwarder. It lets a sharer behind NAT be reachable, and provides a fallback path when a direct connection can't be punched. Its defining property: it **never terminates the peers' end-to-end encryption** — it holds no keys, runs no handshake, and reads no plaintext. It only matches the two sides and shuttles bytes between them.

A public relay is built into the client, so most users never run one. Run your own to avoid depending on the default, to hold the accountability record yourself, or to serve a particular network. (If your exit is on an Internet-routable machine you can skip the relay altogether — see `--direct` in the top-level README.)

## What it forwards

Every carrier pairs a sharer and client by the **public 20-byte routing key** (the client-facing half of a Spora URL). The sharer registers `routing_key -> its address`; a client presents the routing key, and the relay splices the two together. It never needs — or gets — anything secret to do this.

- **UDP / QUIC** (default). The client's first packet is a QUIC Initial whose DCID *is* the routing key. The relay reads the DCID out of the long header, looks up the sharer, installs a bidirectional flow `(client <-> sharer)`, and forwards every later packet (long- or short-header) by source address.
- **UDP / Noise (`nz`)**. A non-QUIC-shaped carrier for networks that fingerprint or throttle QUIC. The client's first packet is `routing_key(20) | session index(4) | Noise NNpsk0 msg1(48)`; the relay routes on the leading 20-byte prefix — the same public value it reads from a QUIC DCID — then forwards by flow. It's checked even when a packet happens to look QUIC-shaped but matches no registered DCID.
- **TCP / TLS** (`--tcp-port`). For networks that block UDP/QUIC entirely. Sharers *park* a small pool of TCP connections at their routing key; a client CONNECTs, and the relay pops one and blind-splices the pair with `copy_bidirectional`. The end-to-end TLS runs through the splice, so — as with the UDP carriers — the relay sees no plaintext.

Only one client is served per routing key at a time. A second client that merely knows the (public) routing key can't displace an established one; a short grace window around the sharer's keep-alive keeps a live-but-idle session protected.

## Registration & trust

Sharer registrations are **signed and replay-guarded**. A REGISTER carries the routing key, a timestamp, the sharer's cert, and a signature. The relay verifies the signature, checks that `routing_key == SHA-256(cert)[..20]` (so the key commits to the cert), and requires a strictly increasing timestamp (a captured registration can't be replayed). The relay stores no secret — it only verifies.

By default the relay is **open**: any valid self-signed registration is accepted. Pass one or more `--issuer-key <base64 pubkey>` to require **capability-token authorization** — a sharer must then present a token signed by a trusted issuer and bound to its routing key. Keys and tokens are made with the `spora-issuer` tool (built from this crate):

```bash
spora-issuer gen --out issuer.key          # prints the public key to pass as --issuer-key
spora-issuer issue --key issuer.key --routing-key <hex-from-`spora share`>   # mint a token for one sharer
```

The sharer supplies the minted token via `spora-cli share --relay-token <token|file>`. Key *possession* is still proven end-to-end by the pinned cert during the peers' own handshake — the relay's check only gates who may register.

## Session log

By default the deployed relay keeps a **session log**: its own accountability record of each matched flow (client address ↔ sharer routing key, with timing and byte counts), separate from the sharer's connection log. Retention defaults to 90 days.

- `--no-session-log` disables it.
- `--session-log <path>` / `--session-log-retention-days <n>` configure it.
- Under systemd, set `StateDirectory=` and the log lands in `$STATE_DIRECTORY` automatically. The relay opens the log **before** binding and exits loudly if the path isn't writable, so a misconfiguration never becomes a silent gap.

## Running it

```bash
relay                          # UDP/443, dual-stack (::); binding :443 needs privilege
relay --port 51820             # unprivileged port
relay --bind 0.0.0.0           # v4-only host
relay --tcp-port 443           # also serve the TCP/TLS carrier
relay --issuer-key <pubkey>    # require capability tokens (omit for open mode)
```

Point sharers at it with `spora-cli share --relay <host>:<port>` (repeat for several). 443 is the default port because it blends with HTTPS; a real deployment usually wants it there (and behind a hardened systemd unit with `StateDirectory=`).
