# Run your own relay

By default a share registers with the built-in public relay, so links work
with zero setup. Running your own removes that dependency, and it is a
small job: the relay is a deliberately dumb UDP forwarder. It carries
encrypted packets between the two ends without being able to read them,
holds no keys, and speaks no protocol of its own beyond a registration
message.

The relay ships as its own tarball in the same GitHub release
(`spora-relay-…`, which contains the `spora-relay` binary and the
`spora-issuer` token tool) and builds from the same repository (where a
source build names the binary plain `relay`).

```bash
# on a machine with a public address
spora-relay --port 51820

# on the sharing machine
spora share --relay your.host:51820
```

The relay's address is baked into the share URL, so clients need nothing
extra. Repeat `--relay` to register with several relays; clients try them
IPv6-first, then in listed order, which makes a second relay a cheap
fallback. A hostname with
both A and AAAA records counts as one relay per address family, and gives
you IPv6 connectivity for free.

## Skipping the relay entirely

If the sharing machine itself has a public, reachable address, no relay is
needed at all:

```bash
spora share --direct your.public.host:51820
```

Clients then dial the sharer directly. Combine with `--relay` to offer
both and let clients fall back.

## Restricting who may use your relay

An open relay forwards for any sharer that registers. To limit yours to
sharers you have authorized, the relay supports capability tokens; the
repository's [relay/README.md](https://github.com/atereshkin/spora/blob/main/relay/README.md)
covers issuing them, the alternative TCP and Noise carriers for networks
that block UDP or fingerprint QUIC, and the relay's own session log.
