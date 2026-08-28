# Split tunnels and other client setups

The default `spora use` routes everything. These are the other shapes it
supports.

## Split tunnel: only some destinations

Route only chosen prefixes through the sharer and leave the rest of your
traffic alone:

```bash
sudo spora use "$URL" --route 203.0.113.0/24 --route 198.51.100.0/24
```

Only those networks go through the tunnel. Your machine's more specific
routes still win, so a `--route` that overlaps your LAN does not cut you
off from it.

DNS still switches to the tunnel resolvers by default, and the resolvers
themselves are routed through the tunnel so lookups to them stay off your
uplink (with the Windows caveat described in
[Connect through a friend](connect.md#dns)). If you want your normal resolver instead, add
`--no-dns`; names will then resolve the way your local network sees them,
which may differ from what the routed destinations expect.

## No routes at all

```bash
sudo spora use "$URL" --no-routes
```

Brings the interface up with its address and MTU and stops there: no
routes, no resolver changes. Add routes yourself with `ip route`, `route`,
or your tooling of choice. This is the "I know what I am doing" mode for
custom policy routing.

## Attach to an interface you manage

```bash
spora use "$URL" --tun-name mytun0
```

Attach to a TUN device that already exists (Linux only). The CLI only
moves packets; the interface's address, MTU, routes, resolver, and cleanup
are entirely yours, and nothing else on the machine is touched. This is
the mode test harnesses drive. Two cautions: create the device and address
it before starting, and never route the relay's own address into the
interface, or the tunnel's transport would chase its own tail.

## Addressing inside the tunnel

The client defaults to `10.11.0.2/24` and `fd00:5350::2/64` inside the
tunnel. If those collide with networks you actually use, pick others with
`--tun-addr` and `--tun-addr6`. They must stay in private (RFC 1918 or
CGNAT) and ULA space respectively; sharers refuse other client addresses.

## Choosing STUN servers

Direct-path discovery asks STUN servers for your public address. The
built-in list works for most people; override it with `--stun host:port`
(repeatable, tried in order) if your network filters them or you prefer
your own.

## Keeping the relay path

`--no-direct-upgrade` disables the direct path entirely: the session stays
on the relay. Useful when a punched path is undesirable, for example when
testing relay behavior itself.
