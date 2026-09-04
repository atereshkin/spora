# Connect through a friend

`spora use <URL>` is a full VPN client. With just the URL it will:

1. bring up a tunnel interface (`spora0` on Linux, a `utun` on macOS, a
   wintun adapter on Windows);
2. connect to the sharer, first through the relay in the URL, then directly
   when a path can be punched;
3. route your traffic into the tunnel, without ever touching your system's
   own default route;
4. send your DNS queries to the sharer, whose exit answers them from its
   own resolvers (or to public resolvers of your choosing);
5. follow the network path's real packet-size budget, so the interface MTU
   is what the path actually supports instead of a guess;
6. put everything back the way it was when you disconnect.

It needs privileges for all of that: `sudo` on Linux and macOS, an elevated
console on Windows. Only one managed tunnel runs at a time.

```bash
sudo spora use "https://spora.to/s/…"
```

## What it deliberately does not touch

Your default route stays untouched. On Linux the tunnel lives in its own
routing table behind policy rules; on macOS and Windows it uses two
half-width routes that take precedence by being more specific. Your LAN
keeps working: destinations your machine has a direct route to (your
printer, your NAS) are never pulled into the tunnel.

The tunnel's own housekeeping traffic (the connection to the relay, the
path discovery probes, the direct connection to the sharer) is pinned to
your physical network, whatever addresses it goes to, so it does not loop
into the tunnel. In the rare situations where it cannot be pinned (no
detectable uplink, for example) spora warns loudly instead of failing
silently.

## DNS

While connected, name lookups go to the sharer. The tunnel carries them to
a fixed resolver address inside it (`100.64.0.53`), and the sharer's exit
answers each one from whatever resolvers the sharer's own machine uses,
so names resolve exactly the way the sharer's network sees the world,
including the resolvers that network hands out, which are often the ones
that work best (or at all) from there. You never learn the sharer's
resolver addresses, and the sharer still carries no traffic to its own
LAN. One honest exception: Windows may
still consult other adapters' resolvers in parallel (its multi-homed name
resolution); the tunnel's resolver is made the preferred one, but a
strict lockdown would need firewall-level filtering that spora does not
install.

On exit the previous resolver settings are restored. If the process is
killed outright, the next start repairs the common leftovers (a replaced
`resolv.conf` on Linux, the per-service settings on macOS).

Pick different resolvers with `--dns` (repeatable), or keep your own setup
with `--no-dns`. Any resolver other than the sharer's must be a public
address: the sharer does not carry traffic to private ones. A sharer that
runs with `--no-dns-forwarder` does not answer the tunnel's resolver
address at all; connect to one with `--dns` and public resolvers.

## MTU

The two ends discover how large a packet the path between them can carry
and the client sets the tunnel interface to exactly that, typically 1414
bytes on an ordinary connection. When the tunnel later switches to a
direct path, the value is measured again and re-applied. Pin it manually
with `--mtu` if you must; below 1280 you also need `--no-ipv6`, because
IPv6 requires 1280.

## IPv6

The tunnel carries IPv6 by default. If the sharer's connection has no
IPv6, v6 connections are reset immediately at the sharer rather than
hanging; most applications (browsers in particular) then retry over v4 on
their own. `--no-ipv6` keeps IPv6 out of the tunnel entirely; note that
on a v6-capable network your v6 traffic then goes around the tunnel, not
through it.

## Disconnecting

Ctrl+C, SIGTERM, closing the console window on Windows: all of them
restore routes, resolver, and interface before the process exits. If the
process is killed outright, the interface disappears with it, and the next
`spora use` cleans up whatever else was left.
