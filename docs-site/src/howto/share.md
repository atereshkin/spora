# Share your connection

`spora share` turns your machine into the exit for someone you trust. No
port forwarding, no public IP, no configuration: the sharer registers with
a relay, and the client reaches it through that relay until a direct path
is punched.

```bash
spora share
```

## Your share URL is a credential

The printed `https://spora.to/s/…` link is the whole secret: whoever has it
can route traffic through your connection. Send it over a channel you
trust, and to people you trust. If it leaks, run `spora share --fresh` to
generate a new identity (and a new URL); the old link stops working.

The URL stays stable across restarts because the identity behind it is
persisted at `~/.config/spora/identity.bin`. Copy that file to move a share
to another machine, or keep several identities with `--identity-file`.

One share serves one client at a time. If a second client connects with the
same URL, it replaces the first.

## The connection log

You carry someone else's traffic, so the CLI keeps a local, private record
of what your connection was used for: which client session reached which
destination IP and port, when, and how much data moved. If your IP is ever
implicated in something you did not do, this is your answer to "what
actually happened".

```bash
spora log query --ip 203.0.113.5 --from 2026-08-01 --to 2026-08-28
spora log sessions
```

The log lives at `~/.local/state/spora/connlog/<routing-key>/`, keeps 90
days by default (`--conn-log-retention-days`), and never leaves your
machine. `spora log hold` pins a time range against retention if you have
been asked to preserve records. `--no-conn-log` disables logging entirely,
which also means you will have no record of what clients did with your IP.
`--conn-log-sessions-only` records who was connected and when, without
per-destination detail.

Be aware of the limits: destinations are IPs, not names, and a session that
stayed on the relay path never directly observes the client's own address.
The log states what kind of evidence each recorded address is.

## Your client's DNS

By default the client resolves names through you. Its queries arrive at a
resolver address inside the tunnel (`100.64.0.53`), and the share answers
them from the resolvers your own machine uses (`/etc/resolv.conf`; the
adapters' DNS servers on Windows), forwarding each query verbatim to one
of them and the answer verbatim back. The client never learns those
addresses, and it still cannot reach anything else on your LAN. Should
your resolvers stop answering, the share falls back to public ones
(8.8.8.8, 1.1.1.1) until they recover. `spora share` prints which
resolvers it is forwarding to.

`--dns-upstream <ip[:port]>` (repeatable) forwards to these servers
instead, and only to them: no public fallback. `--no-dns-forwarder`
switches the forwarding off; the client then needs public resolvers of
its own (`spora use --dns`).

Known limitation: if your system resolves over encrypted DNS configured in
the OS itself (DNS over TLS or HTTPS on Android, macOS, iOS or Windows,
as opposed to a local stub such as systemd-resolved doing it on the
machine's behalf), the share still sends the client's queries in plain
UDP to the same servers. They resolve, but not over the encrypted
transport you chose. With `--os-routing` the forwarder is wired in through
a DNAT rule, so it is unavailable under `--no-nat`.

## Running it permanently

The share is a single foreground process, so a systemd unit is all it
takes:

```ini
[Unit]
Description=Spora share
After=network-online.target

[Service]
ExecStart=/usr/local/bin/spora share
Restart=on-failure
User=spora

[Install]
WantedBy=multi-user.target
```

`systemctl stop` sends SIGTERM, which the CLI handles cleanly.

## The kernel exit

By default the sharer terminates client flows in a userland network stack
and re-originates them from ordinary sockets. That needs no privileges and
works everywhere. On Linux you can instead let the kernel route and NAT the
client's packets through a TUN device:

```bash
sudo spora share --os-routing
```

This performs better under load and behaves like a router rather than a
proxy. It changes the firewall (iptables) and sysctls while running and
undoes those changes on exit. See `spora share --help` for the
`--tun-addr`, `--tun-mtu`, and `--no-nat` knobs.
