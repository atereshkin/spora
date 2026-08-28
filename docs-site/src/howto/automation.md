# Drive the CLI from scripts

Everything the CLI reports has a machine-readable form. This is the same
surface Spora's own test infrastructure drives, so it is kept stable and
exact.

## JSON events

With `--json`, `share` and `use` emit one JSON object per line on stdout
instead of prose:

```bash
spora share --json | while read -r line; do
  event=$(jq -r .event <<<"$line")
  ...
done
```

The first events you care about are `share_ready` (carries the URL) and
`tunnel_ready` (the tunnel interface is up). `path_activated` tells you
which transport is actually carrying traffic, and fires again when the
session upgrades to a punched direct path. The complete vocabulary, with
every field, is in the [JSON events reference](../reference/events.md).

Events are additive: new event types and new fields may appear over time,
so parse by name and ignore what you do not know.

## A tunnel your harness controls

For tests you usually do not want the CLI touching routing at all. Create
the TUN yourself, then attach:

```bash
ip tuntap add dev t0 mode tun user "$USER"
ip addr add 10.231.0.2/24 dev t0
ip link set t0 mtu 1280 up
ip route add 198.51.100.7/32 dev t0    # route the systems under test, never the relay
spora use "$URL" --tun-name t0 --json
```

In this mode the CLI guarantees it changes nothing on the host beyond
pumping packets; `tunnel_ready` reports `"mode": "attached"`. The MTU the
path discovers is still reported (`path_mtu`) so your harness can apply it
if it wants to.

## Clean shutdown

SIGTERM and SIGINT both disconnect cleanly and restore any host changes;
processes exit zero. SIGKILL skips cleanup by definition; the next
`spora use` repairs the client-side leftovers it finds. On Windows,
closing the console counts as a clean shutdown.

## Records for assertions

Every run also writes a diagnostic record: a structured account of what
was attempted and how it ended, with stable reason codes rather than
message strings. `spora record show --json` prints it, `--record-id` lets
you tag a run with your own correlation id, and `--record-dir` puts the
records where your harness expects them. See
[Find out why a connection failed](troubleshoot.md).
