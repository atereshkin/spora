# Find out why a connection failed

You do not have to reproduce a failure with more logging: every run of
`share` and `use` keeps a diagnostic record of what it attempted, what
failed, and why. When someone says "it did not work", the record is the
thing to look at, and to send.

```bash
spora record list
```

```text
when                  id         role   outcome              took  first failure
2026-08-28 18:53:04Z  6a9ec9d2   client never_connected      8.0s  relay_dial connect_timeout
2026-08-28 14:02:11Z  0c81d7a2   client closed_locally     541.2s  punch punch_timeout
```

`spora record show` walks the newest record step by step; `show <id>`
picks one. Failures carry a reason code from a fixed vocabulary, so two
people looking at two records can compare them meaningfully.

```bash
spora record show 6a9ec9d2
spora record export -o run.json     # attach this when asking for help
```

## Reading the common outcomes

**`never_connected`, with a failed `relay_dial` step.** The client never
reached the sharer. The reason code says how it died: `connect_timeout`
means nothing answered at all (the share is not running, the relay in the
URL is unreachable, or the network drops UDP); `handshake_timeout` means
something answered but the session never completed. If the sharer
advertises a TCP carrier, the client falls back to it automatically;
otherwise ask the sharer to add one.

**Connected, but the `punch` steps failed.** The session worked but stayed
on the relay: the record ends `closed_locally` (or `closed_by_peer`), the
`punch` steps show `punch_timeout` or similar, and there is no
`direct path after` line in `spora record show`. That is the designed
fallback, not an error: some NAT combinations (notably symmetric NAT on
both ends) cannot be punched. Expect the relay's bandwidth, not
direct-path bandwidth.

**Outcome `lost`, or repeated `reconnecting`.** The path keeps dying. Look
at the quality samples (`spora record show --samples`): probe loss and
round trip time while the tunnel was up are recorded, and tell you whether
the problem is the path or the endpoints.

**`spora use` refuses to start.** The error names the cause directly:
missing privileges (run with sudo, or elevate the console), another
running instance (only one managed tunnel at a time), or on Windows a
missing `wintun.dll`.

## When you report a problem

Send three things: the record (`spora record export`), the exact command
line, and `spora build-info --json` from both ends. The build info names
the exact source the binary was built from, so nobody debugs the wrong
version.
