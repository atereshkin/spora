# JSON events

With `--json`, `share` and `use` print one JSON object per line on stdout.
Every object has an `"event"` name and a `"v": 1` schema version. The
vocabulary is additive: new events and new fields may appear, so match on
names and ignore unknown members. Log text goes to stderr and never mixes
into the stream.

## Lifecycle

| event | emitted by | meaning |
|---|---|---|
| `share_ready` | share | The share is up and registered. Fields: `url`, `routing_key`, `identity_file`, `tun_name` (with `--os-routing`, else `null`), `record_dir`, `upgrade_enabled`. |
| `tunnel_ready` | use | The tunnel interface is up and pumping. Fields: `mode` (`"vpn"` or `"attached"`), `tun_name`, `record_dir`, `upgrade_enabled`; in `vpn` mode also `tun_addr`, `tun_addr6` (`null` with `--no-ipv6`), `mtu`, `mtu_policy` (`"auto"` or `"fixed"`), `routes`, `dns`, `dns_method` (`null` when the resolver was left alone). |
| `stopping` | both | Shutdown has begun (Ctrl+C, SIGTERM, or console close). |
| `session_ended` | share | The client session ended. Field: `reason`. |

## Paths and transports

| event | emitted by | meaning |
|---|---|---|
| `relay_session_established` | both | The relay-path session is up. Field: `peer`. |
| `path_activated` | both | A transport can now carry tunnel traffic. Fields: `carrier` (`quic`, `tcp_tls`, `nz`), `path` (`relay`, `direct_advertised`, `direct_punched`), `local`, `peer`. Fires for the initial path and again after an acknowledged switch to a punched path, so automation never infers the active transport from log prose. |
| `direct_upgrade_succeeded` | both | A direct path replaced the relay path. Fields: `local`, `peer`. |
| `direct_upgrade_failed` | both | One direct-path attempt failed; the session stays on its current path and retries. Fields: `code` (a stable reason code), `reason` (human text). |
| `reconnecting` | use | The transport died; the client is redialing. |
| `reconnected` | use | The redial succeeded. |

## MTU

| event | emitted by | meaning |
|---|---|---|
| `path_mtu` | use | The path's measured packet budget, reported after path discovery settles and again after a direct upgrade. Field: `mtu`. |
| `tun_mtu` | use | The tunnel interface MTU was changed to match (VPN mode with the default `--mtu` policy). Field: `mtu`. |

## Housekeeping

| event | emitted by | meaning |
|---|---|---|
| `conn_log_degraded` | share | The connection log hit trouble (disk, overload) and marked a gap. Field: `detail`. |
