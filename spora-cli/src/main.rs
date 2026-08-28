use clap::{Parser, Subcommand};
#[cfg(target_os = "linux")]
use spora_core::ExitMode;
use spora_core::record::Record;
use spora_core::{Config, connect, identity::Identity, share};
use std::path::PathBuf;
use url::Url;

/// Share-side netstack bypass (`spora share --os-routing`): Linux only (it
/// drives iptables and kernel forwarding).
#[cfg(target_os = "linux")]
mod os_route;
/// Client-side tunnel integration for `spora use` (interface, routes, MTU,
/// resolver) on Linux, macOS and Windows.
mod vpn;

/// Active keepalive/liveness probe interval (seconds) for the always-on CLI
/// client. Non-zero opts out of spora-core's dormant ("screen off") mode.
const KEEPALIVE_PROBE_SECS: u64 = 10;

/// Use jemalloc on non-Windows glibc targets. The default glibc allocator
/// holds onto pages under heavy alloc/free churn (every IP packet on the
/// share side allocates a `Vec<u8>`); jemalloc returns memory to the OS far
/// more aggressively. Excluded on musl (the static release builds):
/// jemalloc-sys does not build for aarch64-musl, and musl's own allocator
/// does not have glibc's page-retention behavior.
#[cfg(all(not(windows), not(target_env = "musl")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(name = "spora")]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug, Clone)]
enum Mode {
    /// Share over a tunnel. Loads (or creates on first run) a persistent
    /// identity at $XDG_CONFIG_HOME/spora/identity.bin so the share URL stays
    /// the same across invocations.
    Share {
        /// Override the identity file path.
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// Generate a fresh identity for this run and overwrite the
        /// persisted one.
        #[arg(long)]
        fresh: bool,
        /// Bypass the userland netstack: write client packets to a TUN device
        /// and let the kernel route/NAT them. Requires root (or
        /// CAP_NET_ADMIN). Linux only.
        #[arg(long)]
        os_routing: bool,
        /// TUN interface address in CIDR form (with --os-routing).
        #[arg(long, default_value = "10.213.0.1/24", requires = "os_routing")]
        tun_addr: String,
        /// TUN interface IPv6 address in CIDR form (with --os-routing). Must
        /// be a ULA (fc00::/7): clients may only source inner v6 traffic from
        /// ULA space, so a global address here would shadow a real prefix
        /// without ever being reachable.
        #[arg(long, default_value = "fd00:5350::1/64", requires = "os_routing")]
        tun_addr6: String,
        /// TUN MTU (with --os-routing).
        #[arg(long, default_value_t = 1280, requires = "os_routing")]
        tun_mtu: u16,
        /// With --os-routing: don't touch ip_forward or iptables. You are
        /// responsible for forwarding + NAT; per-client return routes on the
        /// TUN are still installed.
        #[arg(long, requires = "os_routing")]
        no_nat: bool,
        /// Override the relay address(es) (host:port) used for registration
        /// and baked into the share URL. Repeat the flag for multiple relays
        /// (the sharer registers with all; the client tries them IPv6-first
        /// then in order). A hostname with both A and AAAA records counts as
        /// two relays.
        #[arg(long)]
        relay: Vec<String>,
        /// Advertise a relay-less DIRECT endpoint (host:port) clients can dial
        /// straight to this sharer — no relay, no relay bandwidth. The sharer
        /// binds this port, so it must be publicly reachable. Repeat for
        /// several advertised addresses (they must share one port). Combine
        /// with --relay for a mix, or use alone for pure relay-less sharing.
        #[arg(long)]
        direct: Vec<String>,
        /// Advertise a TCP/TLS relay endpoint (host:port): a TCP relay carrying
        /// end-to-end TLS, for networks that block UDP/QUIC. The sharer connects
        /// out and parks connections at it. Repeat for several; combine with
        /// --relay to offer both (the client tries them in preference order).
        #[arg(long)]
        tcp_relay: Vec<String>,
        /// Advertise a Noise UDP (`nz`) relay endpoint (host:port): the dumb UDP
        /// relay carrying an end-to-end Noise datagram session — a high-entropy,
        /// non-QUIC-shaped transport for networks that fingerprint or throttle
        /// QUIC. Point it at a relay on a non-443 UDP port. Repeat for several;
        /// combine with --relay to offer both (the client tries them in order).
        #[arg(long)]
        nz_relay: Vec<String>,
        /// Override the ordered STUN servers (host:port) used for
        /// direct-upgrade endpoint discovery. Repeat for fallbacks.
        #[arg(long)]
        stun: Vec<String>,
        /// Keep the session on its initial relay/carrier path instead of
        /// attempting a direct upgrade.
        #[arg(long)]
        no_direct_upgrade: bool,
        /// Capability token authorizing this sharer to use the relay(s), when
        /// the relay requires one. Accepts a base64url token (as printed by
        /// `spora-issuer issue`) or a path to a file containing it. Not needed
        /// for open-mode relays.
        #[arg(long)]
        relay_token: Option<String>,
        /// Disable the connection log. By default the sharer keeps a local
        /// per-flow record (who connected to which destination, when) at
        /// $XDG_STATE_HOME/spora/connlog/<routing-key>/ — the sharer's own
        /// egress accountability record for answering abuse reports.
        #[arg(long)]
        no_conn_log: bool,
        /// Override the connection-log directory.
        #[arg(long, conflicts_with = "no_conn_log")]
        conn_log_dir: Option<PathBuf>,
        /// Connection-log retention in days; older records are deleted
        /// (unless pinned by `spora log hold`).
        #[arg(long, default_value_t = 90, conflicts_with = "no_conn_log")]
        conn_log_retention_days: u32,
        /// Log sessions only (who was connected and when), without per-flow
        /// destination records.
        #[arg(long, conflicts_with = "no_conn_log")]
        conn_log_sessions_only: bool,
        /// Don't keep a diagnostic record of how each connection went.
        #[arg(long)]
        no_record: bool,
        /// Override the diagnostic-record directory (default:
        /// $XDG_STATE_HOME/spora/records/).
        #[arg(long, conflicts_with = "no_record")]
        record_dir: Option<PathBuf>,
        /// Label this machine in every record it writes.
        #[arg(long, conflicts_with = "no_record")]
        record_label: Option<String>,
        /// Tie the records from this run to something outside it — a ticket,
        /// a test run.
        #[arg(long, conflicts_with = "no_record")]
        record_id: Option<String>,
        /// Emit newline-delimited JSON lifecycle events on stdout.
        #[arg(long)]
        json: bool,
    },
    Use {
        url: String,
        /// Override the ordered STUN servers (host:port) used for
        /// direct-upgrade endpoint discovery. Repeat for fallbacks.
        #[arg(long)]
        stun: Vec<String>,
        /// Keep the session on its initial relay/carrier path instead of
        /// attempting a direct upgrade.
        #[arg(long)]
        no_direct_upgrade: bool,
        /// Attach to this pre-created TUN instead of bringing up the tunnel
        /// interface yourself. The caller owns its address, MTU, routes and
        /// cleanup; nothing else on the host is touched (Linux only).
        #[arg(long)]
        tun_name: Option<String>,
        /// Address of the tunnel interface, in CIDR form. Must be private
        /// (RFC1918/CGNAT): sharers refuse other client sources.
        #[arg(long, default_value = vpn::DEFAULT_TUN_ADDR, conflicts_with = "tun_name")]
        tun_addr: String,
        /// IPv6 address of the tunnel interface, in CIDR form (must be a
        /// ULA, fc00::/7).
        #[arg(long, default_value = vpn::DEFAULT_TUN_ADDR6, conflicts_with = "tun_name")]
        tun_addr6: String,
        /// Carry no IPv6 in the tunnel: no v6 address, no v6 routes. On a
        /// v6-capable host, v6 traffic then bypasses the tunnel.
        #[arg(long, conflicts_with = "tun_name")]
        no_ipv6: bool,
        /// Route only this prefix into the tunnel (repeatable) instead of
        /// everything. The host's more specific routes (its LANs) still win.
        #[arg(long, conflicts_with = "tun_name")]
        route: Vec<String>,
        /// Bring the interface up with its address and MTU but install no
        /// routes and leave the resolver alone: you route into it yourself.
        #[arg(long, conflicts_with_all = ["tun_name", "route"])]
        no_routes: bool,
        /// Resolver to use while connected (repeatable; default 8.8.8.8 and
        /// 1.1.1.1). It is reached through the tunnel, so it must be public.
        #[arg(long, conflicts_with_all = ["tun_name", "no_routes"])]
        dns: Vec<String>,
        /// Leave the host's resolver configuration alone.
        #[arg(long, conflicts_with_all = ["tun_name", "dns"])]
        no_dns: bool,
        /// Pin the interface MTU (576..=1500) instead of following the
        /// path's discovered budget.
        #[arg(long, conflicts_with = "tun_name")]
        mtu: Option<u16>,
        /// Don't keep a diagnostic record of how the connection went.
        #[arg(long)]
        no_record: bool,
        /// Override the diagnostic-record directory (default:
        /// $XDG_STATE_HOME/spora/records/).
        #[arg(long, conflicts_with = "no_record")]
        record_dir: Option<PathBuf>,
        /// Label this machine in every record it writes.
        #[arg(long, conflicts_with = "no_record")]
        record_label: Option<String>,
        /// Tie this run's record to something outside it — a ticket, a test
        /// run.
        #[arg(long, conflicts_with = "no_record")]
        record_id: Option<String>,
        /// Emit newline-delimited JSON lifecycle events on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Print the source/build identity embedded in this executable.
    BuildInfo {
        /// Emit the complete build identity as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect the share's connection log (see docs/connection-logging.md).
    Log {
        #[command(subcommand)]
        cmd: LogCmd,
    },
    /// Read the diagnostic records of past connections: what was attempted,
    /// what failed, and why (see docs/diagnostic-record.md).
    Record {
        #[command(subcommand)]
        cmd: RecordCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum RecordCmd {
    /// One line per record: when, which end, how it ended, and the first
    /// thing that failed.
    List {
        /// Record directory (default: $XDG_STATE_HOME/spora/records/).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// How many records to list, newest first.
        #[arg(long, short = 'n', default_value_t = 20)]
        count: usize,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// The full story of one record: every step, in order, with its verdict.
    Show {
        /// Record id (or its first characters). Defaults to the newest.
        id: Option<String>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Machine-readable JSON output — the whole record, folded.
        #[arg(long)]
        json: bool,
        /// Include the quality samples taken while the tunnel was up.
        #[arg(long)]
        samples: bool,
    },
    /// Write records out as JSON, for handing to someone else.
    Export {
        #[arg(long)]
        dir: Option<PathBuf>,
        /// How many records to export, newest first.
        #[arg(long, short = 'n', default_value_t = 20)]
        count: usize,
        /// Write to this file instead of standard output.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum LogCmd {
    /// Query flows: "who connected to destination IP X during [from, to]".
    /// Prints matching flows, the sessions they belong to (with everything
    /// known about the client's outer address), and any log gaps or clock
    /// jumps overlapping the window.
    Query {
        /// Destination IP to match.
        #[arg(long)]
        ip: Option<std::net::IpAddr>,
        /// Destination port to match.
        #[arg(long)]
        port: Option<u16>,
        /// Window start: RFC3339 (2026-06-12T10:00:00Z), a date
        /// (2026-06-12), or unix seconds/milliseconds.
        #[arg(long)]
        from: Option<String>,
        /// Window end (same formats as --from).
        #[arg(long)]
        to: Option<String>,
        /// Machine-readable JSON output (for export/handover).
        #[arg(long)]
        json: bool,
        /// Log directory (default: derived from the identity file;
        /// overrides --identity-file when both are given).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Identity file used to locate the default log directory.
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
    /// List sessions with their address records.
    Sessions {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
    /// Manage legal holds: time ranges pinned against retention expiry
    /// (e.g. after receiving a preservation request).
    Hold {
        #[command(subcommand)]
        cmd: HoldCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum HoldCmd {
    /// Pin [from, to] against the retention sweep.
    Add {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        /// Why this hold exists (e.g. the case/reference number).
        #[arg(long)]
        note: Option<String>,
        /// Log directory; overrides --identity-file when both are given.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Identity file used to locate the default log directory.
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
    /// List active holds.
    List {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
    /// Remove a hold by id (records it pinned become subject to retention
    /// again on the next sweep).
    Remove {
        id: i64,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
}

/// Load a relay capability token from `--relay-token`: either a path to a file
/// containing the base64url token, or the token string itself. Returns the raw
/// (decoded) token bytes for `Config::relay_token`.
fn load_relay_token(arg: &str) -> Result<Vec<u8>, String> {
    let text = match std::fs::read_to_string(arg) {
        Ok(contents) => contents,
        Err(_) => arg.to_string(), // not a readable file: treat as a literal token
    };
    spora_core::authz::decode_b64(text.trim()).map_err(|e| format!("--relay-token: {e}"))
}

/// Split `host:port` on the LAST ':' (so bracketed IPv6 like `[::1]:443`
/// works) and validate the port.
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let Some(idx) = s.rfind(':') else {
        return Err(format!("'{}' is not a host:port pair (no ':' found)", s));
    };
    let (host, port_str) = (&s[..idx], &s[idx + 1..]);
    if host.is_empty() {
        return Err(format!("'{}' has an empty host part", s));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("'{}' is not a valid port in '{}'", port_str, s))?;
    Ok((host.to_string(), port))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("quinn", log::LevelFilter::Warn)
        .filter_module("quinn_proto", log::LevelFilter::Warn)
        .filter_module("quinn_udp", log::LevelFilter::Warn)
        .filter_module("tracing", log::LevelFilter::Warn)
        .filter_module("smoltcp", log::LevelFilter::Warn)
        .init();
    let args = Args::parse();
    match args.mode {
        Mode::Share {
            identity_file,
            fresh,
            os_routing,
            tun_addr,
            tun_addr6,
            tun_mtu,
            no_nat,
            relay,
            direct,
            tcp_relay,
            nz_relay,
            stun,
            no_direct_upgrade,
            relay_token,
            no_conn_log,
            conn_log_dir,
            conn_log_retention_days,
            conn_log_sessions_only,
            no_record,
            record_dir,
            record_label,
            record_id,
            json,
        } => {
            let path = identity_file.unwrap_or_else(default_identity_path);
            let identity = load_or_create_identity(&path, fresh)?;
            let mut config = Config::default();
            if let Some(tok) = relay_token {
                config.relay_token = Some(load_relay_token(&tok)?);
            }
            // --relay (UDP-QUIC) and --direct (relay-less) endpoints compose into
            // one preference-ordered list; if any is given it replaces the
            // built-in default relay.
            let mut relays = Vec::with_capacity(relay.len() + direct.len());
            for r in &relay {
                let (host, port) = parse_host_port(r).map_err(|e| format!("--relay: {}", e))?;
                relays.push(spora_core::identity::RelayEndpoint::new(host, port));
            }
            for d in &direct {
                let (host, port) = parse_host_port(d).map_err(|e| format!("--direct: {}", e))?;
                relays.push(spora_core::identity::RelayEndpoint::with_protocol(
                    host,
                    port,
                    spora_core::identity::RelayProtocol::Direct,
                ));
            }
            for t in &tcp_relay {
                let (host, port) = parse_host_port(t).map_err(|e| format!("--tcp-relay: {}", e))?;
                relays.push(spora_core::identity::RelayEndpoint::with_protocol(
                    host,
                    port,
                    spora_core::identity::RelayProtocol::TcpTls,
                ));
            }
            for z in &nz_relay {
                let (host, port) = parse_host_port(z).map_err(|e| format!("--nz-relay: {}", e))?;
                relays.push(spora_core::identity::RelayEndpoint::with_protocol(
                    host,
                    port,
                    spora_core::identity::RelayProtocol::NoiseUdp,
                ));
            }
            if !relays.is_empty() {
                config.relays = relays;
            }
            if !stun.is_empty() {
                for server in &stun {
                    parse_host_port(server).map_err(|e| format!("--stun: {}", e))?;
                }
                config.stun_servers = stun;
            }
            config.enable_direct_upgrade = !no_direct_upgrade;
            install_json_event_hook(&mut config, json);
            let connlog_dir = if no_conn_log {
                None
            } else {
                let dir = conn_log_dir.unwrap_or_else(|| default_connlog_dir(&identity));
                let mut cl = spora_core::connlog::ConnLogConfig::in_dir(&dir);
                cl.retention =
                    std::time::Duration::from_secs(u64::from(conn_log_retention_days) * 86_400);
                cl.log_destinations = !conn_log_sessions_only;
                #[cfg(target_os = "linux")]
                if os_routing {
                    cl.egress_lookup = Some(os_route::conntrack_egress_lookup());
                }
                config.conn_log = Some(cl);
                Some(dir)
            };
            let record_dir =
                record_config(&mut config, no_record, record_dir, record_label, record_id);
            #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
            let mut routing: Option<ShareRouting> = None;
            if os_routing {
                #[cfg(target_os = "linux")]
                {
                    let opts = os_route::Options::parse(&tun_addr, &tun_addr6, tun_mtu, !no_nat)?;
                    let guard = os_route::OsRoute::setup(&opts)?;
                    config.exit_mode = ExitMode::Custom(guard.session_handler());
                    routing = Some(guard);
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (&tun_addr, &tun_addr6, tun_mtu, no_nat);
                    return Err("--os-routing is only available on Linux (it drives iptables and kernel forwarding); the default netstack exit works everywhere".into());
                }
            }
            let routing_key_hex = spora_core::authz::hex_encode(&identity.routing_key);
            let upgrade_enabled = config.enable_direct_upgrade;
            let session = share(identity, config).await?;
            if json {
                emit_json_event(serde_json::json!({
                    "v": 1,
                    "event": "share_ready",
                    "url": session.url.as_str(),
                    "routing_key": routing_key_hex,
                    "identity_file": path,
                    "tun_name": routing.as_ref().map(|g| g.tun_name()),
                    "record_dir": record_dir,
                    "upgrade_enabled": upgrade_enabled,
                }))?;
            } else {
                println!("Share this URL with the peer that wants to connect:");
                println!("{}", session.url);
                println!("(Identity persisted at {})", path.display());
                println!(
                    "Routing key: {} (give this to your relay operator if the relay requires authorization)",
                    routing_key_hex
                );
                if let Some(g) = &routing {
                    println!(
                        "OS routing enabled: client traffic is forwarded by the kernel via {}.",
                        g.tun_name()
                    );
                }
                match &connlog_dir {
                    Some(dir) => println!(
                        "Connection log: {} (retention {} days; query with `spora log`, disable with --no-conn-log)",
                        dir.display(),
                        conn_log_retention_days
                    ),
                    None => println!(
                        "Connection log DISABLED: you will have no record of what clients did with your IP."
                    ),
                }
                if let Some(dir) = &record_dir {
                    println!(
                        "Diagnostic record: {} (read it with `spora record`, disable with --no-record)",
                        dir.display()
                    );
                }
                println!("Press Ctrl+C to stop sharing.");
            }
            wait_for_shutdown().await?;
            if json {
                emit_json_event(serde_json::json!({"v": 1, "event": "stopping"}))?;
            } else {
                println!("Stopping share session...");
            }
            session.stop().await;
            // `routing` (if any) drops here, after the session has stopped,
            // running OsRoute's cleanup. Dropping at scope end — rather than an
            // explicit call — means cleanup also runs if `share()` errored above
            // or the task panicked.
            drop(routing);
        }
        Mode::Use {
            url,
            stun,
            no_direct_upgrade,
            tun_name,
            tun_addr,
            tun_addr6,
            no_ipv6,
            route,
            no_routes,
            dns,
            no_dns,
            mtu,
            no_record,
            record_dir,
            record_label,
            record_id,
            json,
        } => {
            let mode = match tun_name {
                Some(name) => UseMode::Attach(name),
                None => UseMode::Vpn(vpn::Options::parse(
                    &tun_addr, &tun_addr6, no_ipv6, &route, no_routes, &dns, no_dns, mtu,
                )?),
            };
            run_use(UseArgs {
                url,
                stun,
                no_direct_upgrade,
                mode,
                no_record,
                record_dir,
                record_label,
                record_id,
                json,
            })
            .await?;
        }
        Mode::Log { cmd } => run_log_cmd(cmd)?,
        Mode::Record { cmd } => run_record_cmd(cmd)?,
        Mode::BuildInfo { json } => {
            let build = spora_core::record::build_info();
            if json {
                println!("{}", serde_json::to_string(&build)?);
            } else {
                println!(
                    "{} {}{} ({} {})",
                    build.version,
                    build.commit.as_deref().unwrap_or("unknown commit"),
                    if build.dirty { " +uncommitted" } else { "" },
                    build.target,
                    build.profile
                );
            }
        }
    }
    Ok(())
}

/// Share-side OS routing guard; only Linux has one.
#[cfg(target_os = "linux")]
type ShareRouting = os_route::OsRoute;
#[cfg(not(target_os = "linux"))]
struct ShareRouting;
#[cfg(not(target_os = "linux"))]
impl ShareRouting {
    fn tun_name(&self) -> &str {
        ""
    }
}

/// How `spora use` gets its tunnel interface.
enum UseMode {
    /// Bring the interface up and manage routes/MTU/resolver (the VPN client).
    Vpn(vpn::Options),
    /// Attach to a pre-created TUN and only pump packets: the caller owns the
    /// interface's address, MTU, routes and cleanup. This is the contract the
    /// field lab drives; it must keep touching nothing else on the host.
    Attach(String),
}

struct UseArgs {
    url: String,
    stun: Vec<String>,
    no_direct_upgrade: bool,
    mode: UseMode,
    no_record: bool,
    record_dir: Option<PathBuf>,
    record_label: Option<String>,
    record_id: Option<String>,
    json: bool,
}

async fn run_use(args: UseArgs) -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse(&args.url)?;
    if url.scheme() != "https" {
        return Err(format!(
            "unsupported scheme {}: expected an https:// share URL",
            url.scheme()
        )
        .into());
    }
    let mut config = Config::default();
    if !args.stun.is_empty() {
        for server in &args.stun {
            parse_host_port(server).map_err(|e| format!("--stun: {}", e))?;
        }
        config.stun_servers = args.stun.clone();
    }
    config.enable_direct_upgrade = !args.no_direct_upgrade;
    let json = args.json;

    // Phase 1 (VPN mode): the interface exists with its address and MTU but
    // no routes, so the relay dial and STUN below use the normal network —
    // the same two-phase bring-up as the Android client.
    let session = match &args.mode {
        UseMode::Vpn(opts) => {
            for ip in opts.unreachable_resolvers() {
                log::warn!(
                    "resolver {ip} is a private address: sharers drop traffic to private destinations, so it will not answer through the tunnel"
                );
            }
            Some(std::sync::Arc::new(vpn::Session::setup(opts.clone())?))
        }
        UseMode::Attach(_) => None,
    };
    let weak = session.as_ref().map(std::sync::Arc::downgrade);
    if let Some(s) = &session {
        config.protector = s.protector();
    }
    install_event_hook(&mut config, json, weak.clone());
    install_mtu_hook(&mut config, json, weak);

    let configured_record_dir = record_config(
        &mut config,
        args.no_record,
        args.record_dir,
        args.record_label,
        args.record_id,
    );
    if !json && let Some(dir) = &configured_record_dir {
        println!("Diagnostic record: {}", dir.display());
    }
    let result = match connect(url, &config).await {
        Ok(result) => result,
        Err(e) => return Err(format!("could not connect: {e}").into()),
    };
    // The CLI is always-on and has no screen state, so opt out of the
    // Android dormant/battery semantics. A keepalive knob of 0 means
    // "screen off" to spora-core, which disables the liveness probe
    // (a dead tunnel is never detected) and parks the direct upgrade
    // after a few transient failures. Set an active probe interval so
    // neither happens; only the Android FFI drives the knob to 0.
    result
        .keepalive_knob
        .store(KEEPALIVE_PROBE_SECS, std::sync::atomic::Ordering::Relaxed);
    if let Some(w) = result.keepalive_waker.lock().unwrap().take() {
        w.wake();
    }
    let record = result.record.clone();
    let cancel = result.cancel.clone();
    let upgrade_enabled = config.enable_direct_upgrade;
    let record_dir_json = config.record.as_ref().and_then(|r| r.dir.clone());

    match args.mode {
        UseMode::Attach(name) => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                return Err(
                    "--tun-name (attach to a pre-created TUN) is only available on Linux".into(),
                );
            }
            #[cfg(target_os = "linux")]
            {
                let tun = tokio_tun::Tun::builder()
                    .name(&name)
                    .try_build()
                    .map_err(|e| format!("could not attach TUN {name}: {e}"))?;
                let actual_tun_name = tun.name().to_string();
                if json {
                    emit_json_event(serde_json::json!({
                        "v": 1,
                        "event": "tunnel_ready",
                        "mode": "attached",
                        "tun_name": actual_tun_name,
                        "record_dir": record_dir_json,
                        "upgrade_enabled": upgrade_enabled,
                    }))?;
                } else {
                    println!(
                        "Attached to {actual_tun_name}; its address, MTU and routes are yours to manage."
                    );
                    println!("Press Ctrl+C to disconnect.");
                }
                let pump = spora_core::tun_util::start(result.transport, tun);
                tokio::pin!(pump);
                wait_for_tunnel_end(&mut pump, json, &record, &cancel).await?;
            }
        }
        UseMode::Vpn(_) => {
            let session = session.expect("VPN mode has a session");
            // Phase 2: the session is up and its sockets are protected — now
            // point the host at the tunnel.
            let activation = session.activate()?;
            let pump_handle = session.pump_handle()?;
            let opts = session.options();
            let tun_addr = format!("{}/{}", opts.tun_addr, opts.tun_prefix);
            let tun_addr6 = opts.tun_addr6.map(|(a, p)| format!("{a}/{p}"));
            if json {
                emit_json_event(serde_json::json!({
                    "v": 1,
                    "event": "tunnel_ready",
                    "mode": "vpn",
                    "tun_name": session.tun_name(),
                    "tun_addr": tun_addr,
                    "tun_addr6": tun_addr6,
                    "mtu": session.current_mtu(),
                    "mtu_policy": match opts.mtu {
                        vpn::MtuPolicy::Auto => "auto",
                        vpn::MtuPolicy::Fixed(_) => "fixed",
                    },
                    "routes": activation.routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "dns": activation.dns.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "dns_method": activation.dns_method,
                    "record_dir": record_dir_json,
                    "upgrade_enabled": upgrade_enabled,
                }))?;
            } else {
                let addrs = match &tun_addr6 {
                    Some(a6) => format!("{tun_addr}, {a6}"),
                    None => tun_addr.clone(),
                };
                println!(
                    "Tunnel up on {} ({addrs}), MTU {}{}.",
                    session.tun_name(),
                    session.current_mtu(),
                    match opts.mtu {
                        vpn::MtuPolicy::Auto => " (follows the path)",
                        vpn::MtuPolicy::Fixed(_) => " (pinned)",
                    }
                );
                match &opts.routes {
                    vpn::RouteSet::Default => println!("Routing all traffic through the tunnel."),
                    vpn::RouteSet::Prefixes(_) => println!(
                        "Routing {} through the tunnel.",
                        activation
                            .routes
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    vpn::RouteSet::None => {
                        println!(
                            "No routes installed (--no-routes): route into the interface yourself."
                        )
                    }
                }
                match activation.dns_method {
                    Some(how) => println!(
                        "Resolver: {} (set via {how}; restored on exit).",
                        activation
                            .dns
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    None => println!("Resolver left unchanged."),
                }
                println!("Press Ctrl+C to disconnect.");
            }
            let pump = vpn::run_pump(result.transport, pump_handle);
            tokio::pin!(pump);
            let outcome = wait_for_tunnel_end(&mut pump, json, &record, &cancel).await;
            // Undo the host changes while the interface still exists (the
            // pump, and with it the device, is dropped at scope exit).
            session.shutdown();
            outcome?;
        }
    }
    Ok(())
}

/// Run the pump until the tunnel ends or the user stops us, then close the
/// record explicitly: a process killed mid-run leaves a truncated record,
/// which is honest but much less useful than one with an ending.
async fn wait_for_tunnel_end(
    pump: &mut std::pin::Pin<&mut impl std::future::Future<Output = std::io::Result<()>>>,
    json: bool,
    record: &spora_core::record::Recorder,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::select! {
        _ = wait_for_shutdown() => {
            if json {
                emit_json_event(serde_json::json!({"v": 1, "event": "stopping"}))?;
            } else {
                println!("Disconnecting...");
            }
            cancel.cancel();
            record.close_shutdown(Some(spora_core::record::Reason::LocalShutdown));
            Ok(())
        }
        res = pump => {
            record.close_shutdown(None);
            res.map_err(|e| format!("tunnel: {e}"))?;
            Ok(())
        }
    }
}

/// Route spora-core's MTU reports (the carrier's datagram budget, reported
/// after PMTUD converges and again after a direct upgrade) to the tunnel
/// interface. The callback must not block, so it only queues; a task applies
/// the value off the async runtime and announces both the report and what was
/// set.
fn install_mtu_hook(
    config: &mut Config,
    json: bool,
    session: Option<std::sync::Weak<vpn::Session>>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u16>();
    config.mtu_callback = Some(std::sync::Arc::new(move |mtu| {
        let _ = tx.send(mtu);
    }));
    tokio::spawn(async move {
        while let Some(reported) = rx.recv().await {
            if json {
                let _ = emit_json_event(
                    serde_json::json!({"v": 1, "event": "path_mtu", "mtu": reported}),
                );
            } else {
                log::info!("path MTU budget reported: {reported}");
            }
            let Some(session) = session.as_ref().and_then(std::sync::Weak::upgrade) else {
                continue;
            };
            let applied =
                tokio::task::spawn_blocking(move || session.on_mtu_report(reported)).await;
            match applied {
                Ok(Ok(Some(mtu))) => {
                    if json {
                        let _ = emit_json_event(
                            serde_json::json!({"v": 1, "event": "tun_mtu", "mtu": mtu}),
                        );
                    } else {
                        log::info!("tunnel interface MTU set to {mtu}");
                    }
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => log::warn!("could not apply MTU {reported}: {e}"),
                Err(e) => log::warn!("MTU task: {e}"),
            }
        }
    });
}

fn emit_json_event(value: serde_json::Value) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn install_json_event_hook(config: &mut spora_core::Config, enabled: bool) {
    install_event_hook(config, enabled, None);
}

/// Consume spora-core's lifecycle events: print them as JSON when asked, and
/// let the VPN session re-detect its uplink when the tunnel reconnects (the
/// network may have changed underneath; macOS/Windows bind the outer sockets
/// to it).
fn install_event_hook(
    config: &mut spora_core::Config,
    json: bool,
    session: Option<std::sync::Weak<vpn::Session>>,
) {
    if !json && session.is_none() {
        return;
    }
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    config.event_hook = Some(std::sync::Arc::new(move |event| {
        let _ = sender.send(event);
    }));
    tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            if matches!(event, spora_core::TunnelEvent::Reconnecting)
                && let Some(s) = session.as_ref().and_then(std::sync::Weak::upgrade)
            {
                let _ = tokio::task::spawn_blocking(move || s.refresh_uplink()).await;
            }
            if json {
                let _ = emit_json_event(tunnel_event_json(event));
            }
        }
    });
}

fn tunnel_event_json(event: spora_core::TunnelEvent) -> serde_json::Value {
    use spora_core::TunnelEvent;
    match event {
        TunnelEvent::PathActivated {
            carrier,
            path,
            local,
            peer,
        } => serde_json::json!({
            "v":1,
            "event":"path_activated",
            "carrier":carrier.as_str(),
            "path":path.as_str(),
            "local":local,
            "peer":peer
        }),
        TunnelEvent::RelaySessionEstablished { peer } => {
            serde_json::json!({"v":1,"event":"relay_session_established","peer":peer})
        }
        TunnelEvent::DirectUpgradeSucceeded { local, peer } => serde_json::json!({
            "v":1,"event":"direct_upgrade_succeeded","local":local,"peer":peer
        }),
        TunnelEvent::DirectUpgradeFailed { code, reason } => serde_json::json!({
            "v":1,"event":"direct_upgrade_failed","code":code.as_str(),"reason":reason
        }),
        TunnelEvent::Reconnecting => serde_json::json!({"v":1,"event":"reconnecting"}),
        TunnelEvent::Reconnected => serde_json::json!({"v":1,"event":"reconnected"}),
        TunnelEvent::SessionEnded { reason } => {
            serde_json::json!({"v":1,"event":"session_ended","reason":reason})
        }
        TunnelEvent::ConnLogDegraded { detail } => {
            serde_json::json!({"v":1,"event":"conn_log_degraded","detail":detail})
        }
    }
}

// ---------- `spora log` ----------

fn run_log_cmd(cmd: LogCmd) -> Result<(), Box<dyn std::error::Error>> {
    use spora_core::connlog;
    match cmd {
        LogCmd::Query {
            ip,
            port,
            from,
            to,
            json,
            dir,
            identity_file,
        } => {
            let dir = resolve_connlog_dir(dir, identity_file)?;
            let db = connlog::open_readonly(&dir)?;
            let q = connlog::FlowQuery {
                ip,
                port,
                session: None,
                from_ms: from.as_deref().map(parse_time).transpose()?,
                to_ms: to.as_deref().map(parse_time).transpose()?,
            };
            let flows = connlog::query_flows(&db, &q)?;
            let mut session_ids: Vec<i64> = flows.iter().map(|f| f.session_id).collect();
            session_ids.sort_unstable();
            session_ids.dedup();
            let sessions = if session_ids.is_empty() {
                Vec::new()
            } else {
                connlog::query_sessions(&db, Some(&session_ids))?
            };
            let marks = connlog::query_marks(&db, q.from_ms, q.to_ms)?;
            if json {
                print_query_json(&flows, &sessions, &marks);
            } else {
                print_query_human(&flows, &sessions, &marks);
            }
        }
        LogCmd::Sessions { dir, identity_file } => {
            let dir = resolve_connlog_dir(dir, identity_file)?;
            let db = connlog::open_readonly(&dir)?;
            for s in connlog::query_sessions(&db, None)? {
                print_session(&s);
            }
        }
        LogCmd::Hold { cmd } => match cmd {
            HoldCmd::Add {
                from,
                to,
                note,
                dir,
                identity_file,
            } => {
                let dir = resolve_connlog_dir(dir, identity_file)?;
                let db = connlog::open_readwrite(&dir)?;
                let id =
                    connlog::add_hold(&db, parse_time(&from)?, parse_time(&to)?, note.as_deref())?;
                println!(
                    "hold {} added: records in [{}, {}] are pinned against retention",
                    id, from, to
                );
            }
            HoldCmd::List { dir, identity_file } => {
                let dir = resolve_connlog_dir(dir, identity_file)?;
                let db = connlog::open_readonly(&dir)?;
                let holds = connlog::list_holds(&db)?;
                if holds.is_empty() {
                    println!("no holds");
                }
                for (id, from, to, note) in holds {
                    println!(
                        "hold {}: {} .. {}  {}",
                        id,
                        fmt_ms(from),
                        fmt_ms(to),
                        note.unwrap_or_default()
                    );
                }
            }
            HoldCmd::Remove {
                id,
                dir,
                identity_file,
            } => {
                let dir = resolve_connlog_dir(dir, identity_file)?;
                let db = connlog::open_readwrite(&dir)?;
                if connlog::remove_hold(&db, id)? {
                    println!("hold {} removed", id);
                } else {
                    println!("no hold with id {}", id);
                }
            }
        },
    }
    Ok(())
}

fn print_query_human(
    flows: &[spora_core::connlog::FlowRow],
    sessions: &[spora_core::connlog::SessionRow],
    marks: &[spora_core::connlog::MarkRow],
) {
    if flows.is_empty() {
        println!("no matching flows");
    }
    for f in flows {
        let last = f.last_ms.map(fmt_ms).unwrap_or_else(|| "open".into());
        let mut extra = String::new();
        if let Some(e) = &f.egress_addr {
            extra.push_str(&format!("  egress {}", e));
        }
        if !f.confirmed {
            // Meter-path records: traffic offered to the tunnel; the handler
            // may still have dropped it.
            extra.push_str("  (offered, not confirmed egress)");
        }
        println!(
            "{} .. {}  {} {}:{} -> {}:{}  up {}B down {}B  {}{}  session {:016x}",
            fmt_ms(f.first_ms),
            last,
            proto_name(f.proto),
            f.src,
            f.src_port,
            f.dst,
            f.dst_port,
            f.bytes_up,
            f.bytes_down,
            match (f.end_reason.as_deref(), f.established) {
                (Some(r), true) => format!("established, {}", r),
                (Some(r), false) => format!("unanswered, {}", r),
                (None, true) => "established, still open".into(),
                (None, false) => "unanswered, still open".into(),
            },
            extra,
            f.session_id as u64,
        );
    }
    for s in sessions {
        print_session(s);
    }
    let mut warned = false;
    for m in marks {
        if matches!(m.kind.as_str(), "log_gap" | "clock_jump" | "flow_throttle") {
            if !warned {
                println!("\nWARNING: the log has irregularities overlapping this window:");
                warned = true;
            }
            println!(
                "  {} {} {}",
                fmt_ms(m.ts_ms),
                m.kind,
                m.detail.as_deref().unwrap_or("")
            );
        }
    }
}

fn print_session(s: &spora_core::connlog::SessionRow) {
    println!(
        "\nsession {:016x}: {} .. {}  via relay {}  ({})",
        s.id as u64,
        fmt_ms(s.start_ms),
        s.end_ms.map(fmt_ms).unwrap_or_else(|| "open".into()),
        s.relay_addr,
        s.end_reason.as_deref().unwrap_or("still active")
    );
    for (ts, kind, addr) in &s.addrs {
        let caveat = match kind.as_str() {
            "reported" => "  (client-asserted, UNVERIFIED)",
            "punch_verified" => "  (address-validated by hole punch)",
            "verified" => "  (verified direct connection)",
            "sharer_public" => "  (this sharer's own public address)",
            _ => "",
        };
        println!("  {}  {} {}{}", fmt_ms(*ts), kind, addr, caveat);
    }
    if !s
        .addrs
        .iter()
        .any(|(_, k, _)| k == "verified" || k == "punch_verified")
    {
        println!("  note: relay-via only — the client's outer address was never directly observed");
    }
}

fn print_query_json(
    flows: &[spora_core::connlog::FlowRow],
    sessions: &[spora_core::connlog::SessionRow],
    marks: &[spora_core::connlog::MarkRow],
) {
    let mut out = String::from("{\"flows\":[");
    for (i, f) in flows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"session\":\"{:016x}\",\"proto\":\"{}\",\"src\":\"{}\",\"src_port\":{},\"dst\":\"{}\",\"dst_port\":{},\"first\":\"{}\",\"last\":{},\"bytes_up\":{},\"bytes_down\":{},\"egress\":{},\"established\":{},\"confirmed_egress\":{},\"end_reason\":{}}}",
            f.session_id as u64,
            proto_name(f.proto),
            json_str(&f.src),
            f.src_port,
            json_str(&f.dst),
            f.dst_port,
            fmt_ms(f.first_ms),
            f.last_ms.map(|t| format!("\"{}\"", fmt_ms(t))).unwrap_or_else(|| "null".into()),
            f.bytes_up,
            f.bytes_down,
            f.egress_addr.as_deref().map(|e| format!("\"{}\"", json_str(e))).unwrap_or_else(|| "null".into()),
            f.established,
            f.confirmed,
            f.end_reason.as_deref().map(|r| format!("\"{}\"", json_str(r))).unwrap_or_else(|| "null".into()),
        ));
    }
    out.push_str("],\"sessions\":[");
    for (i, s) in sessions.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"id\":\"{:016x}\",\"start\":\"{}\",\"end\":{},\"end_reason\":{},\"relay\":\"{}\",\"addrs\":[",
            s.id as u64,
            fmt_ms(s.start_ms),
            s.end_ms.map(|t| format!("\"{}\"", fmt_ms(t))).unwrap_or_else(|| "null".into()),
            s.end_reason.as_deref().map(|r| format!("\"{}\"", json_str(r))).unwrap_or_else(|| "null".into()),
            json_str(&s.relay_addr),
        ));
        for (j, (ts, kind, addr)) in s.addrs.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"ts\":\"{}\",\"kind\":\"{}\",\"addr\":\"{}\"}}",
                fmt_ms(*ts),
                json_str(kind),
                json_str(addr)
            ));
        }
        out.push_str("]}");
    }
    out.push_str("],\"marks\":[");
    for (i, m) in marks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Mark details written by the logger are JSON objects already; emit
        // them as nested objects rather than escaped strings.
        let detail = match m.detail.as_deref() {
            Some(d) if d.starts_with('{') => d.to_string(),
            Some(d) => format!("\"{}\"", json_str(d)),
            None => "null".into(),
        };
        out.push_str(&format!(
            "{{\"ts\":\"{}\",\"kind\":\"{}\",\"detail\":{}}}",
            fmt_ms(m.ts_ms),
            json_str(&m.kind),
            detail,
        ));
    }
    out.push_str("]}");
    println!("{}", out);
}

fn json_str(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect()
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "other",
    }
}

fn fmt_ms(ms: i64) -> String {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.max(0) as u64);
    humantime::format_rfc3339_seconds(t).to_string()
}

/// Accepts RFC3339, a bare date (midnight UTC), or unix seconds/milliseconds.
fn parse_time(s: &str) -> Result<i64, String> {
    if let Ok(n) = s.parse::<i64>() {
        // Heuristic: values before ~5138 AD in ms are seconds.
        return Ok(if n < 100_000_000_000 { n * 1000 } else { n });
    }
    let attempt = if s.len() == 10 && s.as_bytes()[4] == b'-' {
        format!("{}T00:00:00Z", s)
    } else {
        s.to_string()
    };
    humantime::parse_rfc3339(&attempt)
        .map_err(|e| {
            format!(
                "'{}' is not a recognized time ({}); use RFC3339, YYYY-MM-DD, or unix seconds",
                s, e
            )
        })
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        })
}

fn resolve_connlog_dir(
    dir: Option<PathBuf>,
    identity_file: Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(d) = dir {
        return Ok(d);
    }
    let path = identity_file.unwrap_or_else(default_identity_path);
    let bytes = std::fs::read(&path).map_err(|e| {
        format!(
            "cannot read identity {} to locate the log ({}); pass --dir explicitly",
            path.display(),
            e
        )
    })?;
    let identity = spora_core::identity::Identity::from_bytes(&bytes)?;
    Ok(default_connlog_dir(&identity))
}

fn default_connlog_dir(identity: &spora_core::identity::Identity) -> PathBuf {
    let rk_hex: String = identity
        .routing_key
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    connlog_base_dir().join(rk_hex)
}

#[cfg(not(windows))]
fn connlog_base_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("spora")
        .join("connlog")
}

#[cfg(windows)]
fn connlog_base_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("spora")
        .join("connlog")
}

// ---------------------------------------------------------------------------
// diagnostic records

/// Point `config` at a record directory unless the user opted out. Recording
/// is on by default here: this is the machine you run when you want to know
/// what happened, and a diagnostic you have to enable before reproducing a
/// problem is one you do not have when it matters.
fn record_config(
    config: &mut Config,
    no_record: bool,
    dir: Option<PathBuf>,
    label: Option<String>,
    correlation_id: Option<String>,
) -> Option<PathBuf> {
    if no_record {
        return None;
    }
    let dir = dir.unwrap_or_else(default_record_dir);
    let mut rc = spora_core::record::RecordConfig::in_dir(&dir);
    rc.label = label;
    rc.correlation_id = correlation_id;
    config.record = Some(rc);
    Some(dir)
}

#[cfg(not(windows))]
fn default_record_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("spora")
        .join("records")
}

#[cfg(windows)]
fn default_record_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("spora")
        .join("records")
}

fn load_records(dir: Option<PathBuf>, limit: usize) -> Result<Vec<Record>, String> {
    let dir = dir.unwrap_or_else(default_record_dir);
    if !dir.exists() {
        return Err(format!(
            "no records at {} (run with recording on, or pass --dir)",
            dir.display()
        ));
    }
    let mut records = Record::read_dir(&dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .into_iter()
        .map(|(_, r)| r)
        .collect::<Vec<_>>();
    records.truncate(limit);
    Ok(records)
}

fn run_record_cmd(cmd: RecordCmd) -> Result<(), String> {
    match cmd {
        RecordCmd::List { dir, count, json } => {
            let records = load_records(dir, count)?;
            if json {
                println!("{}", spora_core::record::records_to_json(&records));
                return Ok(());
            }
            if records.is_empty() {
                println!("no records");
                return Ok(());
            }
            println!(
                "{:<21} {:<10} {:<6} {:<16} {:>8}  first failure",
                "when", "id", "role", "outcome", "took"
            );
            for r in &records {
                let took = r
                    .close
                    .as_ref()
                    .map(|c| format!("{:.1}s", c.at_ms as f64 / 1000.0))
                    .unwrap_or_else(|| "-".into());
                let first = match r.first_failure() {
                    Some(step) => format!(
                        "{} {}",
                        step.kind,
                        step.reason
                            .map(|x| x.to_string())
                            .unwrap_or_else(|| "-".into())
                    ),
                    None => "-".into(),
                };
                println!(
                    "{:<21} {:<10} {:<6} {:<16} {:>8}  {}",
                    spora_core::record::utc_timestamp(r.open.at_unix_ms),
                    short_id(&r.open.id),
                    r.open.role,
                    if r.truncated {
                        "unknown (cut)".to_string()
                    } else {
                        r.outcome().to_string()
                    },
                    took,
                    first
                );
            }
        }
        RecordCmd::Show {
            id,
            dir,
            json,
            samples,
        } => {
            let records = load_records(dir, 200)?;
            let record = match &id {
                Some(want) => records
                    .into_iter()
                    .find(|r| r.open.id.starts_with(want))
                    .ok_or_else(|| format!("no record whose id starts with {want}"))?,
                None => records
                    .into_iter()
                    .next()
                    .ok_or_else(|| "no records".to_string())?,
            };
            if json {
                println!("{}", record.to_json_pretty());
                return Ok(());
            }
            print_record(&record, samples);
        }
        RecordCmd::Export { dir, count, out } => {
            let records = load_records(dir, count)?;
            let json = spora_core::record::records_to_json(&records);
            match out {
                Some(path) => {
                    std::fs::write(&path, json.as_bytes())
                        .map_err(|e| format!("writing {}: {e}", path.display()))?;
                    eprintln!("{} record(s) written to {}", records.len(), path.display());
                }
                None => println!("{json}"),
            }
        }
    }
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

fn print_record(r: &Record, samples: bool) {
    let b = &r.open.build;
    println!(
        "{} {} record {}",
        spora_core::record::utc_timestamp(r.open.at_unix_ms),
        r.open.role,
        r.open.id
    );
    println!(
        "  build   {} {}{}  ({} {})",
        b.version,
        b.commit.as_deref().unwrap_or("unknown commit"),
        if b.dirty { " +uncommitted" } else { "" },
        b.target,
        b.profile
    );
    if let Some(rk) = &r.open.routing_key {
        println!("  identity {rk}");
    }
    if !r.open.endpoints.is_empty() {
        let eps: Vec<String> = r
            .open
            .endpoints
            .iter()
            .map(|e| format!("{}:{} ({})", e.host, e.port, e.carrier))
            .collect();
        println!("  endpoints {}", eps.join(", "));
    }
    if let Some(label) = &r.open.label {
        println!("  label   {label}");
    }
    println!();
    for step in &r.steps {
        let mut where_ = Vec::new();
        if let Some(v) = &step.via {
            where_.push(format!("via {v}"));
        }
        if let Some(p) = &step.peer {
            where_.push(format!("peer {p}"));
        }
        if let Some(c) = step.carrier {
            where_.push(c.to_string());
        }
        if let Some(p) = step.path {
            where_.push(p.to_string());
        }
        println!(
            "{:>8}ms  {:<17} {:<9} {:<18} {:<32} {}",
            step.at_ms,
            step.kind,
            step.outcome,
            step.reason
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".into()),
            where_.join(" "),
            step.dur_ms.map(|d| format!("{d}ms")).unwrap_or_default(),
        );
        if let Some(detail) = &step.detail {
            println!("           {detail}");
        }
    }
    for gap in &r.gaps {
        println!("{:>8}ms GAP: {} entries dropped", gap.at_ms, gap.dropped);
    }
    if samples {
        println!();
        for s in &r.samples {
            println!(
                "{:>8}ms sample {} {} rtt={} tx={}B rx={}B probes={}/{} mtu={}",
                s.at_ms,
                s.path,
                s.carrier,
                s.rtt_ms
                    .map(|v| format!("{v:.0}ms"))
                    .unwrap_or_else(|| "-".into()),
                s.tx_bytes,
                s.rx_bytes,
                s.probes_sent.unwrap_or(0) - s.probes_lost.unwrap_or(0),
                s.probes_sent.unwrap_or(0),
                s.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
            );
        }
    }
    println!();
    match &r.close {
        Some(c) => {
            println!(
                "ended {} after {:.1}s: {} session(s), {} reconnect(s), {:.1}s connected, {}B up / {}B down",
                c.outcome,
                c.at_ms as f64 / 1000.0,
                c.sessions,
                c.reconnects,
                c.connected_ms as f64 / 1000.0,
                c.tx_bytes,
                c.rx_bytes
            );
            if let Some(t) = c.first_connect_ms {
                println!("first connected after {:.1}s", t as f64 / 1000.0);
            }
            if let Some(t) = c.direct_ms {
                println!("direct path after {:.1}s", t as f64 / 1000.0);
            }
        }
        // Not the same as "it failed": the process went away before it could
        // say how this ended.
        None => println!("no ending recorded — the process went away mid-run"),
    }
}

/// Wait for an interactive (Ctrl+C / SIGINT) or service (SIGTERM) shutdown
/// signal. Handling SIGTERM matters for `--os-routing`: `systemctl stop` and
/// `kill` send SIGTERM, and we want OsRoute's cleanup to run before we exit.
async fn wait_for_shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(windows)]
    {
        // Console close, logoff and system shutdown give a few seconds'
        // grace; use them to put the routes and resolver back.
        use tokio::signal::windows::{ctrl_break, ctrl_close, ctrl_logoff, ctrl_shutdown};
        let mut brk = ctrl_break()?;
        let mut close = ctrl_close()?;
        let mut logoff = ctrl_logoff()?;
        let mut shutdown = ctrl_shutdown()?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = brk.recv() => Ok(()),
            _ = close.recv() => Ok(()),
            _ = logoff.recv() => Ok(()),
            _ = shutdown.recv() => Ok(()),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(not(windows))]
fn default_identity_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("spora").join("identity.bin")
}

#[cfg(windows)]
fn default_identity_path() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("spora")
        .join("identity.bin")
}

fn load_or_create_identity(
    path: &std::path::Path,
    fresh: bool,
) -> Result<Identity, Box<dyn std::error::Error>> {
    if !fresh && let Ok(bytes) = std::fs::read(path) {
        return Ok(Identity::from_bytes(&bytes)?);
    }
    let identity = Identity::generate();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_identity_atomically(path, &identity.to_bytes())?;
    Ok(identity)
}

/// Persist the identity (private key + secret) durably and privately.
///
/// `std::fs::write` truncates-then-writes in place: a crash or power loss
/// mid-write leaves a torn file, and `Identity::from_bytes` then fails on every
/// later launch — bricking `spora share` and the user's stable URL. It also
/// creates the file with the umask (typically world-/group-readable) and only
/// chmods afterward, leaving a window where the private key is exposed.
///
/// Instead, write to a sibling temp file created `0600` from the start, fsync
/// it, then atomically rename over the target: a reader (and a crash) sees
/// either the old file or the complete new one, never a truncated mix, and the
/// key bytes are never group/world-readable.
#[cfg(unix)]
fn write_identity_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("identity.bin");
    // Per-process temp name so a concurrent writer can't clobber our partial
    // file before the rename.
    let tmp = dir.join(format!(".{}.{}.tmp", stem, std::process::id()));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    let res = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Windows: the same temp-file-then-rename, without a POSIX mode (the file
/// inherits the profile directory's ACL, which is per-user).
#[cfg(windows)]
fn write_identity_atomically(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("identity.bin");
    let tmp = dir.join(format!(".{}.{}.tmp", stem, std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    let res = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| {
            drop(f);
            // `rename` does not replace an existing file on Windows.
            let _ = std::fs::remove_file(path);
            std::fs::rename(&tmp, path)
        });
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(all(test, unix))]
mod identity_persistence_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A unique scratch dir under the temp dir (no tempfile dependency).
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spora-cli-test-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn created_identity_is_private_and_round_trips() {
        let dir = scratch("create");
        let path = dir.join("identity.bin");

        let id = load_or_create_identity(&path, false).unwrap();

        // The private key must never be group/world readable, even briefly.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "identity file must be 0600");

        // Loading again (fresh=false) returns the SAME identity, not a new one.
        let again = load_or_create_identity(&path, false).unwrap();
        assert_eq!(
            id.to_bytes(),
            again.to_bytes(),
            "persisted identity must be stable across launches"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_write_replaces_without_leaving_a_temp() {
        let dir = scratch("atomic");
        let path = dir.join("identity.bin");

        write_identity_atomically(&path, b"first-version").unwrap();
        write_identity_atomically(&path, b"second-version-which-is-longer").unwrap();

        // The final file holds the complete new content (never a torn mix)...
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"second-version-which-is-longer"
        );
        // ...and the rename consumed the temp — no `.identity.bin.<pid>.tmp` litter.
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "temp file leaked: {:?}", leftover);

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod automation_surface_tests {
    use super::*;

    #[test]
    fn use_accepts_named_tun_json_and_direct_upgrade_control() {
        let args = Args::try_parse_from([
            "spora",
            "use",
            "https://spora.to/s/token?r=127.0.0.1:443",
            "--tun-name",
            "splab-deadbeef",
            "--no-direct-upgrade",
            "--json",
            "--record-id",
            "attempt-1",
            "--stun",
            "first.example:3478",
            "--stun",
            "second.example:53",
        ])
        .unwrap();
        match args.mode {
            Mode::Use {
                tun_name,
                no_direct_upgrade,
                json,
                record_id,
                stun,
                ..
            } => {
                assert_eq!(tun_name.as_deref(), Some("splab-deadbeef"));
                assert!(no_direct_upgrade);
                assert!(json);
                assert_eq!(record_id.as_deref(), Some("attempt-1"));
                assert_eq!(stun, ["first.example:3478", "second.example:53"]);
            }
            _ => panic!("parsed the wrong command"),
        }
    }

    #[test]
    fn build_info_has_machine_readable_mode() {
        let args = Args::try_parse_from(["spora", "build-info", "--json"]).unwrap();
        assert!(matches!(args.mode, Mode::BuildInfo { json: true }));
    }

    #[test]
    fn tunnel_events_have_machine_readable_path_notifications() {
        let activated = tunnel_event_json(spora_core::TunnelEvent::PathActivated {
            carrier: spora_core::record::Carrier::NoiseUdp,
            path: spora_core::record::PathKind::DirectPunched,
            local: Some("192.0.2.1:1234".parse().unwrap()),
            peer: "198.51.100.2:4321".parse().unwrap(),
        });
        assert_eq!(activated["event"], "path_activated");
        assert_eq!(activated["carrier"], "nz");
        assert_eq!(activated["path"], "direct_punched");

        let direct = tunnel_event_json(spora_core::TunnelEvent::DirectUpgradeSucceeded {
            local: "192.0.2.1:1234".parse().unwrap(),
            peer: "198.51.100.2:4321".parse().unwrap(),
        });
        assert_eq!(direct["event"], "direct_upgrade_succeeded");
        assert_eq!(direct["peer"], "198.51.100.2:4321");

        let failed = tunnel_event_json(spora_core::TunnelEvent::DirectUpgradeFailed {
            code: spora_core::record::Reason::StunTimeout,
            reason: "STUN did not answer".into(),
        });
        assert_eq!(failed["event"], "direct_upgrade_failed");
        assert_eq!(failed["code"], "stun_timeout");
    }
}
