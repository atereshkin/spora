//! Dumb UDP relay binary. See `lib.rs` for the protocol and state machine.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use log::info;
use tokio::net::UdpSocket;

use relay::sessionlog::{SessionLog, SessionLogConfig};
use relay::{serve, State};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// UDP port to bind (dual-stack wildcard unless --bind is given)
    #[arg(short, long, default_value_t = 443)]
    port: u16,
    /// Explicit bind address (e.g. 0.0.0.0 for v4-only hosts). Default binds
    /// `::` dual-stack so one socket serves v4 (as v4-mapped) and v6 peers.
    #[arg(short, long)]
    bind: Option<std::net::IpAddr>,
    /// Disable the persistent session log. By default the relay records each
    /// matched flow (client addr ↔ sharer routing key, with timing and byte
    /// counts) — the operator's accountability record (see sessionlog).
    #[arg(long)]
    no_session_log: bool,
    /// Session-log database path. Default: `$STATE_DIRECTORY/relay-sessions.sqlite`
    /// when run under systemd with `StateDirectory=` set (the recommended
    /// deployment), otherwise `relay-sessions.sqlite` in the working directory.
    #[arg(long, conflicts_with = "no_session_log")]
    session_log: Option<PathBuf>,
    /// Session-log retention in days; older sessions are swept.
    #[arg(long, default_value_t = 90, conflicts_with = "no_session_log")]
    session_log_retention_days: u32,
    /// Require capability-token authorization. Repeatable: each value is a
    /// base64url issuer public key (from `spora-issuer gen`). When omitted the
    /// relay runs in OPEN mode — any validly self-signed registration is
    /// accepted. When given, a sharer must present a capability token signed by
    /// one of these issuers and bound to its routing key.
    #[arg(long = "issuer-key", value_name = "BASE64_PUBKEY")]
    issuer_keys: Vec<String>,
    /// Also serve the TCP/TLS relay carrier on this port (alongside the UDP
    /// relay), for clients on networks that block UDP/QUIC. The relay only
    /// blind-splices; the end-to-end TLS stays between the peers.
    #[arg(long)]
    tcp_port: Option<u16>,
}

/// Where the session log lives when `--session-log` is not given. Prefers
/// systemd's `$STATE_DIRECTORY` (an absolute, service-owned, writable path
/// that systemd creates from `StateDirectory=`), so the on-by-default log
/// works under a hardened unit without a writable working directory. Falls
/// back to a cwd-relative file for non-systemd / development runs.
fn default_session_log_path() -> PathBuf {
    if let Some(state) = std::env::var_os("STATE_DIRECTORY") {
        // systemd may list several dirs colon-separated; use the first.
        let lossy = state.to_string_lossy();
        if let Some(first) = lossy.split(':').find(|s| !s.is_empty()) {
            return PathBuf::from(first).join("relay-sessions.sqlite");
        }
    }
    PathBuf::from("relay-sessions.sqlite")
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let bind = SocketAddr::new(
        args.bind
            .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        args.port,
    );

    // Open the session log before binding so a misconfigured/unwritable log
    // fails the operator loudly at startup rather than leaving a silent gap.
    let mut state = State::default();
    if !args.no_session_log {
        let path = args.session_log.unwrap_or_else(default_session_log_path);
        let mut cfg = SessionLogConfig::at(&path);
        cfg.retention = Duration::from_secs(u64::from(args.session_log_retention_days) * 86_400);
        match SessionLog::open(cfg) {
            Ok(log) => {
                info!(
                    "session log at {} (retention {} days)",
                    path.display(),
                    args.session_log_retention_days
                );
                state = state.with_session_log(log);
            }
            Err(e) => {
                eprintln!("relay: {e}");
                eprintln!(
                    "relay: the session log path is not writable. Under systemd, set \
                     `StateDirectory=spora-relay` in the unit (the relay then writes to \
                     $STATE_DIRECTORY automatically), or pass --session-log <writable path>, \
                     or --no-session-log to run without it."
                );
                std::process::exit(1);
            }
        }
    } else {
        info!("session log DISABLED (--no-session-log)");
    }

    // Authorization: with no issuer keys the relay stays in open mode (any valid
    // registration accepted). With one or more, registrations must carry a valid
    // capability token — see relay_client::authz.
    let issuer_keys = args
        .issuer_keys
        .iter()
        .map(|s| relay_client::authz::decode_pubkey(s))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| {
            eprintln!("relay: invalid --issuer-key: {e}");
            std::process::exit(1);
        });
    if issuer_keys.is_empty() {
        info!("authorization DISABLED (open mode): any valid registration is accepted");
    } else {
        info!(
            "authorization ENABLED: {} trusted issuer key(s)",
            issuer_keys.len()
        );
        state = state.with_issuer_keys(issuer_keys.clone());
    }

    // Optionally serve the TCP/TLS carrier alongside the UDP relay.
    if let Some(tcp_port) = args.tcp_port {
        let tcp_bind = SocketAddr::new(bind.ip(), tcp_port);
        match tokio::net::TcpListener::bind(tcp_bind).await {
            Ok(listener) => {
                info!("tcp-relay listening on TCP {tcp_bind}");
                tokio::spawn(relay::tcp::serve_tcp(
                    listener,
                    relay::tcp::TcpRelayState::with_issuer_keys(issuer_keys),
                ));
            }
            Err(e) => {
                eprintln!("relay: bind TCP {tcp_bind} failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let socket = bind_relay_socket(bind).unwrap_or_else(|e| panic!("bind {} failed: {}", bind, e));
    info!("dumb-relay listening on UDP {}", bind);
    serve(socket, state).await;
}

/// Bind the relay socket. A `::` wildcard is made explicitly dual-stack
/// (IPV6_V6ONLY off) rather than trusting the OS default, so v4 peers reach
/// the same socket as v4-mapped addresses and one flow table serves both
/// families — mixed-family flows (v4 sharer, v6 client) included.
fn bind_relay_socket(bind: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind),
        socket2::Type::DGRAM,
        None,
    )?;
    if bind.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    UdpSocket::from_std(socket.into())
}
