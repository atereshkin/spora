mod carrier;
pub mod connlog;
pub mod e2e;
pub mod e2e_noise;
pub mod e2e_tls;
pub mod identity;
mod neg;
mod reassembly;
pub mod record;
pub mod server;
pub mod signal;
pub mod transport;
pub mod tun_util;

use std::collections::HashSet;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use log::{debug, info, warn};
use quinn::Connection;
use stunclient::StunClient;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
pub use tokio_util::sync::CancellationToken;
use url::Url;

use crate::connlog::{AddrKind, ConnLog, ConnLogConfig, SessionLog};
use crate::e2e::{authenticate_incoming, client_connect, client_endpoint, server_endpoint};
use crate::identity::{Identity, ROUTING_KEY_LEN, RelayEndpoint, RelayProtocol, SECRET_LEN, Token};
use crate::neg::{NegChannel, SignalNegChannel};
use crate::record::{
    Carrier, EndpointRef, Fault, MtuSource, Outcome, PathKind, PathState, Reason, Recorder, Role,
    RttSource, StepKind,
};
use crate::server::TunnelError;
pub use crate::server::is_local_address;
use crate::signal::SignalChannel;
use crate::transport::DialFuture;
pub use crate::transport::IpTransport;
use crate::transport::ReconnectTransport;
use crate::transport::keepalive::{
    KeepAliveConfig, KeepAliveMode, KeepAliveTransport, LinkCounters,
};
use crate::transport::upgradable::{UpgradeSender, upgradable_transport};
/// Capability-token authorization helpers (issuer keys, token encode/decode).
/// Re-exported so platform front-ends can present a `Config::relay_token`
/// without depending on `relay-client` directly.
pub use relay_client::authz;

/// Callback invoked once after the end-to-end QUIC connection's PMTUD has
/// converged. The application can use this to configure its TUN device.
pub type MtuCallback = Option<Arc<dyn Fn(u16) + Send + Sync>>;

pub type SocketProtector = Option<Arc<dyn Fn(i32) + Send + Sync>>;

/// Future driving one share-side session; it should resolve when the session
/// ends (transport closed/errored) or its cancellation token fires.
pub type SessionFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Invoked once per accepted client session when `ExitMode::Custom` is set.
/// Receives the fully composed session transport (keepalive + upgradable +
/// QUIC) and a token that is cancelled when a new peer replaces this session
/// or the share stops.
pub type SessionHandler =
    Arc<dyn Fn(IpTransport, CancellationToken) -> SessionFuture + Send + Sync>;

/// How the share side turns tunneled IP packets into real traffic.
#[derive(Clone, Default)]
pub enum ExitMode {
    /// Userland smoltcp netstack (default). Unprivileged: TCP/UDP flows are
    /// terminated in-process and re-originated from ordinary OS sockets.
    #[default]
    Netstack,
    /// Bypass the netstack: hand each session's `IpTransport` to the
    /// application, which is expected to move packets into the OS (e.g. a TUN
    /// device plus kernel forwarding/NAT). Requires privileges on the caller's
    /// side; the core still owns accept, registration, and direct upgrade.
    Custom(SessionHandler),
}

/// Call the protector callback with the socket's raw fd (unix only).
pub fn protect_socket(protector: &SocketProtector, _socket: &UdpSocket) {
    #[cfg(unix)]
    if let Some(f) = protector {
        use std::os::unix::io::AsRawFd;
        f(_socket.as_raw_fd());
    }
}

fn apply_protector_to_std(protector: &SocketProtector, _socket: &std::net::UdpSocket) {
    #[cfg(unix)]
    if let Some(f) = protector {
        use std::os::unix::io::AsRawFd;
        f(_socket.as_raw_fd());
    }
}

pub struct ConnectResult {
    pub transport: IpTransport,
    pub cancel: CancellationToken,
    pub keepalive_knob: Arc<AtomicU64>,
    pub keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    /// This run's diagnostic record (see [`record`]). Disabled — and inert —
    /// unless `Config::record` asked for one. It is closed when `cancel`
    /// fires; a caller that ends the session another way should close it.
    pub record: Recorder,
}

/// Every protocol interval/timeout that used to be a hardcoded constant.
/// `Default` is exactly today's production values; tests and the lab can
/// scale them down to make slow scenarios run in seconds of wall time.
#[derive(Clone, Debug)]
pub struct Timings {
    /// Cadence of the sharer's REGISTER packets to the relay.
    pub register_interval: Duration,
    /// QUIC max idle timeout (both relay-via and direct connections). Also
    /// the nz carrier's recv-idle deadline. This is the passive backstop
    /// reaper for a dead/quiet session (no packets → connection torn down).
    pub quic_idle_timeout: Duration,
    /// Interval of the SHARE side's reactive ICMP keepalive (NOT a quinn
    /// keep-alive anymore — quinn's periodic keepalive was removed so the
    /// transport-agnostic keepalive layer is the single, knob-honoring
    /// control point; see `transport::quic::build_transport_config`). The
    /// client side is knob-driven (Adaptive), not this.
    pub quic_keep_alive: Duration,
    /// `ReconnectTransport` sleep after a failed dial.
    pub reconnect_delay: Duration,
    /// Initiator retry delay after a failed direct-upgrade attempt.
    pub upgrade_retry_delay: Duration,
    /// How long the transport router holds the current transport's death
    /// waiting for an in-flight direct-upgrade swap before propagating it
    /// (see `transport::upgradable`). Must cover the responder's conclusion
    /// racing the initiator's close of the old path — which can trail by a
    /// QUIC PTO or two (hundreds of ms) on high-RTT paths, not just a
    /// reordered flight.
    pub upgrade_rescue_grace: Duration,
    /// Timeout for each of the two punch phases (punch exchange + verify).
    pub punch_phase_timeout: Duration,
    /// Interval between punch/verify packets within a phase.
    pub punch_send_interval: Duration,
    /// Initiator timeout waiting for the responder's endpoint over the
    /// signal channel.
    pub endpoint_exchange_timeout: Duration,
    /// Per-relay budget for the client's relay-via dial (handshake + accept
    /// ack). When it elapses the client fails over to the next relay, so a
    /// dead/censored relay doesn't stall the whole connect on one endpoint.
    pub relay_dial_timeout: Duration,
    /// Adaptive keepalive: send-silence gap that re-activates probing.
    pub keepalive_idle_threshold: Duration,
    /// Adaptive keepalive: how long to wait for a ping response.
    pub keepalive_response_timeout: Duration,
    /// Adaptive keepalive: inbound within this window keeps the peer alive.
    pub keepalive_inbound_grace: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            register_interval: relay_client::DEFAULT_REGISTER_INTERVAL, // 30s
            quic_idle_timeout: Duration::from_secs(30),
            quic_keep_alive: Duration::from_secs(10),
            reconnect_delay: transport::RECONNECT_DELAY, // 5s
            upgrade_retry_delay: Duration::from_secs(15),
            upgrade_rescue_grace: Duration::from_secs(2),
            punch_phase_timeout: Duration::from_secs(5),
            punch_send_interval: Duration::from_millis(300),
            endpoint_exchange_timeout: Duration::from_secs(10),
            relay_dial_timeout: Duration::from_secs(8),
            keepalive_idle_threshold: Duration::from_secs(20),
            keepalive_response_timeout: Duration::from_secs(3),
            keepalive_inbound_grace: Duration::from_secs(5),
        }
    }
}

/// Lifecycle notifications emitted by `share()`/`connect()` sessions.
#[derive(Debug, Clone)]
pub enum TunnelEvent {
    /// A relay-via QUIC session is up (sharer: peer accepted; client:
    /// connected to the sharer). `peer` is the remote address of the QUIC
    /// connection — the relay's address when the path goes through it.
    RelaySessionEstablished { peer: SocketAddr },
    /// A direct connection was established and handed to the transport
    /// router. The actual swap applies on the router's next poll, so traffic
    /// may ride the relay for a brief moment after this event fires.
    DirectUpgradeSucceeded { local: SocketAddr, peer: SocketAddr },
    /// One direct-upgrade attempt failed (the upgrade task may retry).
    /// `code` is the vocabulary entry (see [`record::Reason`]) and is what
    /// anything counting failures should use; `reason` is the same thing in
    /// words, for a human reading a log.
    DirectUpgradeFailed { code: Reason, reason: String },
    /// Client only: a re-dial is starting after the transport died.
    Reconnecting,
    /// Client only: the re-dial succeeded.
    Reconnected,
    /// Share side: the active session ended (replaced by a new peer,
    /// cancelled, or its transport closed).
    SessionEnded { reason: String },
    /// Share side: the connection log could not be written (disk full, IO
    /// error). The tunnel is unaffected; the gap is recorded in the log
    /// itself once writing recovers.
    ConnLogDegraded { detail: String },
}

/// Hook invoked inline from the tunnel's async tasks for every
/// [`TunnelEvent`]. **Hooks must be non-blocking** — do the minimum (e.g.
/// push into an unbounded channel) and return; blocking here stalls the
/// session that emitted the event.
pub type EventHook = Option<Arc<dyn Fn(TunnelEvent) + Send + Sync>>;

fn emit(hook: &EventHook, event: TunnelEvent) {
    if let Some(h) = hook {
        h(event);
    }
}

#[derive(Clone)]
pub struct Config {
    pub stun_server: String,
    /// Relays to use, in preference order. The sharer registers with ALL of
    /// them; the client tries them IPv6-first until one bootstraps a session
    /// (so a censored/dead relay fails over to the next). A hostname that has
    /// both A and AAAA records expands to two endpoints at resolve time.
    pub relays: Vec<crate::identity::RelayEndpoint>,
    pub protector: SocketProtector,
    pub mtu_callback: MtuCallback,
    /// Share side only: what consumes the tunneled IP packets.
    pub exit_mode: ExitMode,
    /// Protocol intervals/timeouts. Defaults are production values.
    pub timings: Timings,
    /// Lifecycle event hook. Must be non-blocking (see [`EventHook`]).
    pub event_hook: EventHook,
    /// Whether to attempt the direct (hole-punched) upgrade after a relay-via
    /// session is established. Disabling holds the session on the relay; the
    /// signal channel is kept open so the peer's upgrade attempts time out
    /// instead of seeing EOF.
    pub enable_direct_upgrade: bool,
    /// Share side only: per-flow connection logging (see [`connlog`]).
    /// `None` disables it at the core level; platforms are expected to
    /// enable it by default with a platform-appropriate directory. When set
    /// but unwritable, `share()` fails loudly rather than running unlogged.
    pub conn_log: Option<ConnLogConfig>,
    /// Whether, and where, to keep a diagnostic record of how each
    /// connection went (see [`record`]). `None` — the default — records
    /// nothing: writing to a user's disk is the platform's decision, not the
    /// core's. Platforms that want the "send logs" story, and the lab, set a
    /// directory here.
    pub record: Option<record::RecordConfig>,
    /// Share side only: an opaque capability token attached to every relay
    /// registration, proving this sharer is authorized to use the relay(s).
    /// `None` registers in open mode (accepted by relays configured without
    /// issuer keys). Obtain one from the relay operator; see
    /// `relay_client::authz`.
    pub relay_token: Option<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stun_server: "stun.l.google.com:19302".into(),
            relays: vec![crate::identity::RelayEndpoint::new("167.71.66.250", 443)],
            protector: None,
            mtu_callback: None,
            exit_mode: ExitMode::Netstack,
            timings: Timings::default(),
            event_hook: None,
            enable_direct_upgrade: true,
            conn_log: None,
            record: None,
            relay_token: None,
        }
    }
}

pub struct ShareSession {
    pub url: Url,
    pub cancel: CancellationToken,
    pub task: JoinHandle<()>,
}

impl ShareSession {
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }

    pub fn abort(self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

/// Start sharing under the given `Identity` (cert + key + secret).
///
/// Identity persistence is the caller's responsibility. Use
/// `Identity::generate()` once and persist `identity.to_bytes()` somewhere
/// platform-appropriate (a file under XDG_CONFIG_HOME on the CLI,
/// SharedPreferences on Android, the registry on Windows, etc.), then load
/// it back with `Identity::from_bytes()` on subsequent launches so the share
/// URL stays the same.
pub async fn share(identity: Identity, config: Config) -> Result<ShareSession, String> {
    let identity = Arc::new(identity);
    let routing_key = identity.routing_key;

    if config.relays.is_empty() {
        return Err("share: Config.relays is empty".into());
    }
    let url = identity.token(config.relays.clone()).to_url();

    // Resolve only the UDP-QUIC relays — the ones the signed-REGISTER loop
    // announces to. `TcpTls` relays are reached by the sharer connecting OUT
    // (spawn_tcp_registrars), not by UDP registration. A `Direct` endpoint is
    // the sharer's own advertised listener (the CLIENT resolves the name), so a
    // Direct/TcpTls hostname the sharer can't resolve locally must NOT abort it.
    let udp_relays: Vec<RelayEndpoint> = config
        .relays
        .iter()
        .filter(|r| r.protocol == RelayProtocol::UdpQuic)
        .cloned()
        .collect();
    let register_addrs: Vec<SocketAddr> = if udp_relays.is_empty() {
        Vec::new()
    } else {
        resolve_relays(&udp_relays)?
            .into_iter()
            .map(|(a, _)| a)
            .collect()
    };

    // A `Direct` (relay-less) sharer must bind the advertised port so clients
    // can dial it; a relay-only sharer keeps an ephemeral port (0). One socket
    // means one port, so all Direct endpoints must agree on it.
    let direct_ports: std::collections::BTreeSet<u16> = config
        .relays
        .iter()
        .filter(|r| !r.protocol.is_relayed())
        .map(|r| r.port)
        .collect();
    let bind_port = match direct_ports.len() {
        0 => 0,
        1 => *direct_ports.iter().next().unwrap(),
        _ => {
            return Err(format!(
                "share: all direct endpoints must use one port (a single socket), got {:?}",
                direct_ports
            ));
        }
    };

    // Bind dual-stack when any endpoint is (or may be) v6: a resolved relay v6,
    // or a Direct endpoint that is a v6 literal or a hostname (which may carry an
    // AAAA record the client will dial). Only a Direct *v4 literal* stays v4-only
    // — resolving the advertised name here (which may be external-only) is
    // avoided, so a dual-stack socket serves whichever family the client picks.
    let want_v6 = register_addrs.iter().any(|a| a.is_ipv6())
        || config
            .relays
            .iter()
            .any(|r| !r.protocol.is_relayed() && r.host.parse::<std::net::Ipv4Addr>().is_err());

    // Sign each relay registration with the identity's certificate key, so the
    // relay (which holds no secret) can verify the routing key is ours and
    // reject an on-path attacker's attempt to rebind it. ONE signer is shared
    // by every registrar generation (see QuicListenerCtx): its strictly-
    // increasing timestamp series must not restart when the listener rolls.
    let signer = Arc::new(std::sync::Mutex::new(
        relay_client::protocol::RegisterSigner::new(
            &identity.cert_der_bytes,
            &identity.key_der_bytes,
        )
        .map_err(|e| format!("build register signer: {}", e))?
        .with_token(config.relay_token.clone()),
    ));

    let cancel = CancellationToken::new();
    let rec = open_record(
        &config,
        Role::Exit,
        Some(&routing_key),
        endpoint_refs(&config.relays),
    );
    let listener_ctx = QuicListenerCtx {
        protector: config.protector.clone(),
        want_v6,
        register_addrs,
        register_interval: config.timings.register_interval,
        signer,
        identity: identity.clone(),
        timings: config.timings.clone(),
        cancel: cancel.clone(),
        rec: rec.clone(),
    };
    // Direct endpoints get their own PERMANENT endpoint on the advertised
    // port: it never rolls (the port is in the URL) and never registers.
    // The relay-facing listener always starts on an ephemeral port and
    // rolls per accepted session. Splitting the two means a mixed
    // Direct + relay config gets the full per-port behavior on its relay
    // path instead of falling back to the legacy shared endpoint.
    let direct_endpoint = if bind_port != 0 {
        let binding = rec
            .step(StepKind::ListenerBind)
            .path(PathKind::DirectAdvertised);
        let sock = match bind_share_udp(&config.protector, want_v6, bind_port) {
            Ok(s) => s,
            Err(e) => {
                binding.fail(Reason::BindFailed, e.clone());
                rec.close(Outcome::NeverConnected, Some(Reason::BindFailed), None);
                return Err(e);
            }
        };
        match sock.local_addr() {
            Ok(a) => binding.local(a).ok(),
            Err(_) => binding.ok(),
        }
        Some(server_endpoint(sock, &identity, &config.timings).map_err(|f| f.detail)?)
    } else {
        None
    };
    // Generation 0; bind errors surface from share() itself.
    let listener = match listener_ctx.spawn_listener(0) {
        Ok(l) => l,
        Err(e) => {
            rec.close(Outcome::NeverConnected, Some(Reason::BindFailed), None);
            return Err(e);
        }
    };
    info!(
        "share: e2e endpoint up, rk {:x?}, registering with {:?}, direct bind_port {}",
        &routing_key[..4],
        listener_ctx.register_addrs,
        bind_port
    );

    // Connection log: opened before the share goes live, so a default-on log
    // that cannot be written fails here loudly instead of running unlogged.
    let conn_log = match &config.conn_log {
        Some(cfg) => match ConnLog::open(cfg.clone(), &identity, config.event_hook.clone()) {
            Ok(cl) => Some(cl),
            Err(e) => {
                rec.close(
                    Outcome::NeverConnected,
                    Some(Reason::StorageError),
                    Some(e.clone()),
                );
                return Err(e);
            }
        },
        None => None,
    };

    let cancel_child = cancel.clone();
    let config_for_loop = config.clone();
    let identity_for_loop = identity.clone();
    let task = tokio::spawn(run_share_loop(
        listener,
        listener_ctx,
        direct_endpoint,
        identity_for_loop,
        cancel_child,
        config_for_loop,
        conn_log,
        rec,
    ));

    Ok(ShareSession { url, cancel, task })
}

/// Closes the exit's record however `run_share_loop` ends — including the
/// endings nobody planned.
struct ShareRecordGuard(Recorder);

impl Drop for ShareRecordGuard {
    fn drop(&mut self) {
        self.0.close_shutdown(Some(Reason::LocalShutdown));
    }
}

/// Everything needed to mint a fresh QUIC listener generation. The rolling
/// listener is the sharer half of the per-port session design: every accepted
/// session PERMANENTLY claims the socket it arrived on (its own endpoint, its
/// own relay flow, its own port), and the routing key immediately moves to a
/// fresh socket via re-registration — the relay's `rk -> addr` binding always
/// points at a port with no active flow, so a new client can never be
/// dropped for an old client's sake (the "actively-serving lockout"), and
/// same-DCID Initials can never be swallowed by a previous session's
/// connection (one endpoint per session). The relay needs no changes: its
/// flow table is keyed by addresses (existing flows keep forwarding), and a
/// REGISTER from a new source displaces the old binding.
///
/// NAT caveat (pre-existing for a client-less sharer, wider now): a listener
/// socket's NAT mapping is kept alive ONLY by its outbound REGISTERs, which
/// the relay never answers — on NATs whose unreplied-UDP timeout is at or
/// below the register interval (netfilter default: 30s, equal to ours;
/// CGNAT often less) the mapping can lapse between REGISTERs and inbound
/// Initials forwarded by the relay are dropped until the next REGISTER
/// re-opens it. The clean fix is a tiny relay REGISTER-ACK (makes the
/// conntrack state "replied", typical timeout 120s+, and doubles as
/// registration confirmation) — relay follow-up, not done here.
struct QuicListenerCtx {
    protector: SocketProtector,
    want_v6: bool,
    register_addrs: Vec<SocketAddr>,
    register_interval: Duration,
    signer: Arc<std::sync::Mutex<relay_client::protocol::RegisterSigner>>,
    identity: Arc<Identity>,
    timings: Timings,
    cancel: CancellationToken,
    rec: Recorder,
}

/// One listener generation: the quinn endpoint clients currently land on and
/// the registrar task announcing its socket to the relays.
struct QuicListener {
    endpoint: quinn::Endpoint,
    registrar: Option<JoinHandle<()>>,
}

impl QuicListenerCtx {
    /// Bind a socket (`bind_port` 0 except for generation 0 of a Direct
    /// sharer), build the endpoint, and start registering from it.
    fn spawn_listener(&self, bind_port: u16) -> Result<QuicListener, String> {
        let binding = self.rec.step(StepKind::ListenerBind);
        let std_socket = match bind_share_udp(&self.protector, self.want_v6, bind_port) {
            Ok(s) => s,
            Err(e) => {
                binding.fail(Reason::BindFailed, e.clone());
                return Err(e);
            }
        };
        match std_socket.local_addr() {
            Ok(a) => binding.local(a).ok(),
            Err(_) => binding.ok(),
        }
        let std_clone = std_socket
            .try_clone()
            .map_err(|e| format!("socket try_clone: {}", e))?;
        std_clone
            .set_nonblocking(true)
            .map_err(|e| format!("set_nonblocking on cloned socket: {}", e))?;
        let registrar_sock = Arc::new(
            tokio::net::UdpSocket::from_std(std_clone)
                .map_err(|e| format!("tokio::from_std: {}", e))?,
        );
        let endpoint =
            server_endpoint(std_socket, &self.identity, &self.timings).map_err(|f| f.detail)?;

        // The registrar selects on the share's cancel token, so `stop()` and
        // `abort()` (which cancels before aborting) both end it; a roll ends
        // it via `QuicListener::demote`. `register_loop`'s first tick fires
        // immediately, so a fresh generation displaces the old registration
        // within one packet's flight time.
        // There is no acknowledgement to wait for: relays never answer a
        // REGISTER, so this records that we started announcing, and nothing
        // about whether anyone accepted it. A registration rejected for a bad
        // token, a stale timestamp or an unauthorized source looks exactly
        // like this, and then like clients that never arrive.
        self.rec
            .mark(StepKind::Register)
            .detail(format!(
                "announcing to {} relay(s) every {:?}; relays do not acknowledge",
                self.register_addrs.len(),
                self.register_interval
            ))
            .ok();
        let registrar = (!self.register_addrs.is_empty()).then(|| {
            let addrs = self.register_addrs.clone();
            let interval = self.register_interval;
            let signer = self.signer.clone();
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = relay_client::register_loop(registrar_sock, addrs, interval, signer) => {}
                }
            })
        });
        Ok(QuicListener {
            endpoint,
            registrar,
        })
    }
}

impl QuicListener {
    /// Demote to session-private: stop announcing this socket (the routing
    /// key belongs to the next generation) and refuse new handshakes — a
    /// client racing the re-registration gets a fast refusal (dial fails,
    /// redial lands on the new port) instead of a hang.
    fn demote(&mut self) {
        if let Some(r) = self.registrar.take() {
            r.abort();
        }
        self.endpoint.set_server_config(None);
    }
}

/// Spawn TCP/TLS registrar pools for every `TcpTls` relay in the config. Each
/// pool worker parks a connection at the relay; when a client is spliced in it
/// runs the E2E TLS server and delivers the session, then re-parks to refill.
fn spawn_tcp_registrars(
    config: &Config,
    identity: Arc<Identity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    cancel: CancellationToken,
    rec: &Recorder,
) {
    // Connections kept parked per relay so a client always finds one.
    const POOL_SIZE: usize = 4;
    // Capability token presented in each REGISTER; empty for an open-mode relay.
    let token = config.relay_token.clone().unwrap_or_default();
    for relay in config
        .relays
        .iter()
        .filter(|r| r.protocol == RelayProtocol::TcpTls)
    {
        let addrs = match resolve_one_relay(relay) {
            Ok(a) => a,
            Err(e) => {
                warn!("tcp registrar: skipping unresolvable {}: {}", relay.host, e);
                continue;
            }
        };
        for addr in addrs {
            for _ in 0..POOL_SIZE {
                tokio::spawn(tcp_park_worker(
                    addr,
                    identity.clone(),
                    session_tx.clone(),
                    cancel.clone(),
                    config.protector.clone(),
                    token.clone(),
                    rec.clone(),
                ));
            }
        }
    }
}

/// One pool worker: keep a connection parked at `relay_addr`, delivering a
/// session whenever a client is spliced in, until cancelled.
#[allow(clippy::too_many_arguments)]
async fn tcp_park_worker(
    relay_addr: SocketAddr,
    identity: Arc<Identity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    cancel: CancellationToken,
    protector: SocketProtector,
    token: Vec<u8>,
    rec: Recorder,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let parking = rec
            .step_now(StepKind::RelayPark)
            .via(relay_addr)
            .carrier(Carrier::TcpTls);
        match park_and_accept(relay_addr, identity.as_ref(), &protector, &token, &cancel).await {
            Ok(Some(session)) => {
                parking.detail("a client was spliced in").ok();
                if session_tx.send((session, None)).is_err() {
                    return; // the share loop is gone
                }
            }
            // Reaped (idle) or refused (a gated relay rejecting a bad/absent
            // token) — re-park after a short pause so a refusal doesn't become a
            // tight reconnect loop.
            Ok(None) => {
                // The relay does not say which of the two this was, and this
                // is not the place to guess.
                parking.fail(
                    Reason::PeerClosed,
                    "the relay closed the parked connection (idle reap, or a refused token)",
                );
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
            }
            Err(e) => {
                debug!("tcp registrar {}: {}", relay_addr, e);
                parking.fail_with(&e);
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    }
}

/// Park one connection at the relay; when a client is spliced in, run the E2E
/// TLS server and return the session. `Ok(None)` = the relay reaped an idle
/// parked connection (re-park). Cancellable while parked.
async fn park_and_accept(
    relay_addr: SocketAddr,
    identity: &Identity,
    protector: &SocketProtector,
    token: &[u8],
    cancel: &CancellationToken,
) -> Result<Option<carrier::PeerSession>, Fault> {
    use tokio::io::AsyncWriteExt;
    let mut tcp = tokio::net::TcpStream::connect(relay_addr)
        .await
        .map_err(|e| Fault::from_io(&e).context("connect relay"))?;
    let _ = tcp.set_nodelay(true);
    carrier::protect_tcp(protector, &tcp);
    tcp.write_all(&relay_client::tcp::build_preamble(
        relay_client::tcp::role::REGISTER,
        &identity.routing_key,
        token,
    ))
    .await
    .map_err(|e| Fault::from_io(&e).context("register preamble"))?;

    // Park: wait (no timeout, cancellable) for the first byte — a client was
    // spliced in. EOF (0) means the relay reaped this idle parked connection
    // (its PARK_TTL); the caller re-parks.
    let mut peek = [0u8; 1];
    let n = tokio::select! {
        _ = cancel.cancelled() => {
            return Err(Fault::new(Reason::Cancelled, "cancelled while parked"));
        }
        r = tcp.peek(&mut peek) => r.map_err(|e| Fault::from_io(&e).context("park peek"))?,
    };
    if n == 0 {
        return Ok(None);
    }

    // A client is here — run the timed E2E TLS server handshake + secret.
    let transport = e2e_tls::accept(tcp, identity).await?;
    Ok(Some(carrier::PeerSession {
        transport,
        remote_addr: relay_addr,
        quic_conn: None,
        signal: None,
        fixed_mtu: carrier::STREAM_TUNNEL_MTU,
    }))
}

/// Sharer-side Noise UDP carrier. Bind a dedicated socket, register every
/// `NoiseUdp` relay from it (so those relays route clients here), and run a
/// multi-client accept dispatcher that delivers each authenticated client as a
/// session into `session_tx`. A no-op when the config lists no `NoiseUdp` relay.
fn spawn_noise_registrar(
    config: &Config,
    identity: Arc<Identity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    cancel: CancellationToken,
) {
    let nz_relays: Vec<RelayEndpoint> = config
        .relays
        .iter()
        .filter(|r| r.protocol == RelayProtocol::NoiseUdp)
        .cloned()
        .collect();
    if nz_relays.is_empty() {
        return;
    }
    let protector = config.protector.clone();
    let token = config.relay_token.clone();
    let cert_der = identity.cert_der_bytes.clone();
    let key_der = identity.key_der_bytes.clone();
    let register_interval = config.timings.register_interval;
    let hs_timeout = config.timings.relay_dial_timeout;
    let idle = config.timings.quic_idle_timeout;

    tokio::spawn(async move {
        let addrs: Vec<SocketAddr> = match resolve_relays(&nz_relays) {
            Ok(a) => a.into_iter().map(|(a, _)| a).collect(),
            Err(e) => {
                warn!("[share] nz: cannot resolve relays: {e}");
                return;
            }
        };
        if addrs.is_empty() {
            return;
        }
        let want_v6 = addrs.iter().any(|a| a.is_ipv6());
        // One signer across every generation: the strictly-increasing
        // timestamp series must survive listener rolls (see QuicListenerCtx).
        let signer = match relay_client::protocol::RegisterSigner::new(&cert_der, &key_der) {
            Ok(s) => Arc::new(std::sync::Mutex::new(s.with_token(token))),
            Err(e) => {
                warn!("[share] nz: build register signer: {e}");
                return;
            }
        };

        // Rolling listener, nz edition: each generation binds a fresh socket,
        // registers it, and serves handshakes until its dispatcher delivers a
        // session — that socket then belongs to the session (the dispatcher
        // keeps pumping it, but stops accepting new handshakes) and the next
        // generation takes over the routing key.
        loop {
            // A transient bind failure must not kill the nz carrier for the
            // share's lifetime — retry until it works or the share stops.
            let socket = loop {
                let bound = bind_share_udp(&protector, want_v6, 0).and_then(|s| {
                    s.set_nonblocking(true)
                        .map_err(|e| format!("set_nonblocking: {e}"))?;
                    UdpSocket::from_std(s)
                        .map(Arc::new)
                        .map_err(|e| format!("from_std: {e}"))
                });
                match bound {
                    Ok(s) => break s,
                    Err(e) => {
                        warn!("[share] nz: listener bind failed: {e}; retrying");
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                        }
                    }
                }
            };
            info!("[share] nz carrier up, registering with {:?}", addrs);

            let registrar = {
                let sock = socket.clone();
                let addrs = addrs.clone();
                let signer = signer.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = relay_client::register_loop(sock, addrs, register_interval, signer) => {}
                    }
                })
            };
            let accepting = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let (rolled_tx, rolled_rx) = tokio::sync::oneshot::channel::<()>();
            let dispatcher = tokio::spawn(noise_accept_dispatcher(
                socket,
                identity.clone(),
                session_tx.clone(),
                hs_timeout,
                idle,
                cancel.clone(),
                accepting,
                Arc::new(std::sync::Mutex::new(Some(rolled_tx))),
            ));

            tokio::select! {
                _ = cancel.cancelled() => {
                    registrar.abort();
                    // The dispatcher exits via its own cancel arm.
                    return;
                }
                // A session claimed this generation's socket: stop announcing
                // it (the dispatcher runs on, serving the session) and roll.
                _ = rolled_rx => {
                    registrar.abort();
                    drop(dispatcher); // detach; it lives with its session
                }
            }
        }
    });
}

/// Read the shared nz socket and route each datagram: to an existing session by
/// its `recv_index`, or — a fresh `routing_key`-prefixed msg1 — to a new
/// `noise_accept` whose dispatcher-assigned index we record for routing. The
/// relay is dumb, so all clients arrive from the relay's one address; demux is
/// purely by the session index, never by source address.
///
/// Rolling-listener wiring: on the FIRST successfully-authenticated session
/// the accept task clears `accepting` and fires `rolled` — the generation
/// manager then registers a fresh socket and this dispatcher becomes
/// session-private: it keeps routing the live session's datagrams but
/// ignores new handshakes, and exits once its routing tables empty out.
#[allow(clippy::too_many_arguments)]
async fn noise_accept_dispatcher(
    socket: Arc<UdpSocket>,
    identity: Arc<Identity>,
    session_tx: tokio::sync::mpsc::UnboundedSender<(carrier::PeerSession, Option<u64>)>,
    hs_timeout: Duration,
    idle: Duration,
    cancel: CancellationToken,
    accepting: Arc<std::sync::atomic::AtomicBool>,
    rolled: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
) {
    use crate::transport::noise::{DATA_MIN_LEN, NZ_MSG1_MIN, NZ_TUNNEL_MTU, noise_accept};
    type RawTx = tokio::sync::mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>;
    // idx_A -> that session's raw-datagram sender.
    let mut by_index: std::collections::HashMap<u32, RawTx> = std::collections::HashMap::new();
    // idx_B -> idx_A, so a client's retransmitted msg1 (its msg2 was lost) is
    // re-delivered to the same session instead of spawning a duplicate.
    let mut by_client: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    // One deobfuscator for this identity's whole flow. It reverses the wire
    // shaping before we inspect recv_index/routing_key at fixed offsets; the
    // clean bytes are what we route AND forward to the per-session channels.
    let shaper = crate::transport::shaper::nz_shaper(&identity.routing_key, &identity.secret);
    // The `routing_key` prefix is cleartext on the wire (a passive censor learns
    // it), so an attacker can forge msg1-shaped packets. We insert routing entries
    // BEFORE the psk-gated handshake completes (they're needed to route msg1
    // retransmits), so a failed accept must reap its entries or the tables grow
    // unbounded (memory-exhaustion DoS). Failed-accept tasks report back here; a
    // hard cap backstops any burst faster than the reap.
    const MAX_INFLIGHT: usize = 4096;
    let (reap_tx, mut reap_rx) = tokio::sync::mpsc::unbounded_channel::<(u32, u32)>();
    let mut buf = vec![0u8; 2048];
    // A demoted dispatcher's session can die SILENTLY (its peer just stops
    // sending), which recv_from alone can never observe — sweep the routing
    // tables for closed session channels on a timer and exit (releasing the
    // socket) once nothing is left to route. Without this, every nz session
    // would leak a socket + task for the share's lifetime.
    let mut cleanup = tokio::time::interval(Duration::from_secs(5));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let demoted = !accepting.load(std::sync::atomic::Ordering::Relaxed);
        let (n, src) = tokio::select! {
            _ = cancel.cancelled() => return,
            _ = cleanup.tick() => {
                if demoted {
                    by_index.retain(|_, tx| !tx.is_closed());
                    by_client.retain(|_, ia| by_index.contains_key(ia));
                    if by_index.is_empty() {
                        debug!("[share] nz: demoted dispatcher done, releasing socket");
                        return;
                    }
                }
                continue;
            }
            // A spawned accept task failed to authenticate — drop its pre-auth
            // routing entries so a forged-msg1 spray can't leak the tables.
            Some((ia, ib)) = reap_rx.recv() => {
                by_index.remove(&ia);
                by_client.remove(&ib);
                if demoted && by_index.is_empty() {
                    return;
                }
                continue;
            }
            r = socket.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(e) => { warn!("[share] nz recv: {e}"); continue; }
            },
        };

        // Reverse the wire shaping first; a non-shaped/garbage datagram drops.
        let Some(clean) = shaper.deobfuscate(&buf[..n]) else {
            continue;
        };

        // 1) Belongs to an existing session? Route by recv_index.
        if clean.len() >= DATA_MIN_LEN {
            let idx = u32::from_be_bytes(clean[0..4].try_into().unwrap());
            if by_index.contains_key(&idx) {
                let dead = by_index[&idx].send((clean.clone(), src)).is_err();
                if dead {
                    by_index.remove(&idx);
                    by_client.retain(|_, v| *v != idx);
                    // A demoted (rolled-away) dispatcher whose session is
                    // gone has nothing left to route: release the socket.
                    if demoted && by_index.is_empty() {
                        return;
                    }
                }
                continue;
            }
        }

        // 2) A handshake msg1 addressed to us (routing_key prefix)?
        if clean.len() >= NZ_MSG1_MIN && clean[0..ROUTING_KEY_LEN] == identity.routing_key {
            let idx_b = u32::from_be_bytes(
                clean[ROUTING_KEY_LEN..ROUTING_KEY_LEN + 4]
                    .try_into()
                    .unwrap(),
            );
            // Retransmit for an IN-FLIGHT handshake: always redeliver, even
            // when demoted — this dispatcher still owns every handshake it
            // started, and the relay keeps forwarding by the client's flow.
            if let Some(&idx_a) = by_client.get(&idx_b) {
                if let Some(tx) = by_index.get(&idx_a) {
                    let _ = tx.send((clean.clone(), src)); // retransmit -> same session
                }
                continue;
            }
            // NEW handshakes only while this socket holds the routing key;
            // once demoted they belong to the next generation.
            if demoted {
                continue;
            }
            // Shed load past the cap so a forged-msg1 burst can't exhaust memory
            // faster than failed accepts reap themselves.
            if by_index.len() >= MAX_INFLIGHT {
                warn!("[share] nz dispatcher at capacity ({MAX_INFLIGHT}); dropping new handshake");
                continue;
            }
            // New client: assign the idx_A the dispatcher will route future
            // packets by, seed the session's channel with this msg1, and drive
            // the responder handshake in its own task.
            let mut idx_a: u32 = rand::random();
            while by_index.contains_key(&idx_a) {
                idx_a = rand::random();
            }
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
            let _ = tx.send((clean.clone(), src));
            by_index.insert(idx_a, tx);
            by_client.insert(idx_b, idx_a);

            let sock = socket.clone();
            let id = identity.clone();
            let stx = session_tx.clone();
            let reap = reap_tx.clone();
            let accepting = accepting.clone();
            let rolled = rolled.clone();
            tokio::spawn(async move {
                match noise_accept(sock, rx, idx_a, None, id.as_ref(), hs_timeout, idle).await {
                    Ok(mut transport) => {
                        let remote_addr = transport.peer_addr();
                        let signal = transport
                            .take_signal()
                            .map(crate::signal::SignalChannel::noise);
                        // Deliver the session FIRST: if the share loop is
                        // gone the send fails and we must not roll (the
                        // manager would otherwise mint generations for a
                        // dead share until cancellation propagates).
                        let delivered = stx
                            .send((
                                carrier::PeerSession {
                                    transport: Box::new(transport),
                                    remote_addr,
                                    quic_conn: None,
                                    signal,
                                    fixed_mtu: NZ_TUNNEL_MTU,
                                },
                                None,
                            ))
                            .is_ok();
                        // The session claims this generation's socket: stop
                        // accepting here and let the manager roll to a
                        // fresh one.
                        if delivered {
                            accepting.store(false, std::sync::atomic::Ordering::Relaxed);
                            if let Some(tx) = rolled.lock().expect("rolled sender").take() {
                                let _ = tx.send(());
                            }
                        }
                    }
                    // Reap the pre-auth routing entries; the live-session case is
                    // covered by the reactive cleanup on a dead by_index sender.
                    Err(e) => {
                        warn!("[share] nz accept failed: {e}");
                        let _ = reap.send((idx_a, idx_b));
                    }
                }
            });
        }
        // else: unknown / garbage — drop.
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_share_loop(
    mut listener: QuicListener,
    roll_ctx: QuicListenerCtx,
    direct_endpoint: Option<quinn::Endpoint>,
    identity: Arc<Identity>,
    cancel: CancellationToken,
    config: Config,
    conn_log: Option<ConnLog>,
    rec: Recorder,
) {
    // EVERY exit from this loop — cancellation, endpoint death, a panic in
    // an event hook — must stop the detached registrar generations and
    // carrier workers, which all select on `cancel`. The guard makes any
    // exit equivalent to an explicit stop; without it, an endpoint-driver
    // death would leave the last registrar re-announcing a dead socket to
    // the relays forever.
    let _cancel_guard = cancel.clone().drop_guard();
    // Any exit from this loop ends the run, so the record gets its ending
    // here — including the exits nobody planned (endpoint death, a panic in
    // a hook), which is when having one matters most.
    let _record_guard = ShareRecordGuard(rec.clone());
    let secret = identity.secret;
    let mut tunnel_cancel: Option<CancellationToken> = None;
    let mut iteration: u32 = 0;
    // Generation of the ACTIVE session's endpoint (None: direct/tcp/nz).
    let mut active_gen: Option<u64> = None;
    // Which listener generation the CURRENT `listener` is; sessions are
    // tagged with the generation they were accepted on so the loop knows
    // whether an arriving session claims the current listener (-> roll) or
    // came from a demoted one / another carrier.
    let mut generation: u64 = 0;
    // Endpoints of demoted generations, kept so their session (at most one
    // is active, plus briefly-draining kicked ones) stays served and the
    // socket is closed once no session can be using it anymore.
    let mut demoted: std::collections::HashMap<u64, quinn::Endpoint> =
        std::collections::HashMap::new();
    // Authenticated sessions arrive here from the per-connection QUIC auth
    // tasks (tagged with their listener generation) and the TCP/TLS + nz
    // registrars (untagged), unified as carrier::PeerSession.
    let (session_tx, mut session_rx) =
        tokio::sync::mpsc::unbounded_channel::<(carrier::PeerSession, Option<u64>)>();

    // Sharer-side TCP/TLS carrier: park connections at each TcpTls relay and
    // deliver each spliced client as a session into the same channel.
    spawn_tcp_registrars(
        &config,
        identity.clone(),
        session_tx.clone(),
        cancel.clone(),
        &rec,
    );

    // Sharer-side Noise UDP carrier: register each NoiseUdp relay from a
    // dedicated socket and deliver each authenticated client into the same
    // channel. No-op when the config lists no NoiseUdp relay.
    spawn_noise_registrar(
        &config,
        identity.clone(),
        session_tx.clone(),
        cancel.clone(),
    );

    info!("[share] waiting for peers");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("share cancelled");
                if let Some(tc) = tunnel_cancel.take() { tc.cancel(); }
                listener.demote();
                listener.endpoint.close(0u32.into(), b"share-cancelled");
                if let Some(ep) = &direct_endpoint {
                    ep.close(0u32.into(), b"share-cancelled");
                }
                for (_, ep) in demoted.drain() {
                    ep.close(0u32.into(), b"share-cancelled");
                }
                break;
            }
            // Accept connection attempts and authenticate each one in its own
            // task, so a peer that stalls the secret read (an attacker who knows
            // only the routing key) can't block the accept loop and starve
            // legitimate peers. The sharer still serves one tunnel at a time;
            // we just no longer serialize the handshake+auth of every attempt.
            incoming = listener.endpoint.accept() => {
                match incoming {
                    None => { info!("share endpoint closed"); break; }
                    Some(incoming) => {
                        let tx = session_tx.clone();
                        let cancel = cancel.clone();
                        let listener_gen = generation;
                        let accept_rec = rec.clone();
                        tokio::spawn(async move {
                            // Written as `started` immediately: a handshake
                            // that hangs, or a task cancelled mid-flight,
                            // then leaves a step saying so rather than
                            // leaving nothing at all.
                            let accepting = accept_rec
                                .step_now(StepKind::Accept)
                                .carrier(Carrier::Quic)
                                .path(PathKind::Relay);
                            tokio::select! {
                                _ = cancel.cancelled() => {
                                    accepting.skip(Reason::Cancelled, "share stopping");
                                }
                                res = authenticate_incoming(incoming, &secret, true) => match res {
                                    Ok(session) => {
                                        accepting.peer(session.conn.remote_address()).ok();
                                        let _ = tx.send((carrier::PeerSession::from_quic(session), Some(listener_gen)));
                                    }
                                    Err(e) => {
                                        warn!("[share] accept failed: {}", e);
                                        accepting.fail_with(&e);
                                    }
                                }
                            }
                        });
                    }
                }
            }
            // Direct (relay-less) clients dial the permanent advertised
            // endpoint; their sessions never trigger a roll (untagged).
            incoming = async { direct_endpoint.as_ref().unwrap().accept().await },
                if direct_endpoint.is_some() =>
            {
                match incoming {
                    None => { info!("share direct endpoint closed"); break; }
                    Some(incoming) => {
                        let tx = session_tx.clone();
                        let cancel = cancel.clone();
                        let accept_rec = rec.clone();
                        tokio::spawn(async move {
                            let accepting = accept_rec
                                .step_now(StepKind::Accept)
                                .carrier(Carrier::Quic)
                                .path(PathKind::DirectAdvertised);
                            tokio::select! {
                                _ = cancel.cancelled() => {
                                    accepting.skip(Reason::Cancelled, "share stopping");
                                }
                                res = authenticate_incoming(incoming, &secret, true) => match res {
                                    Ok(session) => {
                                        accepting.peer(session.conn.remote_address()).ok();
                                        let _ = tx.send((carrier::PeerSession::from_quic(session), None));
                                    }
                                    Err(e) => {
                                        warn!("[share] direct accept failed: {}", e);
                                        accepting.fail_with(&e);
                                    }
                                }
                            }
                        });
                    }
                }
            }
            Some((session, from_gen)) = session_rx.recv() => {
                iteration += 1;
                let remote_addr = session.remote_addr;
                emit(
                    &config.event_hook,
                    TunnelEvent::RelaySessionEstablished { peer: remote_addr },
                );

                // Roll: the session was accepted on the CURRENT listener, so
                // that socket is now its private endpoint — mint the next
                // generation and move the routing key there. On a roll
                // failure (fd exhaustion, ...) keep the current listener:
                // the share degrades to the legacy shared-endpoint behavior
                // instead of dying.
                if from_gen == Some(generation) {
                    let rolling = rec.step(StepKind::ListenerRoll);
                    match roll_ctx.spawn_listener(0) {
                        Ok(next) => {
                            let mut old = std::mem::replace(&mut listener, next);
                            old.demote();
                            demoted.insert(generation, old.endpoint);
                            generation += 1;
                            rolling.detail(format!("generation {generation}")).ok();
                            debug!("[share #{iteration}] rolled listener to generation {generation}");
                        }
                        Err(e) => {
                            // Not fatal — the share degrades to a shared
                            // endpoint — but that degraded mode is the cause
                            // of failures much later, so it is a step.
                            rolling.fail(Reason::BindFailed, e.clone());
                            warn!("[share] listener roll failed: {e}; keeping current listener");
                        }
                    }
                }

                // Close demoted endpoints no session can be using anymore.
                // Kept: the NEW active session's endpoint, and — for one
                // more takeover — the endpoint of the session being
                // replaced, so a stale-generation session that was already
                // queued behind this one cannot have the rug pulled from
                // under a LIVE endpoint (its own arrival will be processed
                // against a still-consistent map and self-heal by kick).
                let prev_gen = active_gen;
                active_gen = from_gen;
                demoted.retain(|g, ep| {
                    if Some(*g) == from_gen || Some(*g) == prev_gen {
                        true
                    } else {
                        ep.close(0u32.into(), b"session-replaced");
                        false
                    }
                });

                if let Some(tc) = tunnel_cancel.take() {
                    info!("[share #{}] new peer, cancelling previous tunnel", iteration);
                    tc.cancel();
                }

                // Sessions accepted here always bootstrap relay-via, so the
                // connection's remote address is the relay's, recorded as such.
                let slog = conn_log.as_ref().map(|cl| cl.session(remote_addr));

                let child_cancel = cancel.child_token();
                tunnel_cancel = Some(child_cancel.clone());
                // A QUIC session that did not arrive on a listener generation
                // came in on the advertised (relay-less) endpoint; every
                // other carrier reaches us through a relay.
                let carrier_kind = session.carrier();
                let path_kind = if carrier_kind == Carrier::Quic && from_gen.is_none() {
                    PathKind::DirectAdvertised
                } else {
                    PathKind::Relay
                };
                spawn_responder_tunnel(
                    session,
                    identity.clone(),
                    &config,
                    child_cancel,
                    slog,
                    rec.for_session(iteration),
                    path_kind,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_responder_tunnel(
    session: carrier::PeerSession,
    identity: Arc<Identity>,
    config: &Config,
    tunnel_cancel: CancellationToken,
    slog: Option<Arc<SessionLog>>,
    rec: Recorder,
    path_kind: PathKind,
) {
    let carrier_kind = session.carrier();
    let carrier::PeerSession {
        transport,
        remote_addr,
        quic_conn,
        signal,
        fixed_mtu,
    } = session;

    // On a relayed carrier `remote_addr` is the *relay's* address: the exit
    // never observes the client's own address unless a punch lands later.
    // `path` is what says which of the two this is.
    rec.mark(StepKind::SessionUp)
        .peer(remote_addr)
        .carrier(carrier_kind)
        .path(path_kind)
        .ok();
    let meters = SessionMeters::new(&rec, carrier_kind, path_kind, quic_conn.clone(), fixed_mtu);
    spawn_sampler(meters.clone(), tunnel_cancel.clone());

    let (upgradable, upgrade_sender, router_handle) =
        upgradable_transport(transport, config.timings.upgrade_rescue_grace);
    // Share-side keepalive: reactive, not always-on. It pings only while the
    // client is active (recently heard from) and goes quiet once the client
    // goes silent — so a dormant client is never forced to ACK share-side
    // pings and gets true radio silence. An active client always pings (its
    // Adaptive knob is on), so the return path stays warm whenever it should.
    let ka_interval = config.timings.quic_keep_alive;
    // Quiet after ~3 ping intervals of client silence: long enough to span an
    // active client's own keepalive cadence (so we don't flap off between its
    // pings), short enough to reach radio silence soon after it goes dormant.
    let active_window = ka_interval * 3;
    let keepalive_cfg = KeepAliveConfig {
        mode: KeepAliveMode::Periodic {
            interval: ka_interval,
            // Declare a silent peer dead after the idle timeout, so the
            // session is reaped even on the TCP carrier — which, unlike QUIC
            // (max_idle_timeout) and nz (reader idle deadline), has NO
            // transport-level idle timeout, so without this a silently-dead
            // TCP client would linger forever (held fd, open connlog record,
            // no SessionEnded). `.max(active_window)` keeps the reaper from
            // firing before the share side has even stopped pinging.
            recv_timeout: Some(config.timings.quic_idle_timeout.max(active_window)),
        },
        active_window: Some(active_window),
        counters: Some(meters.counters.clone()),
        recorder: Some(rec.clone()),
        ..Default::default()
    };
    // The meter (Custom exit mode) must ignore the synthetic keepalive pings
    // riding the tunnel; tell it which inner address pair they use.
    let keepalive_pair = (keepalive_cfg.src_ip, keepalive_cfg.dst_ip);
    let transport: IpTransport =
        Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

    let protector_for_tunnel = config.protector.clone();
    let upgrade_cancel = tunnel_cancel.clone();

    // Responder upgrade: only for a QUIC session with the upgrade enabled. A
    // TcpTls (stream) session has no signal channel or UDP path; and a session
    // whose client is Direct dropped its signal, so try_direct_upgrade
    // terminates via SignalClosed before it STUNs.
    let upgrade_task = match (config.enable_direct_upgrade, signal) {
        (true, Some(signal)) => {
            let stun_server = config.stun_server.clone();
            let protector = config.protector.clone();
            let mtu_cb = config.mtu_callback.clone();
            let timings = config.timings.clone();
            let event_hook = config.event_hook.clone();
            let role = DirectRole::Responder { identity };
            let path_ipv6 = remote_addr.is_ipv6();
            let upgrade_slog = slog.clone();
            let upgrade_meters = meters.clone();
            tokio::spawn(async move {
                try_direct_upgrade(
                    signal,
                    upgrade_sender,
                    &stun_server,
                    role,
                    path_ipv6,
                    &protector,
                    upgrade_cancel,
                    None,
                    mtu_cb,
                    timings,
                    event_hook,
                    upgrade_slog,
                    upgrade_meters,
                )
                .await;
            })
        }
        // No upgrade (stream carrier, or upgrade disabled): drop the
        // UpgradeSender (the router drains, by design) and hold the signal (if
        // any) until the session ends so a QUIC peer's stream doesn't see EOF.
        (_, held_signal) => {
            // Not attempted, and for two quite different reasons — recorded
            // as `skipped`, because "we chose not to" is a different fact
            // from "we tried and it failed".
            let reason = if config.enable_direct_upgrade {
                Reason::UpgradeUnsupported
            } else {
                Reason::UpgradeDisabled
            };
            rec.mark(StepKind::PathSwap)
                .carrier(carrier_kind)
                .skip(reason, "no direct upgrade attempted");
            drop(upgrade_sender);
            tokio::spawn(async move {
                upgrade_cancel.cancelled().await;
                drop(held_signal);
            })
        }
    };

    // MTU: dynamic (PMTUD) for QUIC, fixed for a stream carrier.
    let mtu_rec = rec.clone();
    match quic_conn {
        Some(conn) => {
            let cb = config.mtu_callback.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                match conn.max_datagram_size() {
                    Some(mds) => {
                        info!("e2e max datagram size (post-PMTUD): {}", mds);
                        mtu_rec
                            .mark(StepKind::Mtu)
                            .detail(format!("discovered {mds}"))
                            .ok();
                        if let Some(cb) = cb {
                            cb(mds as u16);
                        }
                    }
                    None => mtu_rec
                        .mark(StepKind::Mtu)
                        .fail(Reason::Unknown, "no datagram size after PMTUD"),
                }
            });
        }
        None => {
            rec.mark(StepKind::Mtu)
                .detail(format!("declared {fixed_mtu}"))
                .ok();
            if let Some(cb) = config.mtu_callback.clone() {
                cb(fixed_mtu);
            }
        }
    }

    let exit_slog = slog.clone();
    let end_cancel = tunnel_cancel.clone();
    rec.mark(StepKind::ExitStart)
        .detail(match &config.exit_mode {
            ExitMode::Netstack => "netstack",
            ExitMode::Custom(_) => "custom handler",
        })
        .ok();
    let session_fut: SessionFuture = match &config.exit_mode {
        ExitMode::Netstack => Box::pin(async move {
            let _ = server::start_tunnel(
                transport,
                protector_for_tunnel,
                tunnel_cancel,
                true,
                exit_slog,
            )
            .await;
        }),
        ExitMode::Custom(handler) => {
            // The handler only moves packets; flow accounting happens in a
            // passive meter wrapped around the transport it receives, so any
            // custom exit (e.g. the CLI's --os-routing) is logged without
            // its own instrumentation.
            let transport = match &exit_slog {
                Some(sl) => Box::new(transport::meter::MeteredTransport::new(
                    transport,
                    sl.clone(),
                    keepalive_pair,
                )) as IpTransport,
                None => transport,
            };
            handler(transport, tunnel_cancel)
        }
    };
    let event_hook = config.event_hook.clone();
    tokio::spawn(async move {
        session_fut.await;
        upgrade_task.abort();
        // Await the aborted task so its SessionLog writes (address records)
        // cannot land after the SessionEnd record below.
        let _ = upgrade_task.await;
        drop(router_handle);
        let reason = if end_cancel.is_cancelled() {
            "cancelled"
        } else {
            "transport_closed"
        };
        // The two cases the core can actually tell apart here. A cancelled
        // session was almost always replaced by a newer peer; a closed one
        // died on its own, and the carrier's own step (if any) says how.
        rec.mark(StepKind::SessionEnd)
            .carrier(carrier_kind)
            .path(meters.path.get())
            .fail(
                if end_cancel.is_cancelled() {
                    Reason::Replaced
                } else {
                    Reason::TransportClosed
                },
                reason,
            );
        if let Some(sl) = &slog {
            sl.end(reason);
        }
        emit(
            &event_hook,
            TunnelEvent::SessionEnded {
                reason: reason.to_string(),
            },
        );
    });
}

/// Connect to a sharer via the URL. Returns the IP-level transport plus the
/// keepalive controls so the caller (CLI/FFI) can toggle dormant mode.
pub async fn connect(url: Url, config: &Config) -> Result<ConnectResult, String> {
    let token = match Token::from_url(&url) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            // Worth a record of its own: "the link is malformed" is a
            // diagnosis, and it is the first thing anyone asks about.
            let rec = open_record(config, Role::Client, None, Vec::new());
            rec.mark(StepKind::TokenParse)
                .fail(Reason::BadToken, e.clone());
            rec.close(Outcome::NeverConnected, Some(Reason::BadToken), None);
            return Err(e);
        }
    };
    let rec = open_record(
        config,
        Role::Client,
        Some(&token.routing_key),
        endpoint_refs(&token.relays),
    );
    rec.mark(StepKind::TokenParse).ok();
    // Resolve every relay in the URL (a hostname may expand to v4+v6) and try
    // them IPv6 first: a v6 relay path drives a v6 hole punch, which succeeds
    // far more often (no NAT, just a stateful firewall) than a v4 one. The
    // order is re-derived on each (re)dial, so DNS changes and censorship
    // failover both take effect on reconnect.
    let resolving = rec.step(StepKind::RelayResolve);
    let relay_addrs = match resolve_relays_preferring_v6(&token.relays) {
        Ok(addrs) => {
            resolving
                .detail(format!("{} endpoint(s) to try", addrs.len()))
                .ok();
            addrs
        }
        Err(e) => {
            resolving.fail_with(&e);
            rec.close(Outcome::NeverConnected, Some(e.reason), None);
            return Err(e.detail);
        }
    };
    info!(
        "connect: relays {:?} for rk {:x?}",
        relay_addrs,
        &token.routing_key[..4]
    );

    let cancel = CancellationToken::new();
    let keepalive_knob = Arc::new(AtomicU64::new(0));
    let keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>> =
        Arc::new(std::sync::Mutex::new(None));

    let initial = match dial_relays(
        &relay_addrs,
        &token,
        config,
        cancel.clone(),
        keepalive_knob.clone(),
        keepalive_waker.clone(),
        &rec.for_cycle(0),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            rec.close(
                Outcome::NeverConnected,
                Some(e.reason),
                Some(e.detail.clone()),
            );
            return Err(format!("initial dial: {}", e));
        }
    };

    let dialer_token = token.clone();
    let dialer_config = config.clone();
    let dialer_cancel = cancel.clone();
    let dialer_knob = keepalive_knob.clone();
    let dialer_waker = keepalive_waker.clone();
    // The last answer DNS gave us. Every redial asks again — that is the
    // point of re-resolving — but a resolver that has just been broken or
    // poisoned must not cost us the addresses we already have, so this is
    // what a failed lookup falls back to.
    let known_relays = Arc::new(std::sync::Mutex::new(relay_addrs.clone()));
    let dialer_rec = rec.clone();
    // Which re-dial cycle a step belongs to. Without it, forty reconnects in
    // an hour are forty indistinguishable piles of steps.
    let cycles = Arc::new(AtomicU64::new(0));
    let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
        let token = dialer_token.clone();
        let config = dialer_config.clone();
        let cancel = dialer_cancel.clone();
        let knob = dialer_knob.clone();
        let waker = dialer_waker.clone();
        let known = known_relays.clone();
        let cycle = cycles.fetch_add(1, Ordering::Relaxed) + 1;
        let rec = dialer_rec.for_cycle(cycle as u32);
        Box::pin(async move {
            emit(&config.event_hook, TunnelEvent::Reconnecting);
            rec.mark(StepKind::Reconnect).ok();
            // Ask DNS again for this cycle: a relay that moved, a hostname
            // whose records changed, and a censor that started poisoning one
            // name are all only visible if we look. Resolution stays on this
            // task rather than a blocking pool thread — the network namespace
            // (and any per-thread resolver state) belongs to this thread.
            let relays = resolve_for_dial(&token.relays, &known, &rec);
            let result = dial_relays(&relays, &token, &config, cancel, knob, waker, &rec).await;
            if result.is_ok() {
                emit(&config.event_hook, TunnelEvent::Reconnected);
            }
            result.map_err(std::io::Error::from)
        })
    });

    let transport = Box::new(ReconnectTransport::new(
        initial,
        dialer,
        config.timings.reconnect_delay,
        Some((keepalive_knob.clone(), keepalive_waker.clone())),
    ));
    // The record outlives the call: it is closed when the caller cancels, so
    // a session that runs for an hour still gets an ending.
    let closing = rec.clone();
    let closing_cancel = cancel.clone();
    tokio::spawn(async move {
        closing_cancel.cancelled().await;
        closing.mark(StepKind::SessionEnd).ok();
        closing.close_shutdown(Some(Reason::LocalShutdown));
    });

    Ok(ConnectResult {
        transport,
        cancel,
        keepalive_knob,
        keepalive_waker,
        record: rec,
    })
}

/// Re-resolve the URL's relays for a redial, remembering the last usable
/// answer.
///
/// DNS is one of the things a censor breaks, and it is broken at exactly the
/// moment we most need to reconnect — so a failed lookup here falls back to
/// the addresses that worked before rather than ending the cycle. Both the
/// lookup and the fallback are recorded: "we are dialling yesterday's
/// addresses because the resolver stopped answering" is a finding.
fn resolve_for_dial(
    endpoints: &[RelayEndpoint],
    known: &std::sync::Mutex<Vec<(SocketAddr, RelayProtocol)>>,
    rec: &Recorder,
) -> Vec<(SocketAddr, RelayProtocol)> {
    let step = rec.step(StepKind::RelayResolve);
    match resolve_relays_preferring_v6(endpoints) {
        Ok(addrs) => {
            step.detail(format!("{} endpoint(s) to try", addrs.len()))
                .ok();
            *known.lock().unwrap_or_else(|e| e.into_inner()) = addrs.clone();
            addrs
        }
        Err(e) => {
            let fallback = known.lock().unwrap_or_else(|e| e.into_inner()).clone();
            warn!(
                "relay resolution failed ({}); dialling {} previously resolved address(es)",
                e,
                fallback.len()
            );
            step.fail_with(&Fault::new(
                e.reason,
                format!(
                    "{}; falling back to {} previously resolved address(es)",
                    e.detail,
                    fallback.len()
                ),
            ));
            fallback
        }
    }
}

/// Try each relay (already ordered IPv6-first) until one bootstraps a
/// relay-via session, time-boxing each attempt by `relay_dial_timeout` so a
/// dead/censored relay — or one the sharer never registered with (a family
/// mismatch looks identical: the Initial is silently dropped) — fails over to
/// the next instead of stalling. Returns the last error if all fail.
#[allow(clippy::too_many_arguments)]
async fn dial_relays(
    relay_addrs: &[(SocketAddr, RelayProtocol)],
    token: &Token,
    config: &Config,
    cancel: CancellationToken,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    rec: &Recorder,
) -> Result<IpTransport, Fault> {
    let mut last_err: Option<Fault> = None;
    for &(relay_addr, protocol) in relay_addrs {
        // One step per endpoint tried, so a record shows every relay that was
        // attempted and how each one refused — not just the last one, which
        // is all the returned error can carry.
        let step = rec
            .step_now(StepKind::RelayDial)
            .via(relay_addr)
            .carrier(Carrier::of_protocol(protocol))
            .path(PathKind::of_protocol(protocol));
        let attempt = dial_initiator(
            relay_addr,
            protocol,
            token,
            config,
            cancel.clone(),
            keepalive_knob.clone(),
            keepalive_waker.clone(),
            rec,
        );
        match tokio::time::timeout(config.timings.relay_dial_timeout, attempt).await {
            Ok(Ok(transport)) => {
                step.ok();
                return Ok(transport);
            }
            Ok(Err(e)) => {
                warn!("relay {} dial failed: {}", relay_addr, e);
                step.fail_with(&e);
                last_err = Some(e);
            }
            Err(_) => {
                warn!(
                    "relay {} dial timed out after {:?}",
                    relay_addr, config.timings.relay_dial_timeout
                );
                let f = Fault::new(
                    Reason::ConnectTimeout,
                    format!(
                        "relay {relay_addr} dial timed out after {:?}",
                        config.timings.relay_dial_timeout
                    ),
                );
                step.fail_with(&f);
                last_err = Some(f);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Fault::new(Reason::NoRelays, "no relays to dial")))
}

#[allow(clippy::too_many_arguments)]
async fn dial_initiator(
    relay_addr: SocketAddr,
    protocol: RelayProtocol,
    token: &Token,
    config: &Config,
    cancel: CancellationToken,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    rec: &Recorder,
) -> Result<IpTransport, Fault> {
    // Select the client-side dialer for this endpoint's protocol. The returned
    // session is end-to-end authenticated (routing-key pinned + secret) whatever
    // the protocol; the relay is never trusted. Relay path: require the sharer's
    // accept ack so a bad/expired token fails here instead of reconnect-looping.
    let client = carrier::relay_client_for(protocol);
    debug!("dialing {} via {:?} carrier", relay_addr, client.protocol());
    let session = client
        .dial(carrier::DialCtx {
            target: relay_addr,
            routing_key: token.routing_key,
            secret: token.secret,
            protector: &config.protector,
            timings: &config.timings,
            expect_ack: true,
            rec,
        })
        .await?;
    let carrier::PeerSession {
        transport,
        remote_addr,
        quic_conn,
        signal,
        fixed_mtu,
    } = session;

    emit(
        &config.event_hook,
        TunnelEvent::RelaySessionEstablished { peer: remote_addr },
    );
    let carrier_kind = Carrier::of_protocol(protocol);
    let path_kind = PathKind::of_protocol(protocol);
    // `remote_addr` is the relay's address on a relayed carrier — the peer's
    // own address is not observable from here, and the record must not imply
    // otherwise. `path` says which it is.
    rec.mark(StepKind::SessionUp)
        .peer(remote_addr)
        .carrier(carrier_kind)
        .path(path_kind)
        .ok();
    let meters = SessionMeters::new(rec, carrier_kind, path_kind, quic_conn.clone(), fixed_mtu);
    spawn_sampler(meters.clone(), cancel.clone());

    let (upgradable, upgrade_sender, router_handle) =
        upgradable_transport(transport, config.timings.upgrade_rescue_grace);
    let upgrade_knob = keepalive_knob.clone();
    let keepalive_cfg = KeepAliveConfig {
        mode: KeepAliveMode::Adaptive {
            knob: keepalive_knob,
            waker: keepalive_waker,
        },
        idle_threshold: config.timings.keepalive_idle_threshold,
        response_timeout: config.timings.keepalive_response_timeout,
        inbound_grace: config.timings.keepalive_inbound_grace,
        counters: Some(meters.counters.clone()),
        recorder: Some(rec.clone()),
        ..Default::default()
    };
    let transport: IpTransport =
        Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

    // MTU: a QUIC carrier reads the PMTUD-converged max_datagram_size after
    // ~1.5s; a stream carrier has no per-datagram limit, so report a fixed MTU.
    let mtu_cb_relay = config.mtu_callback.clone();
    let mtu_rec = rec.clone();
    match quic_conn {
        Some(conn) => {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                match conn.max_datagram_size() {
                    Some(mds) => {
                        info!("e2e max datagram size (post-PMTUD): {}", mds);
                        mtu_rec
                            .mark(StepKind::Mtu)
                            .detail(format!("discovered {mds}"))
                            .ok();
                        if let Some(cb) = mtu_cb_relay {
                            cb(mds as u16);
                        }
                    }
                    // Nothing came of the probing. Silence here used to be
                    // indistinguishable from a converged path.
                    None => mtu_rec
                        .mark(StepKind::Mtu)
                        .fail(Reason::Unknown, "no datagram size after PMTUD"),
                }
            });
        }
        None => {
            rec.mark(StepKind::Mtu)
                .detail(format!("declared {fixed_mtu}"))
                .ok();
            if let Some(cb) = mtu_cb_relay {
                cb(fixed_mtu);
            }
        }
    }

    let upgrade_cancel = cancel.clone();
    // Only a *relayed QUIC* session benefits from a direct upgrade. A Direct
    // session already terminates directly on the sharer; a TcpTls session has
    // no QUIC signal channel and no UDP path to punch. Skipping for Direct also
    // drops the signal now, so the sharer's responder upgrade hits EOF on its
    // first recv_endpoint and stops *before* it ever STUNs.
    let attempt_upgrade = config.enable_direct_upgrade && protocol.is_relayed() && signal.is_some();
    if attempt_upgrade {
        let signal = signal.expect("attempt_upgrade requires a signal channel");
        let role = DirectRole::Initiator {
            routing_key: token.routing_key,
            secret: token.secret,
        };
        let stun_server = config.stun_server.clone();
        let protector = config.protector.clone();
        let mtu_cb = config.mtu_callback.clone();
        let timings = config.timings.clone();
        let event_hook = config.event_hook.clone();
        let path_ipv6 = relay_addr.is_ipv6();
        let upgrade_meters = meters.clone();
        tokio::spawn(async move {
            try_direct_upgrade(
                signal,
                upgrade_sender,
                &stun_server,
                role,
                path_ipv6,
                &protector,
                upgrade_cancel,
                Some(upgrade_knob),
                mtu_cb,
                timings,
                event_hook,
                None, // client side: no connection log
                upgrade_meters,
            )
            .await;
            drop(router_handle);
        });
    } else {
        // Not attempting an initiator upgrade. For a Direct session drop the
        // signal now (stops the peer's responder before STUN). For a relayed
        // session with the upgrade globally disabled, hold the SignalChannel
        // open so the peer's attempts time out instead of seeing EOF. Either
        // way the holder must die with the *session*, not just the connect-level
        // cancel token: each re-dial runs through here again, so a cancel-only
        // holder would accumulate one parked task per redial. The router drops
        // its upgrade receiver when the session ends, so `upgrade_sender.closed()`
        // is exactly the session-death signal.
        // Recorded as skipped, with which of the three reasons it was: not
        // attempting is a different fact from attempting and failing.
        let skip_reason = if !config.enable_direct_upgrade {
            Reason::UpgradeDisabled
        } else {
            Reason::UpgradeUnsupported
        };
        rec.mark(StepKind::PathSwap)
            .carrier(carrier_kind)
            .skip(skip_reason, "no direct upgrade attempted");
        let drop_signal_now = !protocol.is_relayed();
        tokio::spawn(async move {
            // Direct: drop the signal now (peer's responder stops before STUN).
            // Relayed QUIC + disabled: hold it until session death (peer's
            // attempts time out instead of erroring). Stream carrier: None.
            let held_signal = if drop_signal_now {
                drop(signal);
                None
            } else {
                signal
            };
            tokio::select! {
                _ = upgrade_cancel.cancelled() => {}
                _ = upgrade_sender.closed() => {}
            }
            drop(held_signal);
            drop(router_handle);
        });
    }

    Ok(transport)
}

/// Open a record for one run, or a handle that does nothing when the platform
/// has not asked for one (the core does not write to a user's disk uninvited).
fn open_record(
    config: &Config,
    role: Role,
    routing_key: Option<&[u8]>,
    endpoints: Vec<EndpointRef>,
) -> Recorder {
    match config.record.as_ref() {
        Some(cfg) => Recorder::start(
            cfg,
            role,
            routing_key,
            endpoints,
            config.enable_direct_upgrade,
        ),
        None => Recorder::disabled(),
    }
}

/// The configured endpoints, as the record describes them.
fn endpoint_refs(relays: &[RelayEndpoint]) -> Vec<EndpointRef> {
    relays
        .iter()
        .map(|r| EndpointRef {
            host: r.host.clone(),
            port: r.port,
            carrier: Carrier::of_protocol(r.protocol),
            path: PathKind::of_protocol(r.protocol),
            addr: None,
        })
        .collect()
}

/// Everything one live session needs in order to describe itself: where its
/// traffic is going, how much of it there has been, and whatever the carrier
/// is willing to say about the path.
///
/// It is shared with the direct upgrade, which replaces the path (and the
/// connection the numbers come from) underneath a running sampler — so a
/// single series continues across the swap instead of restarting.
#[derive(Clone)]
pub(crate) struct SessionMeters {
    rec: Recorder,
    carrier: Carrier,
    path: Arc<PathState>,
    counters: Arc<LinkCounters>,
    quic: Arc<std::sync::Mutex<Option<Connection>>>,
    /// Set for carriers that declare a fixed frame size instead of probing
    /// for one.
    fixed_mtu: Option<u16>,
}

impl SessionMeters {
    fn new(
        rec: &Recorder,
        carrier: Carrier,
        path: PathKind,
        quic: Option<Connection>,
        fixed_mtu: u16,
    ) -> Self {
        Self {
            rec: rec.clone(),
            carrier,
            path: Arc::new(PathState::new(path)),
            counters: Arc::new(LinkCounters::default()),
            quic: Arc::new(std::sync::Mutex::new(quic.clone())),
            fixed_mtu: quic.is_none().then_some(fixed_mtu),
        }
    }

    /// The direct upgrade landed: from here the numbers come from the new
    /// path and the new connection.
    fn on_direct(&self, path: PathKind, quic: Option<Connection>) {
        self.path.set(path);
        if let Ok(mut slot) = self.quic.lock() {
            *slot = quic;
        }
    }

    fn take_sample(&self) {
        let c = &self.counters;
        let mut s = record::SampleInput {
            path: self.path.get(),
            carrier: self.carrier,
            tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
            tx_pkts: c.tx_pkts.load(Ordering::Relaxed),
            rx_pkts: c.rx_pkts.load(Ordering::Relaxed),
            probes_sent: Some(c.probes_sent.load(Ordering::Relaxed)),
            probes_lost: Some(
                c.probes_sent
                    .load(Ordering::Relaxed)
                    .saturating_sub(c.probes_answered.load(Ordering::Relaxed)),
            ),
            ..Default::default()
        };
        // The probe's round trip goes through the tunnel, so it is the only
        // one comparable across carriers; the carrier's own estimate is
        // better but measures a different thing, so it is labelled.
        if let Some(rtt) = c.last_rtt() {
            s.rtt_ms = Some(rtt.as_secs_f64() * 1000.0);
            s.rtt_src = Some(RttSource::Keepalive);
        }
        let conn = self.quic.lock().ok().and_then(|g| g.clone());
        match conn {
            Some(conn) => {
                let st = conn.stats();
                s.rtt_ms = Some(st.path.rtt.as_secs_f64() * 1000.0);
                s.rtt_src = Some(RttSource::Quic);
                s.cwnd = Some(st.path.cwnd);
                // Send-side only: QUIC tells us what we lost, never what the
                // peer did.
                s.lost_pkts = Some(st.path.lost_packets);
                s.mtu = conn.max_datagram_size().map(|m| m as u16);
                s.mtu_src = Some(MtuSource::Discovered);
            }
            None => {
                s.mtu = self.fixed_mtu;
                s.mtu_src = self.fixed_mtu.map(|_| MtuSource::Declared);
            }
        }
        self.rec.sample(s);
    }
}

/// Sample this session until it is cancelled. Cheap: a few atomics and one
/// `stats()` call per interval.
fn spawn_sampler(meters: SessionMeters, cancel: CancellationToken) {
    let interval = meters.rec.sample_interval();
    if !meters.rec.is_enabled() || interval.is_zero() {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(interval) => meters.take_sample(),
            }
        }
    });
}

// ---------- Direct upgrade ----------

pub(crate) enum DirectRole {
    Initiator {
        routing_key: [u8; ROUTING_KEY_LEN],
        secret: [u8; SECRET_LEN],
    },
    Responder {
        identity: Arc<Identity>,
    },
}

/// Why a single direct-upgrade attempt failed.
#[derive(Debug)]
pub(crate) enum DirectError {
    /// The signal channel is closed — no further negotiation is possible for
    /// this session. Terminal: `try_direct_upgrade` must return (retrying
    /// would fail instantly and hot-spin on the responder side).
    SignalClosed(Fault),
    /// Transient failure (STUN, punch, QUIC handshake, ...); a later attempt
    /// may succeed.
    Transient(Fault),
}

impl DirectError {
    /// A transient failure. Takes anything that converts into a [`Fault`], so
    /// a call site that has not been given a vocabulary code yet still
    /// compiles — and records an honest `unknown` rather than a guess.
    fn transient(e: impl Into<Fault>) -> Self {
        DirectError::Transient(e.into())
    }

    fn signal_closed(e: impl Into<Fault>) -> Self {
        DirectError::SignalClosed(e.into())
    }

    fn fault(&self) -> &Fault {
        match self {
            DirectError::SignalClosed(f) | DirectError::Transient(f) => f,
        }
    }

    fn reason(&self) -> &str {
        &self.fault().detail
    }
}

/// Map a negotiation-channel error to `DirectError`. `NegChannelClosed` is
/// terminal — note this covers both a genuinely closed stream AND a length
/// prefix over the 64 KiB signal limit (framing desync), since `recv_signal`
/// cannot distinguish them; retrying on a desynced stream would be useless
/// anyway. A garbled endpoint *payload* (`ProtocolError`) is transient.
fn neg_err(e: TunnelError) -> DirectError {
    match e {
        TunnelError::NegChannelClosed => {
            DirectError::signal_closed(Fault::new(Reason::SignalClosed, "signal channel closed"))
        }
        // A refused candidate is a policy decision about an address the peer
        // chose, not a broken peer — and on a hostile network the difference
        // is the whole finding.
        TunnelError::PunchTargetRefused(msg) => {
            DirectError::transient(Fault::new(Reason::TargetRejected, msg))
        }
        other => {
            DirectError::transient(Fault::new(Reason::ProtocolViolation, format!("{other:?}")))
        }
    }
}

/// Background task: repeatedly try to establish a direct UDP connection.
/// On success, send the new transport via `upgrade_sender`.
///
/// `path_ipv6` is the relay-via session's address family; the initiator
/// STUNs (and therefore punches) in that family first, since it is the one
/// family both peers are known to have. The responder follows the family of
/// the endpoint the initiator signals.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_direct_upgrade(
    mut signal: SignalChannel,
    upgrade_sender: UpgradeSender,
    stun_server: &str,
    role: DirectRole,
    path_ipv6: bool,
    protector: &SocketProtector,
    cancel: CancellationToken,
    keepalive_knob: Option<Arc<AtomicU64>>,
    mtu_callback: MtuCallback,
    timings: Timings,
    event_hook: EventHook,
    // Share side only: records what each upgrade round learns about the
    // peer's outer address (self-reported endpoint, punch-validated source,
    // verified direct address) and the sharer's own STUN result.
    conn_log: Option<Arc<SessionLog>>,
    // This session's meters: the upgrade writes its steps here, and on
    // success it repoints them at the new path so one quality series
    // continues across the swap.
    meters: SessionMeters,
) {
    const MAX_DORMANT_ATTEMPTS: u32 = 3;
    let mut dormant_attempts: u32 = 0;
    let mut was_active = false;
    let initiator = matches!(role, DirectRole::Initiator { .. });

    loop {
        if cancel.is_cancelled() {
            info!("Direct upgrade cancelled");
            return;
        }
        if upgrade_sender.is_closed() {
            info!("Upgrade channel closed (transport replaced), stopping direct upgrade");
            return;
        }

        if initiator && let Some(ref knob) = keepalive_knob {
            let knob_val = knob.load(std::sync::atomic::Ordering::Relaxed);
            let active = knob_val > 0;
            if active && !was_active {
                dormant_attempts = 0;
            }
            was_active = active;
            if !active && dormant_attempts >= MAX_DORMANT_ATTEMPTS {
                info!("Direct upgrade: dormant attempts exhausted, waiting for screen-on");
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => { info!("Direct upgrade cancelled while parked"); return; }
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                    if upgrade_sender.is_closed() {
                        info!("Upgrade channel closed while parked");
                        return;
                    }
                    if knob.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                        dormant_attempts = 0;
                        was_active = true;
                        break;
                    }
                }
            }
        }

        let result = match &role {
            DirectRole::Initiator {
                routing_key,
                secret,
            } => {
                try_direct_as_initiator(
                    &mut signal,
                    stun_server,
                    path_ipv6,
                    protector,
                    *routing_key,
                    *secret,
                    &timings,
                    &meters.rec,
                )
                .await
            }
            DirectRole::Responder { identity } => {
                try_direct_as_responder(
                    &mut signal,
                    stun_server,
                    protector,
                    identity,
                    &timings,
                    conn_log.as_deref(),
                    &meters.rec,
                )
                .await
            }
        };
        match result {
            Ok((transport, path)) => {
                info!("Direct connection established, upgrading transport");
                let swap = meters
                    .rec
                    .mark(StepKind::PathSwap)
                    .local(path.local)
                    .peer(path.peer)
                    .path(PathKind::DirectPunched)
                    .carrier(meters.carrier);
                if upgrade_sender.send(transport).is_err() {
                    warn!("Failed to send upgrade — tunnel already closed");
                    swap.fail(Reason::SwapFailed, "tunnel already closed");
                    return;
                }
                swap.ok();
                // From here the numbers describe the direct path.
                meters.on_direct(PathKind::DirectPunched, path.quic_conn.clone());
                if let Some(sl) = &conn_log {
                    sl.addr(AddrKind::Verified, path.peer);
                }
                emit(
                    &event_hook,
                    TunnelEvent::DirectUpgradeSucceeded {
                        local: path.local,
                        peer: path.peer,
                    },
                );
                // MTU: a QUIC path reports its PMTUD-converged datagram size after
                // a grace; nz reports its fixed budget immediately.
                let mtu_rec = meters.rec.clone();
                match path.quic_conn {
                    Some(conn) => {
                        let cb = mtu_callback.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(1500)).await;
                            match conn.max_datagram_size() {
                                Some(mds) => {
                                    info!("P2P max datagram size (post-PMTUD): {}", mds);
                                    mtu_rec
                                        .mark(StepKind::Mtu)
                                        .path(PathKind::DirectPunched)
                                        .detail(format!("discovered {mds}"))
                                        .ok();
                                    if let Some(cb) = cb {
                                        cb(mds as u16);
                                    }
                                }
                                None => mtu_rec
                                    .mark(StepKind::Mtu)
                                    .path(PathKind::DirectPunched)
                                    .fail(Reason::Unknown, "no datagram size after PMTUD"),
                            }
                        });
                    }
                    None => {
                        mtu_rec
                            .mark(StepKind::Mtu)
                            .path(PathKind::DirectPunched)
                            .detail(format!("declared {}", path.fixed_mtu))
                            .ok();
                        if let Some(cb) = mtu_callback.clone() {
                            cb(path.fixed_mtu);
                        }
                    }
                }
                return;
            }
            Err(e) => {
                warn!("Direct connection attempt failed: {}", e.reason());
                emit(
                    &event_hook,
                    TunnelEvent::DirectUpgradeFailed {
                        code: e.fault().reason,
                        reason: e.reason().to_string(),
                    },
                );
                if matches!(e, DirectError::SignalClosed(_)) {
                    info!("Signal channel closed — stopping direct upgrade for this session");
                    return;
                }
                if initiator {
                    if let Some(ref knob) = keepalive_knob
                        && knob.load(std::sync::atomic::Ordering::Relaxed) == 0
                    {
                        dormant_attempts += 1;
                    }
                    warn!("Retrying in {:?}...", timings.upgrade_retry_delay);
                    tokio::select! {
                        _ = cancel.cancelled() => { info!("Direct upgrade cancelled during retry wait"); return; }
                        _ = tokio::time::sleep(timings.upgrade_retry_delay) => {}
                    }
                }
            }
        }
    }
}

/// Initiator (B): STUN, exchange endpoint, punch, build direct QUIC client
/// (cert-pinned to `routing_key`, sends `secret` on auth stream). On success
/// also returns the punched socket's local address (for event reporting).
/// The direct path a successful upgrade round produced, carrier-neutral. The
/// old `(transport, quinn::Connection, local)` triple was QUIC-specific; nz has
/// no `Connection`, so the MTU source is split out.
struct DirectPath {
    /// Verified direct peer address.
    peer: SocketAddr,
    /// Local address of the punched socket.
    local: SocketAddr,
    /// The QUIC connection, read for the post-PMTUD dynamic MTU. `None` for nz,
    /// which reports `fixed_mtu` immediately.
    quic_conn: Option<Connection>,
    fixed_mtu: u16,
}

#[allow(clippy::too_many_arguments)]
async fn try_direct_as_initiator(
    signal: &mut SignalChannel,
    stun_server: &str,
    path_ipv6: bool,
    protector: &SocketProtector,
    routing_key: [u8; ROUTING_KEY_LEN],
    secret: [u8; SECRET_LEN],
    timings: &Timings,
    rec: &Recorder,
) -> Result<(IpTransport, DirectPath), DirectError> {
    let stun = rec.step_now(StepKind::Stun).via(stun_server);
    let (socket, external_addr) = match pierce_keep_socket(stun_server, protector, path_ipv6).await
    {
        Ok(x) => {
            stun.local(x.1).ok();
            x
        }
        Err(e) => {
            stun.fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    let exchange = rec
        .step_now(StepKind::EndpointExchange)
        .local(external_addr);
    let peer_addr = {
        let mut neg = SignalNegChannel::new(signal);
        neg.send_endpoint(external_addr).await.map_err(neg_err)?;
        tokio::time::timeout(timings.endpoint_exchange_timeout, neg.recv_endpoint())
            .await
            .map_err(|_| {
                // Not a punch failure: the peer never told us where to aim,
                // which is a different fact about a different stage.
                DirectError::transient(Fault::new(
                    Reason::ExchangeTimeout,
                    format!(
                        "no endpoint from the peer within {:?}",
                        timings.endpoint_exchange_timeout
                    ),
                ))
            })?
            .map_err(neg_err)?
    };
    // The punch socket's family is fixed by our STUN result; a peer endpoint
    // in the other family is unreachable from it. Fail fast (the exchange is
    // one candidate per side, no multi-family negotiation) instead of
    // burning 2x punch_phase_timeout sending packets the OS refuses.
    exchange.peer(peer_addr).ok();
    if peer_addr.is_ipv6() != external_addr.is_ipv6() {
        let f = Fault::new(
            Reason::FamilyMismatch,
            format!("address family mismatch: ours {external_addr}, peer {peer_addr}"),
        );
        rec.mark(StepKind::Punch).peer(peer_addr).fail_with(&f);
        return Err(DirectError::transient(f));
    }

    let punching = rec
        .step_now(StepKind::Punch)
        .local(external_addr)
        .peer(peer_addr);
    let (punch_pkt, verify_pkt) = punch_markers(&secret);
    let (socket, learned_peer) = match punch_and_verify(
        socket,
        peer_addr,
        &punch_pkt,
        &verify_pkt,
        timings.punch_phase_timeout,
        timings.punch_send_interval,
    )
    .await
    {
        Ok(x) => {
            // The address that answered, which is not always the one the peer
            // signalled — that difference is what a symmetric NAT looks like.
            punching.peer(x.1).ok();
            x
        }
        Err(e) => {
            punching.fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    let local_addr = socket
        .local_addr()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("local_addr")))?;
    let building = rec
        .step_now(StepKind::DirectHandshake)
        .peer(learned_peer)
        .local(local_addr)
        .path(PathKind::DirectPunched);
    // Rebuild the direct path with the SAME carrier as the relay path — the
    // signal variant tells us which. nz: a fresh NNpsk0 session over the punched
    // socket (independent keys/counters — a rebuild, not a cipher-state handoff).
    if signal.is_noise() {
        let socket = std::sync::Arc::new(socket);
        let mut transport = match crate::transport::noise::noise_connect(
            socket,
            learned_peer,
            &routing_key,
            &secret,
            timings.relay_dial_timeout,
            timings.quic_idle_timeout,
        )
        .await
        {
            Ok(t) => {
                building.carrier(Carrier::NoiseUdp).ok();
                t
            }
            Err(e) => {
                building.carrier(Carrier::NoiseUdp).fail_with(&e);
                return Err(DirectError::transient(e));
            }
        };
        let _ = transport.take_signal(); // already direct — no further upgrade
        return Ok((
            Box::new(transport),
            DirectPath {
                peer: learned_peer,
                local: local_addr,
                quic_conn: None,
                fixed_mtu: crate::transport::noise::NZ_TUNNEL_MTU,
            },
        ));
    }
    let std_sock = socket
        .into_std()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("into_std")))?;
    let endpoint =
        client_endpoint(std_sock, routing_key, timings).map_err(DirectError::transient)?;
    // Dial the address the peer's packets actually came from — our NAT has a
    // mapping open toward it, which may not be true of the signaled address.
    // No accept ack on the direct path: the secret is already proven good, and
    // waiting on a reverse-direction byte over a fresh punch only adds failures.
    let session = match client_connect(&endpoint, learned_peer, &secret, false).await {
        Ok(s) => {
            building.carrier(Carrier::Quic).ok();
            s
        }
        Err(e) => {
            building.carrier(Carrier::Quic).fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    // Reuse the session's transport: its reader task is already attached to
    // the connection, and building a second QuicPeerTransport here would
    // leave that reader to steal the first inbound datagram before exiting.
    let conn = session.conn;
    Ok((
        Box::new(session.transport),
        DirectPath {
            peer: conn.remote_address(),
            local: local_addr,
            quic_conn: Some(conn),
            fixed_mtu: 0,
        },
    ))
}

/// Responder (A): wait for peer endpoint, STUN, send own endpoint, punch,
/// build direct QUIC server using identity, verify peer's secret. On success
/// also returns the punched socket's local address (for event reporting).
#[allow(clippy::too_many_arguments)]
async fn try_direct_as_responder(
    signal: &mut SignalChannel,
    stun_server: &str,
    protector: &SocketProtector,
    identity: &Identity,
    timings: &Timings,
    conn_log: Option<&SessionLog>,
    rec: &Recorder,
) -> Result<(IpTransport, DirectPath), DirectError> {
    let exchange = rec.step_now(StepKind::EndpointExchange);
    let (peer_addr, socket) = {
        let mut neg = SignalNegChannel::new(signal);
        let peer_addr = neg.recv_endpoint().await.map_err(neg_err)?;
        // Client-asserted, not observed: logged as `reported` and never to
        // be read as anything stronger (a malicious client can put any
        // address here).
        if let Some(sl) = conn_log {
            sl.addr(AddrKind::Reported, peer_addr);
        }
        // Follow the initiator's family: it signaled first, so STUN (and
        // punch) in the family its endpoint lives in.
        let stun = rec.step_now(StepKind::Stun).via(stun_server);
        let (socket, external_addr) =
            match pierce_keep_socket(stun_server, protector, peer_addr.is_ipv6()).await {
                Ok(x) => {
                    stun.local(x.1).ok();
                    x
                }
                Err(e) => {
                    stun.fail_with(&e);
                    return Err(DirectError::transient(e));
                }
            };
        if let Some(sl) = conn_log {
            sl.addr(AddrKind::SharerPublic, external_addr);
        }
        // Send our endpoint even when the families ended up mismatched (no
        // matching-family STUN address resolved): the initiator then detects
        // the mismatch immediately instead of timing out on the exchange.
        neg.send_endpoint(external_addr).await.map_err(neg_err)?;
        exchange.local(external_addr).peer(peer_addr).ok();
        if peer_addr.is_ipv6() != external_addr.is_ipv6() {
            let f = Fault::new(
                Reason::FamilyMismatch,
                format!("address family mismatch: ours {external_addr}, peer {peer_addr}"),
            );
            rec.mark(StepKind::Punch).peer(peer_addr).fail_with(&f);
            return Err(DirectError::transient(f));
        }
        (peer_addr, socket)
    };

    // Responder accepts from whatever source the QUIC Initial arrives on, so
    // the learned peer address is informational for the punch — but it is
    // address-validated (learned from packets the peer actually sourced), so
    // the connection log records it even when the QUIC build below fails.
    let (punch_pkt, verify_pkt) = punch_markers(&identity.secret);
    let punching = rec.step_now(StepKind::Punch).peer(peer_addr);
    let (socket, learned_peer) = match punch_and_verify(
        socket,
        peer_addr,
        &punch_pkt,
        &verify_pkt,
        timings.punch_phase_timeout,
        timings.punch_send_interval,
    )
    .await
    {
        Ok(x) => {
            punching.peer(x.1).ok();
            x
        }
        Err(e) => {
            punching.fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    if let Some(sl) = conn_log {
        sl.addr(AddrKind::PunchVerified, learned_peer);
    }
    let local_addr = socket
        .local_addr()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("local_addr")))?;
    let building = rec
        .step_now(StepKind::DirectHandshake)
        .peer(learned_peer)
        .local(local_addr)
        .path(PathKind::DirectPunched);
    // nz responder: accept a fresh NNpsk0 session on the punched socket (a pump
    // feeds noise_accept, which waits for the initiator's msg1). Same carrier as
    // the relay path; independent keys.
    if signal.is_noise() {
        let socket = std::sync::Arc::new(socket);
        let shaper = crate::transport::shaper::nz_shaper(&identity.routing_key, &identity.secret);
        let (rx, pump) = crate::transport::noise::spawn_socket_pump(socket.clone(), shaper);
        let mut transport = match crate::transport::noise::noise_accept(
            socket,
            rx,
            rand::random(),
            Some(pump),
            identity,
            timings.relay_dial_timeout,
            timings.quic_idle_timeout,
        )
        .await
        {
            Ok(t) => {
                building.carrier(Carrier::NoiseUdp).ok();
                t
            }
            Err(e) => {
                building.carrier(Carrier::NoiseUdp).fail_with(&e);
                return Err(DirectError::transient(e));
            }
        };
        let peer = transport.peer_addr();
        let _ = transport.take_signal(); // already direct — no further upgrade
        return Ok((
            Box::new(transport),
            DirectPath {
                peer,
                local: local_addr,
                quic_conn: None,
                fixed_mtu: crate::transport::noise::NZ_TUNNEL_MTU,
            },
        ));
    }
    let std_sock = socket
        .into_std()
        .map_err(|e| DirectError::transient(Fault::from_io(&e).context("into_std")))?;
    let endpoint = server_endpoint(std_sock, identity, timings).map_err(DirectError::transient)?;
    // Time-box only the wait for the initiator's connection attempt — not the
    // handshake, which keeps its own deadline inside authenticate_incoming.
    // endpoint.accept() blocks until an Incoming arrives; if the initiator's
    // VERIFY replies were lost it never dials, and an unbounded wait would pin
    // this task for the whole session (holding the signal channel, so no retry
    // round can progress). On timeout we return Transient and the upgrade loop
    // retries or observes cancellation. (After a successful mutual punch the
    // initiator dials immediately, so this only fires when it isn't coming.)
    let accept_deadline = timings.punch_phase_timeout * 2;
    let incoming = match tokio::time::timeout(accept_deadline, endpoint.accept()).await {
        Ok(Some(incoming)) => incoming,
        Ok(None) => {
            return Err(DirectError::transient(Fault::new(
                Reason::TransportClosed,
                "direct endpoint closed before accept",
            )));
        }
        Err(_) => {
            return Err(DirectError::transient(Fault::new(
                Reason::VerifyTimeout,
                format!(
                    "direct accept timed out after {accept_deadline:?} (initiator never dialed)"
                ),
            )));
        }
    };
    // No accept ack on the direct path (see the initiator-side note).
    let session = match authenticate_incoming(incoming, &identity.secret, false).await {
        Ok(s) => {
            building.carrier(Carrier::Quic).ok();
            s
        }
        Err(e) => {
            building.carrier(Carrier::Quic).fail_with(&e);
            return Err(DirectError::transient(e));
        }
    };
    // Reuse the session's transport (see the initiator-side note): a second
    // QuicPeerTransport would orphan the session's reader, which eats the
    // first inbound datagram on the fresh direct path.
    let conn = session.conn;
    Ok((
        Box::new(session.transport),
        DirectPath {
            peer: conn.remote_address(),
            local: local_addr,
            quic_conn: Some(conn),
            fixed_mtu: 0,
        },
    ))
}

// ---------- Helpers ----------

/// Resolve the relay to a single address. IP literals (v4, and v6 with or
/// without brackets — `Token::from_url` strips them, but a caller-supplied
/// `Config.relay_host` may not) short-circuit DNS. For hostnames, IPv4 is
/// preferred when both families resolve (the deployed relay is v4-first);
/// an AAAA-only host resolves to its IPv6 address(es).
///
/// A bare/bracketed IP literal short-circuits DNS (one address). A hostname
/// expands to EVERY resolved address — both families — so a dual-record
/// `relay.example` behaves exactly as if its A and AAAA had been listed as
/// separate relays.
fn resolve_one_relay(relay: &RelayEndpoint) -> Result<Vec<SocketAddr>, Fault> {
    let host = &relay.host;
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, relay.port)]);
    }
    let addrs: Vec<SocketAddr> = format!("{}:{}", host, relay.port)
        .to_socket_addrs()
        .map_err(|e| {
            Fault::new(
                Reason::DnsFailure,
                format!("resolve relay {}:{} failed: {e}", host, relay.port),
            )
        })?
        .collect();
    if addrs.is_empty() {
        return Err(Fault::new(
            Reason::DnsNoRecords,
            format!("no address for relay {}:{}", host, relay.port),
        ));
    }
    Ok(addrs)
}

/// Resolve every configured relay into a flat, de-duplicated address list
/// (URL/config order preserved). A per-relay resolution failure is logged and
/// skipped — censorship that blocks one relay's DNS must not take down the
/// rest — so this errors only when NOTHING resolves.
fn resolve_relays(relays: &[RelayEndpoint]) -> Result<Vec<(SocketAddr, RelayProtocol)>, Fault> {
    let mut out: Vec<(SocketAddr, RelayProtocol)> = Vec::new();
    let mut seen: HashSet<(SocketAddr, RelayProtocol)> = HashSet::new();
    for relay in relays {
        match resolve_one_relay(relay) {
            Ok(addrs) => {
                for a in addrs {
                    // Each resolved address inherits its endpoint's protocol; a
                    // hostname with A+AAAA records fans out into several.
                    let entry = (a, relay.protocol);
                    if seen.insert(entry) {
                        out.push(entry);
                    }
                }
            }
            Err(e) => warn!("skipping unresolvable relay: {}", e),
        }
    }
    if out.is_empty() {
        return Err(Fault::new(
            Reason::DnsNoRecords,
            "no relay address resolved from the configured relays",
        ));
    }
    Ok(out)
}

/// Like [`resolve_relays`], but stable-sorted IPv6-first. The client uses
/// this so a v6 relay path (and therefore a v6 hole punch) is tried before
/// v4; within a family the configured order (and protocol) is preserved.
fn resolve_relays_preferring_v6(
    relays: &[RelayEndpoint],
) -> Result<Vec<(SocketAddr, RelayProtocol)>, Fault> {
    let mut addrs = resolve_relays(relays)?;
    addrs.sort_by_key(|(a, _)| !a.is_ipv6()); // false(0)=v6 first, true(1)=v4
    Ok(addrs)
}

/// Bind the sharer's UDP socket. When the relay set spans IPv6 (or is mixed),
/// bind `::` dual-stack (IPV6_V6ONLY off) so one socket reaches relays of both
/// families and receives Initials forwarded by any of them; a pure-v4 relay
/// set keeps a plain `0.0.0.0` socket. Applies the FD protector.
/// UDP socket buffer size for nz sockets. The nz carrier has no tunnel pacer, so
/// an unpaced inner-TCP burst (a full congestion window at once) can overrun the
/// OS default receive buffer (~200 KB) and drop — which collapses the inner
/// TCP. quinn sizes QUIC's sockets internally; nz must size its own. Best-effort:
/// the kernel caps at net.core.{r,w}mem_max.
const NZ_SOCK_BUF: usize = 4 * 1024 * 1024;

/// Enlarge a UDP socket's send/recv buffers (see [`NZ_SOCK_BUF`]). Cross-platform
/// via `socket2::SockRef` (AsFd on unix, AsSocket on Windows). Failures are
/// ignored — a smaller-than-requested buffer still works, just with less burst
/// headroom.
fn tune_udp_buffers<'a, S>(socket: &'a S)
where
    socket2::SockRef<'a>: From<&'a S>,
{
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(NZ_SOCK_BUF);
    let _ = sock.set_send_buffer_size(NZ_SOCK_BUF);
}

fn bind_share_udp(
    protector: &SocketProtector,
    want_v6: bool,
    port: u16,
) -> Result<std::net::UdpSocket, String> {
    // `port` is 0 (ephemeral) for a relay-only sharer, or the advertised port a
    // `Direct` (relay-less) sharer must bind so clients can dial it.
    let std = if want_v6 {
        let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
            .map_err(|e| format!("create v6 socket: {}", e))?;
        sock.set_only_v6(false)
            .map_err(|e| format!("set_only_v6(false): {}", e))?;
        sock.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
            .map_err(|e| format!("bind [::]:{}: {}", port, e))?;
        std::net::UdpSocket::from(sock)
    } else {
        std::net::UdpSocket::bind(("0.0.0.0", port))
            .map_err(|e| format!("bind 0.0.0.0:{}: {}", port, e))?
    };
    std.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;
    tune_udp_buffers(&std);
    apply_protector_to_std(protector, &std);
    Ok(std)
}

/// Bind an ephemeral UDP wildcard socket in `peer`'s address family (so
/// send_to toward it cannot fail with a family mismatch), apply the FD
/// protector, and return it as a `std::net::UdpSocket` ready for handoff to
/// quinn. The client uses this per relay-dial attempt, so the punch family
/// matches the relay family unambiguously (no v4-mapped guessing).
pub(crate) fn bind_local_udp(
    protector: &SocketProtector,
    peer: SocketAddr,
) -> Result<std::net::UdpSocket, Fault> {
    let wildcard: SocketAddr = if peer.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let std = std::net::UdpSocket::bind(wildcard)
        .map_err(|e| Fault::from_io(&e).context(&format!("bind UDP {wildcard}")))?;
    std.set_nonblocking(true)
        .map_err(|e| Fault::from_io(&e).context("set_nonblocking"))?;
    tune_udp_buffers(&std);
    apply_protector_to_std(protector, &std);
    Ok(std)
}

/// Length of the per-session hole-punch markers.
const PUNCH_MARKER_LEN: usize = 16;

/// Per-session hole-punch markers `(probe, verify)`, derived from the shared
/// secret so they are unpredictable to an on-path observer — the secret travels
/// out of band in the share URL, never on the wire — instead of the old fixed
/// `sporaHP1P`/`sporaHP1V` literals a DPI box could byte-match. Both peers
/// derive identical values from the same 16-byte secret; the two markers differ
/// (distinct derivation labels) so a received VERIFY still proves the path is
/// bidirectional. Security still comes from the QUIC handshake that follows —
/// these only steer where we point it.
fn punch_markers(secret: &[u8; SECRET_LEN]) -> ([u8; PUNCH_MARKER_LEN], [u8; PUNCH_MARKER_LEN]) {
    let derive = |label: &[u8]| {
        let mut input = Vec::with_capacity(label.len() + SECRET_LEN);
        input.extend_from_slice(label);
        input.extend_from_slice(secret);
        let digest = ring::digest::digest(&ring::digest::SHA256, &input);
        let mut marker = [0u8; PUNCH_MARKER_LEN];
        marker.copy_from_slice(&digest.as_ref()[..PUNCH_MARKER_LEN]);
        marker
    };
    (
        derive(b"spora-punch-v1-probe"),
        derive(b"spora-punch-v1-verify"),
    )
}

/// Cap on peer-reflexive sources learned during a single punch exchange. A
/// spoofed-source punch flood would otherwise grow the learned/targets lists
/// without bound — and we send to every entry each tick, so the per-tick send
/// fan-out (and an O(n) membership scan per packet) would blow up. The signaled
/// address is always punched regardless, so a flood that fills this cap only
/// costs the peer-reflexive optimization, not the punch itself.
const MAX_PUNCH_SOURCES: usize = 64;

/// Record a peer-reflexive `src` heard during punching. Returns `true` if it was
/// newly added (so the caller starts punching it). Deduped via the set (O(1))
/// and bounded by `MAX_PUNCH_SOURCES`.
fn record_punch_source(
    learned: &mut HashSet<SocketAddr>,
    targets: &mut HashSet<SocketAddr>,
    src: SocketAddr,
) -> bool {
    if learned.contains(&src) || learned.len() >= MAX_PUNCH_SOURCES {
        return false;
    }
    learned.insert(src);
    targets.insert(src);
    true
}

/// Punch through NAT and verify *bidirectional* connectivity, learning the
/// peer's **observed** source address (ICE peer-reflexive style) rather than
/// trusting only the signaled one.
///
/// Why observed-source: a Linux conntrack NAT can remap an outgoing punch to
/// a different external port when an unsolicited inbound punch has already
/// created an `UNREPLIED` entry for the port we wanted ("port-steal"), so the
/// peer's packets routinely arrive from a port we were never told about.
/// Matching only the signaled address makes the punch fail in exactly that
/// case (and every retry re-poisons it). Instead we accept a punch/verify
/// from any source, learn it, and also send to it — which opens our own NAT
/// toward the address that actually works. Pointing the subsequent QUIC dial
/// at a wrong address merely fails the cert-pinned, secret-authenticated
/// handshake and retries, so trusting the observed source is safe.
///
/// Receiving a VERIFY proves both directions at once (it reached us, and the
/// peer sent it only because they received our packet), so success is the
/// first VERIFY received. We reply VERIFY to every source we hear from, plus
/// a few extra on exit, so the peer converges too. Returns the punched socket
/// and the learned peer address to dial.
///
/// `phase_timeout`/`send_interval` come from `Timings` (the total budget is
/// `2 * phase_timeout`, preserving the old two-phase wall-clock).
async fn punch_and_verify(
    socket: UdpSocket,
    signaled: SocketAddr,
    punch_pkt: &[u8],
    verify_pkt: &[u8],
    phase_timeout: Duration,
    send_interval: Duration,
) -> Result<(UdpSocket, SocketAddr), Fault> {
    debug!("Direct connection: punching {} (observed-source)", signaled);

    // Whether anything from the peer ever arrived. It separates the two
    // failures that look alike from the outside — "our packets never reached
    // them, or theirs never reached us" from "we met, but never confirmed it
    // both ways" — and only the first is evidence about the network.
    let heard_peer = std::sync::atomic::AtomicBool::new(false);
    let result = tokio::time::timeout(phase_timeout.saturating_mul(2), async {
        let mut buf = [0u8; 1500];
        let mut interval = tokio::time::interval(send_interval);
        // Always punch the signaled address; add learned sources as we hear
        // from them (and verify those — sending to a source opens our NAT
        // toward it).
        let mut targets: HashSet<SocketAddr> = HashSet::from([signaled]);
        let mut learned: HashSet<SocketAddr> = HashSet::new();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    for t in &targets {
                        let _ = socket.send_to(punch_pkt, *t).await;
                    }
                    for l in &learned {
                        let _ = socket.send_to(verify_pkt, *l).await;
                    }
                }
                result = socket.recv_from(&mut buf) => {
                    let (n, src) = match result {
                        Ok(x) => x,
                        Err(e) => return Err(Fault::from_io(&e).context("punch recv")),
                    };
                    let msg = &buf[..n];
                    if msg != punch_pkt && msg != verify_pkt {
                        continue;
                    }
                    heard_peer.store(true, std::sync::atomic::Ordering::Relaxed);
                    if record_punch_source(&mut learned, &mut targets, src) {
                        debug!("Direct connection: learned peer source {}", src);
                    }
                    // Open our NAT toward this source and tell it we heard it.
                    let _ = socket.send_to(verify_pkt, src).await;
                    if msg == verify_pkt {
                        // Bidirectional confirmed. A few extra VERIFYs so the
                        // peer reaches the same conclusion before we settle.
                        for _ in 0..3 {
                            let _ = socket.send_to(verify_pkt, src).await;
                        }
                        return Ok::<_, Fault>(src);
                    }
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(peer)) => {
            debug!("Bidirectional direct connection confirmed with {}", peer);
            Ok((socket, peer))
        }
        Ok(Err(e)) => Err(e),
        Err(_) if heard_peer.load(std::sync::atomic::Ordering::Relaxed) => Err(Fault::new(
            Reason::VerifyTimeout,
            format!(
                "heard the peer but never confirmed both directions within {:?}",
                phase_timeout.saturating_mul(2)
            ),
        )),
        Err(_) => Err(Fault::new(
            Reason::PunchTimeout,
            format!(
                "nothing from the peer within {:?}",
                phase_timeout.saturating_mul(2)
            ),
        )),
    }
}

/// Like `pierce()` but returns the UDP socket along with the addresses,
/// so it can be reused for the direct connection (same port = same NAT mapping).
///
/// `prefer_ipv6` orders the resolved STUN addresses so the family matching
/// the relay path is tried first (the punch socket is bound in the STUN
/// address's family, and both peers must end up in the same family for the
/// punch to work); the other family remains a fallback for STUN servers
/// without an AAAA/A record.
pub async fn pierce_keep_socket(
    stun_server: &str,
    protector: &SocketProtector,
    prefer_ipv6: bool,
) -> Result<(UdpSocket, SocketAddr), Fault> {
    let resolved: Vec<SocketAddr> = stun_server
        .to_socket_addrs()
        .map_err(|e| {
            Fault::new(
                Reason::DnsFailure,
                format!("resolve stun {stun_server}: {e}"),
            )
        })?
        .collect();
    let mut candidates: Vec<SocketAddr> = Vec::with_capacity(resolved.len());
    candidates.extend(resolved.iter().filter(|a| a.is_ipv6() == prefer_ipv6));
    candidates.extend(resolved.iter().filter(|a| a.is_ipv6() != prefer_ipv6));
    if candidates.is_empty() {
        return Err(Fault::new(
            Reason::DnsNoRecords,
            format!("stun {stun_server} resolved to no address"),
        ));
    }

    let mut last: Option<Fault> = None;
    for stun_addr in candidates {
        let wildcard: std::net::IpAddr = if stun_addr.is_ipv6() {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        };
        let mut local_port = server::BASE_PORT;
        while local_port < server::BASE_PORT + 10 {
            let local_addr = SocketAddr::new(wildcard, local_port);
            let udp = match tokio::net::UdpSocket::bind(&local_addr).await {
                Ok(udp) => udp,
                Err(e) => {
                    last = Some(Fault::from_io(&e).context(&format!("bind {local_addr}")));
                    local_port += 1;
                    continue;
                }
            };
            tune_udp_buffers(&udp);
            protect_socket(protector, &udp);
            debug!("Local addr: {}", &local_addr);

            let mut c = StunClient::new(stun_addr);
            // Drop the default SOFTWARE attribute ("SimpleRustStunClient"): it
            // is a near-unique cleartext fingerprint in every binding request.
            c.set_software(None);
            let f = c.query_external_address_async(&udp);
            match f.await {
                Ok(external_addr) => return Ok((udp, external_addr)),
                Err(e) => {
                    // The STUN client folds "no reply" and "unusable reply"
                    // into one error, so this cannot honestly claim the
                    // stronger of the two.
                    last = Some(Fault::new(
                        Reason::StunTimeout,
                        format!("stun query to {stun_addr} from :{local_port}: {e}"),
                    ));
                    local_port += 1;
                    continue;
                }
            };
        }
    }
    Err(last.unwrap_or_else(|| Fault::new(Reason::StunFailed, "no STUN candidate could be tried")))
}

pub async fn pierce(stun_server: &str) -> Result<(SocketAddr, SocketAddr), String> {
    let (socket, external_addr) = pierce_keep_socket(stun_server, &None, false).await?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local addr: {}", e))?;
    Ok((local_addr, external_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::{E2eSession, accept_one};

    #[test]
    fn punch_source_recording_is_deduped_and_bounded() {
        let mut learned = HashSet::new();
        let mut targets = HashSet::new();
        let a: SocketAddr = "1.2.3.4:5".parse().unwrap();

        // New source recorded into both sets.
        assert!(record_punch_source(&mut learned, &mut targets, a));
        assert!(learned.contains(&a) && targets.contains(&a));
        // Duplicate is not re-recorded.
        assert!(!record_punch_source(&mut learned, &mut targets, a));

        // Fill to the cap with distinct sources, then a flood source is refused.
        for i in 0..MAX_PUNCH_SOURCES as u32 {
            let s = SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 9));
            record_punch_source(&mut learned, &mut targets, s);
        }
        assert_eq!(
            learned.len(),
            MAX_PUNCH_SOURCES,
            "learned is bounded by the cap"
        );
        let flood: SocketAddr = "9.9.9.9:9".parse().unwrap();
        assert!(!record_punch_source(&mut learned, &mut targets, flood));
        assert_eq!(learned.len(), MAX_PUNCH_SOURCES);
    }
    use crate::transport::upgradable::upgradable_transport;

    /// Regression test: a CLOSED signal channel must be terminal for
    /// `try_direct_upgrade`. The responder used to loop straight back into
    /// `try_direct_as_responder` on any error; with the peer's signal stream
    /// gone, `recv_endpoint` fails instantly and the task hot-spins forever.
    #[tokio::test]
    async fn responder_upgrade_terminates_when_signal_closes() {
        let _ = env_logger::builder().is_test(true).try_init();
        let timings = Timings::default();
        let identity = Arc::new(Identity::generate());
        let secret = identity.secret;

        // Direct A<->B QUIC session on loopback (no relay needed: we only
        // want a real SignalChannel riding a real bidi stream).
        let a_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        a_std.set_nonblocking(true).unwrap();
        let a_addr = a_std.local_addr().unwrap();
        let a_endpoint = server_endpoint(a_std, &identity, &timings).unwrap();

        let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b_std.set_nonblocking(true).unwrap();
        let b_endpoint = client_endpoint(b_std, identity.routing_key, &timings).unwrap();

        let accept_task = tokio::spawn(async move {
            accept_one(&a_endpoint, &secret, false)
                .await
                .unwrap()
                .unwrap()
        });
        let b_session = client_connect(&b_endpoint, a_addr, &secret, false)
            .await
            .unwrap();
        let a_session = accept_task.await.unwrap();

        // Keep B's connection alive but drop ONLY its signal half, so A's
        // upgrade-sender stays open (the relay-via transport is still up)
        // while A's `recv_endpoint` hits a closed stream.
        let E2eSession {
            conn: _b_conn,
            transport: _b_transport,
            signal: b_signal,
        } = b_session;
        drop(b_signal);

        // A live UpgradeSender (router task running over A's transport).
        let (_upgradable, upgrade_sender, _router_handle) = upgradable_transport(
            Box::new(a_session.transport),
            Timings::default().upgrade_rescue_grace,
        );
        assert!(!upgrade_sender.is_closed());

        let cancel = CancellationToken::new();
        let upgrade_task = tokio::spawn(async move {
            try_direct_upgrade(
                a_session.signal,
                upgrade_sender,
                "127.0.0.1:1", // never reached: recv_endpoint fails first
                DirectRole::Responder { identity },
                false,
                &None,
                cancel,
                None,
                None,
                Timings::default(),
                None,
                None,
                SessionMeters::new(
                    &Recorder::disabled(),
                    Carrier::Quic,
                    PathKind::Relay,
                    None,
                    1200,
                ),
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), upgrade_task)
            .await
            .expect("responder upgrade task must terminate once the signal channel is closed")
            .unwrap();
    }
}
