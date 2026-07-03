mod carrier;
mod neg;
mod reassembly;
pub mod connlog;
pub mod e2e;
pub mod identity;
pub mod server;
pub mod signal;
pub mod transport;
pub mod tun_util;

use std::collections::HashSet;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use log::{debug, info, warn};
use quinn::Connection;
use stunclient::StunClient;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
pub use tokio_util::sync::CancellationToken;
use url::Url;

use crate::connlog::{AddrKind, ConnLog, ConnLogConfig, SessionLog};
use crate::e2e::{
    authenticate_incoming, client_connect, client_endpoint, server_endpoint, E2eSession,
};
use crate::identity::{Identity, RelayEndpoint, RelayProtocol, Token, ROUTING_KEY_LEN, SECRET_LEN};
use crate::neg::{NegChannel, SignalNegChannel};
use crate::server::TunnelError;
use crate::signal::SignalChannel;
use crate::transport::keepalive::{KeepAliveConfig, KeepAliveMode, KeepAliveTransport};
use crate::transport::upgradable::{upgradable_transport, UpgradeSender};
use crate::transport::DialFuture;
use crate::transport::ReconnectTransport;
pub use crate::server::is_local_address;
pub use crate::transport::IpTransport;
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
pub type SessionHandler = Arc<dyn Fn(IpTransport, CancellationToken) -> SessionFuture + Send + Sync>;

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
}

/// Every protocol interval/timeout that used to be a hardcoded constant.
/// `Default` is exactly today's production values; tests and the lab can
/// scale them down to make slow scenarios run in seconds of wall time.
#[derive(Clone, Debug)]
pub struct Timings {
    /// Cadence of the sharer's REGISTER packets to the relay.
    pub register_interval: Duration,
    /// QUIC max idle timeout (both relay-via and direct connections).
    pub quic_idle_timeout: Duration,
    /// QUIC keep-alive interval.
    pub quic_keep_alive: Duration,
    /// `ReconnectTransport` sleep after a failed dial.
    pub reconnect_delay: Duration,
    /// Initiator retry delay after a failed direct-upgrade attempt.
    pub upgrade_retry_delay: Duration,
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
    DirectUpgradeFailed { reason: String },
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
    // Resolve every configured relay (a hostname may expand to v4+v6). The
    // sharer registers with each *relayed* endpoint; `Direct` endpoints are the
    // sharer's own advertised listener — accepted directly, never registered.
    let resolved = resolve_relays(&config.relays)?;
    let url = identity.token(config.relays.clone()).to_url();
    let register_addrs: Vec<SocketAddr> = resolved
        .iter()
        .filter(|(_, p)| p.is_relayed())
        .map(|(a, _)| *a)
        .collect();

    // One socket serves quinn (accepting clients forwarded by ANY relay, or
    // dialing us directly) and registration with all relays. It must be
    // dual-stack when the endpoint set spans families, so a single socket can
    // send to both v4 and v6 relays (v4 as v4-mapped) and receive Initials from
    // either; a pure-v4 set keeps a plain v4 socket (unchanged behavior).
    let want_v6 = resolved.iter().any(|(a, _)| a.is_ipv6());
    let std_socket = bind_share_udp(&config.protector, want_v6)?;
    let std_clone = std_socket
        .try_clone()
        .map_err(|e| format!("socket try_clone: {}", e))?;
    std_clone
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking on cloned socket: {}", e))?;
    let registrar = Arc::new(
        tokio::net::UdpSocket::from_std(std_clone)
            .map_err(|e| format!("tokio::from_std: {}", e))?,
    );

    let endpoint = server_endpoint(std_socket, &identity, &config.timings)?;
    info!(
        "share: e2e endpoint up, rk {:x?}, endpoints {:?}, registering with {:?}",
        &routing_key[..4],
        resolved,
        register_addrs
    );

    // Sign each relay registration with the identity's certificate key, so the
    // relay (which holds no secret) can verify the routing key is ours and
    // reject an on-path attacker's attempt to rebind it.
    let signer =
        relay_client::protocol::RegisterSigner::new(&identity.cert_der_bytes, &identity.key_der_bytes)
            .map_err(|e| format!("build register signer: {}", e))?
            .with_token(config.relay_token.clone());

    // Connection log: opened before the share goes live, so a default-on log
    // that cannot be written fails here loudly instead of running unlogged.
    let conn_log = match &config.conn_log {
        Some(cfg) => Some(ConnLog::open(
            cfg.clone(),
            &identity,
            config.event_hook.clone(),
        )?),
        None => None,
    };

    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    let config_for_loop = config.clone();
    let identity_for_loop = identity.clone();
    let register_interval = config.timings.register_interval;
    let task = tokio::spawn(async move {
        // Run the relay registrar concurrently *inside* this task rather than
        // as a detached child. `register_loop` never returns, so the select
        // resolves only when `run_share_loop` does (on cancellation or endpoint
        // close), and dropping this task's future — e.g. via `ShareSession::abort()`,
        // which aborts before the cancelled branch can be re-polled — drops the
        // registrar with it. A detached `tokio::spawn` would instead leak: its
        // `JoinHandle` is a local here, and dropping a `JoinHandle` does not abort
        // the task, so the registrar would keep flapping the relay binding forever.
        tokio::select! {
            _ = relay_client::register_loop(registrar, register_addrs, register_interval, signer) => {}
            _ = run_share_loop(endpoint, identity_for_loop, cancel_child, config_for_loop, conn_log) => {}
        }
    });

    Ok(ShareSession { url, cancel, task })
}

async fn run_share_loop(
    endpoint: quinn::Endpoint,
    identity: Arc<Identity>,
    cancel: CancellationToken,
    config: Config,
    conn_log: Option<ConnLog>,
) {
    let secret = identity.secret;
    let mut tunnel_cancel: Option<CancellationToken> = None;
    let mut iteration: u32 = 0;
    // Authenticated sessions arrive here from the per-connection auth tasks.
    let (session_tx, mut session_rx) = tokio::sync::mpsc::unbounded_channel::<E2eSession>();

    info!("[share] waiting for peers");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("share cancelled");
                if let Some(tc) = tunnel_cancel.take() { tc.cancel(); }
                endpoint.close(0u32.into(), b"share-cancelled");
                break;
            }
            // Accept connection attempts and authenticate each one in its own
            // task, so a peer that stalls the secret read (an attacker who knows
            // only the routing key) can't block the accept loop and starve
            // legitimate peers. The sharer still serves one tunnel at a time;
            // we just no longer serialize the handshake+auth of every attempt.
            incoming = endpoint.accept() => {
                match incoming {
                    None => { info!("share endpoint closed"); break; }
                    Some(incoming) => {
                        let tx = session_tx.clone();
                        let cancel = cancel.clone();
                        tokio::spawn(async move {
                            tokio::select! {
                                _ = cancel.cancelled() => {}
                                res = authenticate_incoming(incoming, &secret, true) => match res {
                                    Ok(session) => { let _ = tx.send(session); }
                                    Err(e) => warn!("[share] accept failed: {}", e),
                                }
                            }
                        });
                    }
                }
            }
            Some(session) = session_rx.recv() => {
                iteration += 1;
                emit(
                    &config.event_hook,
                    TunnelEvent::RelaySessionEstablished {
                        peer: session.conn.remote_address(),
                    },
                );

                if let Some(tc) = tunnel_cancel.take() {
                    info!("[share #{}] new peer, cancelling previous tunnel", iteration);
                    tc.cancel();
                }

                // Sessions accepted here always bootstrap relay-via, so the
                // connection's remote address is the relay's, recorded as such.
                let slog = conn_log
                    .as_ref()
                    .map(|cl| cl.session(session.conn.remote_address()));

                let child_cancel = cancel.child_token();
                tunnel_cancel = Some(child_cancel.clone());
                spawn_responder_tunnel(session, identity.clone(), &config, child_cancel, slog);
            }
        }
    }
}

fn spawn_responder_tunnel(
    session: E2eSession,
    identity: Arc<Identity>,
    config: &Config,
    tunnel_cancel: CancellationToken,
    slog: Option<Arc<SessionLog>>,
) {
    let E2eSession {
        conn,
        transport,
        signal,
    } = session;

    let (upgradable, upgrade_sender, router_handle) = upgradable_transport(Box::new(transport));
    let keepalive_cfg = KeepAliveConfig::default();
    // The meter (Custom exit mode) must ignore the synthetic keepalive pings
    // riding the tunnel; tell it which inner address pair they use.
    let keepalive_pair = (keepalive_cfg.src_ip, keepalive_cfg.dst_ip);
    let transport: IpTransport = Box::new(KeepAliveTransport::new(
        Box::new(upgradable),
        keepalive_cfg,
    ));

    let protector_for_tunnel = config.protector.clone();
    let conn_for_mtu = conn.clone();
    let upgrade_cancel = tunnel_cancel.clone();

    let upgrade_task = if config.enable_direct_upgrade {
        let stun_server = config.stun_server.clone();
        let protector = config.protector.clone();
        let mtu_cb = config.mtu_callback.clone();
        let timings = config.timings.clone();
        let event_hook = config.event_hook.clone();
        let role = DirectRole::Responder { identity };
        let path_ipv6 = conn.remote_address().is_ipv6();
        let upgrade_slog = slog.clone();
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
            )
            .await;
        })
    } else {
        // Direct upgrade disabled: drop the UpgradeSender (the upgradable
        // router then drains forever, by design) but keep the SignalChannel
        // alive for the session's lifetime so the peer's signal stream
        // doesn't see EOF.
        drop(upgrade_sender);
        tokio::spawn(async move {
            upgrade_cancel.cancelled().await;
            drop(signal);
        })
    };

    if let Some(cb) = config.mtu_callback.clone() {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            if let Some(mds) = conn_for_mtu.max_datagram_size() {
                info!("e2e max datagram size (post-PMTUD): {}", mds);
                cb(mds as u16);
            }
        });
    }

    let exit_slog = slog.clone();
    let end_cancel = tunnel_cancel.clone();
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
    let token = Arc::new(Token::from_url(&url)?);
    // Resolve every relay in the URL (a hostname may expand to v4+v6) and try
    // them IPv6 first: a v6 relay path drives a v6 hole punch, which succeeds
    // far more often (no NAT, just a stateful firewall) than a v4 one. The
    // order is re-derived on each (re)dial, so DNS changes and censorship
    // failover both take effect on reconnect.
    let relay_addrs = Arc::new(resolve_relays_preferring_v6(&token.relays)?);
    info!(
        "connect: relays {:?} for rk {:x?}",
        relay_addrs,
        &token.routing_key[..4]
    );

    let cancel = CancellationToken::new();
    let keepalive_knob = Arc::new(AtomicU64::new(0));
    let keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>> =
        Arc::new(std::sync::Mutex::new(None));

    let initial = dial_relays(
        &relay_addrs,
        &token,
        config,
        cancel.clone(),
        keepalive_knob.clone(),
        keepalive_waker.clone(),
    )
    .await
    .map_err(|e| format!("initial dial: {}", e))?;

    let dialer_token = token.clone();
    let dialer_config = config.clone();
    let dialer_cancel = cancel.clone();
    let dialer_knob = keepalive_knob.clone();
    let dialer_waker = keepalive_waker.clone();
    let dialer_relays = relay_addrs.clone();
    let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
        let token = dialer_token.clone();
        let config = dialer_config.clone();
        let cancel = dialer_cancel.clone();
        let knob = dialer_knob.clone();
        let waker = dialer_waker.clone();
        let relays = dialer_relays.clone();
        Box::pin(async move {
            emit(&config.event_hook, TunnelEvent::Reconnecting);
            let result = dial_relays(&relays, &token, &config, cancel, knob, waker).await;
            if result.is_ok() {
                emit(&config.event_hook, TunnelEvent::Reconnected);
            }
            result
        })
    });

    let transport = Box::new(ReconnectTransport::new(
        initial,
        dialer,
        config.timings.reconnect_delay,
    ));
    Ok(ConnectResult {
        transport,
        cancel,
        keepalive_knob,
        keepalive_waker,
    })
}

/// Try each relay (already ordered IPv6-first) until one bootstraps a
/// relay-via session, time-boxing each attempt by `relay_dial_timeout` so a
/// dead/censored relay — or one the sharer never registered with (a family
/// mismatch looks identical: the Initial is silently dropped) — fails over to
/// the next instead of stalling. Returns the last error if all fail.
async fn dial_relays(
    relay_addrs: &[(SocketAddr, RelayProtocol)],
    token: &Token,
    config: &Config,
    cancel: CancellationToken,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
) -> std::io::Result<IpTransport> {
    let mut last_err: Option<std::io::Error> = None;
    for &(relay_addr, protocol) in relay_addrs {
        let attempt = dial_initiator(
            relay_addr,
            protocol,
            token,
            config,
            cancel.clone(),
            keepalive_knob.clone(),
            keepalive_waker.clone(),
        );
        match tokio::time::timeout(config.timings.relay_dial_timeout, attempt).await {
            Ok(Ok(transport)) => return Ok(transport),
            Ok(Err(e)) => {
                warn!("relay {} dial failed: {}", relay_addr, e);
                last_err = Some(e);
            }
            Err(_) => {
                warn!(
                    "relay {} dial timed out after {:?}",
                    relay_addr, config.timings.relay_dial_timeout
                );
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("relay {} dial timed out", relay_addr),
                ));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no relays to dial")
    }))
}

async fn dial_initiator(
    relay_addr: SocketAddr,
    protocol: RelayProtocol,
    token: &Token,
    config: &Config,
    cancel: CancellationToken,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
) -> std::io::Result<IpTransport> {
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
        })
        .await
        .map_err(std::io::Error::other)?;
    let E2eSession {
        conn,
        transport,
        signal,
    } = session;

    emit(
        &config.event_hook,
        TunnelEvent::RelaySessionEstablished {
            peer: conn.remote_address(),
        },
    );

    let (upgradable, upgrade_sender, router_handle) = upgradable_transport(Box::new(transport));
    let upgrade_knob = keepalive_knob.clone();
    let keepalive_cfg = KeepAliveConfig {
        mode: KeepAliveMode::Adaptive {
            knob: keepalive_knob,
            waker: keepalive_waker,
        },
        idle_threshold: config.timings.keepalive_idle_threshold,
        response_timeout: config.timings.keepalive_response_timeout,
        inbound_grace: config.timings.keepalive_inbound_grace,
        ..Default::default()
    };
    let transport: IpTransport =
        Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

    let upgrade_cancel = cancel.clone();
    if config.enable_direct_upgrade {
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
            )
            .await;
            drop(router_handle);
        });
    } else {
        // Direct upgrade disabled: hold the SignalChannel open so the peer's
        // signal stream doesn't see EOF. The holder must die with the
        // *session*, not just the connect-level cancel token: each re-dial
        // runs through here again, so a cancel-only holder would accumulate
        // one parked task (pinning a dead connection's streams) per redial.
        // The router drops its upgrade receiver when the session ends, so
        // `upgrade_sender.closed()` is exactly the session-death signal.
        tokio::spawn(async move {
            tokio::select! {
                _ = upgrade_cancel.cancelled() => {}
                _ = upgrade_sender.closed() => {}
            }
            drop(signal);
            drop(router_handle);
        });
    }

    if let Some(cb) = config.mtu_callback.clone() {
        let conn = conn.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            if let Some(mds) = conn.max_datagram_size() {
                info!("e2e max datagram size (post-PMTUD): {}", mds);
                cb(mds as u16);
            }
        });
    }

    Ok(transport)
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
    SignalClosed(String),
    /// Transient failure (STUN, punch, QUIC handshake, ...); a later attempt
    /// may succeed.
    Transient(String),
}

impl DirectError {
    fn reason(&self) -> &str {
        match self {
            DirectError::SignalClosed(r) | DirectError::Transient(r) => r,
        }
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
            DirectError::SignalClosed("signal channel closed".into())
        }
        other => DirectError::Transient(format!("{:?}", other)),
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

        if initiator
            && let Some(ref knob) = keepalive_knob
        {
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
                )
                .await
            }
        };
        match result {
            Ok((transport, conn, local)) => {
                info!("Direct connection established, upgrading transport");
                if upgrade_sender.send(transport).is_err() {
                    warn!("Failed to send upgrade — tunnel already closed");
                    return;
                }
                if let Some(sl) = &conn_log {
                    sl.addr(AddrKind::Verified, conn.remote_address());
                }
                emit(
                    &event_hook,
                    TunnelEvent::DirectUpgradeSucceeded {
                        local,
                        peer: conn.remote_address(),
                    },
                );
                if let Some(cb) = mtu_callback.clone() {
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        if let Some(mds) = conn.max_datagram_size() {
                            info!("P2P max datagram size (post-PMTUD): {}", mds);
                            cb(mds as u16);
                        }
                    });
                }
                return;
            }
            Err(e) => {
                warn!("Direct connection attempt failed: {}", e.reason());
                emit(
                    &event_hook,
                    TunnelEvent::DirectUpgradeFailed {
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
async fn try_direct_as_initiator(
    signal: &mut SignalChannel,
    stun_server: &str,
    path_ipv6: bool,
    protector: &SocketProtector,
    routing_key: [u8; ROUTING_KEY_LEN],
    secret: [u8; SECRET_LEN],
    timings: &Timings,
) -> Result<(IpTransport, Connection, SocketAddr), DirectError> {
    let (socket, external_addr) = pierce_keep_socket(stun_server, protector, path_ipv6)
        .await
        .map_err(DirectError::Transient)?;
    let peer_addr = {
        let mut neg = SignalNegChannel::new(signal);
        neg.send_endpoint(external_addr).await.map_err(neg_err)?;
        tokio::time::timeout(timings.endpoint_exchange_timeout, neg.recv_endpoint())
            .await
            .map_err(|_| {
                DirectError::Transient("timed out waiting for peer endpoint".to_string())
            })?
            .map_err(neg_err)?
    };
    // The punch socket's family is fixed by our STUN result; a peer endpoint
    // in the other family is unreachable from it. Fail fast (the exchange is
    // one candidate per side, no multi-family negotiation) instead of
    // burning 2x punch_phase_timeout sending packets the OS refuses.
    if peer_addr.is_ipv6() != external_addr.is_ipv6() {
        return Err(DirectError::Transient(format!(
            "address family mismatch: ours {}, peer {}",
            external_addr, peer_addr
        )));
    }

    let (punch_pkt, verify_pkt) = punch_markers(&secret);
    let (socket, learned_peer) = punch_and_verify(
        socket,
        peer_addr,
        &punch_pkt,
        &verify_pkt,
        timings.punch_phase_timeout,
        timings.punch_send_interval,
    )
    .await
    .map_err(DirectError::Transient)?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| DirectError::Transient(format!("local_addr: {}", e)))?;
    let std_sock = socket
        .into_std()
        .map_err(|e| DirectError::Transient(format!("into_std: {}", e)))?;
    let endpoint =
        client_endpoint(std_sock, routing_key, timings).map_err(DirectError::Transient)?;
    // Dial the address the peer's packets actually came from — our NAT has a
    // mapping open toward it, which may not be true of the signaled address.
    // No accept ack on the direct path: the secret is already proven good, and
    // waiting on a reverse-direction byte over a fresh punch only adds failures.
    let session = client_connect(&endpoint, learned_peer, &secret, false)
        .await
        .map_err(DirectError::Transient)?;
    // Reuse the session's transport: its reader task is already attached to
    // the connection, and building a second QuicPeerTransport here would
    // leave that reader to steal the first inbound datagram before exiting.
    let conn = session.conn;
    let transport: IpTransport = Box::new(session.transport);
    Ok((transport, conn, local_addr))
}

/// Responder (A): wait for peer endpoint, STUN, send own endpoint, punch,
/// build direct QUIC server using identity, verify peer's secret. On success
/// also returns the punched socket's local address (for event reporting).
async fn try_direct_as_responder(
    signal: &mut SignalChannel,
    stun_server: &str,
    protector: &SocketProtector,
    identity: &Identity,
    timings: &Timings,
    conn_log: Option<&SessionLog>,
) -> Result<(IpTransport, Connection, SocketAddr), DirectError> {
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
        let (socket, external_addr) =
            pierce_keep_socket(stun_server, protector, peer_addr.is_ipv6())
                .await
                .map_err(DirectError::Transient)?;
        if let Some(sl) = conn_log {
            sl.addr(AddrKind::SharerPublic, external_addr);
        }
        // Send our endpoint even when the families ended up mismatched (no
        // matching-family STUN address resolved): the initiator then detects
        // the mismatch immediately instead of timing out on the exchange.
        neg.send_endpoint(external_addr).await.map_err(neg_err)?;
        if peer_addr.is_ipv6() != external_addr.is_ipv6() {
            return Err(DirectError::Transient(format!(
                "address family mismatch: ours {}, peer {}",
                external_addr, peer_addr
            )));
        }
        (peer_addr, socket)
    };

    // Responder accepts from whatever source the QUIC Initial arrives on, so
    // the learned peer address is informational for the punch — but it is
    // address-validated (learned from packets the peer actually sourced), so
    // the connection log records it even when the QUIC build below fails.
    let (punch_pkt, verify_pkt) = punch_markers(&identity.secret);
    let (socket, learned_peer) = punch_and_verify(
        socket,
        peer_addr,
        &punch_pkt,
        &verify_pkt,
        timings.punch_phase_timeout,
        timings.punch_send_interval,
    )
    .await
    .map_err(DirectError::Transient)?;
    if let Some(sl) = conn_log {
        sl.addr(AddrKind::PunchVerified, learned_peer);
    }
    let local_addr = socket
        .local_addr()
        .map_err(|e| DirectError::Transient(format!("local_addr: {}", e)))?;
    let std_sock = socket
        .into_std()
        .map_err(|e| DirectError::Transient(format!("into_std: {}", e)))?;
    let endpoint = server_endpoint(std_sock, identity, timings).map_err(DirectError::Transient)?;
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
            return Err(DirectError::Transient(
                "direct endpoint closed before accept".into(),
            ));
        }
        Err(_) => {
            return Err(DirectError::Transient(
                "direct accept timed out (initiator never dialed)".into(),
            ));
        }
    };
    // No accept ack on the direct path (see the initiator-side note).
    let session = authenticate_incoming(incoming, &identity.secret, false)
        .await
        .map_err(DirectError::Transient)?;
    // Reuse the session's transport (see the initiator-side note): a second
    // QuicPeerTransport would orphan the session's reader, which eats the
    // first inbound datagram on the fresh direct path.
    let conn = session.conn;
    let transport: IpTransport = Box::new(session.transport);
    Ok((transport, conn, local_addr))
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
fn resolve_one_relay(relay: &RelayEndpoint) -> Result<Vec<SocketAddr>, String> {
    let host = &relay.host;
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, relay.port)]);
    }
    let addrs: Vec<SocketAddr> = format!("{}:{}", host, relay.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve relay {}:{} failed: {}", host, relay.port, e))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("no address for relay {}:{}", host, relay.port));
    }
    Ok(addrs)
}

/// Resolve every configured relay into a flat, de-duplicated address list
/// (URL/config order preserved). A per-relay resolution failure is logged and
/// skipped — censorship that blocks one relay's DNS must not take down the
/// rest — so this errors only when NOTHING resolves.
fn resolve_relays(relays: &[RelayEndpoint]) -> Result<Vec<(SocketAddr, RelayProtocol)>, String> {
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
        return Err("no relay address resolved from the configured relays".into());
    }
    Ok(out)
}

/// Like [`resolve_relays`], but stable-sorted IPv6-first. The client uses
/// this so a v6 relay path (and therefore a v6 hole punch) is tried before
/// v4; within a family the configured order (and protocol) is preserved.
fn resolve_relays_preferring_v6(
    relays: &[RelayEndpoint],
) -> Result<Vec<(SocketAddr, RelayProtocol)>, String> {
    let mut addrs = resolve_relays(relays)?;
    addrs.sort_by_key(|(a, _)| !a.is_ipv6()); // false(0)=v6 first, true(1)=v4
    Ok(addrs)
}

/// Bind the sharer's UDP socket. When the relay set spans IPv6 (or is mixed),
/// bind `::` dual-stack (IPV6_V6ONLY off) so one socket reaches relays of both
/// families and receives Initials forwarded by any of them; a pure-v4 relay
/// set keeps a plain `0.0.0.0` socket. Applies the FD protector.
fn bind_share_udp(protector: &SocketProtector, want_v6: bool) -> Result<std::net::UdpSocket, String> {
    let std = if want_v6 {
        let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
            .map_err(|e| format!("create v6 socket: {}", e))?;
        sock.set_only_v6(false)
            .map_err(|e| format!("set_only_v6(false): {}", e))?;
        sock.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)).into())
            .map_err(|e| format!("bind [::]:0: {}", e))?;
        std::net::UdpSocket::from(sock)
    } else {
        std::net::UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| format!("bind 0.0.0.0:0: {}", e))?
    };
    std.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;
    apply_protector_to_std(protector, &std);
    Ok(std)
}

/// Bind an ephemeral UDP wildcard socket in `peer`'s address family (so
/// send_to toward it cannot fail with a family mismatch), apply the FD
/// protector, and return it as a `std::net::UdpSocket` ready for handoff to
/// quinn. The client uses this per relay-dial attempt, so the punch family
/// matches the relay family unambiguously (no v4-mapped guessing).
pub(crate) fn bind_local_udp(protector: &SocketProtector, peer: SocketAddr) -> Result<std::net::UdpSocket, String> {
    let wildcard: SocketAddr = if peer.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let std = std::net::UdpSocket::bind(wildcard)
        .map_err(|e| format!("bind UDP {}: {}", wildcard, e))?;
    std.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;
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
    (derive(b"spora-punch-v1-probe"), derive(b"spora-punch-v1-verify"))
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
) -> Result<(UdpSocket, SocketAddr), String> {
    debug!("Direct connection: punching {} (observed-source)", signaled);

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
                        Err(e) => return Err(format!("recv error: {}", e)),
                    };
                    let msg = &buf[..n];
                    if msg != punch_pkt && msg != verify_pkt {
                        continue;
                    }
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
                        return Ok::<_, String>(src);
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
        Err(_) => Err("timed out during punch exchange".into()),
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
) -> Result<(UdpSocket, SocketAddr), String> {
    let resolved: Vec<SocketAddr> = stun_server
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve stun address: {}", e))?
        .collect();
    let mut candidates: Vec<SocketAddr> = Vec::with_capacity(resolved.len());
    candidates.extend(resolved.iter().filter(|a| a.is_ipv6() == prefer_ipv6));
    candidates.extend(resolved.iter().filter(|a| a.is_ipv6() != prefer_ipv6));
    if candidates.is_empty() {
        return Err("stun address did not resolve".into());
    }

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
                Err(_) => {
                    local_port += 1;
                    continue;
                }
            };
            protect_socket(protector, &udp);
            debug!("Local addr: {}", &local_addr);

            let mut c = StunClient::new(stun_addr);
            // Drop the default SOFTWARE attribute ("SimpleRustStunClient"): it
            // is a near-unique cleartext fingerprint in every binding request.
            c.set_software(None);
            let f = c.query_external_address_async(&udp);
            match f.await {
                Ok(external_addr) => return Ok((udp, external_addr)),
                Err(_) => {
                    local_port += 1;
                    continue;
                }
            };
        }
    }
    Err("failed to pierce".into())
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
    use crate::e2e::accept_one;

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
        assert_eq!(learned.len(), MAX_PUNCH_SOURCES, "learned is bounded by the cap");
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
            accept_one(&a_endpoint, &secret, false).await.unwrap().unwrap()
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
        let (_upgradable, upgrade_sender, _router_handle) =
            upgradable_transport(Box::new(a_session.transport));
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
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), upgrade_task)
            .await
            .expect("responder upgrade task must terminate once the signal channel is closed")
            .unwrap();
    }
}
