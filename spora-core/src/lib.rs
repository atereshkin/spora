mod neg;
mod reassembly;
pub mod e2e;
pub mod identity;
pub mod server;
pub mod signal;
pub mod transport;
pub mod tun_util;

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

use crate::e2e::{accept_one, client_connect, client_endpoint, server_endpoint, E2eSession};
use crate::identity::{Identity, Token, ROUTING_KEY_LEN, SECRET_LEN};
use crate::neg::{NegChannel, SignalNegChannel};
use crate::server::TunnelError;
use crate::signal::SignalChannel;
use crate::transport::keepalive::{KeepAliveConfig, KeepAliveMode, KeepAliveTransport};
use crate::transport::upgradable::{upgradable_transport, UpgradeSender};
use crate::transport::DialFuture;
use crate::transport::ReconnectTransport;
pub use crate::server::is_local_address;
pub use crate::transport::IpTransport;

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
    pub relay_host: String,
    pub relay_port: u16,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stun_server: "stun.l.google.com:19302".into(),
            relay_host: "167.71.66.250".into(),
            relay_port: 443,
            protector: None,
            mtu_callback: None,
            exit_mode: ExitMode::Netstack,
            timings: Timings::default(),
            event_hook: None,
            enable_direct_upgrade: true,
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

    let relay_addr = resolve_relay(&config.relay_host, config.relay_port)?;
    let url = identity
        .token(config.relay_host.clone(), config.relay_port)
        .to_url();

    let std_socket = bind_local_udp(&config.protector)?;
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
        "share: e2e endpoint up, rk {:x?}, relay {}",
        &routing_key[..4],
        relay_addr
    );

    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    let config_for_loop = config.clone();
    let identity_for_loop = identity.clone();
    let register_interval = config.timings.register_interval;
    let task = tokio::spawn(async move {
        let register_task = tokio::spawn(relay_client::register_loop(
            registrar,
            relay_addr,
            routing_key,
            register_interval,
        ));
        run_share_loop(endpoint, identity_for_loop, cancel_child, config_for_loop).await;
        register_task.abort();
    });

    Ok(ShareSession { url, cancel, task })
}

async fn run_share_loop(
    endpoint: quinn::Endpoint,
    identity: Arc<Identity>,
    cancel: CancellationToken,
    config: Config,
) {
    let secret = identity.secret;
    let mut tunnel_cancel: Option<CancellationToken> = None;
    let mut iteration: u32 = 0;

    loop {
        iteration += 1;
        info!("[share #{}] waiting for peer", iteration);
        let session = tokio::select! {
            _ = cancel.cancelled() => {
                info!("share cancelled");
                if let Some(tc) = tunnel_cancel.take() { tc.cancel(); }
                endpoint.close(0u32.into(), b"share-cancelled");
                break;
            }
            result = accept_one(&endpoint, &secret) => match result {
                None => { info!("share endpoint closed"); break; }
                Some(Ok(s)) => s,
                Some(Err(e)) => { warn!("[share #{}] accept failed: {}", iteration, e); continue; }
            },
        };

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

        let child_cancel = cancel.child_token();
        tunnel_cancel = Some(child_cancel.clone());
        spawn_responder_tunnel(session, identity.clone(), &config, child_cancel);
    }
}

fn spawn_responder_tunnel(
    session: E2eSession,
    identity: Arc<Identity>,
    config: &Config,
    tunnel_cancel: CancellationToken,
) {
    let E2eSession {
        conn,
        transport,
        signal,
    } = session;

    let (upgradable, upgrade_sender, router_handle) = upgradable_transport(Box::new(transport));
    let transport: IpTransport = Box::new(KeepAliveTransport::new(
        Box::new(upgradable),
        KeepAliveConfig::default(),
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
        tokio::spawn(async move {
            try_direct_upgrade(
                signal,
                upgrade_sender,
                &stun_server,
                role,
                &protector,
                upgrade_cancel,
                None,
                mtu_cb,
                timings,
                event_hook,
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

    let session_fut: SessionFuture = match &config.exit_mode {
        ExitMode::Netstack => Box::pin(async move {
            let _ = server::start_tunnel(transport, protector_for_tunnel, tunnel_cancel, true).await;
        }),
        ExitMode::Custom(handler) => handler(transport, tunnel_cancel),
    };
    tokio::spawn(async move {
        session_fut.await;
        upgrade_task.abort();
        drop(router_handle);
    });
}

/// Connect to a sharer via the URL. Returns the IP-level transport plus the
/// keepalive controls so the caller (CLI/FFI) can toggle dormant mode.
pub async fn connect(url: Url, config: &Config) -> Result<ConnectResult, String> {
    let token = Arc::new(Token::from_url(&url)?);
    let relay_addr = resolve_relay(&token.relay_host, token.relay_port)?;
    info!(
        "connect: relay {} for rk {:x?}",
        relay_addr,
        &token.routing_key[..4]
    );

    let cancel = CancellationToken::new();
    let keepalive_knob = Arc::new(AtomicU64::new(0));
    let keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>> =
        Arc::new(std::sync::Mutex::new(None));

    let initial = dial_initiator(
        relay_addr,
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
    let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
        let token = dialer_token.clone();
        let config = dialer_config.clone();
        let cancel = dialer_cancel.clone();
        let knob = dialer_knob.clone();
        let waker = dialer_waker.clone();
        Box::pin(async move {
            emit(&config.event_hook, TunnelEvent::Reconnecting);
            let result =
                dial_initiator(relay_addr, &token, &config, cancel, knob, waker).await;
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

async fn dial_initiator(
    relay_addr: SocketAddr,
    token: &Token,
    config: &Config,
    cancel: CancellationToken,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
) -> std::io::Result<IpTransport> {
    let std_socket = bind_local_udp(&config.protector).map_err(std::io::Error::other)?;
    let endpoint = client_endpoint(std_socket, token.routing_key, &config.timings)
        .map_err(std::io::Error::other)?;
    let session = client_connect(&endpoint, relay_addr, &token.secret)
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
        tokio::spawn(async move {
            try_direct_upgrade(
                signal,
                upgrade_sender,
                &stun_server,
                role,
                &protector,
                upgrade_cancel,
                Some(upgrade_knob),
                mtu_cb,
                timings,
                event_hook,
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_direct_upgrade(
    mut signal: SignalChannel,
    upgrade_sender: UpgradeSender,
    stun_server: &str,
    role: DirectRole,
    protector: &SocketProtector,
    cancel: CancellationToken,
    keepalive_knob: Option<Arc<AtomicU64>>,
    mtu_callback: MtuCallback,
    timings: Timings,
    event_hook: EventHook,
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
                    protector,
                    *routing_key,
                    *secret,
                    &timings,
                )
                .await
            }
            DirectRole::Responder { identity } => {
                try_direct_as_responder(&mut signal, stun_server, protector, identity, &timings)
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
    protector: &SocketProtector,
    routing_key: [u8; ROUTING_KEY_LEN],
    secret: [u8; SECRET_LEN],
    timings: &Timings,
) -> Result<(IpTransport, Connection, SocketAddr), DirectError> {
    let (socket, external_addr) = pierce_keep_socket(stun_server, protector)
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

    let socket = punch_and_verify(
        socket,
        peer_addr,
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
    let session = client_connect(&endpoint, peer_addr, &secret)
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
) -> Result<(IpTransport, Connection, SocketAddr), DirectError> {
    let (peer_addr, socket) = {
        let mut neg = SignalNegChannel::new(signal);
        let peer_addr = neg.recv_endpoint().await.map_err(neg_err)?;
        let (socket, external_addr) = pierce_keep_socket(stun_server, protector)
            .await
            .map_err(DirectError::Transient)?;
        neg.send_endpoint(external_addr).await.map_err(neg_err)?;
        (peer_addr, socket)
    };

    let socket = punch_and_verify(
        socket,
        peer_addr,
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
    let endpoint = server_endpoint(std_sock, identity, timings).map_err(DirectError::Transient)?;
    let Some(session_result) = accept_one(&endpoint, &identity.secret).await else {
        return Err(DirectError::Transient(
            "direct endpoint closed before accept".into(),
        ));
    };
    let session = session_result.map_err(DirectError::Transient)?;
    // Reuse the session's transport (see the initiator-side note): a second
    // QuicPeerTransport would orphan the session's reader, which eats the
    // first inbound datagram on the fresh direct path.
    let conn = session.conn;
    let transport: IpTransport = Box::new(session.transport);
    Ok((transport, conn, local_addr))
}

// ---------- Helpers ----------

fn resolve_relay(host: &str, port: u16) -> Result<SocketAddr, String> {
    format!("{}:{}", host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve relay {}:{} failed: {}", host, port, e))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("no IPv4 for relay {}:{}", host, port))
}

/// Bind an ephemeral UDP socket on 0.0.0.0, apply the FD protector, and
/// return it as a `std::net::UdpSocket` ready for handoff to quinn.
fn bind_local_udp(protector: &SocketProtector) -> Result<std::net::UdpSocket, String> {
    let std = std::net::UdpSocket::bind(("0.0.0.0", 0))
        .map_err(|e| format!("bind UDP: {}", e))?;
    std.set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;
    apply_protector_to_std(protector, &std);
    Ok(std)
}

const VERIFY_MARKER: &[u8; 7] = b"SPORA_V";

/// Punch through NAT and verify *bidirectional* connectivity.
///
/// Phase 1 — punch exchange: send punch packets repeatedly while waiting for
/// the peer's punch.
///
/// Phase 2 — bidirectional verify: both sides send VERIFY packets. Receiving
/// the peer's VERIFY proves they also completed phase 1.
///
/// `phase_timeout` bounds each phase; `send_interval` is the packet cadence
/// within a phase (see `Timings::punch_phase_timeout` / `punch_send_interval`).
async fn punch_and_verify(
    socket: UdpSocket,
    peer_addr: SocketAddr,
    phase_timeout: Duration,
    send_interval: Duration,
) -> Result<UdpSocket, String> {
    debug!("Direct connection: punching {}", peer_addr);

    let phase1 = tokio::time::timeout(phase_timeout, async {
        let mut buf = [0u8; 1500];
        let mut interval = tokio::time::interval(send_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = socket.send_to(&[0u8; 1], peer_addr).await;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((_, addr)) if addr == peer_addr => return Ok::<_, String>(()),
                        Ok(_) => continue,
                        Err(e) => return Err(format!("recv error: {}", e)),
                    }
                }
            }
        }
    })
    .await;
    match phase1 {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("timed out during punch exchange".into()),
    }

    debug!("Punch received from {}, verifying bidirectional...", peer_addr);

    let phase2 = tokio::time::timeout(phase_timeout, async {
        let mut buf = [0u8; 1500];
        let mut interval = tokio::time::interval(send_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = socket.send_to(VERIFY_MARKER, peer_addr).await;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr))
                            if addr == peer_addr
                                && len == VERIFY_MARKER.len()
                                && &buf[..len] == VERIFY_MARKER =>
                        {
                            let _ = socket.send_to(VERIFY_MARKER, peer_addr).await;
                            return Ok::<_, String>(());
                        }
                        Ok(_) => continue,
                        Err(e) => return Err(format!("recv error: {}", e)),
                    }
                }
            }
        }
    })
    .await;

    match phase2 {
        Ok(Ok(())) => {
            debug!("Bidirectional direct connection confirmed with {}", peer_addr);
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("direct connection is not bidirectional — not upgrading".into()),
    }
    Ok(socket)
}

/// Like `pierce()` but returns the UDP socket along with the addresses,
/// so it can be reused for the direct connection (same port = same NAT mapping).
pub async fn pierce_keep_socket(
    stun_server: &str,
    protector: &SocketProtector,
) -> Result<(UdpSocket, SocketAddr), String> {
    let Some(stun_addr) = stun_server
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve stun address: {}", e))?
        .find(|x| x.is_ipv4())
    else {
        return Err("stun address did not resolve into an IPv4".into());
    };

    let mut local_port = server::BASE_PORT;
    while local_port < server::BASE_PORT + 10 {
        let local_addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], local_port));
        let udp = match tokio::net::UdpSocket::bind(&local_addr).await {
            Ok(udp) => udp,
            Err(_) => {
                local_port += 1;
                continue;
            }
        };
        protect_socket(protector, &udp);
        debug!("Local addr: {}", &local_addr);

        let c = StunClient::new(stun_addr);
        let f = c.query_external_address_async(&udp);
        match f.await {
            Ok(external_addr) => return Ok((udp, external_addr)),
            Err(_) => {
                local_port += 1;
                continue;
            }
        };
    }
    Err("failed to pierce".into())
}

pub async fn pierce(stun_server: &str) -> Result<(SocketAddr, SocketAddr), String> {
    let (socket, external_addr) = pierce_keep_socket(stun_server, &None).await?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local addr: {}", e))?;
    Ok((local_addr, external_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let accept_task =
            tokio::spawn(async move { accept_one(&a_endpoint, &secret).await.unwrap().unwrap() });
        let b_session = client_connect(&b_endpoint, a_addr, &secret).await.unwrap();
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
                &None,
                cancel,
                None,
                None,
                Timings::default(),
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
