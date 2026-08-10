uniffi::setup_scaffolding!();

use crate::ConnectError::InvalidUrl;
use once_cell::sync::Lazy;
use spora_core;
use spora_core::tun_util;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;
use log::info;

/// Callback interface that Kotlin implements to protect sockets from VPN routing.
#[uniffi::export(callback_interface)]
pub trait SocketProtectorCallback: Send + Sync {
    fn protect(&self, fd: i32);
}

/// Callback interface for MTU notifications.
///
/// Called when the effective tunnel MTU is discovered (via PMTUD).
/// May be called multiple times: once after relay connection, and again after
/// direct P2P upgrade. The Android app can use the value to configure the TUN device MTU.
#[uniffi::export(callback_interface)]
pub trait MtuCallback: Send + Sync {
    fn on_mtu(&self, mtu: i32);
}

/// Tunnel lifecycle events surfaced to the host (used by the Apple client to
/// drive status UI: reconnecting, direct-path upgrade, session ended). Mirrors
/// [`spora_core::TunnelEvent`] with string-typed socket addresses so it lowers
/// cleanly over UniFFI.
#[derive(uniffi::Enum)]
pub enum SporaEvent {
    /// A relay-via session is up. `peer` is the remote address (the relay's
    /// address when the path goes through it).
    RelaySessionEstablished { peer: String },
    /// A direct (hole-punched) connection was established and handed to the
    /// transport router; the actual swap applies shortly after.
    DirectUpgradeSucceeded { local: String, peer: String },
    /// One direct-upgrade attempt failed (the upgrade task may retry).
    DirectUpgradeFailed { reason: String },
    /// Client only: a re-dial is starting after the transport died.
    Reconnecting,
    /// Client only: the re-dial succeeded.
    Reconnected,
    /// The active session ended (peer replaced, cancelled, or transport closed).
    SessionEnded { reason: String },
    /// Share side: the connection log could not be written.
    ConnLogDegraded { detail: String },
}

impl From<spora_core::TunnelEvent> for SporaEvent {
    fn from(e: spora_core::TunnelEvent) -> Self {
        use spora_core::TunnelEvent as T;
        match e {
            T::RelaySessionEstablished { peer } => {
                SporaEvent::RelaySessionEstablished { peer: peer.to_string() }
            }
            T::DirectUpgradeSucceeded { local, peer } => SporaEvent::DirectUpgradeSucceeded {
                local: local.to_string(),
                peer: peer.to_string(),
            },
            T::DirectUpgradeFailed { reason } => SporaEvent::DirectUpgradeFailed { reason },
            T::Reconnecting => SporaEvent::Reconnecting,
            T::Reconnected => SporaEvent::Reconnected,
            T::SessionEnded { reason } => SporaEvent::SessionEnded { reason },
            T::ConnLogDegraded { detail } => SporaEvent::ConnLogDegraded { detail },
        }
    }
}

/// Callback interface for tunnel lifecycle events. Implementations MUST be
/// non-blocking (enqueue and return) — the callback is invoked inline from the
/// tunnel's async tasks (see [`spora_core::EventHook`]).
#[uniffi::export(callback_interface)]
pub trait EventCallback: Send + Sync {
    fn on_event(&self, event: SporaEvent);
}

/// Wrap a UniFFI event callback into the non-blocking hook spora-core expects.
fn wrap_event_hook(cb: Option<Box<dyn EventCallback>>) -> spora_core::EventHook {
    cb.map(|cb| {
        let cb = Arc::new(cb);
        Arc::new(move |ev: spora_core::TunnelEvent| {
            cb.on_event(ev.into());
        }) as Arc<dyn Fn(spora_core::TunnelEvent) + Send + Sync>
    })
}

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime")
});

static NEXT_HANDLE: AtomicI32 = AtomicI32::new(1);
static SESSIONS: Lazy<Mutex<HashMap<i32, TunnelSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

struct TunnelSession {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    keepalive_knob: Arc<AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
}

struct ShareSessionEntry {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

static SHARE_SESSIONS: Lazy<Mutex<HashMap<i32, ShareSessionEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(uniffi::Record)]
pub struct ShareResult {
    pub handle: i32,
    pub url: String,
}

#[cfg(target_os = "android")]
#[uniffi::export]
pub fn init_android_logging() {
    use android_logger::FilterBuilder;
    use log::LevelFilter;
    let filter = FilterBuilder::new()
        .filter_module("quinn", LevelFilter::Warn)
        .filter_module("quinn_proto", LevelFilter::Warn)
        .filter_module("quinn_udp", LevelFilter::Warn)
        .filter_module("tracing", LevelFilter::Warn)
        .filter_module("smoltcp", LevelFilter::Warn)
        .filter_level(LevelFilter::Debug)
        .build();
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("spora")
            .with_max_level(LevelFilter::Trace)
            .with_filter(filter),
    );
}

/// Initialize logging on Apple platforms. Routes the `log` crate into the
/// unified logging system (visible in Console.app and `log stream --predicate
/// 'subsystem == "to.spora"'`). Safe to call more than once. This is the
/// Apple counterpart to [`init_android_logging`]; a macOS/iOS client calls it
/// once at startup (and again from the tunnel extension process, which is
/// separate).
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[uniffi::export]
pub fn init_apple_logging() {
    use log::LevelFilter;
    // Ignore the error if a logger is already installed (idempotent across the
    // app and extension calling in, and across repeated starts).
    let _ = oslog::OsLogger::new("to.spora")
        .level_filter(LevelFilter::Debug)
        .category_level_filter("quinn", LevelFilter::Warn)
        .category_level_filter("quinn_proto", LevelFilter::Warn)
        .category_level_filter("quinn_udp", LevelFilter::Warn)
        .category_level_filter("smoltcp", LevelFilter::Warn)
        .init();
}

#[derive(Debug, uniffi::Error)]
pub enum ShareError {
    Generic(String),
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareError::Generic(s) => s.fmt(f),
        }
    }
}

/// Wrap a UniFFI callback into the closure type that spora-core expects.
fn wrap_protector(cb: Box<dyn SocketProtectorCallback>) -> spora_core::SocketProtector {
    let cb = Arc::new(cb);
    Some(Arc::new(move |fd: i32| {
        cb.protect(fd);
    }))
}

/// Generate a fresh identity and return its serialized bytes. The platform
/// (Android app) is expected to persist these bytes — e.g. in
/// SharedPreferences — and pass them back to `share()` on subsequent
/// invocations so the share URL stays stable across launches.
#[uniffi::export]
pub fn make_identity() -> Vec<u8> {
    spora_core::identity::Identity::generate().to_bytes()
}

/// Starts sharing this device's connection.
///
/// Connection logging (the sharer-side per-flow record, see spora-core's
/// `connlog`): pass `conn_log_dir` to enable it. The app should pass a
/// directory under its files dir (e.g. `filesDir/connlog`) and exclude it
/// from Android auto-backup. `conn_log_dir = None` disables logging.
/// `conn_log_retention_days = None` uses the core default (90 days).
/// `conn_log_sessions_only = true` records who was connected and when, but
/// no per-flow destination records.
///
/// Fails if `conn_log_dir` is set but not writable — a default-on liability
/// log must not silently degrade at startup.
#[uniffi::export]
pub fn share(
    identity_bytes: Vec<u8>,
    protector: Option<Box<dyn SocketProtectorCallback>>,
    conn_log_dir: Option<String>,
    conn_log_retention_days: Option<u32>,
    conn_log_sessions_only: bool,
) -> Result<ShareResult, ShareError> {
    let identity = spora_core::identity::Identity::from_bytes(&identity_bytes)
        .map_err(ShareError::Generic)?;
    let conn_log = conn_log_dir.map(|dir| {
        let mut cfg = spora_core::connlog::ConnLogConfig::in_dir(dir);
        if let Some(days) = conn_log_retention_days {
            cfg.retention = std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60);
        }
        cfg.log_destinations = !conn_log_sessions_only;
        cfg
    });
    let config = spora_core::Config {
        protector: protector.and_then(wrap_protector),
        conn_log,
        ..spora_core::Config::default()
    };
    let session = RUNTIME
        .block_on(spora_core::share(identity, config))
        .map_err(|e| ShareError::Generic(e.to_string()))?;

    let url = session.url.to_string();
    let cancel = session.cancel.clone();
    let task = session.task;

    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    SHARE_SESSIONS
        .lock()
        .unwrap()
        .insert(id, ShareSessionEntry { cancel, task });

    Ok(ShareResult { handle: id, url })
}

/// Stops the share session associated with the given handle.
#[uniffi::export]
pub fn stop_share(handle: i32) -> Result<(), TunnelError> {
    let mut sessions = SHARE_SESSIONS.lock().unwrap();
    let entry = sessions.remove(&handle).ok_or(TunnelError::InvalidHandle)?;
    entry.cancel.cancel();
    entry.task.abort();
    Ok(())
}

#[derive(Debug, uniffi::Error)]
pub enum ConnectError {
    InvalidUrl,
    Generic(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Generic(s) => s.fmt(f),
            InvalidUrl => "Invalid URL".fmt(f),
        }
    }
}

#[derive(Debug, uniffi::Error)]
pub enum TunnelError {
    InvalidHandle,
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::InvalidHandle => "Invalid tunnel handle".fmt(f),
        }
    }
}

/// Establishes a tunnel connection and returns a handle for managing it.
///
/// Blocks until the connection is established (relay negotiation),
/// then spawns the tunnel loop in the background and returns immediately.
/// The `protector` callback is invoked on every new socket fd so that
/// Android can call `VpnService.protect()` to bypass VPN routing.
/// Use `disconnect` to tear down the tunnel.
#[uniffi::export]
pub fn connect(url: String, tun_fd: RawFd, protector: Box<dyn SocketProtectorCallback>, mtu_callback: Option<Box<dyn MtuCallback>>) -> Result<i32, ConnectError> {
    info!("FFI connect() called with tun_fd={}", tun_fd);

    let url = Url::parse(&url).map_err(|_| InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(InvalidUrl);
    }

    let mtu_cb: spora_core::MtuCallback = mtu_callback.map(|cb| {
        let cb = Arc::new(cb);
        Arc::new(move |mtu: u16| {
            cb.on_mtu(mtu as i32);
        }) as Arc<dyn Fn(u16) + Send + Sync>
    });

    let config = spora_core::Config {
        protector: wrap_protector(protector),
        mtu_callback: mtu_cb,
        ..spora_core::Config::default()
    };

    let result = RUNTIME.block_on(async {
        spora_core::connect(url, &config)
            .await
            .map_err(ConnectError::Generic)
    })?;

    let cancel = result.cancel;
    let keepalive_knob = result.keepalive_knob;
    let keepalive_waker = result.keepalive_waker;
    info!("FFI connect(): relay established");

    // Spawn the tunnel loop in the background.
    let task = RUNTIME.spawn(async move {
        info!("FFI tunnel task: starting with tun_fd={}", tun_fd);
        let tun = unsafe { OwnedFd::from_raw_fd(tun_fd) };
        match tun_util::start_fd(result.transport, tun).await {
            Ok(()) => info!("FFI tunnel task: exited normally"),
            Err(e) => log::error!("FFI tunnel task: exited with error: {}", e),
        }
    });

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    info!("FFI connect(): returning handle={}", handle);
    SESSIONS
        .lock()
        .unwrap()
        .insert(handle, TunnelSession { cancel, task, keepalive_knob, keepalive_waker });

    Ok(handle)
}

/// Apple counterpart to [`connect`]. Establishes a tunnel and pumps packets
/// against an Apple `utun` descriptor (4-byte AF framing, unlike Android's raw
/// TUN). A `protector` (bind sockets to the physical interface via
/// `IP_BOUND_IF`) is required on macOS: unlike iOS, the OS does not auto-bypass
/// provider sockets, so without it the relay dial loops back into the tunnel and
/// dead-locks. An optional [`EventCallback`] surfaces lifecycle events for
/// status UI.
///
/// Blocks until the relay session is established, then spawns the tunnel loop
/// and returns a handle. The `tun_fd` ownership is transferred to Rust, which
/// closes it when the tunnel ends (the caller must hand over a `dup()` of the
/// provider's utun fd and not use it afterward).
#[uniffi::export]
pub fn connect_utun(
    url: String,
    tun_fd: RawFd,
    protector: Option<Box<dyn SocketProtectorCallback>>,
    mtu_callback: Option<Box<dyn MtuCallback>>,
    event_callback: Option<Box<dyn EventCallback>>,
) -> Result<i32, ConnectError> {
    info!("FFI connect_utun() called with tun_fd={}", tun_fd);

    let url = Url::parse(&url).map_err(|_| InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(InvalidUrl);
    }

    let mtu_cb: spora_core::MtuCallback = mtu_callback.map(|cb| {
        let cb = Arc::new(cb);
        Arc::new(move |mtu: u16| {
            cb.on_mtu(mtu as i32);
        }) as Arc<dyn Fn(u16) + Send + Sync>
    });

    // On Darwin the OS does NOT auto-bypass provider-originated sockets, and
    // NEPacketTunnelNetworkSettings.excludedRoutes are unreliable for a packet
    // tunnel — so the Apple client passes a protector that binds each socket to
    // the physical interface (IP_BOUND_IF). Without it the relay dial routes back
    // into the tunnel and dead-locks.
    let config = spora_core::Config {
        protector: protector.and_then(wrap_protector),
        mtu_callback: mtu_cb,
        event_hook: wrap_event_hook(event_callback),
        ..spora_core::Config::default()
    };

    let result = RUNTIME.block_on(async {
        spora_core::connect(url, &config)
            .await
            .map_err(ConnectError::Generic)
    })?;

    let cancel = result.cancel;
    let keepalive_knob = result.keepalive_knob;
    let keepalive_waker = result.keepalive_waker;
    info!("FFI connect_utun(): relay established");

    let task = RUNTIME.spawn(async move {
        info!("FFI utun tunnel task: starting with tun_fd={}", tun_fd);
        let tun = unsafe { OwnedFd::from_raw_fd(tun_fd) };
        match tun_util::start_fd_utun(result.transport, tun).await {
            Ok(()) => info!("FFI utun tunnel task: exited normally"),
            Err(e) => log::error!("FFI utun tunnel task: exited with error: {}", e),
        }
    });

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    info!("FFI connect_utun(): returning handle={}", handle);
    SESSIONS
        .lock()
        .unwrap()
        .insert(handle, TunnelSession { cancel, task, keepalive_knob, keepalive_waker });

    Ok(handle)
}

/// Tears down the tunnel associated with the given handle.
#[uniffi::export]
pub fn disconnect(handle: i32) -> Result<(), TunnelError> {
    info!("FFI disconnect() called with handle={}", handle);
    let mut sessions = SESSIONS.lock().unwrap();
    let session = sessions.remove(&handle).ok_or(TunnelError::InvalidHandle)?;
    info!("FFI disconnect(): cancelling token...");
    session.cancel.cancel();
    info!("FFI disconnect(): aborting task...");
    session.task.abort();
    info!("FFI disconnect(): done");
    Ok(())
}

/// Controls the keepalive behavior for a client tunnel.
///
/// - `interval_secs = 0`: on-demand mode (dormant when idle, probes on traffic after gap).
/// - `interval_secs > 0`: always probe at that interval (e.g. 20 when screen is on).
///
/// Transition from 0→N sends an immediate ping to detect dead connections.
#[uniffi::export]
pub fn set_keepalive(handle: i32, interval_secs: u32) -> Result<(), TunnelError> {
    info!("FFI set_keepalive(handle={}, interval_secs={})", handle, interval_secs);
    let sessions = SESSIONS.lock().unwrap();
    let session = sessions.get(&handle).ok_or(TunnelError::InvalidHandle)?;
    session.keepalive_knob.store(interval_secs as u64, Ordering::Relaxed);
    // Wake the transport task so it notices the knob change immediately.
    // Without this, a Dormant transport has no timers and would sleep until
    // the next inbound/outbound packet.
    if let Some(w) = session.keepalive_waker.lock().unwrap().take() {
        w.wake();
    }
    Ok(())
}
