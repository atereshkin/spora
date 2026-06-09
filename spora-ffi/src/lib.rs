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
extern crate android_logger;
use log::{info, LevelFilter};
use android_logger::FilterBuilder;

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

#[uniffi::export]
pub fn init_android_logging() {
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

#[uniffi::export]
pub fn share(
    identity_bytes: Vec<u8>,
    protector: Option<Box<dyn SocketProtectorCallback>>,
) -> Result<ShareResult, ShareError> {
    let identity = spora_core::identity::Identity::from_bytes(&identity_bytes)
        .map_err(ShareError::Generic)?;
    let config = spora_core::Config {
        protector: protector.and_then(wrap_protector),
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
