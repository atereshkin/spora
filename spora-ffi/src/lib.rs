uniffi::setup_scaffolding!();

use crate::ConnectError::InvalidUrl;
use once_cell::sync::Lazy;
use spora_core;
use spora_core::tun_util;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::os::fd::RawFd;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;
extern crate android_logger;
use log::LevelFilter;

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
    task: JoinHandle<()>,
    socket_fd: RawFd,
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
    let _ = android_logger::init_once(
        android_logger::Config::default()
            .with_tag("my-rust-lib") // shows as the Logcat tag
            .with_max_level(LevelFilter::Trace),
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

#[uniffi::export]
pub fn share() -> Result<ShareResult, ShareError> {
    let session = RUNTIME
        .block_on(spora_core::share(spora_core::Config::default()))
        .map_err(|e| ShareError::Generic(e.to_string()))?;

    let url = format!("spora://{}/{}", session.endpoint, session.key);
    let cancel = session.cancel.clone();
    let task = session.task;

    // Detach the cancel token from ShareSession so we manage it ourselves.
    // We don't call session.stop() — we store the pieces directly.
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
/// Blocks until the connection is established (STUN + pubsub negotiation),
/// then spawns the tunnel loop in the background and returns immediately.
/// Use `get_tunnel_socket_fd` to obtain the UDP socket for VPN protection,
/// and `disconnect` to tear down the tunnel.
#[uniffi::export]
pub fn connect(url: String, tun_fd: RawFd) -> Result<i32, ConnectError> {
    let url = Url::parse(&url).map_err(|_| InvalidUrl)?;
    if url.scheme() != "spora" {
        return Err(InvalidUrl);
    }

    // Block until the connection is established so the socket fd is available
    // immediately after connect() returns.
    let result = RUNTIME.block_on(async {
        spora_core::connect(url, &spora_core::Config::default())
            .await
            .map_err(ConnectError::Generic)
    })?;

    let socket_fd = result.relay_socket_fd;

    // Spawn the tunnel loop in the background.
    let task = RUNTIME.spawn(async move {
        let tun = unsafe { tokio::fs::File::from_raw_fd(tun_fd) };
        if let Err(e) = tun_util::start(result.transport, tun).await {
            log::error!("Tunnel loop exited with error: {}", e);
        }
    });

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    SESSIONS
        .lock()
        .unwrap()
        .insert(handle, TunnelSession { task, socket_fd });

    Ok(handle)
}

/// Returns the raw file descriptor of the tunnel's UDP socket.
///
/// On Android, pass this to `VpnService.protect()` to prevent the tunnel
/// traffic from being routed back through the VPN.
#[uniffi::export]
pub fn get_tunnel_socket_fd(handle: i32) -> Result<i32, TunnelError> {
    let sessions = SESSIONS.lock().unwrap();
    let session = sessions.get(&handle).ok_or(TunnelError::InvalidHandle)?;
    Ok(session.socket_fd)
}

/// Tears down the tunnel associated with the given handle.
#[uniffi::export]
pub fn disconnect(handle: i32) -> Result<(), TunnelError> {
    let mut sessions = SESSIONS.lock().unwrap();
    let session = sessions.remove(&handle).ok_or(TunnelError::InvalidHandle)?;
    session.task.abort();
    Ok(())
}
