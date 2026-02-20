uniffi::setup_scaffolding!();

use crate::ConnectError::InvalidUrl;
use once_cell::sync::Lazy;
use spora_core;
use spora_core::tun_util;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::os::fd::RawFd;
use std::os::unix::io::FromRawFd;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;
extern crate android_logger;
use log::{info, LevelFilter};

/// Callback interface that Kotlin implements to protect sockets from VPN routing.
#[uniffi::export(callback_interface)]
pub trait SocketProtectorCallback: Send + Sync {
    fn protect(&self, fd: i32);
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
            .with_tag("spora")
            .with_max_level(LevelFilter::Debug),
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
pub fn make_secret_key() -> String {
    spora_core::make_secret_key()
}

/// Wrap a UniFFI callback into the closure type that spora-core expects.
fn wrap_protector(cb: Box<dyn SocketProtectorCallback>) -> spora_core::SocketProtector {
    let cb = Arc::new(cb);
    Some(Arc::new(move |fd: i32| {
        cb.protect(fd);
    }))
}

#[uniffi::export]
pub fn share(key: String, protector: Option<Box<dyn SocketProtectorCallback>>) -> Result<ShareResult, ShareError> {
    let config = spora_core::Config {
        protector: protector.and_then(wrap_protector),
        ..spora_core::Config::default()
    };
    let session = RUNTIME
        .block_on(spora_core::share(key, config))
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
/// Blocks until the connection is established (relay + pubsub negotiation),
/// then spawns the tunnel loop in the background and returns immediately.
/// The `protector` callback is invoked on every new socket fd so that
/// Android can call `VpnService.protect()` to bypass VPN routing.
/// Use `disconnect` to tear down the tunnel.
#[uniffi::export]
pub fn connect(url: String, tun_fd: RawFd, protector: Box<dyn SocketProtectorCallback>) -> Result<i32, ConnectError> {
    info!("FFI connect() called with tun_fd={}", tun_fd);

    let url = Url::parse(&url).map_err(|_| InvalidUrl)?;
    if url.scheme() != "spora" {
        return Err(InvalidUrl);
    }

    let config = spora_core::Config {
        protector: wrap_protector(protector),
        ..spora_core::Config::default()
    };

    let result = RUNTIME.block_on(async {
        spora_core::connect(url, &config)
            .await
            .map_err(ConnectError::Generic)
    })?;

    let cancel = result.cancel;
    info!("FFI connect(): relay established");

    // Spawn the tunnel loop in the background.
    let task = RUNTIME.spawn(async move {
        info!("FFI tunnel task: starting with tun_fd={}", tun_fd);
        let tun = unsafe { tokio::fs::File::from_raw_fd(tun_fd) };
        match tun_util::start(result.transport, tun).await {
            Ok(()) => info!("FFI tunnel task: exited normally"),
            Err(e) => log::error!("FFI tunnel task: exited with error: {}", e),
        }
    });

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    info!("FFI connect(): returning handle={}", handle);
    SESSIONS
        .lock()
        .unwrap()
        .insert(handle, TunnelSession { cancel, task });

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
