uniffi::setup_scaffolding!();

use crate::ConnectError::InvalidUrl;
use once_cell::sync::Lazy;
use spora_core;
use spora_core::tun_util;
use std::fmt::Formatter;
use std::os::fd::RawFd;
use std::os::unix::io::FromRawFd;
use tokio::runtime::Runtime;
use url::Url;
extern crate android_logger;
use log::LevelFilter;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime")
});

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
pub async fn share() -> Result<String, ShareError> {
    let handle = RUNTIME.spawn(async move { spora_core::share(spora_core::Config::default()).await });
    match handle.await.unwrap() {
        Ok(result) => Ok(format!("spora://{}/{}", result.endpoint, result.key)),
        Err(e) => Err(ShareError::Generic(e.to_string())),
    }
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

#[uniffi::export]
pub async fn connect(url: String, tun_fd: RawFd) -> Result<(), ConnectError> {
    let url = Url::parse(&url).map_err(|_| InvalidUrl)?;
    if url.scheme() != "spora" {
        return Err(InvalidUrl);
    }
    let handle = RUNTIME.spawn(async move {
        let transport = spora_core::connect(url, &spora_core::Config::default())
            .await
            .map_err(|e| ConnectError::Generic(e))?;
        let tun = unsafe { tokio::fs::File::from_raw_fd(tun_fd) };

        match tun_util::start(transport, tun).await {
            Ok(()) => Ok(()),
            Err(e) => Err(ConnectError::Generic(format!(
                "Failed to start tunnel: {}",
                e
            ))),
        }
    });
    handle.await.unwrap()
}
