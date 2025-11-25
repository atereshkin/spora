uniffi::setup_scaffolding!();

use std::fmt::Formatter;
use once_cell::sync::Lazy;
use spora_core;
use tokio::runtime::Runtime;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime")
});

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
    let handle = RUNTIME.spawn(async move { spora_core::share().await });
    match handle.await.unwrap() {
        Ok(result) => Ok(format!("spora://{}/{}", result.endpoint, result.key)),
        Err(e) => Err(ShareError::Generic(e.to_string()))
    }
}

