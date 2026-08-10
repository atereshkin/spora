//! Regression test for the `register_loop` leak: stopping a share session must
//! also stop its relay registrar. The registrar used to be a detached
//! `tokio::spawn` whose `JoinHandle` lived inside the share task; aborting the
//! share task (the FFI/wincore `stop_share` path) dropped that handle without
//! aborting the task, so the registrar kept sending REGISTER forever and — on a
//! same-process re-share — flapped the relay's routing-key binding.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket as TokioUdp;

use relay_client::protocol::{Classified, classify, ctrl};
use spora_core::identity::Identity;
use spora_core::{Config, Timings, share};

/// Bind a fake relay that just counts REGISTER control packets it receives.
async fn counting_relay() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, _)) => {
                    if let Classified::Control { ty, .. } = classify(&buf[..n]) {
                        if ty == ctrl::REGISTER {
                            count_clone.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
    (addr, count)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_stops_the_relay_registrar() {
    let _ = env_logger::builder().is_test(true).try_init();

    let (relay_addr, register_count) = counting_relay().await;

    let interval = Duration::from_millis(50);
    let config = Config {
        relays: vec![spora_core::identity::RelayEndpoint::new(
            "127.0.0.1",
            relay_addr.port(),
        )],
        timings: Timings {
            register_interval: interval,
            ..Timings::default()
        },
        ..Config::default()
    };

    let session = share(Identity::generate(), config).await.expect("share()");

    // Let several registration ticks land so we know the loop is running.
    tokio::time::sleep(interval * 6).await;
    let before = register_count.load(Ordering::SeqCst);
    assert!(
        before >= 2,
        "registrar should have sent REGISTER packets while sharing, got {before}"
    );

    // Abort — the FFI/wincore stop path. This must also stop the registrar.
    session.abort();

    // Allow any in-flight tick to drain, then snapshot and wait well past
    // several intervals: a leaked registrar would keep incrementing.
    tokio::time::sleep(interval * 2).await;
    let after_abort = register_count.load(Ordering::SeqCst);
    tokio::time::sleep(interval * 10).await;
    let final_count = register_count.load(Ordering::SeqCst);

    assert_eq!(
        final_count, after_abort,
        "registrar kept sending after abort() (leaked task): {after_abort} -> {final_count}"
    );
}
