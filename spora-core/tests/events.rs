//! Lifecycle-event smoke test: `share()` and `connect()` must emit
//! `RelaySessionEstablished` through `Config::event_hook`, and
//! `enable_direct_upgrade = false` must keep the data path (and the peer's
//! signal channel) working while the session stays on the relay.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket as TokioUdp;
use tokio::sync::mpsc;

use spora_core::identity::Identity;
use spora_core::{connect, share, Config, ExitMode, SessionHandler, TunnelEvent};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_session_events_and_disabled_direct_upgrade() {
    let _ = env_logger::builder().is_test(true).try_init();

    let relay_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_sock.local_addr().unwrap();
    tokio::spawn(relay::serve(relay_sock, relay::State::default()));

    // Echo exit handler: send every packet straight back until cancelled.
    let handler: SessionHandler = Arc::new(|mut transport, cancel| {
        Box::pin(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = transport.next() => match res {
                        Some(Ok(pkt)) => {
                            let _ = transport.send(pkt).await;
                        }
                        Some(Err(_)) | None => break,
                    },
                }
            }
        })
    });

    let (share_tx, mut share_rx) = mpsc::unbounded_channel();
    let share_config = Config {
        relays: vec![spora_core::identity::RelayEndpoint::new("127.0.0.1", relay_addr.port())],
        exit_mode: ExitMode::Custom(handler),
        event_hook: Some(Arc::new(move |ev| {
            let _ = share_tx.send(ev);
        })),
        enable_direct_upgrade: false,
        ..Config::default()
    };
    let session = share(Identity::generate(), share_config)
        .await
        .expect("share()");
    tokio::time::sleep(Duration::from_millis(300)).await; // let registration land

    let (client_tx, mut client_rx) = mpsc::unbounded_channel();
    let client_config = Config {
        event_hook: Some(Arc::new(move |ev| {
            let _ = client_tx.send(ev);
        })),
        enable_direct_upgrade: false,
        ..Config::default()
    };
    let result = connect(session.url.clone(), &client_config)
        .await
        .expect("connect()");

    // Both sides emit RelaySessionEstablished, pointed at the relay.
    let ev = tokio::time::timeout(Duration::from_secs(5), client_rx.recv())
        .await
        .expect("client should emit an event")
        .expect("client event channel open");
    match ev {
        TunnelEvent::RelaySessionEstablished { peer } => assert_eq!(peer, relay_addr),
        other => panic!("expected client RelaySessionEstablished, got {:?}", other),
    }
    let ev = tokio::time::timeout(Duration::from_secs(5), share_rx.recv())
        .await
        .expect("share should emit an event")
        .expect("share event channel open");
    assert!(
        matches!(ev, TunnelEvent::RelaySessionEstablished { .. }),
        "expected share RelaySessionEstablished, got {:?}",
        ev
    );

    // Data still flows with direct upgrade disabled on both sides.
    let mut pkt = Vec::new();
    etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
        .icmpv4_echo_request(0x4242, 1)
        .write(&mut pkt, b"events")
        .unwrap();
    let mut transport = result.transport;
    transport.send(pkt.clone()).await.expect("send packet");
    let echoed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match transport.next().await {
                Some(Ok(p)) if p == pkt => return true,
                Some(Ok(_)) => continue, // keepalive or other noise
                _ => return false,
            }
        }
    })
    .await
    .expect("timed out waiting for the echoed packet");
    assert!(echoed, "echo should flow over the relay-held session");

    result.cancel.cancel();
    session.stop().await;
}
