//! End-to-end test for `ExitMode::Custom`: the share side must hand each
//! accepted session's transport to the configured handler instead of the
//! netstack, and packets must flow through it both ways (here: a simple echo).

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket as TokioUdp;

use spora_core::e2e::{E2eSession, client_connect, client_endpoint};
use spora_core::identity::{Identity, Token};
use spora_core::{Config, ExitMode, SessionHandler, Timings, share};

fn icmp_echo(seq: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
        .icmpv4_echo_request(0x1234, seq)
        .write(&mut pkt, b"exit-mode")
        .unwrap();
    pkt
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_exit_mode_pumps_packets() {
    let _ = env_logger::builder().is_test(true).try_init();

    let relay_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_sock.local_addr().unwrap();
    tokio::spawn(relay::serve(relay_sock, relay::State::default()));

    // Echo handler: send every packet straight back until cancelled.
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

    let config = Config {
        relays: vec![spora_core::identity::RelayEndpoint::new(
            "127.0.0.1",
            relay_addr.port(),
        )],
        exit_mode: ExitMode::Custom(handler),
        ..Config::default()
    };
    let session = share(Identity::generate(), config).await.expect("share()");
    let token = Token::from_url(&session.url).expect("parse url");
    tokio::time::sleep(Duration::from_millis(300)).await; // let registration land

    let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    b_std.set_nonblocking(true).unwrap();
    let b_endpoint =
        client_endpoint(b_std, token.routing_key, &Timings::default()).expect("client_endpoint");
    let endpoint = Box::leak(Box::new(b_endpoint));
    let E2eSession {
        conn: _conn,
        transport,
        signal: _signal,
    } = client_connect(endpoint, relay_addr, &token.secret, true)
        .await
        .expect("client_connect");
    let (mut sink, mut stream) = transport.split();

    let sent = icmp_echo(7);
    sink.send(sent.clone()).await.expect("send packet");

    let echoed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match stream.next().await {
                Some(Ok(pkt)) if pkt == sent => return true,
                Some(Ok(_)) => continue, // share-side keepalive or other noise
                _ => return false,
            }
        }
    })
    .await
    .expect("timed out waiting for the echoed packet");
    assert!(
        echoed,
        "custom exit handler should have echoed the packet back"
    );

    session.stop().await;
}
