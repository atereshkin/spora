//! Memory-growth probes for `share()`.
//!
//! Run a single probe with:
//!   cargo test -p spora-core --test share_memory <name> -- --ignored --nocapture
//!
//! Marked `#[ignore]` because they're slow and noisy. RSS is sampled via
//! `/proc/self/statm` so they're Linux-only.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket as TokioUdp;

use spora_core::e2e::{client_connect, client_endpoint, E2eSession};
use spora_core::identity::{Identity, Token};
use spora_core::{Config, Timings, share};

fn rss_kb() -> usize {
    let s = std::fs::read_to_string("/proc/self/statm").expect("read /proc/self/statm");
    let resident_pages: usize = s
        .split_whitespace()
        .nth(1)
        .expect("statm has at least 2 fields")
        .parse()
        .expect("statm field is a number");
    resident_pages * 4
}

fn print_sample(label: &str, kb: usize, baseline: usize) {
    let delta = kb as i64 - baseline as i64;
    println!("[{}] RSS={} KB (Δ={:+} KB)", label, kb, delta);
}

async fn start_relay() -> std::net::SocketAddr {
    let sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(relay::serve(sock, relay::State::default()));
    addr
}

async fn start_share() -> (std::net::SocketAddr, Token, spora_core::ShareSession) {
    let relay_addr = start_relay().await;
    let identity = Identity::generate();
    let config = Config {
        relay_host: "127.0.0.1".into(),
        relay_port: relay_addr.port(),
        ..Config::default()
    };
    let session = share(identity, config).await.expect("share()");
    let token = Token::from_url(&session.url).expect("parse url");
    tokio::time::sleep(Duration::from_millis(300)).await;
    (relay_addr, token, session)
}

async fn open_client(relay_addr: std::net::SocketAddr, token: &Token) -> E2eSession {
    let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    b_std.set_nonblocking(true).unwrap();
    let b_endpoint =
        client_endpoint(b_std, token.routing_key, &Timings::default()).expect("client_endpoint");
    // Endpoint must outlive the connection; we leak it deliberately for the
    // lifetime of the test process (tests are short-lived).
    let endpoint = Box::leak(Box::new(b_endpoint));
    client_connect(endpoint, relay_addr, &token.secret, true)
        .await
        .expect("client_connect")
}

fn icmp_echo(seq: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
        .icmpv4_echo_request(0x1234, seq)
        .write(&mut pkt, b"test")
        .unwrap();
    pkt
}

/// Probe 1: one peer, no traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn share_idle_one_peer_30s() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (relay_addr, token, _share) = start_share().await;
    let _peer = open_client(relay_addr, &token).await;
    let baseline = rss_kb();
    print_sample("baseline", baseline, baseline);
    for tick in 0..6 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        print_sample(&format!("idle t={}s", (tick + 1) * 5), rss_kb(), baseline);
    }
}

/// Probe 2: one peer, ICMP echo request flood. smoltcp generates echo
/// replies which flow back through the tunnel; we drain them on B's side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn share_icmp_flood_30s() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (relay_addr, token, _share) = start_share().await;
    let peer = open_client(relay_addr, &token).await;
    let E2eSession {
        conn: _conn,
        transport,
        signal: _signal,
    } = peer;
    let (mut sink, mut stream) = transport.split();

    // Drain B's incoming so the QUIC datagram channel doesn't fill up.
    let drain_handle = tokio::spawn(async move {
        let mut rx_count: u64 = 0;
        while let Some(res) = stream.next().await {
            if res.is_err() {
                break;
            }
            rx_count += 1;
        }
        eprintln!("B drained {} packets", rx_count);
    });

    let baseline = rss_kb();
    print_sample("baseline", baseline, baseline);

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut sent: u64 = 0;
    let mut last_report = Instant::now();
    let mut seq: u16 = 0;
    while Instant::now() < deadline {
        let pkt = icmp_echo(seq);
        seq = seq.wrapping_add(1);
        if sink.send(pkt).await.is_err() {
            eprintln!("send failed at {}", sent);
            break;
        }
        sent += 1;
        if sent.is_multiple_of(500) {
            tokio::task::yield_now().await;
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            print_sample(&format!("t≈+{}s sent={}", last_report.elapsed().as_secs(), sent), rss_kb(), baseline);
            last_report = Instant::now();
        }
    }
    println!("Sent {} packets total", sent);

    tokio::time::sleep(Duration::from_secs(3)).await;
    print_sample("after 3s quiesce", rss_kb(), baseline);
    drain_handle.abort();
}

/// Probe 3: maximum-throughput ICMP flood for shorter duration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn share_icmp_burst_15s() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (relay_addr, token, _share) = start_share().await;
    let peer = open_client(relay_addr, &token).await;
    let E2eSession {
        conn: _conn,
        transport,
        signal: _signal,
    } = peer;
    let (mut sink, mut stream) = transport.split();

    let drain_handle = tokio::spawn(async move {
        let mut rx_count: u64 = 0;
        while let Some(res) = stream.next().await {
            if res.is_err() {
                break;
            }
            rx_count += 1;
        }
        eprintln!("B drained {} packets", rx_count);
    });

    let baseline = rss_kb();
    print_sample("baseline", baseline, baseline);

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut sent: u64 = 0;
    let mut last_report = Instant::now();
    let mut seq: u16 = 0;
    while Instant::now() < deadline {
        for _ in 0..500 {
            let pkt = icmp_echo(seq);
            seq = seq.wrapping_add(1);
            if sink.send(pkt).await.is_err() {
                break;
            }
            sent += 1;
        }
        tokio::task::yield_now().await;
        if last_report.elapsed() >= Duration::from_secs(2) {
            print_sample(&format!("sent={}", sent), rss_kb(), baseline);
            last_report = Instant::now();
        }
    }
    println!("Sent {} packets total", sent);

    tokio::time::sleep(Duration::from_secs(3)).await;
    print_sample("after 3s quiesce", rss_kb(), baseline);
    drain_handle.abort();
}
