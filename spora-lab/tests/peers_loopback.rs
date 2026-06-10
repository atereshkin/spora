//! Traffic-driver validation over an in-process loopback relay with an
//! `ExitMode::Custom` UDP-reflecting share handler — no namespaces, no
//! privileges, plain libtest: runs on any Linux.
//!
//! Exercises the REAL pieces end to end: the dumb relay (`relay::serve`),
//! `share()` with a custom session handler, `connect()`'s full client
//! composition (QuicPeerTransport → Upgradable → KeepAlive → Reconnect),
//! and the REAL `TrafficPump` via `peers::drive_client` (`peers::start_client`
//! itself needs a `Netns`, so the pump + connect logic is driven directly).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use spora_core::identity::Identity;
use spora_core::{CancellationToken, ExitMode, IpTransport, SessionHandler, TunnelEvent};
use spora_lab::peers::{self, LabPeerOpts};
use spora_lab::traffic::TrafficCmd;

/// Arbitrary "server" the lab client aims its echo at: the reflect handler
/// answers for any destination, like a wildcard internet.
const FAKE_SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 99), 7);

#[tokio::test(flavor = "multi_thread")]
async fn udp_echo_over_loopback_relay() {
    let _ = env_logger::builder().is_test(true).try_init();

    // In-process dumb relay on loopback.
    let relay_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind relay socket");
    let relay_addr = relay_sock.local_addr().unwrap();
    let _relay_task = tokio::spawn(relay::serve(relay_sock, relay::State::default()));

    // Hold both sessions on the relay: deterministic, and STUN is never hit.
    let mut opts = LabPeerOpts::new(relay_addr, "127.0.0.1:3478");
    opts.enable_direct_upgrade = false;

    // Sharer: production share() with a UDP-reflecting session handler
    // instead of the netstack (which would need real egress).
    let (mut share_cfg, mut share_events) = opts.config();
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());
    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("share() starts");
    let url = session.url.clone();

    // Client: production connect(), full transport composition.
    let (client_cfg, mut client_events) = opts.config();
    let connected = spora_core::connect(url, &client_cfg)
        .await
        .expect("connect() establishes the relay-via session");

    // The real pump, driven exactly as peers::start_client drives it.
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let pump = tokio::spawn(peers::drive_client(connected, cmd_rx));

    // 20 x 64 B echo against the reflecting share handler: zero loss.
    let (tx, rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrafficCmd::UdpEcho {
            server: FAKE_SERVER,
            count: 20,
            payload_len: 64,
            respond: tx,
        })
        .expect("pump is alive");
    let stats = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .expect("echo finishes within the deadline")
        .expect("pump answers the command")
        .expect("echo run succeeds");
    assert_eq!(stats.sent, 20);
    assert_eq!(stats.received, 20, "echo lost packets: {stats:?}");
    assert!(
        stats.rtt_min <= stats.rtt_avg && stats.rtt_avg <= stats.rtt_max,
        "inconsistent RTTs: {stats:?}"
    );
    assert!(stats.rtt_max < Duration::from_secs(5), "absurd RTT: {stats:?}");

    // wait_event semantics: both RelaySessionEstablished events fired during
    // session setup, long before these calls — they must still match from
    // the buffer. (EventStream::wait_event is blocking by design — scenario
    // code runs on a plain thread — so hop to the blocking pool here.)
    let (mut client_events, ev) = tokio::task::spawn_blocking(move || {
        let ev = client_events.wait_event(
            |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
            Duration::from_secs(1),
        );
        (client_events, ev)
    })
    .await
    .unwrap();
    ev.expect("client's RelaySessionEstablished is buffered and matches");

    let ev = tokio::task::spawn_blocking(move || {
        share_events.wait_event(
            |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
            Duration::from_secs(5),
        )
    })
    .await
    .unwrap();
    ev.expect("sharer's RelaySessionEstablished is buffered and matches");

    // A matched event is consumed, and a never-emitted event times out:
    // both waits must return Err quickly.
    tokio::task::spawn_blocking(move || {
        assert!(
            client_events
                .wait_event(
                    |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
                    Duration::from_millis(200),
                )
                .is_err(),
            "RelaySessionEstablished was already consumed; second wait must time out"
        );
        assert!(
            client_events
                .wait_event(
                    |e| matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. }),
                    Duration::from_millis(200),
                )
                .is_err(),
            "direct upgrade is disabled; the event must never fire"
        );
    })
    .await
    .unwrap();

    // Closing the command channel ends the pump.
    drop(cmd_tx);
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("pump exits when the command channel closes")
        .unwrap();
    session.abort();
}

/// Session handler that reflects IPv4/UDP packets: swap src/dst addresses
/// and ports, rebuild with valid checksums via etherparse, echo the payload.
/// Non-UDP (the client's keepalive ICMP) and fragments are ignored.
fn reflect_handler() -> SessionHandler {
    Arc::new(|transport: IpTransport, cancel: CancellationToken| {
        Box::pin(async move {
            let mut transport = transport;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    pkt = transport.next() => match pkt {
                        Some(Ok(p)) => {
                            if let Some(reply) = reflect_udp(&p)
                                && transport.send(reply).await.is_err()
                            {
                                break;
                            }
                        }
                        Some(Err(e)) => log::warn!("reflect: transport error: {e}"),
                        None => break,
                    },
                }
            }
        })
    })
}

fn reflect_udp(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None; // not IPv4/UDP
    }
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if flags_frag & 0x3fff != 0 {
        return None; // fragment — can't parse a UDP header out of it
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let src: [u8; 4] = pkt[12..16].try_into().unwrap();
    let dst: [u8; 4] = pkt[16..20].try_into().unwrap();
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
    if udp_len < 8 || pkt.len() < ihl + udp_len {
        return None;
    }
    let payload = &pkt[ihl + 8..ihl + udp_len];

    let mut reply = Vec::with_capacity(28 + payload.len());
    etherparse::PacketBuilder::ipv4(dst, src, 20)
        .udp(dst_port, src_port)
        .write(&mut reply, payload)
        .ok()?;
    Some(reply)
}
