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
            server: FAKE_SERVER.into(),
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
    assert!(
        stats.rtt_min <= stats.rtt_p50
            && stats.rtt_p50 <= stats.rtt_p95
            && stats.rtt_p95 <= stats.rtt_max,
        "inconsistent RTT percentiles: {stats:?}"
    );
    assert!(stats.rtt_p50 > Duration::ZERO, "zero p50 with 20 echoes in: {stats:?}");
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

/// Outer-v6 twin of the test above on `[::1]`: the cheapest regression test
/// for the v6 socket path — share URL with a bracketed v6 relay literal,
/// family-matched binds, relay forwarding between v6 peers — that runs on
/// any platform, no namespaces or ip6tables (the netns `ipv6` suite covers
/// the rest: NAT66, STUN, punch, inner v6).
#[tokio::test(flavor = "multi_thread")]
async fn udp_echo_over_v6_loopback_relay() {
    let _ = env_logger::builder().is_test(true).try_init();

    let relay_sock = tokio::net::UdpSocket::bind("[::1]:0")
        .await
        .expect("bind v6 relay socket");
    let relay_addr = relay_sock.local_addr().unwrap();
    let _relay_task = tokio::spawn(relay::serve(relay_sock, relay::State::default()));

    let mut opts = LabPeerOpts::new(relay_addr, "[::1]:3478");
    opts.enable_direct_upgrade = false;

    let (mut share_cfg, _share_events) = opts.config();
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());
    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("share() starts against a v6 relay");
    assert!(
        session.url.as_str().contains("?r=[::1]:"),
        "share URL must bracket the v6 relay literal, got {}",
        session.url
    );

    let (client_cfg, _client_events) = opts.config();
    let connected = spora_core::connect(session.url.clone(), &client_cfg)
        .await
        .expect("connect() establishes the relay-via session over v6");

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let pump = tokio::spawn(peers::drive_client(connected, cmd_rx));

    let (tx, rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrafficCmd::UdpEcho {
            server: FAKE_SERVER.into(),
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
    assert_eq!(stats.received, 20, "echo lost packets over the v6 relay: {stats:?}");

    drop(cmd_tx);
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("pump exits when the command channel closes")
        .unwrap();
    session.abort();
}

/// Relay-less DIRECT sharing: no relay anywhere in the path. The sharer binds
/// its advertised port and serves `connect()` directly; the client dials the
/// `direct/` URL straight to it. Exercises the `Direct` carrier on both sides
/// (DirectRelayClient + the sharer-side advertised-port bind) plus the full
/// transport composition, with zero relay bandwidth.
#[tokio::test(flavor = "multi_thread")]
async fn udp_echo_over_relayless_direct() {
    let _ = env_logger::builder().is_test(true).try_init();

    // A free loopback UDP port for the sharer to bind and advertise.
    let port = {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    };
    let direct = spora_core::identity::RelayEndpoint::with_protocol(
        "127.0.0.1",
        port,
        spora_core::identity::RelayProtocol::Direct,
    );

    // No relay is spawned. Leave enable_direct_upgrade at its production default
    // (true): the Direct carrier must skip the upgrade INTERNALLY (the session
    // is already direct). The STUN name is deliberately unresolvable, so a buggy
    // upgrade attempt would emit DirectUpgradeFailed within milliseconds — its
    // absence proves the client skipped STUN/punch entirely.
    let opts = LabPeerOpts::new("127.0.0.1:0".parse().unwrap(), "stun.invalid:3478");

    let (mut share_cfg, _share_events) = opts.config();
    share_cfg.relays = vec![direct];
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());
    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("relay-less share() starts");
    assert!(
        session
            .url
            .as_str()
            .contains(&format!("r=direct/127.0.0.1:{port}")),
        "URL must advertise the direct endpoint, got {}",
        session.url
    );

    let (client_cfg, mut client_events) = opts.config();
    let connected = spora_core::connect(session.url.clone(), &client_cfg)
        .await
        .expect("connect() establishes a relay-less direct session");

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let pump = tokio::spawn(peers::drive_client(connected, cmd_rx));

    let (tx, rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrafficCmd::UdpEcho {
            server: FAKE_SERVER.into(),
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
    assert_eq!(
        stats.received, 20,
        "echo lost packets over the direct path: {stats:?}"
    );

    // The client must NOT attempt a direct upgrade on an already-direct session.
    // With the unresolvable STUN name, a (buggy) attempt would emit
    // DirectUpgradeFailed near-instantly; its absence over this window proves
    // the Direct carrier skipped STUN/punch.
    let upgrade_ev = tokio::task::spawn_blocking(move || {
        client_events.wait_event(
            |e| {
                matches!(
                    e,
                    TunnelEvent::DirectUpgradeFailed { .. } | TunnelEvent::DirectUpgradeSucceeded { .. }
                )
            },
            Duration::from_secs(2),
        )
    })
    .await
    .unwrap();
    assert!(
        upgrade_ev.is_err(),
        "a Direct session must skip the direct-upgrade, but an upgrade event fired: {upgrade_ev:?}"
    );

    drop(cmd_tx);
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("pump exits when the command channel closes")
        .unwrap();
    session.abort();
}

/// End-to-end over the TCP/TLS relay carrier: the sharer parks connections at
/// the TCP relay, the client dials the `tcptls/` URL, the relay blind-splices
/// them, and the end-to-end TLS carries the tunnel. Exercises the full
/// stream-native path (StreamPeerTransport + e2e_tls + the parked-pool relay)
/// through the real `share()`/`connect()` composition.
#[tokio::test(flavor = "multi_thread")]
async fn udp_echo_over_tcp_tls_relay() {
    let _ = env_logger::builder().is_test(true).try_init();

    // In-process TCP/TLS relay on loopback.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(relay::tcp::serve_tcp(listener, relay::tcp::TcpRelayState::new()));

    let tcp_ep = spora_core::identity::RelayEndpoint::with_protocol(
        "127.0.0.1",
        relay_addr.port(),
        spora_core::identity::RelayProtocol::TcpTls,
    );

    // TcpTls has no hole-punch upgrade; STUN is never hit.
    let mut opts = LabPeerOpts::new("127.0.0.1:0".parse().unwrap(), "stun.invalid:3478");
    opts.enable_direct_upgrade = false;

    let (mut share_cfg, _share_events) = opts.config();
    share_cfg.relays = vec![tcp_ep];
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());
    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("tcp-tls share() starts");
    assert!(
        session
            .url
            .as_str()
            .contains(&format!("r=tcptls/127.0.0.1:{}", relay_addr.port())),
        "URL must advertise the tcptls endpoint, got {}",
        session.url
    );

    // Let the sharer's registrar pool park connections at the relay.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (client_cfg, _client_events) = opts.config();
    let connected = spora_core::connect(session.url.clone(), &client_cfg)
        .await
        .expect("connect() establishes over the tcp-tls relay");

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let pump = tokio::spawn(peers::drive_client(connected, cmd_rx));

    let (tx, rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrafficCmd::UdpEcho {
            server: FAKE_SERVER.into(),
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
    assert_eq!(
        stats.received, 20,
        "echo lost packets over the tcp-tls relay: {stats:?}"
    );

    drop(cmd_tx);
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("pump exits when the command channel closes")
        .unwrap();
    session.abort();
}

/// Regression: a pure-`Direct` sharer whose advertised host is a name the
/// sharer itself CANNOT resolve locally (split-horizon / external-only DNS)
/// must still start — it binds a wildcard socket and the CLIENT resolves the
/// advertised name. share() must not resolve `Direct` endpoints.
#[tokio::test(flavor = "multi_thread")]
async fn relayless_share_with_unresolvable_advertised_host_starts() {
    let _ = env_logger::builder().is_test(true).try_init();

    let port = {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    };
    let opts = LabPeerOpts::new("127.0.0.1:0".parse().unwrap(), "stun.invalid:3478");
    let (mut share_cfg, _events) = opts.config();
    share_cfg.relays = vec![spora_core::identity::RelayEndpoint::with_protocol(
        "sharer.unresolvable.invalid",
        port,
        spora_core::identity::RelayProtocol::Direct,
    )];
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());

    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("relay-less share() must start even when the advertised host does not resolve locally");
    assert!(
        session
            .url
            .as_str()
            .contains(&format!("r=direct/sharer.unresolvable.invalid:{port}")),
        "URL must advertise the (unresolved) hostname, got {}",
        session.url
    );
    session.abort();
}

/// Spawn a bare dumb relay on `bind` (loopback), returning its bound address.
async fn spawn_relay(bind: &str) -> std::net::SocketAddr {
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .unwrap_or_else(|e| panic!("bind relay {bind}: {e}"));
    let addr = sock.local_addr().unwrap();
    tokio::spawn(relay::serve(sock, relay::State::default()));
    addr
}

/// Multi-relay: with a v6 and a v4 relay both live, the sharer registers with
/// BOTH and the client prefers IPv6 — so the relay-via session rides the v6
/// relay (the lever that later drives a v6 hole punch). Exercises
/// `resolve_relays_preferring_v6` + register-with-all over the real
/// `share()`/`connect()`.
#[tokio::test(flavor = "multi_thread")]
async fn multi_relay_prefers_ipv6() {
    let _ = env_logger::builder().is_test(true).try_init();

    let v4_relay = spawn_relay("127.0.0.1:0").await;
    let v6_relay = spawn_relay("[::1]:0").await;

    // URL order is v4-then-v6 on purpose: preference must come from the
    // family sort, not the listed order.
    let opts = LabPeerOpts::new(v4_relay, "127.0.0.1:3478").with_relays([v4_relay, v6_relay]);
    let (mut share_cfg, _se) = opts.config();
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());
    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("share() starts with two relays");

    let (client_cfg, mut client_events) = opts.config();
    let connected = spora_core::connect(session.url.clone(), &client_cfg)
        .await
        .expect("connect() establishes via a relay");
    let cancel = connected.cancel.clone();
    let _pump = tokio::spawn(peers::drive_client(connected, {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        rx
    }));

    let ev = tokio::task::spawn_blocking(move || {
        client_events.wait_event(
            |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
            Duration::from_secs(10),
        )
    })
    .await
    .unwrap()
    .expect("relay-via session established");
    match ev {
        TunnelEvent::RelaySessionEstablished { peer } => {
            assert_eq!(
                peer, v6_relay,
                "client must prefer the IPv6 relay, connected via {peer}"
            );
        }
        other => panic!("unexpected event {other:?}"),
    }
    cancel.cancel();
    session.abort();
}

/// Multi-relay failover: the preferred (IPv6) relay is DEAD (nothing listening
/// at its address), so the client must fail over to the live v4 relay within
/// `relay_dial_timeout` and still connect — the sharer registered with both,
/// so the v4 relay can route. This is also exactly the family-mismatch path
/// (a v6 relay the sharer couldn't register with looks identical: the Initial
/// is silently dropped).
#[tokio::test(flavor = "multi_thread")]
async fn multi_relay_fails_over_when_preferred_is_dead() {
    let _ = env_logger::builder().is_test(true).try_init();

    // A v6 relay address with nothing listening: bind then drop the socket.
    let dead_v6 = {
        let sock = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        sock.local_addr().unwrap()
    };
    let v4_relay = spawn_relay("127.0.0.1:0").await;

    let mut opts =
        LabPeerOpts::new(v4_relay, "127.0.0.1:3478").with_relays([dead_v6, v4_relay]);
    // Snappy failover so the dead-relay attempt doesn't stretch the test.
    opts.timings.relay_dial_timeout = Duration::from_secs(2);

    let (mut share_cfg, _se) = opts.config();
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());
    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("share() starts");

    let (client_cfg, mut client_events) = opts.config();
    let connected = tokio::time::timeout(
        Duration::from_secs(20),
        spora_core::connect(session.url.clone(), &client_cfg),
    )
    .await
    .expect("connect must not hang past the failover budget")
    .expect("connect() fails over to the live v4 relay");
    let cancel = connected.cancel.clone();
    let _pump = tokio::spawn(peers::drive_client(connected, {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        rx
    }));

    let ev = tokio::task::spawn_blocking(move || {
        client_events.wait_event(
            |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
            Duration::from_secs(10),
        )
    })
    .await
    .unwrap()
    .expect("relay-via session established after failover");
    match ev {
        TunnelEvent::RelaySessionEstablished { peer } => {
            assert_eq!(peer, v4_relay, "must have failed over to the v4 relay, got {peer}");
        }
        other => panic!("unexpected event {other:?}"),
    }
    cancel.cancel();
    session.abort();
}

/// `TrafficCmd::CpuTime` must return a growing value as the pump does work.
///
/// Uses the default current-thread flavor deliberately: the pump task is
/// then pinned to this one thread for its whole life (exactly like a lab
/// host's runtime), so consecutive `CLOCK_THREAD_CPUTIME_ID` readings are
/// comparable. On a multi-thread runtime the pump could migrate between
/// workers and the readings would be from different clocks.
#[tokio::test]
async fn pump_cpu_time_grows_with_work() {
    let _ = env_logger::builder().is_test(true).try_init();

    let relay_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind relay socket");
    let relay_addr = relay_sock.local_addr().unwrap();
    let _relay_task = tokio::spawn(relay::serve(relay_sock, relay::State::default()));

    let mut opts = LabPeerOpts::new(relay_addr, "127.0.0.1:3478");
    opts.enable_direct_upgrade = false;

    let (mut share_cfg, _share_events) = opts.config();
    share_cfg.exit_mode = ExitMode::Custom(reflect_handler());
    let session = spora_core::share(Identity::generate(), share_cfg)
        .await
        .expect("share() starts");

    let (client_cfg, _client_events) = opts.config();
    let connected = spora_core::connect(session.url.clone(), &client_cfg)
        .await
        .expect("connect() establishes the relay-via session");

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let pump = tokio::spawn(peers::drive_client(connected, cmd_rx));

    let cpu_before = pump_cpu(&cmd_tx).await;
    // The QUIC handshake already burned cycles on this thread.
    assert!(cpu_before > Duration::ZERO, "zero CPU after a QUIC handshake");

    // 30 echoes' worth of pump + QUIC work, all on this same thread; the
    // run also covers the p50/p95 ordering on a fresh stats instance.
    let (tx, rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrafficCmd::UdpEcho {
            server: FAKE_SERVER.into(),
            count: 30,
            payload_len: 64,
            respond: tx,
        })
        .expect("pump is alive");
    let stats = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .expect("echo finishes within the deadline")
        .expect("pump answers the command")
        .expect("echo run succeeds");
    assert!(stats.received > 0, "no echoes came back: {stats:?}");
    assert!(
        stats.rtt_min <= stats.rtt_p50
            && stats.rtt_p50 <= stats.rtt_p95
            && stats.rtt_p95 <= stats.rtt_max,
        "inconsistent RTT percentiles: {stats:?}"
    );
    assert!(stats.rtt_p95 < Duration::from_secs(5), "absurd p95: {stats:?}");

    let cpu_after = pump_cpu(&cmd_tx).await;
    assert!(
        cpu_after > cpu_before,
        "thread CPU time did not grow across an echo run: {cpu_before:?} -> {cpu_after:?}"
    );

    drop(cmd_tx);
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("pump exits when the command channel closes")
        .unwrap();
    session.abort();
}

async fn pump_cpu(cmd_tx: &tokio::sync::mpsc::UnboundedSender<TrafficCmd>) -> Duration {
    let (tx, rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrafficCmd::CpuTime { respond: tx })
        .expect("pump is alive");
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("cpu time answered within the deadline")
        .expect("pump answers the command")
        .expect("clock_gettime(CLOCK_THREAD_CPUTIME_ID) succeeds")
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
