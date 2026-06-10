//! Infrastructure smoke: topology/NAT/netem sanity with plain sockets,
//! no spora peers.
//!
//! Proves the lab plumbing end to end: routed wan + /30 legs + svc0 services
//! reachable through real iptables NAT; per-NatKind RFC 4787 mapping and
//! filtering semantics observable from a client socket; netem latency shapes
//! RTT across both legs; targeted iptables blocks create (and lift) outages.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};

use spora_core::TunnelEvent;
use spora_lab::netns::Netns;
use spora_lab::peers::{self, LabPeerOpts};
use spora_lab::services::{self, WHOAMI2_UDP_PORT};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{
    ECHO_TCP_PORT, ECHO_UDP_PORT, NatKind, STUN_PORT, WAN_SERVICES_IP, WHOAMI_UDP_PORT, netem,
};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "smoke",
        spora_lab::scenarios![
            connectivity_basic,
            nat_mapping_semantics,
            nat_filtering_semantics,
            netem_latency,
            outage_blocks,
            peers_netstack_validation,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// helpers

const RECV_TIMEOUT: Duration = Duration::from_secs(2);

fn svc_ip() -> Ipv4Addr {
    WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses")
}

fn svc(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(svc_ip(), port)
}

/// Run an async closure on a fresh host thread pinned inside `ns`, blocking
/// the (main-thread) scenario until it reports back through a channel.
fn in_ns<T, F, Fut>(ns: &Netns, label: &str, timeout: Duration, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let host = ns.spawn_host(label, move |_cancel| async move {
        let _ = tx.send(f().await);
    })?;
    let out = rx
        .recv_timeout(timeout)
        .map_err(|e| format!("{label}: host did not report back: {e}"));
    host.stop();
    out?
}

/// Query a whoami service through `sock`, returning the externally observed
/// source address. Errors mention "timed out" on recv timeout (asserted on
/// by the outage scenario).
async fn whoami_via(sock: &UdpSocket, dst: SocketAddrV4) -> Result<SocketAddrV4, String> {
    sock.send_to(b"whoami", dst)
        .await
        .map_err(|e| format!("send to {dst}: {e}"))?;
    let mut buf = [0u8; 256];
    let (n, from) = tokio::time::timeout(RECV_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .map_err(|_| format!("whoami {dst}: timed out waiting for reply"))?
        .map_err(|e| format!("whoami {dst}: recv: {e}"))?;
    if from != SocketAddr::V4(dst) {
        return Err(format!("whoami reply from unexpected source {from}"));
    }
    let text = std::str::from_utf8(&buf[..n]).map_err(|e| format!("whoami reply not utf8: {e}"))?;
    match text.parse::<SocketAddr>() {
        Ok(SocketAddr::V4(v4)) => Ok(v4),
        Ok(other) => Err(format!("whoami reported non-IPv4 address {other}")),
        Err(e) => Err(format!("whoami reply unparseable {text:?}: {e}")),
    }
}

/// Bind a fresh socket inside `ns` and query the primary whoami service.
fn query_whoami(ns: &Netns, label: &str) -> Result<SocketAddrV4, String> {
    let dst = svc(WHOAMI_UDP_PORT);
    in_ns(ns, label, Duration::from_secs(15), move || async move {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind: {e}"))?;
        whoami_via(&sock, dst).await
    })
}

fn fail(msg: String) -> Result<(), String> {
    Err(msg)
}

// ---------------------------------------------------------------------------
// 1. connectivity_basic

fn connectivity_basic() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;

    // whoami through each NAT shows the side's external leg address.
    let seen = query_whoami(&topo.client, "cli-whoami")?;
    if *seen.ip() != topo.ext_ip_b {
        return fail(format!(
            "client observed external ip {} but expected {}",
            seen.ip(),
            topo.ext_ip_b
        ));
    }
    let seen = query_whoami(&topo.sharer, "shr-whoami")?;
    if *seen.ip() != topo.ext_ip_a {
        return fail(format!(
            "sharer observed external ip {} but expected {}",
            seen.ip(),
            topo.ext_ip_a
        ));
    }

    // UDP echo round-trips from the client namespace.
    let echo_dst = svc(ECHO_UDP_PORT);
    in_ns(
        &topo.client,
        "cli-udp-echo",
        Duration::from_secs(15),
        move || async move {
            let sock = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("bind: {e}"))?;
            let payload = b"spora-lab smoke udp echo payload";
            sock.send_to(payload, echo_dst)
                .await
                .map_err(|e| format!("send: {e}"))?;
            let mut buf = [0u8; 2048];
            let (n, from) = tokio::time::timeout(RECV_TIMEOUT, sock.recv_from(&mut buf))
                .await
                .map_err(|_| "udp echo timed out".to_string())?
                .map_err(|e| format!("recv: {e}"))?;
            if from != SocketAddr::V4(echo_dst) || &buf[..n] != payload {
                return Err(format!("bad echo: {n} bytes from {from}"));
            }
            Ok(())
        },
    )?;

    // TCP echo round-trips (plain tokio TcpStream from the client ns host).
    let tcp_dst = svc(ECHO_TCP_PORT);
    in_ns(
        &topo.client,
        "cli-tcp-echo",
        Duration::from_secs(15),
        move || async move {
            let mut conn = tokio::time::timeout(RECV_TIMEOUT, TcpStream::connect(tcp_dst))
                .await
                .map_err(|_| "tcp connect timed out".to_string())?
                .map_err(|e| format!("connect: {e}"))?;
            let data: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
            conn.write_all(&data)
                .await
                .map_err(|e| format!("write: {e}"))?;
            let mut back = vec![0u8; data.len()];
            tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut back))
                .await
                .map_err(|_| "tcp echo read timed out".to_string())?
                .map_err(|e| format!("read: {e}"))?;
            if back != data {
                return Err("tcp echo payload mismatch".to_string());
            }
            Ok(())
        },
    )?;

    // STUN binding through the NAT reports the external mapping.
    let stun_dst = svc(STUN_PORT);
    let expect_ip = topo.ext_ip_b;
    in_ns(
        &topo.client,
        "cli-stun",
        Duration::from_secs(15),
        move || async move {
            let sock = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("bind: {e}"))?;
            let mut req = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
            req.extend_from_slice(&[0x5A; 12]);
            sock.send_to(&req, stun_dst)
                .await
                .map_err(|e| format!("send: {e}"))?;
            let mut buf = [0u8; 256];
            let (n, _) = tokio::time::timeout(RECV_TIMEOUT, sock.recv_from(&mut buf))
                .await
                .map_err(|_| "stun timed out".to_string())?
                .map_err(|e| format!("recv: {e}"))?;
            let b = &buf[..n];
            if b.len() < 32 || b[0..2] != [0x01, 0x01] || b[8..20] != req[8..20] {
                return Err(format!("bad stun reply ({} bytes): {b:02X?}", b.len()));
            }
            if b[20..24] != [0x00, 0x20, 0x00, 0x08] {
                return Err("stun reply missing XOR-MAPPED-ADDRESS".to_string());
            }
            let ip = Ipv4Addr::new(b[28] ^ 0x21, b[29] ^ 0x12, b[30] ^ 0xA4, b[31] ^ 0x42);
            if ip != expect_ip {
                return Err(format!("stun mapped ip {ip}, expected {expect_ip}"));
            }
            Ok(())
        },
    )?;

    // The relay restart machinery responds (fresh socket + fresh State).
    wan.restart_relay()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. nat_mapping_semantics

fn nat_mapping_semantics() -> Result<(), String> {
    for kind in [
        NatKind::PortRestricted,
        NatKind::FullCone,
        NatKind::Symmetric,
    ] {
        let topo = Topology::build(&TopologySpec::new(NatKind::PortRestricted, kind))?;
        let _wan = services::start_wan(&topo.wan, relay::State::default)?;

        in_ns(
            &topo.client,
            &format!("cli-map-{kind:?}"),
            Duration::from_secs(30),
            move || async move {
                let mut last = None;
                // One attempt settles non-symmetric kinds; Symmetric rebinds
                // a fresh socket on the (~2^-16) random-port collision.
                for _ in 0..5 {
                    let sock = UdpSocket::bind("0.0.0.0:0")
                        .await
                        .map_err(|e| format!("bind: {e}"))?;
                    let local_port = sock.local_addr().map_err(|e| e.to_string())?.port();
                    let m1 = whoami_via(&sock, svc(WHOAMI_UDP_PORT)).await?;
                    let m2 = whoami_via(&sock, svc(WHOAMI2_UDP_PORT)).await?;
                    match kind {
                        NatKind::PortRestricted | NatKind::FullCone => {
                            if m1.port() != m2.port() {
                                return Err(format!(
                                    "{kind:?}: expected endpoint-independent mapping, \
                                     got {m1} vs {m2}"
                                ));
                            }
                            if m1.port() != local_port {
                                return Err(format!(
                                    "{kind:?}: expected port preservation (fresh ns), \
                                     local {local_port} mapped to {}",
                                    m1.port()
                                ));
                            }
                            return Ok(());
                        }
                        NatKind::Symmetric => {
                            if m1.port() != m2.port() {
                                return Ok(()); // endpoint-dependent mapping observed
                            }
                            last = Some((m1, m2));
                        }
                        NatKind::Open => unreachable!("Open is never iterated here"),
                    }
                }
                Err(format!(
                    "Symmetric: identical external ports toward both destinations \
                     across 5 fresh sockets (last: {last:?})"
                ))
            },
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. nat_filtering_semantics

fn nat_filtering_semantics() -> Result<(), String> {
    for (kind, expect_delivery) in [(NatKind::PortRestricted, false), (NatKind::FullCone, true)] {
        let topo = Topology::build(&TopologySpec::new(NatKind::PortRestricted, kind))?;
        let _wan = services::start_wan(&topo.wan, relay::State::default)?;

        let (map_tx, map_rx) = std::sync::mpsc::channel::<Result<SocketAddrV4, String>>();
        let (go_tx, mut go_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (res_tx, res_rx) = std::sync::mpsc::channel::<Result<Option<Vec<u8>>, String>>();

        // Client host: learn our mapping, hold the socket open, then (on
        // signal) listen 1s for the unsolicited wan probe.
        let host = topo
            .client
            .spawn_host("cli-filter", move |_cancel| async move {
                let sock = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = map_tx.send(Err(format!("bind: {e}")));
                        return;
                    }
                };
                match whoami_via(&sock, svc(WHOAMI_UDP_PORT)).await {
                    Ok(mapped) => {
                        let _ = map_tx.send(Ok(mapped));
                    }
                    Err(e) => {
                        let _ = map_tx.send(Err(e));
                        return;
                    }
                }
                if go_rx.recv().await.is_none() {
                    return;
                }
                let mut buf = [0u8; 2048];
                let outcome =
                    match tokio::time::timeout(Duration::from_secs(1), sock.recv_from(&mut buf))
                        .await
                    {
                        Ok(Ok((n, _from))) => Ok(Some(buf[..n].to_vec())),
                        Ok(Err(e)) => Err(format!("probe recv: {e}")),
                        Err(_) => Ok(None), // nothing arrived within 1s
                    };
                let _ = res_tx.send(outcome);
            })?;

        let mapped = map_rx
            .recv_timeout(Duration::from_secs(15))
            .map_err(|e| format!("{kind:?}: no mapping reported: {e}"))??;
        if mapped.ip() != &topo.ext_ip_b {
            return fail(format!(
                "{kind:?}: mapping {mapped} not at external ip {}",
                topo.ext_ip_b
            ));
        }

        // Unsolicited probe from the wan host: svc0 source ip, a DIFFERENT
        // (ephemeral, never 7001) source port, aimed at the observed mapping.
        let bind_ip = svc_ip();
        in_ns(
            &topo.wan,
            "wan-probe",
            Duration::from_secs(15),
            move || async move {
                let sock = UdpSocket::bind((bind_ip, 0))
                    .await
                    .map_err(|e| format!("bind probe: {e}"))?;
                let port = sock.local_addr().map_err(|e| e.to_string())?.port();
                if port == WHOAMI_UDP_PORT {
                    return Err("probe landed on the whoami port".to_string());
                }
                sock.send_to(b"unsolicited-probe", SocketAddr::V4(mapped))
                    .await
                    .map_err(|e| format!("send probe: {e}"))?;
                Ok(())
            },
        )?;

        go_tx
            .send(())
            .map_err(|_| format!("{kind:?}: client host gone before probe check"))?;
        let outcome = res_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|e| format!("{kind:?}: no probe outcome: {e}"))??;
        host.stop();

        match (expect_delivery, outcome) {
            (false, None) => {} // PortRestricted filtered the probe — correct
            (true, Some(payload)) if payload == b"unsolicited-probe" => {} // DNAT delivered
            (false, Some(p)) => {
                return fail(format!(
                    "{kind:?}: unsolicited probe LEAKED through the NAT ({} bytes)",
                    p.len()
                ));
            }
            (true, None) => {
                return fail(format!("{kind:?}: unsolicited probe was NOT delivered"));
            }
            (true, Some(p)) => {
                return fail(format!("{kind:?}: probe delivered with wrong payload {p:02X?}"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. netem_latency

fn netem_latency() -> Result<(), String> {
    // Sharer side Open so a plain UDP echo server in the sharer ns is
    // publicly reachable — echo traffic then crosses BOTH legs (4 × 50ms).
    let topo = Topology::build(&TopologySpec::new(NatKind::Open, NatKind::PortRestricted))?;

    // UDP echo host on the (public) sharer.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let echo_host = topo.sharer.spawn_host("shr-echo", move |_cancel| async move {
        let sock = match UdpSocket::bind("0.0.0.0:7").await {
            Ok(s) => {
                let _ = ready_tx.send(Ok(()));
                s
            }
            Err(e) => {
                let _ = ready_tx.send(Err(format!("bind echo: {e}")));
                return;
            }
        };
        let mut buf = [0u8; 2048];
        loop {
            if let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], src).await;
            }
        }
    })?;
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| format!("echo host not ready: {e}"))??;

    // 50ms egress delay on both ends of both legs => 200ms RTT end to end.
    netem::netem(&topo.wan, &topo.wan_if_a, "delay 50ms")?;
    netem::netem(&topo.wan, &topo.wan_if_b, "delay 50ms")?;
    netem::netem(&topo.sharer, "wan0", "delay 50ms")?; // Open side: peer owns the leg
    let nat_b = topo.nat_b.as_ref().ok_or("client side must be NATed")?;
    netem::netem(nat_b, "wan0", "delay 50ms")?;

    let target = SocketAddrV4::new(topo.ext_ip_a, 7);
    let rtts = in_ns(
        &topo.client,
        "cli-rtt",
        Duration::from_secs(40),
        move || async move {
            let sock = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("bind: {e}"))?;
            let mut buf = [0u8; 2048];
            // Warmup exchange absorbs ARP resolution on the delayed hops.
            let _ = sock.send_to(b"warmup", target).await;
            let _ = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await;

            let mut rtts = Vec::new();
            for i in 0..5u32 {
                let payload = format!("latency-probe-{i}");
                let started = Instant::now();
                sock.send_to(payload.as_bytes(), target)
                    .await
                    .map_err(|e| format!("send: {e}"))?;
                let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
                    .await
                    .map_err(|_| format!("echo {i} timed out"))?
                    .map_err(|e| format!("recv: {e}"))?;
                if buf[..n] != *payload.as_bytes() {
                    return Err(format!("echo {i} payload mismatch"));
                }
                rtts.push(started.elapsed());
            }
            Ok(rtts)
        },
    )?;

    let avg = rtts.iter().sum::<Duration>() / rtts.len() as u32;
    if let Some(fast) = rtts.iter().find(|r| **r < Duration::from_millis(180)) {
        return fail(format!(
            "RTT {fast:?} under the 180ms floor (all: {rtts:?}) — netem not in effect?"
        ));
    }
    if avg >= Duration::from_millis(800) {
        return fail(format!("average RTT {avg:?} over the 800ms ceiling (all: {rtts:?})"));
    }

    // Exercise the clear path too.
    netem::clear_netem(&topo.wan, &topo.wan_if_a)?;
    netem::clear_netem(&topo.wan, &topo.wan_if_b)?;
    netem::clear_netem(&topo.sharer, "wan0")?;
    netem::clear_netem(nat_b, "wan0")?;
    echo_host.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. outage_blocks

fn outage_blocks() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let _wan = services::start_wan(&topo.wan, relay::State::default)?;

    // Baseline: whoami works.
    query_whoami(&topo.client, "cli-pre-block")?;

    // Block client-external -> services. The whoami traffic terminates IN
    // the wan ns, so the INPUT half of the block is what bites.
    netem::block(&topo.wan, topo.ext_ip_b, svc_ip())?;
    match query_whoami(&topo.client, "cli-blocked") {
        Err(e) if e.contains("timed out") => {}
        Ok(m) => return fail(format!("whoami succeeded ({m}) despite block")),
        Err(e) => return fail(format!("expected a recv timeout under block, got: {e}")),
    }

    // Unblock: works again.
    netem::unblock(&topo.wan, topo.ext_ip_b, svc_ip())?;
    query_whoami(&topo.client, "cli-post-unblock")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. peers_netstack_validation

/// Production peers end to end through the lab plumbing: sharer (default
/// `ExitMode::Netstack`) and client behind PortRestricted NATs, default
/// timings, direct upgrade disabled on both sides so the session
/// deterministically stays on the relay. Validates:
/// - `RelaySessionEstablished` observed on both handles (buffered events),
/// - UDP echo 20 x 200 B with zero loss,
/// - oversized (1460 B payload) UDP replies round-tripping share→client via
///   tunnel-level IPv4 fragmentation + pump reassembly,
/// - a 128 KiB TCP bulk echo over the smoltcp traffic driver.
fn peers_netstack_validation() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;

    // Padding responder on the services address: replies with the request
    // payload zero-padded to 1400 bytes.
    //
    // Why not `udp_echo(..., payload_len = 1400)` straight at the echo
    // service? The tunnel's QUIC datagram budget (~1414 B of IP packet once
    // PMTUD converges at quinn's 1452 upper bound) is symmetric, and an
    // echo's request and reply are the same size — so any reply big enough
    // to fragment share→client comes from a request that was already
    // tunnel-fragmented client→share, and the share-side netstack cannot
    // reassemble fragments (netstack-smoltcp's UDP path length-checks each
    // IP packet in isolation and drops both pieces). Replying bigger than
    // the request is the only way to exercise share→client fragmentation
    // through the netstack, which is exactly the production shape the
    // fragmentation fix addressed (large DNS/QUIC responses).
    const PAD_PORT: u16 = 7099;
    // 1460 B payload = 1488 B IP packet: above any tunnel datagram budget a
    // 1500-MTU path can yield (quinn caps PMTUD at 1452), so the reply is
    // GUARANTEED to tunnel-fragment even if a future quinn raises the budget
    // — but still under the netstack's 1500 B UDP recv buffer and the wan
    // leg's wire MTU (no kernel fragmentation on the way in).
    const PAD_LEN: usize = 1460;
    let pad_ip = svc_ip();
    let (pad_ready_tx, pad_ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let _pad_host = topo.wan.spawn_host("udp-pad", move |_cancel| async move {
        let sock = match UdpSocket::bind((pad_ip, PAD_PORT)).await {
            Ok(s) => {
                let _ = pad_ready_tx.send(Ok(()));
                s
            }
            Err(e) => {
                let _ = pad_ready_tx.send(Err(format!("bind pad responder: {e}")));
                return;
            }
        };
        let mut buf = vec![0u8; 2048];
        loop {
            if let Ok((n, src)) = sock.recv_from(&mut buf).await {
                let mut reply = buf[..n].to_vec();
                if reply.len() < PAD_LEN {
                    reply.resize(PAD_LEN, 0x5A);
                }
                let _ = sock.send_to(&reply, src).await;
            }
        }
    })?;
    pad_ready_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| format!("pad responder not ready: {e}"))??;

    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.enable_direct_upgrade = false;
    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;

    // Both sides observed the relay-via session. The client's event fired
    // before start_client even returned — buffered-event semantics.
    client.wait_event(
        |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
        Duration::from_secs(15),
    )?;
    sharer.wait_event(
        |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
        Duration::from_secs(15),
    )?;

    // 20 x 200 B UDP echo: zero loss through netstack + kernel NAT + wan.
    let stats = client.udp_echo(svc(ECHO_UDP_PORT), 20, 200, Duration::from_secs(30))?;
    if stats.received != 20 {
        return fail(format!("udp echo lost packets: {stats:?}"));
    }

    // Small requests, 1400 B replies: each reply leaves the share netstack
    // as a 1428 B IP packet, is IPv4-fragmented by the tunnel, and must be
    // reassembled by the client pump.
    let frag = client.udp_echo(
        SocketAddrV4::new(pad_ip, PAD_PORT),
        5,
        64,
        Duration::from_secs(30),
    )?;
    if frag.received != 5 {
        return fail(format!("fragmented-reply echo lost packets: {frag:?}"));
    }

    // 128 KiB TCP bulk echo over the smoltcp driver.
    let bulk = client.tcp_bulk(svc(ECHO_TCP_PORT), 128 * 1024, Duration::from_secs(90))?;
    if bulk.bytes != 128 * 1024 {
        return fail(format!("tcp bulk incomplete: {bulk:?}"));
    }
    log::info!(
        "peers_netstack_validation: echo {stats:?}, frag {frag:?}, bulk {:.2} Mbps",
        bulk.throughput_mbps()
    );

    client.stop();
    sharer.stop();
    Ok(())
}
