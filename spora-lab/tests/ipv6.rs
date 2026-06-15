//! IPv6: the outer transport over v6 (relay, STUN, hole punch) and inner v6
//! carried through the tunnel (netstack egress, tunnel-level fragmentation).
//!
//! All scenarios run on a dual-stack topology (`TopologySpec::ipv6`): the
//! same veths carry a v4 plan (unchanged from every other suite) plus
//! documentation-prefix wan legs / ULA LANs, with NAT66 via ip6tables. The
//! wan services dual-bind, and the relay runs on ONE dual-stack wildcard
//! socket — the deployed binary's shape — so the mixed-family scenario
//! exercises a single flow table serving both families.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use spora_core::TunnelEvent;
use spora_core::identity::Token;
use spora_lab::peers::{self, LabPeerOpts};
use spora_lab::services;
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{ECHO_TCP_PORT, ECHO_UDP_PORT, NatKind, WAN_SERVICES_IP, WAN_SERVICES_IP6};

fn main() {
    let ok = spora_lab::harness::lab_main_with_tools(
        "ipv6",
        spora_lab::scenarios![
            outer_v6_relay_session,
            outer_v6_direct_upgrade,
            firewalled_v6_direct_upgrade,
            inner_v6_through_v4_tunnel,
            mixed_family_relay_forwarding,
        ],
        &["ip6tables"],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// helpers

fn svc(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(WAN_SERVICES_IP.parse().unwrap(), port)
}

fn svc6(port: u16) -> SocketAddr {
    let ip: Ipv6Addr = WAN_SERVICES_IP6.parse().unwrap();
    SocketAddr::from((ip, port))
}

fn dual_topology(sharer: NatKind, client: NatKind) -> Result<Topology, String> {
    let mut spec = TopologySpec::new(sharer, client);
    spec.ipv6 = true;
    Topology::build(&spec)
}

fn fail(msg: String) -> Result<(), String> {
    Err(msg)
}

/// Wait for `RelaySessionEstablished` on both handles and return the
/// client-side peer address (the relay as the client saw it).
fn wait_relay_session(
    sharer: &mut peers::SharerHandle,
    client: &mut peers::ClientHandle,
) -> Result<SocketAddr, String> {
    let ev = client.wait_event(
        |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
        Duration::from_secs(15),
    )?;
    sharer.wait_event(
        |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
        Duration::from_secs(15),
    )?;
    match ev {
        TunnelEvent::RelaySessionEstablished { peer } => Ok(peer),
        _ => unreachable!("predicate matched RelaySessionEstablished"),
    }
}

// ---------------------------------------------------------------------------
// 1. outer_v6_relay_session
//
// Sharer and client behind PortRestricted NAT66, registration + the whole
// relay-via QUIC session over IPv6 (direct upgrade disabled so the path
// deterministically stays on the relay). Inner traffic is plain v4 — this
// scenario isolates the OUTER transport's family.

fn outer_v6_relay_session() -> Result<(), String> {
    let topo = dual_topology(NatKind::PortRestricted, NatKind::PortRestricted)?;
    let wan = services::start_wan_dual(&topo.wan, relay::State::default)?;

    let mut opts = LabPeerOpts::new(wan.relay_addr6()?, wan.stun_server6()?);
    opts.enable_direct_upgrade = false;
    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    if !sharer.url().as_str().contains(&format!("[{WAN_SERVICES_IP6}]")) {
        return fail(format!(
            "share URL must carry the bracketed v6 relay literal, got {}",
            sharer.url()
        ));
    }
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;

    let relay_peer = wait_relay_session(&mut sharer, &mut client)?;
    if !relay_peer.is_ipv6() {
        return fail(format!("client session peer should be the v6 relay, got {relay_peer}"));
    }

    // Inner-v4 traffic across the v6 outer path: zero loss + a bulk echo.
    let stats = client.udp_echo(svc(ECHO_UDP_PORT), 20, 200, Duration::from_secs(30))?;
    if stats.received != 20 {
        return fail(format!("udp echo lost packets over v6 relay path: {stats:?}"));
    }
    let bulk = client.tcp_bulk(svc(ECHO_TCP_PORT), 64 * 1024, Duration::from_secs(90))?;
    if bulk.bytes != 64 * 1024 {
        return fail(format!("tcp bulk incomplete over v6 relay path: {bulk:?}"));
    }

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. outer_v6_direct_upgrade
//
// Open×Open over v6: STUN (family-0x02 XOR-MAPPED-ADDRESS), endpoint
// exchange with bracketed v6 literals, hole punch, and the direct QUIC
// rebuild all run on IPv6. The relay is then killed to prove traffic rides
// the direct v6 path.

fn outer_v6_direct_upgrade() -> Result<(), String> {
    let topo = dual_topology(NatKind::Open, NatKind::Open)?;
    let wan = services::start_wan_dual(&topo.wan, relay::State::default)?;

    let opts = LabPeerOpts::new(wan.relay_addr6()?, wan.stun_server6()?);
    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    wait_relay_session(&mut sharer, &mut client)?;

    let upgraded = client.wait_event(
        |e| matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. }),
        Duration::from_secs(30),
    )?;
    let TunnelEvent::DirectUpgradeSucceeded { local, peer } = upgraded else {
        unreachable!("predicate matched DirectUpgradeSucceeded");
    };
    if !local.is_ipv6() || !peer.is_ipv6() {
        return fail(format!("direct path should be v6 on both ends: {local} -> {peer}"));
    }
    let expect_peer = topo.ext_ip6_a.expect("dual topology has v6 externals");
    if peer.ip() != std::net::IpAddr::V6(expect_peer) {
        return fail(format!(
            "direct peer should be the sharer's v6 external {expect_peer}, got {peer}"
        ));
    }
    sharer.wait_event(
        |e| matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. }),
        Duration::from_secs(30),
    )?;

    // No relay, no problem: the session is direct now.
    wan.stop_relay()?;
    let stats = client.udp_echo(svc(ECHO_UDP_PORT), 20, 200, Duration::from_secs(30))?;
    if stats.received != 20 {
        return fail(format!("udp echo lost packets on the direct v6 path: {stats:?}"));
    }

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. firewalled_v6_direct_upgrade
//
// The realistic IPv6 home shape (RFC 6092 "simple security"): both peers
// hold ROUTABLE addresses behind stateful default-deny filters — no
// translation anywhere. The scenario first proves the topology is what it
// claims (the peer's observed address:port is its own, and unsolicited
// inbound is dropped), then that the punch upgrades to direct at the lab's
// sub-millisecond RTT. That last part is the point: v4 PortRestricted ×
// PortRestricted needs production-like RTT here (conntrack port-steal, see
// nat_matrix's PunchSafe profile), but with no SNAT there is no port to
// steal — a firewall-only path must punch even at raw lab speed.

fn firewalled_v6_direct_upgrade() -> Result<(), String> {
    use tokio::net::UdpSocket;

    let topo = dual_topology(NatKind::Firewalled, NatKind::Firewalled)?;
    let wan = services::start_wan_dual(&topo.wan, relay::State::default)?;
    let client_ext = topo.ext_ip6_b.expect("dual topology has v6 externals");
    let sharer_ext = topo.ext_ip6_a.expect("dual topology has v6 externals");

    // --- Topology self-check, plain sockets ---
    // (a) No translation: whoami sees the client's own address and port.
    // (b) Default-deny: an unsolicited wan probe at that exact endpoint —
    //     from a source the client never talked to — must NOT arrive.
    let whoami = svc6(spora_lab::WHOAMI_UDP_PORT);
    let (map_tx, map_rx) = std::sync::mpsc::channel::<Result<SocketAddr, String>>();
    let (go_tx, mut go_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let (probe_tx, probe_rx) = std::sync::mpsc::channel::<Result<bool, String>>();
    let cli_host = topo.client.spawn_host("fw-cli-check", move |_cancel| async move {
        let result = async {
            let sock = UdpSocket::bind(("::", 0))
                .await
                .map_err(|e| format!("bind: {e}"))?;
            let local_port = sock.local_addr().map_err(|e| e.to_string())?.port();
            // Retry: the first packet on a fresh veth path is lost to NDP
            // neighbor resolution (the v4 ARP-warmup the netem scenario
            // documents). A real client/STUN exchange retransmits the same
            // way. The conntrack entry the firewall needs is still created
            // by the FIRST outbound packet — so this only warms NDP, it does
            // not change what the filter test below proves.
            let mut buf = [0u8; 256];
            let observed = loop {
                sock.send_to(b"whoami", whoami)
                    .await
                    .map_err(|e| format!("send: {e}"))?;
                match tokio::time::timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) => {
                        let text = std::str::from_utf8(&buf[..n]).map_err(|e| e.to_string())?;
                        break text.parse::<SocketAddr>().map_err(|e| format!("parse {text:?}: {e}"))?;
                    }
                    Ok(Err(e)) => return Err(format!("recv: {e}")),
                    // Timeout: keep warming NDP within the host's 15s budget.
                    Err(_) => continue,
                }
            };
            if observed.port() != local_port {
                return Err(format!("port translated: local {local_port}, observed {observed}"));
            }
            Ok((sock, observed))
        }
        .await;
        let (sock, observed) = match result {
            Ok(x) => {
                let _ = map_tx.send(Ok(x.1));
                x
            }
            Err(e) => {
                let _ = map_tx.send(Err(e));
                return;
            }
        };
        let _ = observed;
        if go_rx.recv().await.is_none() {
            return;
        }
        // Listen for the probe by its PAYLOAD: the NDP warmup above sent
        // several whoami packets, and a late whoami *reply* can land in this
        // window — only the exact probe bytes count as a leak (mirrors the
        // v4 smoke filtering test).
        let mut buf = [0u8; 256];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let got = loop {
            match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) if &buf[..n] == b"unsolicited" => break Ok(true),
                Ok(Ok(_)) => continue, // stale whoami reply — ignore
                Ok(Err(e)) => break Err(format!("probe recv: {e}")),
                Err(_) => break Ok(false),
            }
        };
        let _ = probe_tx.send(got);
    })?;

    let observed = map_rx
        .recv_timeout(Duration::from_secs(15))
        .map_err(|e| format!("no whoami mapping reported: {e}"))??;
    if observed.ip() != std::net::IpAddr::V6(client_ext) {
        return fail(format!(
            "firewalled client should keep its own address {client_ext}, observed {observed}"
        ));
    }

    // Unsolicited probe from the services address, fresh source port.
    let probe_dst = observed;
    let svc_ip: Ipv6Addr = WAN_SERVICES_IP6.parse().unwrap();
    let (sent_tx, sent_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let _probe_host = topo.wan.spawn_host("fw-probe", move |_cancel| async move {
        let result = async {
            let sock = UdpSocket::bind((svc_ip, 0))
                .await
                .map_err(|e| format!("bind probe: {e}"))?;
            sock.send_to(b"unsolicited", probe_dst)
                .await
                .map_err(|e| format!("send probe: {e}"))?;
            Ok(())
        }
        .await;
        let _ = sent_tx.send(result);
    })?;
    sent_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| format!("probe never sent: {e}"))??;
    go_tx.send(()).map_err(|_| "client check host gone".to_string())?;
    let delivered = probe_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| format!("no probe outcome: {e}"))??;
    cli_host.stop();
    if delivered {
        return fail(
            "unsolicited probe LEAKED through the firewall — the filter recipe is broken, \
             so a punch success here would prove nothing"
                .into(),
        );
    }

    // --- The actual claim: punch through both filters at sub-ms RTT. ---
    let opts = LabPeerOpts::new(wan.relay_addr6()?, wan.stun_server6()?);
    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    wait_relay_session(&mut sharer, &mut client)?;

    let upgraded = client.wait_event(
        |e| matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. }),
        Duration::from_secs(30),
    )?;
    let TunnelEvent::DirectUpgradeSucceeded { peer, .. } = upgraded else {
        unreachable!("predicate matched DirectUpgradeSucceeded");
    };
    // No NAT: the direct peer is the sharer's REAL address — the signaled,
    // learned, and actual endpoints all coincide.
    if peer.ip() != std::net::IpAddr::V6(sharer_ext) {
        return fail(format!(
            "direct peer should be the sharer's own address {sharer_ext}, got {peer}"
        ));
    }
    sharer.wait_event(
        |e| matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. }),
        Duration::from_secs(30),
    )?;

    wan.stop_relay()?;
    let stats = client.udp_echo(svc6(ECHO_UDP_PORT), 20, 200, Duration::from_secs(30))?;
    if stats.received != 20 {
        return fail(format!("udp echo lost packets on the firewalled direct path: {stats:?}"));
    }

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. inner_v6_through_v4_tunnel
//
// The converse of scenario 1: the outer transport is plain v4 (the relay's
// v4 address, direct upgrade disabled), and the TUNNELED packets are IPv6 —
// the share netstack terminates v6 TCP/UDP flows and re-originates them from
// v6 OS sockets. The oversized echo exercises tunnel-level IPv6
// fragmentation (RFC 8200 Fragment header) in BOTH directions: client→share
// reassembled in front of the netstack, share→client by the lab pump.

fn inner_v6_through_v4_tunnel() -> Result<(), String> {
    let topo = dual_topology(NatKind::PortRestricted, NatKind::PortRestricted)?;
    let wan = services::start_wan_dual(&topo.wan, relay::State::default)?;

    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.enable_direct_upgrade = false;
    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    let relay_peer = wait_relay_session(&mut sharer, &mut client)?;
    if !relay_peer.is_ipv4() {
        return fail(format!("outer path should be v4 here, got {relay_peer}"));
    }

    // 20 x 200 B inner-v6 UDP echo: netstack v6 egress, zero loss.
    let stats = client.udp_echo(svc6(ECHO_UDP_PORT), 20, 200, Duration::from_secs(30))?;
    if stats.received != 20 {
        return fail(format!("inner-v6 udp echo lost packets: {stats:?}"));
    }

    // Oversized echo: a 1600 B payload is a 1648 B IPv6 packet — above any
    // tunnel datagram budget a 1500-MTU path can yield — so the request
    // v6-fragments client→share (share-side reassembler) and the equal-size
    // reply v6-fragments share→client (lab pump reassembler).
    let frag = client.udp_echo(svc6(ECHO_UDP_PORT), 5, 1600, Duration::from_secs(30))?;
    if frag.received != 5 {
        return fail(format!(
            "oversized inner-v6 echo lost packets (v6 fragmentation regression?): {frag:?}"
        ));
    }

    // 128 KiB TCP bulk echo over inner v6 (smoltcp dual-stack driver).
    let bulk = client.tcp_bulk(svc6(ECHO_TCP_PORT), 128 * 1024, Duration::from_secs(90))?;
    if bulk.bytes != 128 * 1024 {
        return fail(format!("inner-v6 tcp bulk incomplete: {bulk:?}"));
    }
    log::info!(
        "inner_v6: echo {stats:?}, frag {frag:?}, bulk {:.2} Mbps",
        bulk.throughput_mbps()
    );

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. mixed_family_relay_forwarding
//
// The dumb relay's DCID routing is family-blind: a sharer registered over
// IPv4 is reachable by a client arriving over IPv6 on the SAME dual-stack
// relay socket (one flow table). The client's URL is rewritten to the v6
// relay literal — simulating a v6 network resolving the relay's AAAA where
// the sharer used the A record.

fn mixed_family_relay_forwarding() -> Result<(), String> {
    let topo = dual_topology(NatKind::Open, NatKind::Open)?;
    let wan = services::start_wan_dual(&topo.wan, relay::State::default)?;

    // Sharer registers over v4.
    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.enable_direct_upgrade = false;
    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;

    // Client dials the same relay over v6: rewrite the token to a single v6
    // relay endpoint (simulating a v6 network that resolved the relay's AAAA
    // where the sharer used the A record).
    let mut token = Token::from_url(sharer.url()).map_err(|e| format!("parse share url: {e}"))?;
    token.relays = vec![spora_core::identity::RelayEndpoint::new(
        WAN_SERVICES_IP6.to_string(),
        wan.relay_addr().port(),
    )];
    let url6 = token.to_url();
    let mut client = peers::start_client(&topo.client, url6, &opts)?;

    let client_peer = wait_relay_session(&mut sharer, &mut client)?;
    if !client_peer.is_ipv6() {
        return fail(format!("client should see the v6 relay, got {client_peer}"));
    }

    let stats = client.udp_echo(svc(ECHO_UDP_PORT), 20, 200, Duration::from_secs(30))?;
    if stats.received != 20 {
        return fail(format!("udp echo lost packets across the mixed-family relay: {stats:?}"));
    }

    client.stop();
    sharer.stop();
    Ok(())
}
