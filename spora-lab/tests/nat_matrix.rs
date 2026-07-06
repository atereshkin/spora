//! NAT pairing matrix: direct upgrade vs relay fallback.
//!
//! `punch_and_verify` (spora-core) uses observed-source (ICE peer-reflexive)
//! punching — it learns the address the peer's packets actually arrive from,
//! not just the signaled one — so:
//! - pairings among {Open, FullCone, PortRestricted} upgrade to direct
//!   (PortRestricted x PortRestricted needs production-like RTT — see
//!   `WanLatency::PunchSafe` — because at sub-ms RTT a conntrack port-steal
//!   shifts both sides' punch ports and their port-restricted filters then
//!   reject each other's packets, leaving nothing to learn);
//! - FullCone x Symmetric ALSO upgrades (the new win from observed-source):
//!   the full-cone NAT delivers the symmetric peer's punch (endpoint-
//!   independent filtering), the sharer learns that random source, and its
//!   endpoint-independent mapping lets the verify reach the symmetric side's
//!   signaled address;
//! - Symmetric x {PortRestricted, Symmetric} still falls back: the
//!   restricted/symmetric side never receives the symmetric peer's punch in
//!   the first place (its filter only admits the signaled source, which the
//!   symmetric mapping doesn't present), so there is nothing to learn.
//!
//! Direct pairings are proven load-bearing by killing the relay and asserting
//! traffic flows on; symmetric_cone by killing the relay and asserting it
//! STOPS.
//!
//! All scenarios run the production peers (netstack exit) end to end through
//! real kernel NAT. Punch timings stay at production defaults; only
//! `symmetric_cone_fallback` scales the non-punch timings so QUIC notices
//! relay death in seconds.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use spora_core::{Timings, TunnelEvent};
use spora_lab::peers::{self, ClientHandle, LabPeerOpts, SharerHandle};
use spora_lab::services::{self, WanHandle};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{ECHO_TCP_PORT, ECHO_UDP_PORT, NatKind, WAN_SERVICES_IP, netem};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "nat_matrix",
        spora_lab::scenarios![
            open_open_direct,
            nz_open_open_direct,
            cone_cone_direct,
            fullcone_symmetric_direct,
            symmetric_cone_fallback,
            symmetric_symmetric_fallback,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// helpers

/// Client (initiator) deadline for `DirectUpgradeSucceeded`: a clean punch
/// completes in ~2s; the margin absorbs one transient-failure retry
/// (`upgrade_retry_delay` 15s) under CI contention.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(30);
/// Deadline for one full failed attempt: endpoint exchange (instant, both
/// sides connected) + punch phase timeout (5s) + slack. 45s also covers an
/// extra retry round in case the first event is somehow missed.
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(45);
/// Relay-session establishment (already done when `start_client` returns —
/// the event is buffered — so this only guards the sharer-side accept path).
const SESSION_TIMEOUT: Duration = Duration::from_secs(15);

const ECHO_COUNT: usize = 10;
const ECHO_LEN: usize = 200;

fn svc(port: u16) -> SocketAddrV4 {
    let ip: Ipv4Addr = WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses");
    SocketAddrV4::new(ip, port)
}

fn is_relay_session(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::RelaySessionEstablished { .. })
}

fn is_upgrade_success(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. })
}

fn is_upgrade_outcome(e: &TunnelEvent) -> bool {
    matches!(
        e,
        TunnelEvent::DirectUpgradeSucceeded { .. } | TunnelEvent::DirectUpgradeFailed { .. }
    )
}

/// Scaled non-punch timings for failure/recovery assertions (relay death must
/// be detected in seconds). Punch-related timings stay at production values.
fn scaled_timings() -> Timings {
    Timings {
        register_interval: Duration::from_secs(1),
        quic_idle_timeout: Duration::from_secs(3),
        quic_keep_alive: Duration::from_secs(1),
        reconnect_delay: Duration::from_millis(500),
        ..Timings::default()
    }
}

/// Relay timeouts matching [`scaled_timings`] (registration 6s, flow 3s,
/// sweep 500ms).
fn scaled_relay_state() -> relay::State {
    relay::State::with_timeouts(
        Duration::from_secs(6),
        Duration::from_secs(3),
        Duration::from_millis(500),
    )
}

/// Wan latency profile for a scenario.
enum WanLatency {
    /// No shaping: sub-ms RTTs everywhere.
    Zero,
    /// Latency that makes hole punching deterministic for port-restricted
    /// cone x cone. Observed-source punching unlocks full-cone x symmetric but
    /// NOT port-restricted x port-restricted under the lab's sub-ms RTT: there
    /// the conntrack port-steal shifts a punch's source port, and BOTH sides'
    /// port-restricted filters then reject the peer's shifted-port packets, so
    /// neither side ever receives one to learn from. Production RTT avoids the
    /// steal in the first place (the early punch lands after the peer's own
    /// mapping exists); this profile reproduces that geometry:
    /// - wan->natA egress: plain 25ms netem;
    /// - wan->natB egress: 10ms netem for everything EXCEPT relay-sourced
    ///   packets (tc u32 filter on src 203.0.113.100), so the relay detour is
    ///   not slower than the direct path.
    PunchSafe,
}

/// Fresh topology + wan services + both peers; returns once the relay-via
/// session is up on both sides. Defaults to the UDP-QUIC carrier.
fn setup(
    sharer_kind: NatKind,
    client_kind: NatKind,
    timings: Timings,
    relay_state: fn() -> relay::State,
    latency: WanLatency,
) -> Result<(Topology, WanHandle, SharerHandle, ClientHandle), String> {
    setup_carrier(
        sharer_kind,
        client_kind,
        timings,
        relay_state,
        latency,
        spora_core::identity::RelayProtocol::UdpQuic,
    )
}

/// Like [`setup`], but pins both peers to `carrier` (on the same relay, which
/// routes nz and QUIC alike by routing key).
fn setup_carrier(
    sharer_kind: NatKind,
    client_kind: NatKind,
    timings: Timings,
    relay_state: fn() -> relay::State,
    latency: WanLatency,
    carrier: spora_core::identity::RelayProtocol,
) -> Result<(Topology, WanHandle, SharerHandle, ClientHandle), String> {
    let topo = Topology::build(&TopologySpec::new(sharer_kind, client_kind))?;
    match latency {
        WanLatency::Zero => {}
        WanLatency::PunchSafe => {
            netem::netem(&topo.wan, &topo.wan_if_a, "delay 25ms")?;
            let dev = &topo.wan_if_b;
            topo.wan.run(&format!(
                "tc qdisc add dev {dev} root handle 1: prio bands 2 \
                 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
            ))?;
            topo.wan
                .run(&format!("tc qdisc add dev {dev} parent 1:1 handle 10: netem delay 10ms"))?;
            topo.wan
                .run(&format!("tc qdisc add dev {dev} parent 1:2 handle 20: pfifo"))?;
            topo.wan.run(&format!(
                "tc filter add dev {dev} parent 1: protocol ip u32 \
                 match ip src {WAN_SERVICES_IP}/32 flowid 1:2"
            ))?;
        }
    }
    let wan = services::start_wan(&topo.wan, relay_state)?;

    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.timings = timings;
    opts.enable_direct_upgrade = true;
    // Non-default carrier: point both peers at it on the same relay.
    if carrier != spora_core::identity::RelayProtocol::UdpQuic {
        let a = wan.relay_addr();
        opts.relays = vec![spora_core::identity::RelayEndpoint::with_protocol(
            a.ip().to_string(),
            a.port(),
            carrier,
        )];
    }

    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;

    client
        .wait_event(is_relay_session, SESSION_TIMEOUT)
        .map_err(|e| format!("client relay session: {e}"))?;
    sharer
        .wait_event(is_relay_session, SESSION_TIMEOUT)
        .map_err(|e| format!("sharer relay session: {e}"))?;
    Ok((topo, wan, sharer, client))
}

/// UDP echo through the tunnel with zero tolerated loss (the lab has no
/// lossy links; anything dropped means a product/path problem).
fn assert_echo_works(client: &ClientHandle, label: &str) -> Result<(), String> {
    let stats = client.udp_echo(svc(ECHO_UDP_PORT), ECHO_COUNT, ECHO_LEN, Duration::from_secs(30))?;
    if stats.received != ECHO_COUNT {
        return Err(format!("{label}: udp echo lost packets: {stats:?}"));
    }
    log::info!("{label}: echo ok ({stats:?})");
    Ok(())
}

/// Wait for the initiator's next direct-upgrade outcome and require a
/// punch-shaped failure. An unexpected success on one of these pairings means
/// the symmetric side's punch reached the restricted/symmetric peer (whose
/// filter should have dropped it) — a behavior change worth investigating.
fn expect_punch_failure(
    client: &mut ClientHandle,
    pairing: &str,
    timeout: Duration,
) -> Result<String, String> {
    match client.wait_event(is_upgrade_outcome, timeout)? {
        TunnelEvent::DirectUpgradeFailed { reason } => {
            // Both punch-phase failures are acceptable shapes; anything else
            // (STUN, endpoint exchange, QUIC) means the punch never ran.
            if reason.contains("punch exchange") || reason.contains("bidirectional") {
                Ok(reason)
            } else {
                Err(format!(
                    "{pairing}: upgrade failed before/after the punch instead of in it: {reason:?}"
                ))
            }
        }
        TunnelEvent::DirectUpgradeSucceeded { local, peer } => Err(format!(
            "{pairing}: PRODUCT FINDING — direct upgrade SUCCEEDED ({local} -> {peer}) on a \
             pairing expected to stay on the relay. The symmetric side's port-restricted/\
             symmetric peer should never have received its punch. Investigate spora-core's \
             observed-source punch logic / the NAT recipe."
        )),
        other => Err(format!("{pairing}: unexpected event {other:?}")),
    }
}

/// Assert no `DirectUpgradeSucceeded` is buffered or arrives within `window`.
/// (`wait_event` scans the buffer first, so an earlier success can't hide.)
fn assert_no_client_upgrade(client: &mut ClientHandle, pairing: &str) -> Result<(), String> {
    if let Ok(ev) = client.wait_event(is_upgrade_success, Duration::from_secs(2)) {
        return Err(format!(
            "{pairing}: MAJOR PRODUCT FINDING — client observed {ev:?} after a failed punch"
        ));
    }
    Ok(())
}

fn assert_no_sharer_upgrade(sharer: &mut SharerHandle, pairing: &str) -> Result<(), String> {
    if let Ok(ev) = sharer.wait_event(is_upgrade_success, Duration::from_secs(1)) {
        return Err(format!(
            "{pairing}: MAJOR PRODUCT FINDING — sharer observed {ev:?} after a failed punch"
        ));
    }
    Ok(())
}

/// Shared body for the punchable pairings: upgrade succeeds on both sides,
/// then the relay dies and traffic (UDP echo + a small TCP bulk) keeps
/// flowing on the direct path.
fn direct_pair_case(
    sharer_kind: NatKind,
    client_kind: NatKind,
    latency: WanLatency,
) -> Result<(), String> {
    let pairing = format!("{sharer_kind:?} x {client_kind:?}");
    let (_topo, wan, mut sharer, mut client) = setup(
        sharer_kind,
        client_kind,
        Timings::default(),
        relay::State::default,
        latency,
    )?;

    let ev = client
        .wait_event(is_upgrade_success, UPGRADE_TIMEOUT)
        .map_err(|e| format!("{pairing}: client never saw DirectUpgradeSucceeded: {e}"))?;
    log::info!("{pairing}: client upgraded: {ev:?}");
    sharer
        .wait_event(is_upgrade_success, Duration::from_secs(15))
        .map_err(|e| format!("{pairing}: sharer never saw DirectUpgradeSucceeded: {e}"))?;

    // Regression guard: a fresh direct path must NOT lose inbound datagrams.
    // (A zombie QuicPeerTransport reader used to steal exactly one inbound
    // datagram per side right after the upgrade — fixed in spora-core by
    // reusing the E2eSession's embedded transport in try_direct_as_*. The
    // strict zero-loss assertion below is the regression test.)

    assert_echo_works(&client, &format!("{pairing}: post-upgrade"))?;

    // Kill the relay. The direct path must be load-bearing: traffic continues
    // unaffected (and would be 100% lost if the session still rode the relay).
    wan.stop_relay()?;
    assert_echo_works(&client, &format!("{pairing}: relay dead"))?;

    let bulk = client.tcp_bulk(svc(ECHO_TCP_PORT), 64 * 1024, Duration::from_secs(60))?;
    if bulk.bytes != 64 * 1024 {
        return Err(format!("{pairing}: post-relay-death tcp bulk incomplete: {bulk:?}"));
    }
    log::info!(
        "{pairing}: post-relay-death bulk ok ({:.2} Mbps)",
        bulk.throughput_mbps()
    );

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. open_open_direct

fn open_open_direct() -> Result<(), String> {
    // No NATs anywhere: the punch is trivially symmetric, no latency needed.
    direct_pair_case(NatKind::Open, NatKind::Open, WanLatency::Zero)
}

/// The nz (Noise UDP) carrier's relay->direct upgrade: bootstrap relay-via over
/// nz, exchange endpoints on the in-band signal channel, hole punch, then stand
/// up a FRESH NNpsk0 session over the punched socket (a rebuild, not a
/// cipher-state handoff). Open x Open isolates the nz-specific rebuild from NAT
/// punch subtleties. Killing the relay proves the direct nz path is load-bearing.
fn nz_open_open_direct() -> Result<(), String> {
    let (_topo, wan, mut sharer, mut client) = setup_carrier(
        NatKind::Open,
        NatKind::Open,
        Timings::default(),
        relay::State::default,
        WanLatency::Zero,
        spora_core::identity::RelayProtocol::NoiseUdp,
    )?;

    client
        .wait_event(is_upgrade_success, UPGRADE_TIMEOUT)
        .map_err(|e| format!("nz: client never saw DirectUpgradeSucceeded: {e}"))?;
    sharer
        .wait_event(is_upgrade_success, Duration::from_secs(15))
        .map_err(|e| format!("nz: sharer never saw DirectUpgradeSucceeded: {e}"))?;

    assert_echo_works(&client, "nz: post-upgrade")?;

    // The direct nz path must be load-bearing: with the relay gone, traffic
    // would be 100% lost if the session still rode it.
    wan.stop_relay()?;
    assert_echo_works(&client, "nz: relay dead")?;

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. cone_cone_direct — the classic punch case

/// PortRestricted x PortRestricted. Hole punching between two Linux-conntrack
/// NATs used to be subject to a "port-steal" race: if either peer's punch
/// reached the other's NAT before that peer's own punch had left, the
/// unsolicited inbound created an UNREPLIED conntrack entry that broke
/// MASQUERADE port preservation, so the late punch egressed from a shifted
/// source port — and the old `punch_and_verify`, which accepted only the
/// signaled source, ignored it and timed out (deterministically at the lab's
/// sub-ms RTT, and as a coin flip in production whenever the relay detour was
/// not faster than the direct path). Observed-source punching fixes it: each
/// side learns the address the peer's packets actually arrive from and points
/// the verify + QUIC dial there, so the shifted port is no longer fatal. This
/// scenario runs at sub-ms RTT — exactly the geometry that used to fail — as
/// the regression test.
fn cone_cone_direct() -> Result<(), String> {
    direct_pair_case(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
        WanLatency::PunchSafe,
    )
}

// ---------------------------------------------------------------------------
// 3. fullcone_symmetric_direct — observed-source unlocks this pairing

/// FullCone (sharer) x Symmetric (client). The full-cone NAT DNATs the
/// client's punch all the way to the sharer's punch socket; it arrives from
/// the client's per-destination (random) mapping, NOT the signaled
/// STUN-learned one. The old signaled-only matcher ignored it and the pairing
/// fell back to the relay. With observed-source punching the sharer learns
/// that random source and verifies back to it (its own full-cone mapping is
/// endpoint-independent, so its reply reaches the client from the signaled
/// address the client's symmetric filter accepts) — and the pairing now
/// upgrades directly. Regression test for that improvement.
fn fullcone_symmetric_direct() -> Result<(), String> {
    direct_pair_case(NatKind::FullCone, NatKind::Symmetric, WanLatency::Zero)
}

// ---------------------------------------------------------------------------
// 4. symmetric_cone_fallback — relay proven load-bearing

/// Symmetric (sharer) x PortRestricted (client): punch fails, traffic flows
/// via the relay, and killing the relay kills the traffic — proving the
/// session never left it. Scaled non-punch timings so QUIC detects the dead
/// path within ~3s (`quic_idle_timeout`).
fn symmetric_cone_fallback() -> Result<(), String> {
    let pairing = "Symmetric x PortRestricted";
    let (_topo, wan, mut sharer, mut client) = setup(
        NatKind::Symmetric,
        NatKind::PortRestricted,
        scaled_timings(),
        scaled_relay_state,
        WanLatency::Zero,
    )?;

    let reason = expect_punch_failure(&mut client, pairing, FALLBACK_TIMEOUT)?;
    log::info!("{pairing}: punch failed as expected: {reason:?}");
    assert_no_client_upgrade(&mut client, pairing)?;
    assert_no_sharer_upgrade(&mut sharer, pairing)?;

    assert_echo_works(&client, &format!("{pairing}: via relay"))?;

    // Kill the relay and give QUIC a moment to actually lose the path
    // (scaled idle timeout 3s); the client's ReconnectTransport then redials
    // the dead relay forever, dropping outbound packets meanwhile.
    wan.stop_relay()?;
    std::thread::sleep(Duration::from_secs(5));

    match client.udp_echo(svc(ECHO_UDP_PORT), 5, ECHO_LEN, Duration::from_secs(20)) {
        // Both shapes prove the relay was load-bearing: either the pump
        // reports total loss (sends dropped by the reconnect drop-policy) or
        // the command fails outright on a dead transport.
        Ok(stats) if stats.received == 0 => {
            log::info!("{pairing}: echo correctly dead after relay death ({stats:?})");
        }
        Ok(stats) => {
            return Err(format!(
                "{pairing}: PRODUCT FINDING — relay is dead but {}/{} echoes still arrived; \
                 the session was not riding the relay after a failed punch ({stats:?})",
                stats.received, stats.sent
            ));
        }
        Err(e) => {
            log::info!("{pairing}: echo correctly failed after relay death: {e}");
        }
    }

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. symmetric_symmetric_fallback

fn symmetric_symmetric_fallback() -> Result<(), String> {
    let pairing = "Symmetric x Symmetric";
    // Shrink the initiator's retry delay so the suite observes the SECOND
    // attempt too — at the default 15s the negative-upgrade windows below
    // close long before a retry could ever punch through, leaving a
    // retry-succeeds regression invisible. Punch-physics timings stay default.
    let timings = Timings {
        upgrade_retry_delay: Duration::from_secs(2),
        ..Timings::default()
    };
    let (_topo, _wan, mut sharer, mut client) = setup(
        NatKind::Symmetric,
        NatKind::Symmetric,
        timings,
        relay::State::default,
        WanLatency::Zero,
    )?;

    let reason = expect_punch_failure(&mut client, pairing, FALLBACK_TIMEOUT)?;
    log::info!("{pairing}: punch failed as expected: {reason:?}");
    // The retry (attempt 2) must fail the same way.
    let retry_reason = expect_punch_failure(&mut client, pairing, FALLBACK_TIMEOUT)?;
    log::info!("{pairing}: retry also failed as expected: {retry_reason:?}");
    assert_no_client_upgrade(&mut client, pairing)?;
    assert_no_sharer_upgrade(&mut sharer, pairing)?;

    assert_echo_works(&client, &format!("{pairing}: via relay"))?;

    client.stop();
    sharer.stop();
    Ok(())
}
