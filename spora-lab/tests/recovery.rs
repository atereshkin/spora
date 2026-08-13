//! Recovery/UX spec suite: what reconnects, roaming, sleep, and NAT expiry
//! SHOULD feel like, asserted as time budgets across every carrier.
//!
//! Unlike `resilience` (which pins CURRENT behavior with generous ceilings),
//! this suite encodes the DESIRED user experience: after any single ordinary
//! event — a client crash, a clean close, a network move, a doze, a NAT
//! mapping expiry — user traffic should resume within seconds (scaled), on
//! the FIRST dial attempt, and a dormant client should be radio-silent.
//! Today's code misses several of these budgets by design of this suite:
//! each such assertion is wrapped in `known_gap(<root-cause-tag>, ..)` naming
//! the product defect it waits on. The tags map 1:1 onto the planned
//! redesign items (see the tag constants below).
//!
//! Modes:
//! - default (strict): a missed budget FAILS the scenario — run this locally
//!   to see the real state of the world.
//! - `SPORA_LAB_RECOVERY=xfail` (CI): a missed budget on a tagged gap is
//!   reported as an expected failure and the scenario continues; a tagged
//!   budget that STARTS PASSING fails the scenario, forcing the marker to be
//!   removed with the fix. Untagged assertions are always strict.
//!
//! Timing scale: like `resilience`, peers run register 1s / QUIC idle 3s /
//! keep-alive 1s / redial delay 500ms against a relay with registration 6s /
//! flow 3s / sweep 500ms. This suite ADDITIONALLY scales relay_dial_timeout
//! (8s -> 2s) and the adaptive-keepalive triple (20/3/5s -> 2/1/1s), because
//! dial cadence and keepalive-based death detection ARE under test here.
//! Punch timings stay at production defaults (punching is not under test;
//! direct upgrade is disabled everywhere).
//!
//! State of the world (2026-08-13, after the rolling-listener/per-port fix
//! AND the keepalive redesign): the takeover budgets are GREEN and strict
//! (per-port regression tests), and the dormancy budgets are GREEN and strict
//! (quinn keepalive removed → the transport-agnostic ICMP keepalive is the
//! sole, knob-honoring control point; the share side goes quiet when the
//! client does; the reconnect loop parks while dormant). The only remaining
//! known_gap is `slow-rebind-detection` (roam + NAT rebind): the redial is
//! instant now, so what's left is the keepalive detection latency itself.
//!
//! Clients default to ACTIVE (`establish` sets the knob, mirroring the CLI):
//! their keepalive detects a dead path and their reconnect loop redials. A
//! dormant (knob 0) client deliberately does neither — the dormancy
//! scenarios opt into that.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use spora_core::TunnelEvent;
use spora_core::identity::{Identity, RelayEndpoint, RelayProtocol};
use spora_lab::netns::Netns;
use spora_lab::peers::{self, ClientHandle, LabPeerOpts, SharerHandle};
use spora_lab::services::{self, WanHandle};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{ECHO_UDP_PORT, NatKind, WAN_SERVICES_IP, metrics, netem};
use url::Url;

fn main() {
    let mut ok = spora_lab::harness::lab_main(
        "recovery",
        spora_lab::scenarios![
            // reconnect: a new client takes over after the old one is gone
            quic_crash_takeover,
            quic_graceful_close_takeover,
            nz_crash_takeover,
            tcp_crash_takeover,
            direct_crash_takeover,
            // reconnect: the same client recovers from faults
            quic_blackout_same_client_reconnect,
            quic_sharer_restart_same_identity,
            // roaming (Wi-Fi -> cellular address change)
            quic_roam_recovery,
            nz_roam_recovery,
            tcp_roam_recovery,
            // sleep / dormancy (battery)
            dormant_no_spurious_reconnect,
            dormant_radio_silence,
            sleep_reconnect_respects_dormancy,
            // NAT mapping expiry
            nat_keepalive_maintains_mapping,
            nat_symmetric_rebind_recovery,
            tcp_dead_client_reaped,
        ],
    );
    // Print/record outage metrics even when budgets failed — a red run is
    // exactly the one worth diffing (perf.rs pattern).
    if !metrics::global().lock().expect("metrics mutex").is_empty()
        && let Err(e) = metrics::finish("recovery")
    {
        eprintln!("recovery: {e}");
        ok = false;
    }
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// Known-gap tags: the product defects the red budgets wait on. Each tag is a
// redesign work item; when the fix lands, the xfail run flags the budget as
// "unexpectedly PASSED" and the marker gets deleted with the fix's PR.

// FIXED 2026-08-13 (rolling listener, per-port sessions): the former
// `relay-lockout`, `no-close-deregistration`, and `dcid-swallow` gaps. The
// sharer now re-registers from a FRESH socket the moment a session is
// accepted, so the routing key always points at a flow-free relay port (no
// one-flow lockout for crashed OR cleanly-closed predecessors, no
// REVERSE_ACTIVITY_GRACE exposure — production arithmetic used to be ~30s
// idle + 20s grace ~= 50s of "restart the relay to connect"), and every
// session gets its own quinn endpoint (no same-DCID Initial swallow);
// Direct dials use random initial DCIDs (the routing-key DCID exists only
// for relay routing). The takeover scenarios below are the strict
// regression tests: they measured 3.5-6s and 2-4 dial attempts before, and
// single-digit milliseconds on the first attempt after.

// FIXED 2026-08-13 (quinn keepalive removed + reactive share-side keepalive +
// reconnect-parking): the former `quinn-keepalive-ignores-dormancy` and
// `reconnect-ignores-dormancy` gaps. The transport-agnostic ICMP keepalive is
// now the sole keepalive of record and honors the knob; the share side goes
// quiet once the client does; and the client's reconnect loop parks while
// dormant instead of spinning. dormant_radio_silence / sleep_reconnect_* /
// dormant_no_spurious_reconnect are the strict regression tests.

// FIXED 2026-08-13 (keepalive redesign + per-port): the former
// `slow-rebind-detection` gap. An ACTIVE client's keepalive-response-deadline
// now detects a blackholed path (roam / NAT rebind) instead of waiting out
// the idle timeout, and the per-port redial lands immediately. quic_roam /
// nz_roam / nat_symmetric_rebind_recovery are the strict regression tests.
//
// Retained for FUTURE gaps: the known_gap / SPORA_LAB_RECOVERY=xfail
// machinery below currently has no callers (every diagnosed gap is fixed),
// but is kept so the next red-by-design budget can use it.

// ---------------------------------------------------------------------------
// UX budgets (scaled units). Derivations assume the scaled timings below.

/// A NEW client with a valid URL dials into a sharer whose previous client
/// is gone (crashed or closed): nothing needs detecting — the slot should be
/// free or freeable on arrival, so success belongs on the FIRST attempt,
/// within one dial round-trip + handshake.
const TAKEOVER_BUDGET: Duration = Duration::from_secs(3);
/// Same, after the previous client closed CLEANLY: the close was delivered,
/// so every resource should already be released.
const GRACEFUL_TAKEOVER_BUDGET: Duration = Duration::from_secs(2);
/// Roam: an active client's keepalive detects the address change and redials
/// (instant, per-port). Measured ~4s at scaled timings — dominated by the
/// share side's `active_window` (it keeps pinging the OLD address, which the
/// lab's route-flip roam still delivers via the old gateway's lingering
/// conntrack, masking death until it goes quiet). A real Wi-Fi→cellular roam
/// takes the old interface DOWN, so that masking doesn't happen and detection
/// is faster — the lab is the pessimistic case. Generous CI margin over ~4s.
const ROAM_BUDGET: Duration = Duration::from_secs(8);
/// Roam on the TCP carrier: adaptive-keepalive detection (probe 1s +
/// response 1s + grace 1s) + one redial cycle.
const TCP_ROAM_BUDGET: Duration = Duration::from_secs(6);
/// Sharer restart with the same identity: client detection (idle 3s +
/// rescue grace 0.5s) + one redial once the new instance has registered
/// (1s). Measured ~4s; the margin is for CI load — the assertion pins the
/// MECHANISM (new-port re-registration displaces the old flow), not the
/// exact latency.
const SHARER_RESTART_BUDGET: Duration = Duration::from_secs(8);
/// Wake-from-doze once the network is back and the knob went active.
const WAKE_BUDGET: Duration = Duration::from_secs(4);
/// Packets a dormant client may transmit over a 10s window (straggler ARP /
/// ND chatter allowance). A keepalive-per-second client would send ~20;
/// measured ~3 with the redesign, so this cleanly separates silence from the
/// old chatter while tolerating stray link-layer packets under CI load.
const DORMANT_TX_TOLERANCE: u64 = 8;

/// The keepalive knob a lab client uses when "active" (screen on / in use),
/// mirroring the CLI's non-zero default: probe every second at scaled
/// timings. `establish()` sets it so an in-use client auto-reconnects (the
/// reconnect loop parks only while dormant, knob 0). Dormancy scenarios set
/// it back to 0 explicitly.
const ACTIVE_KNOB: u64 = 1;

/// Ceiling for "eventually recovers" waits — far above every budget, so a
/// budget miss still lets the scenario finish and report the measured value.
const RECOVERY_CEILING: Duration = Duration::from_secs(25);
const EVENT_TIMEOUT: Duration = Duration::from_secs(15);
const ECHO_COUNT: usize = 10;

// ---------------------------------------------------------------------------
// shared knobs & helpers

/// Scaled relay expiry: registration 6s, flow 3s, sweep 500ms (the
/// resilience-suite convention).
fn scaled_relay_state() -> relay::State {
    relay::State::with_timeouts(
        Duration::from_secs(6),
        Duration::from_secs(3),
        Duration::from_millis(500),
    )
}

/// Scaled peer timings. Beyond the 4-field resilience convention this also
/// scales relay_dial_timeout and the adaptive-keepalive triple — redial
/// cadence and keepalive-based death detection are subjects here, not
/// background (see the suite doc comment). Punch timings stay production.
fn scaled_timings() -> spora_core::Timings {
    spora_core::Timings {
        register_interval: Duration::from_secs(1),
        quic_idle_timeout: Duration::from_secs(3),
        quic_keep_alive: Duration::from_secs(1),
        reconnect_delay: Duration::from_millis(500),
        relay_dial_timeout: Duration::from_secs(2),
        keepalive_idle_threshold: Duration::from_secs(2),
        keepalive_response_timeout: Duration::from_secs(1),
        keepalive_inbound_grace: Duration::from_secs(1),
        // Deviation from the "never scale punch fields" convention, on
        // purpose: with enable_direct_upgrade=false the signal-holder task
        // keeps the upgrade channel open, so the upgradable router holds
        // EVERY carrier-level death for the full rescue grace before
        // ReconnectTransport sees it — an unscaled 2s would hide a constant
        // 2s in every death-propagation path measured here (and make the
        // roam budgets unsatisfiable even after the tagged fixes land).
        upgrade_rescue_grace: Duration::from_millis(500),
        ..Default::default()
    }
}

/// Relay-pinned peer options for `carrier` (direct upgrade off everywhere:
/// the relay/carrier path is the subject).
fn carrier_opts(wan: &WanHandle, carrier: RelayProtocol) -> LabPeerOpts {
    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.timings = scaled_timings();
    opts.enable_direct_upgrade = false;
    let addr = match carrier {
        RelayProtocol::TcpTls => wan.tcp_relay_addr(),
        _ => wan.relay_addr(),
    };
    opts.relays = vec![RelayEndpoint::with_protocol(
        addr.ip().to_string(),
        addr.port(),
        carrier,
    )];
    opts
}

fn svc_ip() -> Ipv4Addr {
    WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses")
}

fn svc(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(svc_ip(), port)
}

fn is_relay_established(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::RelaySessionEstablished { .. })
}

fn is_reconnecting(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::Reconnecting)
}

fn is_reconnected(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::Reconnected)
}

fn xfail_mode() -> bool {
    std::env::var("SPORA_LAB_RECOVERY").as_deref() == Ok("xfail")
}

/// UX-budget assertion with known-gap accounting (see the suite doc
/// comment): strict mode returns `result` tagged; xfail mode converts a miss
/// into a logged expected failure and an unexpected PASS into an error so
/// the marker is removed together with the fix.
///
/// Currently unused — every diagnosed gap is fixed and its scenario is a
/// strict regression test. Retained (with `allow(dead_code)`) so the next
/// red-by-design budget can wrap itself here and get the xfail-in-CI
/// treatment without rebuilding the machinery. The CI env var
/// `SPORA_LAB_RECOVERY=xfail` stays wired for the same reason.
#[allow(dead_code)]
fn known_gap(tag: &str, result: Result<(), String>) -> Result<(), String> {
    match result {
        Ok(()) if xfail_mode() => Err(format!(
            "known gap [{tag}] unexpectedly PASSED — a fix landed; remove this known_gap marker"
        )),
        Ok(()) => Ok(()),
        Err(e) if xfail_mode() => {
            println!("    xfail [{tag}]: {e}");
            log::warn!("xfail [{tag}]: {e}");
            Ok(())
        }
        Err(e) => Err(format!("[{tag}] {e}")),
    }
}

/// UDP-echo through the tunnel and require zero loss (quiet veth path; the
/// smoke suite pins 20/20 the same way).
fn expect_clean_echo(client: &ClientHandle, what: &str) -> Result<(), String> {
    let stats = client
        .udp_echo(svc(ECHO_UDP_PORT), ECHO_COUNT, 200, Duration::from_secs(30))
        .map_err(|e| format!("{what}: {e}"))?;
    if stats.received != ECHO_COUNT {
        return Err(format!("{what}: udp echo lost packets: {stats:?}"));
    }
    log::info!("{what}: {stats:?}");
    Ok(())
}

/// Start sharer + client on `carrier` and wait for the session on both
/// sides. TCP/nz sharers need a beat for their registrar (TCP conn park /
/// dedicated-socket REGISTER) before the first client dial.
fn establish(
    topo: &Topology,
    opts: &LabPeerOpts,
    carrier: RelayProtocol,
) -> Result<(SharerHandle, ClientHandle), String> {
    let mut sharer = peers::start_sharer(&topo.sharer, opts)?;
    if !matches!(carrier, RelayProtocol::UdpQuic) {
        std::thread::sleep(Duration::from_millis(500));
    }
    // Setup is not the subject: tolerate one registration race (nz/TCP
    // registrars park asynchronously; under load the 500ms beat can slip).
    let mut client = match peers::start_client(&topo.client, sharer.url().clone(), opts) {
        Ok(c) => c,
        Err(first) => {
            log::warn!("establish: first dial failed ({first}); retrying once");
            std::thread::sleep(Duration::from_millis(700));
            peers::start_client(&topo.client, sharer.url().clone(), opts)?
        }
    };
    client
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("client session: {e}"))?;
    sharer
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("sharer session: {e}"))?;
    // Default to an ACTIVE client (mirrors the CLI's non-zero knob): its
    // keepalive detects a dead path and its reconnect loop redials. A
    // dormant (knob 0) client deliberately does neither — dormancy scenarios
    // opt into that explicitly.
    client.set_keepalive(ACTIVE_KNOB);
    expect_clean_echo(&client, "pre-fault echo")?;
    Ok((sharer, client))
}

/// Dial `url` repeatedly (a user re-tapping "connect") until a session comes
/// up or `ceiling` elapses. Returns (client, attempts, elapsed-since-`t0`).
/// `t0` is taken by the CALLER — before the fault/teardown — so that host
/// join and spawn latency count INTO the measurement: CI load can only push
/// elapsed toward red, never flip a tagged budget to a spurious pass.
fn connect_until(
    ns: &Netns,
    url: &Url,
    opts: &LabPeerOpts,
    t0: Instant,
    ceiling: Duration,
) -> Result<(ClientHandle, usize, Duration), String> {
    let mut attempts = 0usize;
    let mut last_err = String::new();
    while t0.elapsed() < ceiling {
        attempts += 1;
        match peers::start_client(ns, url.clone(), opts) {
            Ok(client) => return Ok((client, attempts, t0.elapsed())),
            Err(e) => last_err = e,
        }
    }
    Err(format!(
        "no session within {ceiling:?} after {attempts} attempts (last: {last_err})"
    ))
}

/// Probe the tunnel until an echo makes it through; returns time since `t0`.
fn wait_traffic_restored(
    client: &ClientHandle,
    t0: Instant,
    ceiling: Duration,
) -> Result<Duration, String> {
    loop {
        if t0.elapsed() > ceiling {
            return Err(format!("traffic not restored within {ceiling:?}"));
        }
        if client
            .udp_probe(svc(ECHO_UDP_PORT), Duration::from_millis(400))?
            .is_some()
        {
            return Ok(t0.elapsed());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Count already-emitted events matching `pred` (drains the buffer; a 500ms
/// settle catches in-flight emissions without eating a whole redial cycle).
fn count_events<P: Fn(&TunnelEvent) -> bool + Copy>(events_of: &mut ClientHandle, pred: P) -> usize {
    let mut n = 0;
    while events_of
        .wait_event(pred, Duration::from_millis(500))
        .is_ok()
    {
        n += 1;
    }
    n
}

/// Total radio silence for the client: drop everything it transmits (its
/// own OUTPUT chain) and everything headed to it (the wan router's OUTPUT —
/// relay/service traffic to the client originates IN the wan ns, so
/// netem::block's INPUT/FORWARD rules never see it). Models the radio going
/// off in sleep; timers keep running (fidelity limit: a real doze freezes
/// timers too — that failure mode is STRICTLY MILDER than this one, so
/// budgets that hold here hold there).
fn radio_off(topo: &Topology) -> Result<(), String> {
    topo.client.run("iptables -w -A OUTPUT -j DROP")?;
    topo.wan
        .run(&format!("iptables -w -A OUTPUT -d {} -j DROP", topo.ext_ip_b))?;
    Ok(())
}

fn radio_on(topo: &Topology) -> Result<(), String> {
    topo.client.run("iptables -w -D OUTPUT -j DROP")?;
    topo.wan
        .run(&format!("iptables -w -D OUTPUT -d {} -j DROP", topo.ext_ip_b))?;
    Ok(())
}

/// Whether this kernel exposes per-netns nf_conntrack timeout sysctls in
/// the gateway namespace. Absence is an ENVIRONMENT property, not a product
/// failure — the NAT-expiry scenarios self-skip on it (println + Ok), the
/// per-scenario analogue of the harness's suite-level skip.
fn conntrack_sysctls_available(gw: &Netns) -> bool {
    gw.command("sh")
        .args(["-c", "test -w /proc/sys/net/netfilter/nf_conntrack_udp_timeout"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Write a per-netns sysctl by /proc path (no `sysctl` tool dependency —
/// same mechanism as topology::enable_ip_forward).
fn write_sysctl(ns: &Netns, key: &str, val: &str) -> Result<(), String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    let status = ns
        .command("sh")
        .args(["-c", &format!("echo {val} > {path}")])
        .status()
        .map_err(|e| format!("sysctl {key}: spawn: {e}"))?;
    if !status.success() {
        return Err(format!(
            "sysctl {key}={val} failed — nf_conntrack sysctls unavailable in this kernel?"
        ));
    }
    Ok(())
}

/// Shrink a NAT gateway's conntrack UDP timeouts (both the initial and the
/// assured/stream state) so mapping expiry happens in scenario time.
fn shrink_udp_conntrack(gw: &Netns, secs: u64) -> Result<(), String> {
    let s = secs.to_string();
    write_sysctl(gw, "net.netfilter.nf_conntrack_udp_timeout", &s)?;
    write_sysctl(gw, "net.netfilter.nf_conntrack_udp_timeout_stream", &s)
}

/// Interface TX packet counter (iproute2 JSON) — the client's entire radio
/// footprint on the quiet lab veth.
fn iface_tx_packets(ns: &Netns, dev: &str) -> Result<u64, String> {
    let out = ns.run(&format!("ip -s -j link show dev {dev}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&out).map_err(|e| format!("ip -j parse: {e}"))?;
    v.get(0)
        .and_then(|l| l.pointer("/stats64/tx/packets"))
        .and_then(|p| p.as_u64())
        .ok_or_else(|| format!("no stats64.tx.packets in: {out}"))
}

fn record_outage(name: &str, d: Duration) {
    metrics::record(&format!("outage_s.{name}"), d.as_secs_f64(), "s", false, 50.0);
}

fn record_attempts(name: &str, attempts: usize) {
    metrics::record(
        &format!("attempts.{name}"),
        attempts as f64,
        "dials",
        false,
        50.0,
    );
}

/// The standard topology for relay-path scenarios.
fn pr_pr() -> Result<Topology, String> {
    Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))
}

// ---------------------------------------------------------------------------
// takeover scenarios: a new client dials while the old one is gone.
//
// Shared shape: establish sharer+client1, remove client1 (crash or clean
// close), immediately dial client2 in a retry loop and measure
// time-to-usable + attempts. Desired: first attempt, seconds. The relay's
// one-flow slot (QUIC/nz) and the sharer's DCID routing make it miss today.

fn takeover(
    carrier: RelayProtocol,
    name: &str,
    graceful: bool,
    budget: Duration,
    gap: Option<&str>,
) -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, carrier);
    let (mut sharer, client1) = establish(&topo, &opts, carrier)?;

    if graceful {
        client1.shutdown_clean(Duration::from_secs(3))?;
    }
    sharer.discard_events();
    let t0 = Instant::now();
    client1.stop();

    let (client2, attempts, elapsed) =
        connect_until(&topo.client, sharer.url(), &opts, t0, RECOVERY_CEILING)?;
    record_outage(name, elapsed);
    record_attempts(name, attempts);
    log::info!("{name}: takeover in {elapsed:.1?} after {attempts} attempt(s)");

    let budget_check = if elapsed <= budget && attempts == 1 {
        Ok(())
    } else {
        Err(format!(
            "takeover took {elapsed:.1?} and {attempts} dial attempts \
             (budget {budget:?} on the first attempt)"
        ))
    };
    match gap {
        Some(tag) => known_gap(tag, budget_check)?,
        None => budget_check?,
    }

    // Eventual recovery is strict regardless of the budget: the sharer
    // accepted a NEW session and traffic flows.
    let mut client2 = client2;
    client2
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("client2 session event: {e}"))?;
    sharer
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("sharer never accepted client2: {e}"))?;
    expect_clean_echo(&client2, "post-takeover echo")?;
    client2.stop();
    sharer.stop();
    Ok(())
}

/// Client crashes (no close on the wire); the next client gets in on the
/// first dial. REGRESSION TEST for the rolling listener: before it, the
/// relay's one-flow slot stayed "actively serving" the dead client (sharer
/// keepalives refreshed it until the sharer's own idle timeout, then the
/// 20s grace) and the sharer's shared endpoint swallowed same-DCID
/// Initials — measured 6.0s / 4 dial attempts here, ~50s on production
/// timings (the live-debug "restart the relay to connect" bug). With
/// per-port sessions: ~6ms, first attempt.
fn quic_crash_takeover() -> Result<(), String> {
    takeover(
        RelayProtocol::UdpQuic,
        "quic_crash_takeover",
        false,
        TAKEOVER_BUDGET,
        None,
    )
}

/// Client closes CLEANLY — every resource is released the moment the close
/// lands. REGRESSION TEST for the rolling listener (before it, even the
/// politest disconnect left the relay flow to die by idling out: 4.0s / 3
/// attempts; after: ~7ms, first attempt).
fn quic_graceful_close_takeover() -> Result<(), String> {
    takeover(
        RelayProtocol::UdpQuic,
        "quic_graceful_close_takeover",
        true,
        GRACEFUL_TAKEOVER_BUDGET,
        None,
    )
}

/// nz rides the identical relay flow table (routing-key prefix instead of
/// QUIC DCID) and rolls its listener the same way. REGRESSION TEST (before:
/// 3.5s / 2 attempts against the flow-timeout eviction; after: ~20ms, first
/// attempt).
fn nz_crash_takeover() -> Result<(), String> {
    takeover(
        RelayProtocol::NoiseUdp,
        "nz_crash_takeover",
        false,
        GRACEFUL_TAKEOVER_BUDGET,
        None,
    )
}

/// The TCP carrier is park-and-splice (a pool of sharer connections, one
/// consumed per client) — no shared slot, no lockout. This budget is
/// expected to PASS: it pins the property the QUIC/nz redesign is chasing.
fn tcp_crash_takeover() -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::TcpTls);
    let (mut sharer, client1) = establish(&topo, &opts, RelayProtocol::TcpTls)?;

    sharer.discard_events();
    let t0 = Instant::now();
    client1.stop();
    let (client2, attempts, elapsed) =
        connect_until(&topo.client, sharer.url(), &opts, t0, RECOVERY_CEILING)?;
    record_outage("tcp_crash_takeover", elapsed);
    record_attempts("tcp_crash_takeover", attempts);

    if elapsed > TAKEOVER_BUDGET || attempts != 1 {
        return Err(format!(
            "PRODUCT REGRESSION — the TCP carrier used to take over instantly \
             (pool pop): {elapsed:.1?}, {attempts} attempts"
        ));
    }
    let mut client2 = client2;
    client2
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("client2 session event: {e}"))?;
    expect_clean_echo(&client2, "post-takeover echo")?;
    client2.stop();
    sharer.stop();
    Ok(())
}

/// Direct (relay-less) carrier: no relay in the picture, so a crashed
/// client's replacement used to meet the sharer-side quinn DCID routing in
/// pure form — new Initials (DCID = routing_key) absorbed by the previous
/// connection until it idled out and drained. REGRESSION TEST for the
/// random-initial-DCID fix on Direct dials (before: 3.0s / 2 attempts;
/// after: ~5ms, first attempt). A Direct sharer cannot roll its advertised
/// port, so the DCID fix is what carries this scenario.
fn direct_crash_takeover() -> Result<(), String> {
    const DIRECT_PORT: u16 = 51000;
    let topo = Topology::build(&TopologySpec::new(
        NatKind::Open,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let mut opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    opts.relays = vec![RelayEndpoint::with_protocol(
        topo.ext_ip_a.to_string(),
        DIRECT_PORT,
        RelayProtocol::Direct,
    )];

    let (mut sharer, client1) = establish(&topo, &opts, RelayProtocol::Direct)?;
    sharer.discard_events();
    let t0 = Instant::now();
    client1.stop();

    let (client2, attempts, elapsed) =
        connect_until(&topo.client, sharer.url(), &opts, t0, RECOVERY_CEILING)?;
    record_outage("direct_crash_takeover", elapsed);
    record_attempts("direct_crash_takeover", attempts);
    log::info!("direct takeover in {elapsed:.1?} after {attempts} attempt(s)");

    if elapsed > GRACEFUL_TAKEOVER_BUDGET || attempts != 1 {
        return Err(format!(
            "PRODUCT REGRESSION — direct takeover took {elapsed:.1?} and \
             {attempts} attempts (budget {GRACEFUL_TAKEOVER_BUDGET:?} on the \
             first attempt); is the Direct dial back on a routing-key DCID?"
        ));
    }

    let mut client2 = client2;
    client2
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("client2 session event: {e}"))?;
    expect_clean_echo(&client2, "post-takeover echo")?;
    client2.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// same-client recovery

/// A mid-session bidirectional blackout (client <-> relay) longer than the
/// idle timeout: the tunnel dies, the client's redial loop spins against the
/// outage, and once the network returns traffic must resume within a couple
/// of redial cycles. STRICT with a 5s post-unblock ceiling.
///
/// (Historical note: pre-per-port, post-unblock redials raced the relay's
/// protected flow slot — observed 1.0-2.5s resumes on phase luck, ~50s
/// lockouts at production timings. With the rolling listener the redial
/// meets a fresh port and resume is one clean cycle.)
fn quic_blackout_same_client_reconnect() -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    let (mut sharer, mut client) = establish(&topo, &opts, RelayProtocol::UdpQuic)?;

    // Bidirectional cut, client-side only (sharer keeps registering).
    netem::block(&topo.wan, topo.ext_ip_b, svc_ip())?;
    topo.wan
        .run(&format!("iptables -w -A OUTPUT -d {} -j DROP", topo.ext_ip_b))?;
    client.discard_events();
    sharer.discard_events();

    // Past the idle timeout (3s): death detected, redials failing.
    std::thread::sleep(Duration::from_secs(4));
    client
        .wait_event(is_reconnecting, Duration::from_secs(5))
        .map_err(|e| format!("client never detected the blackout: {e}"))?;

    netem::unblock(&topo.wan, topo.ext_ip_b, svc_ip())?;
    topo.wan
        .run(&format!("iptables -w -D OUTPUT -d {} -j DROP", topo.ext_ip_b))?;
    let t0 = Instant::now();

    let restored = wait_traffic_restored(&client, t0, RECOVERY_CEILING)?;
    record_outage("quic_blackout_resume", restored);
    log::info!("post-unblock resume in {restored:.1?}");

    // Three redial cycles (2.5s each) with margin; observed 1.0-2.5s.
    if restored > Duration::from_secs(8) {
        return Err(format!(
            "traffic took {restored:.1?} after the network returned \
             (ceiling 8s ~= three redial cycles)"
        ));
    }

    client
        .wait_event(is_reconnected, Duration::from_secs(5))
        .map_err(|e| format!("no Reconnected after unblock: {e}"))?;
    expect_clean_echo(&client, "post-unblock echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

/// Sharer restarts (crash + relaunch, SAME identity, new socket = new port).
/// This scenario predates the rolling listener and proved its premise: a
/// REGISTER from a fresh port displaces the old registration and the
/// surviving client's next redial lands immediately. Now it doubles as the
/// restart-shaped regression test for the same mechanism the share loop
/// performs on every accepted session. STRICT.
fn quic_sharer_restart_same_identity() -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let mut opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    opts.identity = Some(Identity::generate());

    let (sharer1, mut client) = establish(&topo, &opts, RelayProtocol::UdpQuic)?;
    let url = sharer1.url().clone();
    client.discard_events();
    let t0 = Instant::now();
    sharer1.stop();

    let mut sharer2 = peers::start_sharer(&topo.sharer, &opts)?;
    if sharer2.url() != &url {
        return Err("same identity produced a different share URL".into());
    }

    let restored = wait_traffic_restored(&client, t0, RECOVERY_CEILING)?;
    record_outage("sharer_restart_resume", restored);
    log::info!("sharer-restart resume in {restored:.1?}");
    if restored > SHARER_RESTART_BUDGET {
        return Err(format!(
            "PRODUCT REGRESSION — sharer restart used to recover within \
             {SHARER_RESTART_BUDGET:?} via new-port re-registration \
             (the per-port redesign premise); took {restored:.1?}"
        ));
    }
    client
        .wait_event(is_reconnected, Duration::from_secs(5))
        .map_err(|e| format!("no Reconnected after sharer restart: {e}"))?;
    sharer2
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("new sharer never accepted the client: {e}"))?;
    expect_clean_echo(&client, "post-restart echo")?;
    client.stop();
    sharer2.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// roaming

/// Shared roam shape. The client is ACTIVE (establish sets the knob), so its
/// keepalive detects the address change and its reconnect loop redials —
/// modeling the realistic "using the app while the network switches" case.
/// `gap: Some(tag)` wraps the budget in known_gap; `None` asserts it strictly.
fn roam(
    carrier: RelayProtocol,
    name: &str,
    budget: Duration,
    gap: Option<&str>,
) -> Result<(), String> {
    let mut spec = TopologySpec::new(NatKind::PortRestricted, NatKind::PortRestricted);
    spec.client_alt_gateway = true;
    let topo = Topology::build(&spec)?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, carrier);
    let (mut sharer, mut client) = establish(&topo, &opts, carrier)?;
    // Let the active keepalive settle into its probing rhythm.
    std::thread::sleep(Duration::from_millis(500));

    // Wi-Fi -> cellular: default route flips to the alt gateway; the old
    // gateway keeps its conntrack state; the external address changes.
    topo.switch_client_gateway()?;
    let t0 = Instant::now();
    client.discard_events();
    sharer.discard_events();

    let restored = wait_traffic_restored(&client, t0, RECOVERY_CEILING)?;
    record_outage(name, restored);
    log::info!("{name}: roam recovery in {restored:.1?}");

    let budget_check = if restored <= budget {
        Ok(())
    } else {
        Err(format!(
            "roam recovery took {restored:.1?} (budget {budget:?}) — \
             death detection after an address change is idle-timeout-bound; \
             production equivalent tens of seconds"
        ))
    };
    match gap {
        Some(tag) => known_gap(tag, budget_check)?,
        None => budget_check?,
    }

    client
        .wait_event(is_reconnected, Duration::from_secs(5))
        .map_err(|e| format!("no Reconnected after roam: {e}"))?;
    sharer
        .wait_event(is_relay_established, EVENT_TIMEOUT)
        .map_err(|e| format!("sharer never accepted the roamed client: {e}"))?;
    expect_clean_echo(&client, "post-roam echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

/// QUIC relay-path roam. REGRESSION TEST (was 8.5s + a relay lockout before
/// per-port, then idle-timeout-bound detection): the active client's
/// keepalive detects the address change and the per-port redial lands
/// immediately. Measured ~4s. STRICT.
fn quic_roam_recovery() -> Result<(), String> {
    roam(RelayProtocol::UdpQuic, "quic_roam", ROAM_BUDGET, None)
}

/// nz data packets carry no routing key, so a roamed nz client can never
/// re-match the relay flow — only a fresh handshake can. STRICT ceiling
/// rather than a tagged budget: at scaled timings nz roam recovery races
/// flow eviction (~3-4s — no quinn keepalives prolong it, and the sharer's
/// hardcoded 10s ICMP keepalive refreshes it at an arbitrary phase) against
/// 1x-idle detection (3s — unlike QUIC, no sharer keepalives reach the
/// roamed client), so the outcome distribution straddles any honest desired
/// budget. The lockout is pinned deterministically by the takeover
/// scenarios and quic_roam; this pins "an nz roam recovers at all, within
/// a few redial cycles".
fn nz_roam_recovery() -> Result<(), String> {
    roam(RelayProtocol::NoiseUdp, "nz_roam", Duration::from_secs(10), None)
}

/// TCP carrier roam. Detection is the adaptive ICMP keepalive (knob 1 here —
/// TCP has NO transport-level liveness; a knob-0 idle client would hang
/// FOREVER after a roam, an even worse gap than the timing asserted here)
/// and the redial meets no lockout (pool pop), so this budget is STRICT:
/// expected to pass within its detection-bound budget today.
fn tcp_roam_recovery() -> Result<(), String> {
    roam(RelayProtocol::TcpTls, "tcp_roam", TCP_ROAM_BUDGET, None)
}

// ---------------------------------------------------------------------------
// sleep / dormancy

/// Cooperate-with-sleep: a dormant client does NOT spuriously reconnect on
/// an otherwise-fine network. With quinn keepalive gone and the client
/// keepalive dormant, the connection idles out during a long dormancy — but
/// the reconnect loop PARKS rather than spinning the radio, so no Reconnecting
/// fires. On wake the parked redial fires and traffic resumes fast (per-port).
/// STRICT — regression test for the reconnect-parking + radio-silence design.
fn dormant_no_spurious_reconnect() -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    let (sharer, mut client) = establish(&topo, &opts, RelayProtocol::UdpQuic)?;

    // Go dormant (screen off) and hold ~4x the idle timeout on a live network.
    client.set_keepalive(0);
    client.discard_events();
    std::thread::sleep(Duration::from_secs(12));

    let reconnects = count_events(&mut client, is_reconnecting);
    if reconnects != 0 {
        return Err(format!(
            "dormant client emitted {reconnects} Reconnecting during a quiet \
             hold — the reconnect loop must park while dormant, not spin"
        ));
    }

    // Wake (screen on): the parked redial fires; traffic resumes fast.
    client.set_keepalive(ACTIVE_KNOB);
    let t0 = Instant::now();
    let restored = wait_traffic_restored(&client, t0, RECOVERY_CEILING)?;
    record_outage("dormant_wake_resume", restored);
    log::info!("dormant wake resume in {restored:.1?}");
    if restored > WAKE_BUDGET {
        return Err(format!(
            "wake recovery took {restored:.1?} (budget {WAKE_BUDGET:?})"
        ));
    }
    expect_clean_echo(&client, "post-wake echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

/// The battery scenario: a dormant client must be RADIO-SILENT. quinn's
/// keep-alive is gone (the transport-agnostic ICMP layer is the sole
/// keepalive, and it honors the knob), and the share side's reactive
/// keepalive goes quiet once the client does — so a dormant client neither
/// pings nor is forced to ACK. Measured after the share side's active_window
/// (3x the keepalive interval) has elapsed, so its post-establish pings have
/// stopped. STRICT — was ~18 packets/10s (quinn keepalive + ACKs), now ~0.
fn dormant_radio_silence() -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    let (sharer, client) = establish(&topo, &opts, RelayProtocol::UdpQuic)?;

    // Screen off. Drain past the share side's active_window (3x quic_keep_alive
    // = 3s scaled) plus margin, so its reactive pings — which the client would
    // ACK — have stopped before we start counting.
    client.set_keepalive(0);
    std::thread::sleep(Duration::from_secs(5));
    let before = match iface_tx_packets(&topo.client, "lan0") {
        Ok(n) => n,
        // iproute2 without JSON stats — environment, not product.
        Err(e) => {
            println!("SKIPPED (no ip -s -j link stats: {e}) ... ");
            client.stop();
            sharer.stop();
            return Ok(());
        }
    };
    std::thread::sleep(Duration::from_secs(10));
    let delta = iface_tx_packets(&topo.client, "lan0")?.saturating_sub(before);
    metrics::record("dormant_tx_pkts.10s", delta as f64, "pkts", false, 50.0);
    log::info!("dormant client transmitted {delta} packets in 10s");

    if delta > DORMANT_TX_TOLERANCE {
        return Err(format!(
            "dormant client transmitted {delta} packets in 10s \
             (tolerance {DORMANT_TX_TOLERANCE}) — expected radio silence"
        ));
    }
    client.stop();
    sharer.stop();
    Ok(())
}

/// Doze with the network gone (radio off), then wake: the dormant client's
/// redial loop HOLDS while dormant (each attempt would be a radio hit that
/// can't succeed) and fires on wake. STRICT — regression test for
/// reconnect-parking under a blackout.
fn sleep_reconnect_respects_dormancy() -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    let (sharer, mut client) = establish(&topo, &opts, RelayProtocol::UdpQuic)?;

    client.set_keepalive(0);
    radio_off(&topo)?;
    client.discard_events();
    // 12s "asleep with no network": the tunnel idles out, but the reconnect
    // loop parks (knob 0) instead of spinning against the dead radio.
    std::thread::sleep(Duration::from_secs(12));
    let attempts = count_events(&mut client, is_reconnecting);
    metrics::record("sleep_redials.12s", attempts as f64, "dials", false, 50.0);
    log::info!("redial attempts while asleep: {attempts}");

    if attempts > 1 {
        return Err(format!(
            "{attempts} redial attempts during a 12s dormant blackout \
             (parked reconnect should emit 0) — the loop ignored the knob"
        ));
    }

    // Wake: radio back + knob active. Recovery from here is fast.
    radio_on(&topo)?;
    client.set_keepalive(ACTIVE_KNOB);
    let t0 = Instant::now();
    let restored = wait_traffic_restored(&client, t0, RECOVERY_CEILING)?;
    record_outage("wake_resume", restored);
    if restored > WAKE_BUDGET {
        return Err(format!(
            "wake recovery took {restored:.1?} (budget {WAKE_BUDGET:?})"
        ));
    }
    expect_clean_echo(&client, "post-wake echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// NAT mapping expiry

/// Baseline: with aggressive NAT timeouts (5s — mobile-carrier territory)
/// an ACTIVE keepalive regime holds the mapping and the session across a
/// long idle stretch. STRICT — this pins the "keepalive interval must beat
/// real-world NAT timeouts" sizing requirement.
fn nat_keepalive_maintains_mapping() -> Result<(), String> {
    let topo = pr_pr()?;
    let nat_b = topo.nat_b.as_ref().ok_or("client side must be NATed")?;
    if !conntrack_sysctls_available(nat_b) {
        println!("SKIPPED (no per-netns nf_conntrack sysctls) ... ");
        return Ok(());
    }
    shrink_udp_conntrack(nat_b, 5)?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    let (sharer, mut client) = establish(&topo, &opts, RelayProtocol::UdpQuic)?;

    client.set_keepalive(1);
    client.discard_events();
    std::thread::sleep(Duration::from_secs(12));

    let reconnects = count_events(&mut client, is_reconnecting);
    if reconnects != 0 {
        return Err(format!(
            "session reconnected {reconnects}x under a 5s NAT timeout — \
             keepalives failed to hold the mapping"
        ));
    }
    expect_clean_echo(&client, "post-idle echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

/// NAT rebind while ACTIVELY in use: a symmetric NAT drops the mapping during
/// a brief radio gap (1s conntrack timeout, 1.5s radio-off), so afterward the
/// client egresses from a NEW random port; the relay drops those (unknown
/// source) and the sharer's traffic to the dead mapping is blackholed. An
/// active client's keepalive-response-deadline detects the dead path (rather
/// than waiting out the idle timeout), then per-port makes the redial land
/// immediately. Recovery ~= radio-gap + detection (response 1s + grace 1s) +
/// redial. Production equivalent of the OLD idle-bound path was ~30s idle +
/// ~50s lockout; this is the "morning NAT'd sharer" failure class from the
/// live debug, client-side edition.
fn nat_symmetric_rebind_recovery() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::Symmetric,
    ))?;
    let nat_b = topo.nat_b.as_ref().ok_or("client side must be NATed")?;
    if !conntrack_sysctls_available(nat_b) {
        println!("SKIPPED (no per-netns nf_conntrack sysctls) ... ");
        return Ok(());
    }
    shrink_udp_conntrack(nat_b, 1)?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::UdpQuic);
    let (mut sharer, mut client) = establish(&topo, &opts, RelayProtocol::UdpQuic)?;

    // Quiet spell: long enough to expire the 1s mapping, short enough that
    // neither side's 3s idle timeout fires — the rebind itself is silent.
    radio_off(&topo)?;
    client.discard_events();
    sharer.discard_events();
    std::thread::sleep(Duration::from_millis(1500));
    radio_on(&topo)?;
    let t0 = Instant::now();

    let restored = wait_traffic_restored(&client, t0, RECOVERY_CEILING)?;
    record_outage("symmetric_rebind_resume", restored);
    log::info!("post-rebind resume in {restored:.1?}");

    // Active-keepalive detection (response 1s + grace 1s) + redial, measured
    // from radio-on. Measured ~3s; STRICT with CI margin.
    let budget = Duration::from_secs(6);
    if restored > budget {
        return Err(format!(
            "rebind recovery took {restored:.1?} (budget {budget:?}) — \
             blackhole detection slower than the keepalive response deadline"
        ));
    }

    expect_clean_echo(&client, "post-rebind echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

/// TCP half-open reaper. REGRESSION TEST for the reactive-keepalive change:
/// the TCP carrier has NO transport-level idle timeout (unlike QUIC's
/// max_idle_timeout and nz's reader idle deadline), so a silently-idle client
/// would linger forever on the share side — held fd, open connlog record, no
/// SessionEnded — once the share side stopped its (now reactive) pings. The
/// share keepalive's recv_timeout closes that: after ~idle_timeout of client
/// silence it declares the peer dead and reaps the session, matching how
/// QUIC/nz already behave (uniform cooperate-with-sleep reaping). Asserted by
/// the sharer emitting SessionEnded; before the fix it never would.
fn tcp_dead_client_reaped() -> Result<(), String> {
    let topo = pr_pr()?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = carrier_opts(&wan, RelayProtocol::TcpTls);
    let (mut sharer, client) = establish(&topo, &opts, RelayProtocol::TcpTls)?;

    // Screen off → the client goes silent and the share side, after its
    // active_window, stops pinging. recv_timeout (idle_timeout, 3s scaled)
    // then reaps the session.
    client.set_keepalive(0);
    sharer.discard_events();
    let t0 = Instant::now();
    sharer
        .wait_event(
            |e| matches!(e, TunnelEvent::SessionEnded { .. }),
            Duration::from_secs(12),
        )
        .map_err(|e| {
            format!("share side never reaped the silent TCP client — half-open leak: {e}")
        })?;
    let reaped = t0.elapsed();
    record_outage("tcp_reap", reaped);
    log::info!("tcp dead-client reaped in {reaped:.1?}");

    client.stop();
    sharer.stop();
    Ok(())
}
