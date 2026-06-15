//! Tier-0 DPI-censorship scenarios: a signature-matching middlebox in the wan
//! namespace ([`spora_lab::censor`]) drops Spora's on-wire fingerprints, and we
//! assert (a) today's protocol IS blockable by one trivial signature, and
//! (b) the censor leaves everything else flowing — so when an obfuscation layer
//! removes a fingerprint, the same scenario flips from blocked→connected (the
//! red→green ratchet for the DPI-resistance effort; see docs/lab.md).
//!
//! Each scenario ties an audited fingerprint to the real-world censor technique
//! that catches it:
//!   register_magic_signature — CTRL_MAGIC `0x80 'spR' 0x01` | fixed magic-prefix DPI
//!   quic_v1_wholesale        — QUIC v1 long-header version  | TSPU version+port block
//!   punch_marker_signature   — `sporaHP1P`/`sporaHP1V`      | magic-prefix DPI (direct leg)
//!
//! Non-punch timings are scaled (registration expiry / relay death in seconds),
//! mirroring resilience.rs; the punch scenario keeps production punch geometry
//! (per nat_matrix). The suite green-skips if the iptables `string` match
//! (`xt_string`) is unavailable — unless `SPORA_LAB=require`, which turns that
//! into a hard failure (a silent skip would certify nothing).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use spora_core::{Timings, TunnelEvent};
use spora_lab::netns::Netns;
use spora_lab::peers::{self, ClientHandle, LabPeerOpts};
use spora_lab::services::{self, WanHandle};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::traffic::EchoStats;
use spora_lab::{ECHO_UDP_PORT, NatKind, RELAY_PORT, WAN_SERVICES_IP, censor};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "censorship",
        spora_lab::scenarios![
            register_magic_signature,
            quic_v1_wholesale,
            punch_marker_signature,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// shared knobs & helpers (mirroring resilience.rs / nat_matrix.rs)

/// Scaled relay expiry: registration 6s, flow 3s, sweep 500ms.
fn scaled_relay_state() -> relay::State {
    relay::State::with_timeouts(
        Duration::from_secs(6),
        Duration::from_secs(3),
        Duration::from_millis(500),
    )
}

/// Scaled peer timings (everything punch-related stays at defaults).
fn scaled_timings() -> Timings {
    Timings {
        register_interval: Duration::from_secs(1),
        quic_idle_timeout: Duration::from_secs(3),
        quic_keep_alive: Duration::from_secs(1),
        reconnect_delay: Duration::from_millis(500),
        ..Default::default()
    }
}

/// Relay-pinned peer options: scaled timings + direct upgrade disabled (the
/// relay path is the subject in scenarios 1–2).
fn relay_pinned_opts(wan: &WanHandle) -> LabPeerOpts {
    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.timings = scaled_timings();
    opts.enable_direct_upgrade = false;
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

fn is_upgrade_success(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. })
}

fn is_upgrade_outcome(e: &TunnelEvent) -> bool {
    matches!(
        e,
        TunnelEvent::DirectUpgradeSucceeded { .. } | TunnelEvent::DirectUpgradeFailed { .. }
    )
}

const ECHO_COUNT: usize = 10;

/// UDP-echo through the tunnel and require zero loss (the quiet lab veth path
/// delivers every datagram; smoke/resilience pin it the same way).
fn expect_clean_echo(client: &ClientHandle, what: &str) -> Result<(), String> {
    let stats: EchoStats = client
        .udp_echo(svc(ECHO_UDP_PORT), ECHO_COUNT, 200, Duration::from_secs(30))
        .map_err(|e| format!("{what}: {e}"))?;
    if stats.received != ECHO_COUNT {
        return Err(format!("{what}: udp echo lost packets: {stats:?}"));
    }
    log::info!("{what}: {stats:?}");
    Ok(())
}

/// Gate a scenario on the `xt_string` module. `Ok(true)` → run; `Ok(false)` →
/// green-skip (module absent, not under `require`); `Err` → hard fail under
/// `SPORA_LAB=require`. Mirrors the harness's tool self-skip.
fn censor_available(wan: &Netns) -> Result<bool, String> {
    if censor::string_match_available(wan) {
        return Ok(true);
    }
    if std::env::var("SPORA_LAB").as_deref() == Ok("require") {
        return Err(
            "iptables `string` match (xt_string) unavailable but SPORA_LAB=require".into(),
        );
    }
    log::warn!("censorship: SKIPPED scenario — iptables xt_string module unavailable");
    Ok(false)
}

// ---------------------------------------------------------------------------
// 1. register_magic_signature
//
// Fingerprint: the REGISTER control packet's literal 5-byte prefix
// `0x80 'spR' 0x01` (relay-client/src/protocol.rs:11,19). Threat: fixed
// magic-prefix DPI (GFW/TSPU/Iran) — one observed sample → a permanent drop
// rule. We drop ONLY that signature; QUIC to the relay is untouched. Yet
// without a fresh registration the relay has no routing_key→sharer mapping, so
// a client cannot be routed and connect() fails. Remove the signature (the
// obfuscation analogue) and the sharer re-registers, so a client connects.

fn register_magic_signature() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    if !censor_available(&topo.wan)? {
        return Ok(());
    }
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = relay_pinned_opts(&wan);

    // Sharer only — it registers immediately and then every 1s.
    let sharer = peers::start_sharer(&topo.sharer, &opts)?;

    // Censor the control channel by its literal signature alone.
    censor::drop_signature(&topo.wan, censor::SIG_REGISTER_MAGIC)?;
    // Let the last good registration expire (registration_timeout 6s + sweep).
    std::thread::sleep(Duration::from_secs(8));

    match peers::start_client(&topo.client, sharer.url().clone(), &opts) {
        Ok(client) => {
            client.stop();
            return Err(
                "client connected while REGISTER was signature-dropped — expected failure".into(),
            );
        }
        Err(e) if e.contains("connect() failed") => {
            log::info!("register-magic block: connect failed as expected: {e}");
        }
        Err(e) => {
            return Err(format!(
                "expected a fail-fast connect() error during the magic block, got: {e}"
            ));
        }
    }

    // Remove the signature; the sharer re-registers within a couple intervals.
    censor::clear_signature(&topo.wan, censor::SIG_REGISTER_MAGIC)?;
    std::thread::sleep(Duration::from_secs(4));

    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)
        .map_err(|e| format!("connect should succeed once the signature is gone: {e}"))?;
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client relay session after signature cleared: {e}"))?;
    expect_clean_echo(&client, "post-clear echo")?;

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. quic_v1_wholesale
//
// Fingerprint: the outer transport is plain QUIC v1; its Initials carry the
// long-header version word `00 00 00 01`. Threat: TSPU-style wholesale block
// keyed on QUIC version + dst port + size. We drop QUIC v1 long-header packets
// bound for the relay. REGISTER (fixed bit clear, no version word) still flows,
// so the sharer stays registered — proving it is the QUIC HANDSHAKE that dies,
// with NO outer TCP fallback to save it (relay-via AND direct are both QUIC/UDP
// today). Remove the rule and the handshake completes.

fn quic_v1_wholesale() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    if !censor_available(&topo.wan)? {
        return Ok(());
    }
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = relay_pinned_opts(&wan);

    let sharer = peers::start_sharer(&topo.sharer, &opts)?;

    // TSPU-style block: drop QUIC v1 long-header packets to the relay.
    censor::drop_quic_v1(&topo.wan, svc_ip(), RELAY_PORT)?;

    match peers::start_client(&topo.client, sharer.url().clone(), &opts) {
        Ok(client) => {
            client.stop();
            return Err("client connected while QUIC v1 Initials were dropped — expected \
                        failure (documents the missing outer TCP fallback)"
                .into());
        }
        Err(e) if e.contains("connect() failed") => {
            log::info!("quic-v1 block: connect failed as expected — no TCP fallback: {e}");
        }
        Err(e) => {
            return Err(format!(
                "expected a fail-fast connect() error during the QUIC-v1 block, got: {e}"
            ));
        }
    }

    // Allow QUIC v1 again. REGISTER was never blocked, so the sharer is still
    // registered and the next client Initial gets through immediately.
    censor::clear_quic_v1(&topo.wan, svc_ip(), RELAY_PORT)?;

    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)
        .map_err(|e| format!("connect should succeed once QUIC v1 is allowed: {e}"))?;
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client relay session after QUIC v1 allowed: {e}"))?;
    expect_clean_echo(&client, "post-clear echo")?;

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. punch_marker_signature
//
// Fingerprint: the hole-punch probe sends literal `sporaHP1P`/`sporaHP1V`
// markers (spora-core/src/lib.rs:1229). Threat: magic-prefix DPI on the DIRECT
// leg. Open/Open is trivially punchable (mirrors nat_matrix::open_open_direct),
// so a clean direct upgrade is the baseline. With the markers dropped on the
// wan router (they transit FORWARD), the punch fails — while the relay path
// keeps working (path independence). Clear the signature and the next upgrade
// retry punches and succeeds, proving the marker literal was the only thing
// blocking the direct path.

/// Client deadline for `DirectUpgradeSucceeded` after the censor lifts: a clean
/// punch is ~2s, plus one scaled `upgrade_retry_delay` (3s) and CI slack.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(30);
/// Deadline for one full FAILED attempt: endpoint exchange (instant on Open/
/// Open) + punch phase (5s, run twice) + slack.
const FAIL_TIMEOUT: Duration = Duration::from_secs(25);

/// Production punch geometry (per nat_matrix) but a short `upgrade_retry_delay`
/// so the post-clear retry fires quickly.
fn fast_retry_timings() -> Timings {
    Timings {
        upgrade_retry_delay: Duration::from_secs(3),
        ..Default::default()
    }
}

fn punch_marker_signature() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(NatKind::Open, NatKind::Open))?;
    if !censor_available(&topo.wan)? {
        return Ok(());
    }
    // Production relay timeouts (registration 120s): this scenario runs long
    // enough that a scaled 6s registration would expire under it.
    let wan = services::start_wan(&topo.wan, relay::State::default)?;
    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.timings = fast_retry_timings();
    opts.enable_direct_upgrade = true;

    // Censor the punch markers BEFORE the peers come up, so the very first
    // upgrade attempt is already blocked.
    censor::drop_signature(&topo.wan, censor::SIG_PUNCH_MARKER)?;

    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client relay session: {e}"))?;
    sharer
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("sharer relay session: {e}"))?;

    // Path independence: the relay path is unaffected by the punch censor...
    expect_clean_echo(&client, "relay echo under punch censor")?;

    // ...and the direct upgrade attempt fails (markers dropped in FORWARD).
    match client.wait_event(is_upgrade_outcome, FAIL_TIMEOUT) {
        Ok(TunnelEvent::DirectUpgradeFailed { reason }) => {
            log::info!("punch-marker block: upgrade failed as expected: {reason}");
        }
        Ok(TunnelEvent::DirectUpgradeSucceeded { local, peer }) => {
            return Err(format!(
                "direct upgrade SUCCEEDED while punch markers were dropped \
                 (local={local}, peer={peer}) — the censor did not bite"
            ));
        }
        Ok(other) => return Err(format!("unexpected event waiting for upgrade outcome: {other:?}")),
        Err(e) => return Err(format!("no direct-upgrade attempt under the punch censor: {e}")),
    }

    // Lift the censor: the next retry punches and succeeds.
    censor::clear_signature(&topo.wan, censor::SIG_PUNCH_MARKER)?;
    client
        .wait_event(is_upgrade_success, UPGRADE_TIMEOUT)
        .map_err(|e| format!("direct upgrade never succeeded after clearing the markers: {e}"))?;
    expect_clean_echo(&client, "post-upgrade echo")?;

    client.stop();
    sharer.stop();
    Ok(())
}
