//! Tier-3-lite red→green for the nz Shaper: capture a live nz relay session off
//! the wan leg and verify — from the actual wire — that the Shaper removed the
//! structural DPI tells a passive censor keys on (the fixed 72-byte msg1 and the
//! idx_B echo). The "red" (that the inspector flags those tells) is proven by the
//! synthetic unit tests in `spora_lab::entropy_inspect`; this is the "green": the
//! real shaped flow carries neither. Needs tcpdump (self-skips without it).

use std::time::Duration;

use spora_core::identity::{RelayEndpoint, RelayProtocol, Token};
use spora_core::{Timings, TunnelEvent};
use spora_lab::capture::Capture;
use spora_lab::peers::{self, LabPeerOpts};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{NatKind, entropy_inspect, services};

fn main() {
    let ok = spora_lab::harness::lab_main_with_tools(
        "shaper",
        spora_lab::scenarios![shaped_nz_has_no_structural_tells],
        &["tcpdump"],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

fn scaled_relay_state() -> relay::State {
    relay::State::with_timeouts(
        Duration::from_secs(6),
        Duration::from_secs(3),
        Duration::from_millis(500),
    )
}

fn scaled_timings() -> Timings {
    Timings {
        register_interval: Duration::from_secs(1),
        quic_idle_timeout: Duration::from_secs(3),
        quic_keep_alive: Duration::from_secs(1),
        reconnect_delay: Duration::from_millis(500),
        ..Default::default()
    }
}

fn is_relay_established(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::RelaySessionEstablished { .. })
}

// ---------------------------------------------------------------------------
// shaped_nz_has_no_structural_tells
//
// Bring up a relay-via nz session (direct upgrade off, so the wan leg carries the
// relay-path handshake), tap the wan bridge, then analyze the captured payloads
// against the known routing_key. Bare nz would show a 72-byte first packet and
// the idx_B echo (see entropy_inspect's unit tests); the shaped flow must show
// neither — msg1 is nonce+pad (always > 72) and the echo is masked away.

fn shaped_nz_has_no_structural_tells() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    // Tap the client's wan-side leg before any traffic flows.
    let cap = Capture::start(&topo.wan, &topo.wan_if_b)?;

    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.timings = scaled_timings();
    opts.enable_direct_upgrade = false;
    opts.relays = vec![RelayEndpoint::with_protocol(
        wan.relay_addr().ip().to_string(),
        wan.relay_addr().port(),
        RelayProtocol::NoiseUdp,
    )];

    let sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let routing_key = Token::from_url(sharer.url())
        .map_err(|e| format!("parse share url: {e}"))?
        .routing_key;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("nz relay session: {e}"))?;

    client.stop();
    sharer.stop();
    let pcap = cap.stop()?;

    let report = entropy_inspect::analyze_pcap(&pcap, &routing_key);
    log::info!(
        "nz shaped flow: datagrams={} msg1_sizes={:?} index_echo={} first_msg1_popcount={:?}",
        report.datagrams,
        report.msg1_sizes,
        report.index_echo,
        report.first_msg1_popcount,
    );

    if report.datagrams == 0 {
        return Err("no UDP datagrams captured on the wan leg".into());
    }
    if report.msg1_sizes.is_empty() {
        return Err(
            "no msg1 (routing_key-prefixed) datagram captured — flow never handshook".into(),
        );
    }
    if report.looks_like_bare_nz() {
        return Err(format!(
            "bare-nz structural signature present on the wire: {report:?}"
        ));
    }
    if !report.passes_shaping() {
        return Err(format!(
            "shaped nz still shows a structural tell (want: all msg1 > {}, no echo): {report:?}",
            entropy_inspect::BARE_MSG1_LEN,
        ));
    }
    Ok(())
}
