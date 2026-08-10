//! Tier-1 fingerprint inspection: capture the client's QUIC handshake off the
//! wan leg and decrypt the Initial **in-tree** ([`spora_lab::quic_inspect`], no
//! external nDPI/tshark) to recover what an on-path classifier sees. Verifies
//! the de-branded ClientHello from the actual wire — ALPN `h3`, no SNI (the
//! `spora-e2e/1`/`spora.peer` literals are gone) — and emits the JA4-Q
//! fingerprint. Needs tcpdump (self-skips without it).

use std::time::Duration;

use spora_core::{Timings, TunnelEvent};
use spora_lab::capture::Capture;
use spora_lab::peers::{self, LabPeerOpts};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{NatKind, quic_inspect, services};

fn main() {
    let ok = spora_lab::harness::lab_main_with_tools(
        "fingerprint",
        spora_lab::scenarios![handshake_clienthello],
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
// handshake_clienthello
//
// Tap the client's wan leg, bring up a relay-via session (direct upgrade off —
// the relay-leg Initial carries the same client ClientHello), then decrypt the
// captured Initial and check what an on-path DPI box would extract. The QUIC
// Initial is encrypted only with keys derived from its cleartext DCID, so this
// is exactly the censor's view. Asserts the de-branding (ALPN h3, no SNI) and
// logs the JA4-Q — which, with SNI dropped, begins `q13i…`; real HTTP/3
// browsers send SNI and begin `q13d…`, so the value is logged for the
// browser-blend gap (a Tier-1 follow-up: realistic SNI + ClientHello mimicry).

fn handshake_clienthello() -> Result<(), String> {
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

    let sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("relay session: {e}"))?;

    // Tear down before reading the capture.
    client.stop();
    sharer.stop();
    let pcap = cap.stop()?;

    let ch = quic_inspect::first_client_hello(&pcap)
        .ok_or("no decryptable QUIC Initial captured on the client leg")?;
    log::info!(
        "captured client ClientHello: alpns={:?} sni={:?} ja4={} ciphers={:04x?}",
        ch.alpns,
        ch.sni,
        ch.ja4,
        ch.cipher_suites
    );

    // De-branding, verified from the wire (not the config):
    if ch.alpns != ["h3"] {
        return Err(format!(
            "ALPN on the wire = {:?}, expected [\"h3\"] (was spora-e2e/1)",
            ch.alpns
        ));
    }
    if let Some(sni) = &ch.sni {
        return Err(format!(
            "SNI on the wire = {sni:?}, expected none (was spora.peer)"
        ));
    }

    // JA4-Q shape: QUIC (q), TLS 1.3 (13), no SNI (i). Pin the prefix; the full
    // value is logged above for tracking against a browser reference.
    if !ch.ja4.starts_with("q13i") {
        return Err(format!(
            "unexpected JA4_a shape: {} (expected q13i…)",
            ch.ja4
        ));
    }

    Ok(())
}
