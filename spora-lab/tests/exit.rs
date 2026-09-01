//! Exit-side netstack behavior under abandoned inner TCP flows.
//!
//! Encodes the September 2026 field finding from the Russian exit: the
//! share-side netstack admits an inner TCP handshake, eagerly allocates one
//! of `MAX_TCP_SOCKETS` (256) session slots, and starts its outbound dial —
//! but the dial has no connect timeout and is not cancelled when the inner
//! side gives up, so a dial toward a destination that silently drops SYNs
//! pins the slot for the kernel's SYN-retry timeout (~2 minutes). A desktop
//! full of retrying apps behind a lossy egress (DNS-degraded resolvers,
//! filtered endpoints) sustains a few failing attempts per second, wedges
//! the pool in under a minute, and every NEW TCP connection through the
//! tunnel is then refused — while the ICMP keepalive, answered in-stack,
//! keeps the tunnel looking perfectly healthy (no reconnect, no recovery).
//!
//! The contract this suite pins: inner connections the client has already
//! abandoned must not starve new connections. Enforced strictly since the
//! exit-dial lifecycle fix (`dial_watching_inner` in spora-core server.rs:
//! a connect timeout, plus the dial — and with it the netstack slot — is
//! released the moment the inner side closes). Before that fix this suite
//! failed with "254 established+aborted, 66 refused … connection closed
//! early". The known_gap/xfail machinery below is retained (unused) for
//! the next red-by-design finding, the recovery suite's model.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use spora_lab::peers::{self, LabPeerOpts};
use spora_lab::services::{self, TCP_SOURCE_PORT};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::traffic::TcpOpts;
use spora_lab::{ECHO_UDP_PORT, NatKind, WAN_SERVICES_IP};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "exit",
        spora_lab::scenarios![tcp_pool_starved_by_aborted_dials],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

/// A wan-host port with NO listener and an iptables DROP rule: SYNs the
/// exit dials at it are silently discarded, so the exit-side connect hangs
/// in SYN_SENT exactly like a blackholed real-world destination. (Without
/// the rule the wan kernel would answer RST — a fast, slot-freeing failure,
/// which is NOT the failure mode under test.)
const SINKHOLE_TCP_PORT: u16 = 7999;

/// More abandoned attempts than the netstack has session slots (256), issued
/// back-to-back — a compressed rendition of a retry-storming desktop. Every
/// one of them is FIN-closed by the client the instant it establishes.
const STORM_ATTEMPTS: usize = 320;

/// Attempts completed before the mid-storm control download. Far below the
/// pool cap, so this download succeeding proves the storm mechanism itself
/// (aborted flows, sinkhole rule, RSTs) does not break the tunnel — only
/// pool exhaustion later does.
const EARLY_CHECK_AT: usize = 40;

const DOWNLOAD_BYTES: usize = 64 * 1024;

fn svc(port: u16) -> SocketAddrV4 {
    let ip: Ipv4Addr = WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses");
    SocketAddrV4::new(ip, port)
}

fn xfail_mode() -> bool {
    std::env::var("SPORA_LAB_EXIT").as_deref() == Ok("xfail")
}

/// Known-gap accounting, the recovery suite's model: strict mode returns the
/// result tagged; xfail mode (CI) converts the expected miss into a logged
/// expected failure, and an unexpected PASS into an error so this marker is
/// removed together with the fix. Currently unused — the exit-dial gap is
/// fixed; retained for the next red-by-design finding.
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

fn download(client: &peers::ClientHandle, what: &str) -> Result<(), String> {
    let stats = client
        .tcp_download(
            svc(TCP_SOURCE_PORT),
            DOWNLOAD_BYTES,
            TcpOpts::default(),
            Duration::from_secs(30),
        )
        .map_err(|e| format!("{what}: {e}"))?;
    log::info!("{what}: {} bytes in {:?}", stats.bytes, stats.elapsed);
    Ok(())
}

fn tcp_pool_starved_by_aborted_dials() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;

    // Sinkhole: silently drop SYNs to the dead port on the wan host.
    topo.wan.run(&format!(
        "iptables -A INPUT -p tcp --dport {SINKHOLE_TCP_PORT} -j DROP"
    ))?;

    // Relay-pinned session: the wedge is path-independent (verified in the
    // field on both relay and punched-direct), so skip upgrade nondeterminism.
    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.enable_direct_upgrade = false;

    let sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    client.set_keepalive(1);

    download(&client, "baseline download")?;

    let sink = svc(SINKHOLE_TCP_PORT);
    let mut established = 0usize;
    let mut refused = 0usize;
    for i in 0..STORM_ATTEMPTS {
        if i == EARLY_CHECK_AT {
            download(&client, "mid-storm control download (pool far from cap)")?;
        }
        match client.tcp_aborted_connect(sink, Duration::from_secs(8))? {
            true => established += 1,
            false => refused += 1,
        }
    }
    log::info!(
        "storm complete: {established} aborted after handshake, {refused} refused by the netstack"
    );

    // The tunnel itself must be alive — the whole point of the bug is that
    // it wedges silently, without the keepalive noticing anything.
    let probe = client
        .udp_probe(svc(ECHO_UDP_PORT), Duration::from_secs(3))
        .map_err(|e| format!("udp probe: {e}"))?;
    if probe.is_none() {
        return Err("tunnel is not passing UDP at all after the storm — \
                    that is a different failure than the TCP pool wedge"
            .into());
    }

    // THE CONTRACT: every one of those 320 connections was FIN-closed by
    // the client before this point, so none of them may still hold a
    // session slot against a fresh, legitimate connection.
    download(
        &client,
        "post-storm download (abandoned flows must not starve it)",
    )
    .map_err(|e| {
        format!(
            "netstack TCP pool starved by abandoned dials \
                 ({established} established+aborted, {refused} refused): {e}"
        )
    })?;

    client.stop();
    sharer.stop();
    Ok(())
}
