//! Failure/recovery scenarios over the RELAY path: relay restart mid-session,
//! sharer registration blackout, client roaming between gateways, and live
//! session takeover (new peer kicks previous via the rolling listener).
//!
//! Direct upgrade is disabled on both peers in every scenario (the relay path
//! is the subject under test) and both sides sit behind PortRestricted NAT.
//! Scaled-down timings keep failure detection in seconds of wall time:
//!   peers: register 1s, QUIC idle 3s / keep-alive 1s, redial delay 500ms
//!   relay: registration timeout 6s, flow timeout 3s, sweep every 500ms
//! Punch-related timings stay at production defaults (punching is not under
//! test here).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;

use spora_core::TunnelEvent;
use spora_lab::netns::Netns;
use spora_lab::peers::{self, ClientHandle, LabPeerOpts};
use spora_lab::services::{self, WanHandle};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::traffic::EchoStats;
use spora_lab::{ECHO_UDP_PORT, NatKind, WAN_SERVICES_IP, WHOAMI_UDP_PORT, netem};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "resilience",
        spora_lab::scenarios![
            relay_restart_recovery,
            registration_blackout,
            roaming_gateway_switch,
            sharer_session_replacement,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// shared knobs & helpers

/// Scaled relay expiry: registration 6s, flow 3s, sweep 500ms.
fn scaled_relay_state() -> relay::State {
    relay::State::with_timeouts(
        Duration::from_secs(6),
        Duration::from_secs(3),
        Duration::from_millis(500),
    )
}

/// Scaled peer timings (everything punch-related stays at defaults).
fn scaled_timings() -> spora_core::Timings {
    spora_core::Timings {
        register_interval: Duration::from_secs(1),
        quic_idle_timeout: Duration::from_secs(3),
        quic_keep_alive: Duration::from_secs(1),
        reconnect_delay: Duration::from_millis(500),
        ..Default::default()
    }
}

/// Relay-pinned peer options: scaled timings + direct upgrade disabled.
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

const ECHO_COUNT: usize = 10;

/// UDP-echo through the tunnel and require zero loss (the quiet lab veth
/// path delivers every datagram; the smoke suite pins 20/20 the same way).
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

/// Run an async closure on a fresh host thread pinned inside `ns`, blocking
/// the scenario (main thread) until it reports back.
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

/// Bind a fresh UDP socket inside `ns` and ask the wan whoami service for
/// the externally observed source address (i.e. which gateway the namespace
/// currently egresses through).
fn query_whoami(ns: &Netns, label: &str) -> Result<SocketAddrV4, String> {
    let dst = svc(WHOAMI_UDP_PORT);
    in_ns(ns, label, Duration::from_secs(15), move || async move {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind: {e}"))?;
        sock.send_to(b"whoami", dst)
            .await
            .map_err(|e| format!("send to {dst}: {e}"))?;
        let mut buf = [0u8; 256];
        let (n, from) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .map_err(|_| format!("whoami {dst}: timed out waiting for reply"))?
            .map_err(|e| format!("whoami {dst}: recv: {e}"))?;
        if from != SocketAddr::V4(dst) {
            return Err(format!("whoami reply from unexpected source {from}"));
        }
        let text =
            std::str::from_utf8(&buf[..n]).map_err(|e| format!("whoami reply not utf8: {e}"))?;
        match text.parse::<SocketAddr>() {
            Ok(SocketAddr::V4(v4)) => Ok(v4),
            Ok(other) => Err(format!("whoami reported non-IPv4 address {other}")),
            Err(e) => Err(format!("whoami reply unparseable {text:?}: {e}")),
        }
    })
}

// ---------------------------------------------------------------------------
// 1. relay_restart_recovery
//
// Restarting the relay loses registrations AND flows. The client's QUIC
// connection dies by idle timeout (3s), ReconnectTransport emits
// Reconnecting and redials; the sharer re-registers within register_interval
// (1s), so a redial Initial installs a fresh flow and the sharer accepts a
// brand-new session (second RelaySessionEstablished). Traffic then flows
// again end to end.

fn relay_restart_recovery() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = relay_pinned_opts(&wan);

    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    // Active client (like the CLI): its reconnect loop redials on a dead
    // path. A dormant (knob 0) client parks instead — that's the
    // cooperate-with-sleep path, not what this scenario exercises.
    client.set_keepalive(1);
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client relay session: {e}"))?;
    sharer
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("sharer relay session: {e}"))?;
    expect_clean_echo(&client, "pre-restart echo")?;

    // Fresh relay socket + fresh State: registrations and flows are gone.
    wan.restart_relay()?;
    // Anchor the waits below to the restart: a spurious pre-fault reconnect
    // cycle must not satisfy them with stale buffered events.
    client.discard_events();
    sharer.discard_events();

    // QUIC idle (3s) detects the dead path; a redial cycle or two (500ms
    // delay each) later the client is back. ~20s is a generous ceiling.
    client
        .wait_event(
            |e| matches!(e, TunnelEvent::Reconnecting),
            Duration::from_secs(20),
        )
        .map_err(|e| format!("client never started reconnecting after relay restart: {e}"))?;
    client
        .wait_event(
            |e| matches!(e, TunnelEvent::Reconnected),
            Duration::from_secs(20),
        )
        .map_err(|e| format!("client never reconnected after relay restart: {e}"))?;

    // The redial is a brand-new QUIC connection: the sharer must have
    // accepted a SECOND session (the first established event was consumed
    // above, so this requires a fresh emission).
    sharer
        .wait_event(is_relay_established, Duration::from_secs(20))
        .map_err(|e| format!("sharer never accepted a new session after relay restart: {e}"))?;

    expect_clean_echo(&client, "post-restart echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. registration_blackout
//
// Cut the sharer off from the relay (its registrations terminate IN the wan
// namespace, so the INPUT half of the block bites), let the registration
// expire (6s + sweep), and a new client must fail to connect. Unblock, give
// the sharer a couple of register intervals, and a new client succeeds.
//
// REGRESSION TEST for the stale-registration fix: `handle_packet` now checks
// registration freshness on the DCID lookup. Relay expiry is otherwise
// sweep-driven and a quiet relay (blocked sharer, no client) never sweeps, so
// without that check the blocked-phase client's Initial would be forwarded to
// the sharer off the STALE registration AND install a flow that blocks the
// sharer's one-flow slot for flow_timeout. With the fix the relay drops that
// Initial (registration older than registration_timeout) and installs nothing,
// so the connect fails cleanly and recovery only needs the sharer to
// re-register after the unblock.

fn registration_blackout() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = relay_pinned_opts(&wan);

    // Sharer only — it registers immediately and then every 1s.
    let sharer = peers::start_sharer(&topo.sharer, &opts)?;

    // Sever sharer-external -> services (registrations AND any sharer->relay
    // QUIC traffic).
    netem::block(&topo.wan, topo.ext_ip_a, svc_ip())?;

    // Past registration_timeout (6s) + sweep (500ms), with margin.
    std::thread::sleep(Duration::from_secs(8));

    // A client must now FAIL to connect. connect() fails fast (the e2e
    // handshake gives up within ~10s); start_client's own 40s ceiling means
    // a hang would surface as the "never reported" variant, which we reject.
    match peers::start_client(&topo.client, sharer.url().clone(), &opts) {
        Ok(client) => {
            client.stop();
            return Err(
                "client connected during the registration blackout — expected failure".into(),
            );
        }
        Err(e) if e.contains("connect() failed") => {
            log::info!("blackout connect failed as expected: {e}");
        }
        Err(e) => {
            return Err(format!(
                "expected a fail-fast connect() error during the blackout, got: {e}"
            ));
        }
    }

    // Lift the outage; the sharer re-registers within register_interval (1s).
    // No stale flow blocks the slot (see NOTE — the relay dropped the
    // blackout-phase Initial), so a few register intervals of margin suffice.
    netem::unblock(&topo.wan, topo.ext_ip_a, svc_ip())?;
    std::thread::sleep(Duration::from_secs(4));

    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)
        .map_err(|e| format!("post-unblock connect should succeed: {e}"))?;
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client relay session after unblock: {e}"))?;
    expect_clean_echo(&client, "post-unblock echo")?;

    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. roaming_gateway_switch
//
// The client roams to a second gateway mid-session (Wi-Fi -> cellular). The
// relay flow is keyed to the OLD source address, so client traffic is
// blackholed — and a redial Initial from the NEW address is also dropped
// while the old flow entry lives (the one-flow check keys on the sharer's
// flow entry, kept fresh by sharer keepalives until ITS QUIC idle timeout
// fires). Once that entry expires (~ idle 3s + flow 3s + sweep), a redial
// lands: Reconnecting -> Reconnected, traffic resumes from the new address.

/// External address of the alt client gateway's wan leg (topology builder:
/// B2 leg is 203.0.113.9/.10).
const ALT_CLIENT_EXT_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

fn roaming_gateway_switch() -> Result<(), String> {
    let mut spec = TopologySpec::new(NatKind::PortRestricted, NatKind::PortRestricted);
    spec.client_alt_gateway = true;
    let topo = Topology::build(&spec)?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = relay_pinned_opts(&wan);

    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    // Active client (see relay_restart_recovery): a roaming user is in use,
    // so its reconnect loop redials rather than parking.
    client.set_keepalive(1);
    client
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client relay session: {e}"))?;
    sharer
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("sharer relay session: {e}"))?;
    expect_clean_echo(&client, "pre-roam echo")?;

    // The client namespace currently egresses via the primary gateway.
    let before = query_whoami(&topo.client, "cli-whoami-pre")?;
    if *before.ip() != topo.ext_ip_b {
        return Err(format!(
            "pre-roam external ip {} != expected {}",
            before.ip(),
            topo.ext_ip_b
        ));
    }

    // Roam: flip the default route to the alt gateway. Old conntrack state
    // stays behind on the old gateway.
    topo.switch_client_gateway()?;
    // Anchor the post-roam waits to the roam (see relay_restart_recovery).
    client.discard_events();
    sharer.discard_events();

    // The external address really changed (fresh socket egresses via B2).
    let after = query_whoami(&topo.client, "cli-whoami-post")?;
    if *after.ip() != ALT_CLIENT_EXT_IP {
        return Err(format!(
            "post-roam external ip {} != alt gateway {} (before: {})",
            after.ip(),
            ALT_CLIENT_EXT_IP,
            before.ip()
        ));
    }

    // Death detection is slower here than a relay restart: the client keeps
    // RECEIVING the sharer's keepalives via the old return path until the
    // sharer's side idles out (~3s), then idles out itself (~3s more).
    client
        .wait_event(
            |e| matches!(e, TunnelEvent::Reconnecting),
            Duration::from_secs(20),
        )
        .map_err(|e| format!("client never started reconnecting after roaming: {e}"))?;
    client
        .wait_event(
            |e| matches!(e, TunnelEvent::Reconnected),
            Duration::from_secs(30),
        )
        .map_err(|e| format!("client never reconnected after roaming: {e}"))?;

    // The sharer accepted the redial as a brand-new session.
    sharer
        .wait_event(is_relay_established, Duration::from_secs(20))
        .map_err(|e| format!("sharer never accepted the roamed client: {e}"))?;

    expect_clean_echo(&client, "post-roam echo")?;
    client.stop();
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. sharer_session_replacement
//
// REGRESSION TEST for the rolling listener (2026-08-13): a second client
// against the same URL connects IMMEDIATELY — its dial lands on the fresh
// listener generation, and the sharer kicks the previous session
// ("new peer kicks previous"). Before the per-port change this scenario
// asserted the OPPOSITE: the relay's one-flow slot dropped client2's
// Initials while client1's flow was alive (~50s lockout at production
// timings; the "restart the relay to connect" bug).
//
// Known consequence, deliberate for now: TWO live clients that both
// auto-reconnect will alternate ownership at reconnect_delay cadence (each
// kick closes the loser's connection, its ReconnectTransport redials after
// the fixed delay and kicks back). The fixed, never-shrinking
// reconnect_delay is the anti-storm pacing (see transport/mod.rs); real
// multi-client sessions are the eventual fix (per-port already gives each
// session its own endpoint). The scenario stops client1 right after the
// takeover so the alternation cannot race the assertions.

fn sharer_session_replacement() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, scaled_relay_state)?;
    let opts = relay_pinned_opts(&wan);

    let mut sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let mut client1 = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    client1
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client1 relay session: {e}"))?;
    sharer
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("sharer session for client1: {e}"))?;
    expect_clean_echo(&client1, "client1 echo")?;

    // A second client takes over while client1 is ALIVE: first dial, no
    // waiting on any expiry.
    let mut client2 = peers::start_client(&topo.client, sharer.url().clone(), &opts)
        .map_err(|e| format!("client2 should take over immediately, got: {e}"))?;
    // Retire client1 before its paced redial can kick client2 back (the
    // mutual-eviction alternation documented above; reconnect_delay 500ms
    // scaled leaves comfortable room for these two calls).
    client1.stop();

    client2
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("client2 relay session: {e}"))?;
    sharer
        .wait_event(is_relay_established, Duration::from_secs(15))
        .map_err(|e| format!("sharer session for client2: {e}"))?;
    expect_clean_echo(&client2, "client2 echo after live takeover")?;

    client2.stop();
    sharer.stop();
    Ok(())
}
