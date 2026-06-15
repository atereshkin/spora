//! Connection-log e2e: real tunneled traffic through the production sharer
//! (default `ExitMode::Netstack`) must produce correct records in the
//! sharer's connlog database (`Config::conn_log`, spora-core/src/connlog.rs).
//!
//! Scenarios:
//! - `tcp_flow_recorded`: a TCP bulk echo through the tunnel yields exactly
//!   one closed, established, confirmed TCP flow row with byte counts and an
//!   egress address; the session row carries the relay address and gains
//!   `end_ms` once the share stops.
//! - `udp_flow_recorded`: a UDP echo yields a proto-17 flow row to the right
//!   destination with bytes counted in both directions.
//! - `punch_addrs_recorded`: a successful direct upgrade records
//!   address-validated (`punch_verified` / `verified`) session addresses.
//!
//! The connlog writer thread is asynchronous to the tunnel, so every
//! assertion polls the database with a deadline (the `wait_for` pattern from
//! the connlog unit tests); the per-scenario config uses a 50ms flush
//! interval to keep that fast.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use spora_core::TunnelEvent;
use spora_core::connlog::{self, ConnLogConfig, FlowQuery, FlowRow, SessionRow};
use spora_lab::peers::{self, ClientHandle, LabPeerOpts, SharerHandle};
use spora_lab::services::{self, WanHandle};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{CLIENT_INNER_IP, ECHO_TCP_PORT, ECHO_UDP_PORT, NatKind, WAN_SERVICES_IP};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "connlog",
        spora_lab::scenarios![
            tcp_flow_recorded,
            udp_flow_recorded,
            punch_addrs_recorded,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// helpers

const SESSION_TIMEOUT: Duration = Duration::from_secs(15);
/// Deadline for polled database assertions. The writer flushes every 50ms
/// here; the margin covers CI scheduling noise, not protocol time.
const DB_TIMEOUT: Duration = Duration::from_secs(15);
/// Client deadline for `DirectUpgradeSucceeded` (see nat_matrix: a clean
/// punch completes in ~2s; the margin absorbs one transient-failure retry).
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(30);

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

fn svc_ip() -> Ipv4Addr {
    WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses")
}

fn svc(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(svc_ip(), port)
}

fn is_relay_session(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::RelaySessionEstablished { .. })
}

fn is_upgrade_success(e: &TunnelEvent) -> bool {
    matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. })
}

/// Fresh per-scenario log directory. The lab's mount namespace leaves /tmp
/// shared with the suite process, and the sharer host thread only changes its
/// *network* namespace, so the main thread reads exactly what the sharer's
/// writer thread wrote. A leftover directory from a previous run would belong
/// to that run's identity (`ConnLog::open` refuses a foreign database), so it
/// is removed first.
fn fresh_log_dir(scenario: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("spora-lab-connlog-{scenario}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| format!("remove stale log dir {}: {e}", dir.display()))?;
    }
    Ok(dir)
}

/// Sharer-side connlog config: fast flush so polled assertions settle quickly.
fn conn_log_cfg(dir: &Path) -> ConnLogConfig {
    let mut cfg = ConnLogConfig::in_dir(dir);
    cfg.flush_interval = Duration::from_millis(50);
    cfg
}

/// Poll the database until `f` yields `Some` or the deadline passes. `f`
/// re-opens the database read-only on every attempt; transient errors (e.g.
/// the file not existing yet) only fail at the deadline.
fn poll_db<T>(
    what: &str,
    timeout: Duration,
    f: impl Fn() -> Result<Option<T>, String>,
) -> Result<T, String> {
    let deadline = Instant::now() + timeout;
    let mut last_err = String::new();
    loop {
        match f() {
            Ok(Some(v)) => return Ok(v),
            Ok(None) => last_err.clear(),
            Err(e) => last_err = e,
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{what}: not satisfied within {timeout:?} (last db error: {last_err:?})"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn query_flows_to(dir: &Path, port: u16) -> Result<Vec<FlowRow>, String> {
    let db = connlog::open_readonly(dir)?;
    connlog::query_flows(
        &db,
        &FlowQuery {
            ip: Some(svc_ip().into()),
            port: Some(port),
            ..Default::default()
        },
    )
}

fn query_all_sessions(dir: &Path) -> Result<Vec<SessionRow>, String> {
    let db = connlog::open_readonly(dir)?;
    connlog::query_sessions(&db, None)
}

/// Production peers with the connection log enabled on the SHARER only
/// (`Config::conn_log` is share-side; the client never opens a database).
/// Returns once the relay-via session is up on both sides.
fn start_logged_peers(
    topo: &Topology,
    wan: &WanHandle,
    log_dir: &Path,
    enable_direct_upgrade: bool,
) -> Result<(SharerHandle, ClientHandle), String> {
    let mut sharer_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    sharer_opts.enable_direct_upgrade = enable_direct_upgrade;
    sharer_opts.conn_log = Some(conn_log_cfg(log_dir));
    let mut client_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    client_opts.enable_direct_upgrade = enable_direct_upgrade;

    let mut sharer = peers::start_sharer(&topo.sharer, &sharer_opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &client_opts)?;
    client
        .wait_event(is_relay_session, SESSION_TIMEOUT)
        .map_err(|e| format!("client relay session: {e}"))?;
    sharer
        .wait_event(is_relay_session, SESSION_TIMEOUT)
        .map_err(|e| format!("sharer relay session: {e}"))?;
    Ok((sharer, client))
}

// ---------------------------------------------------------------------------
// 1. tcp_flow_recorded

/// A 64 KiB TCP bulk echo through the relay-pinned tunnel (netstack exit)
/// must land as exactly one flow row to the echo service: proto 6,
/// established (the outbound OS connect succeeded), confirmed (netstack
/// re-origination), exact byte counts both ways, an egress address
/// (`getsockname()` of the re-origination socket), and a clean close reason.
/// The session row carries the relay's address; stopping the share sets its
/// `end_ms`.
fn tcp_flow_recorded() -> Result<(), String> {
    let dir = fresh_log_dir("tcp")?;
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;
    let (sharer, client) = start_logged_peers(&topo, &wan, &dir, false)?;

    const BULK: usize = 64 * 1024;
    let bulk = client.tcp_bulk(svc(ECHO_TCP_PORT), BULK, Duration::from_secs(90))?;
    if bulk.bytes != BULK {
        return Err(format!("tcp bulk incomplete: {bulk:?}"));
    }

    // The driver completed the TCP close handshake, so the share-side proxy
    // finishes and closes the flow record; byte counts are persisted at
    // close, so wait for the closed row.
    let flows = poll_db("closed tcp flow row", DB_TIMEOUT, || {
        let flows = query_flows_to(&dir, ECHO_TCP_PORT)?;
        Ok(flows.iter().any(|f| f.end_reason.is_some()).then_some(flows))
    })?;
    if flows.len() != 1 {
        return Err(format!(
            "expected exactly one TCP flow row to {}:{ECHO_TCP_PORT}, got {flows:#?}",
            svc_ip()
        ));
    }
    let f = &flows[0];
    if f.proto != PROTO_TCP {
        return Err(format!("flow proto {} != TCP: {f:#?}", f.proto));
    }
    if f.src != CLIENT_INNER_IP.to_string() {
        return Err(format!("flow src {} is not the inner client address: {f:#?}", f.src));
    }
    if !f.established {
        return Err(format!("flow not marked established: {f:#?}"));
    }
    if !f.confirmed {
        return Err(format!("netstack flow must be confirmed: {f:#?}"));
    }
    // The echo doubles every byte: BULK up (client->service) and BULK back.
    if f.bytes_up != BULK as u64 || f.bytes_down != BULK as u64 {
        return Err(format!(
            "byte counts up={} down={} != {BULK} each way: {f:#?}",
            f.bytes_up, f.bytes_down
        ));
    }
    if f.egress_addr.is_none() {
        return Err(format!("netstack flow must record an egress address: {f:#?}"));
    }
    match f.end_reason.as_deref() {
        Some("closed") | Some("session_end") => {}
        other => return Err(format!("end_reason {other:?} is not a close: {f:#?}")),
    }

    // One session row, recorded against the relay's address (accepted
    // sessions always bootstrap relay-via), still open.
    let sessions = query_all_sessions(&dir)?;
    if sessions.len() != 1 {
        return Err(format!("expected exactly one session row, got {sessions:#?}"));
    }
    if sessions[0].relay_addr != wan.relay_addr().to_string() {
        return Err(format!(
            "session relay_addr {} != relay {}",
            sessions[0].relay_addr,
            wan.relay_addr()
        ));
    }
    if sessions[0].end_ms.is_some() {
        return Err(format!("session ended while the share is live: {sessions:#?}"));
    }
    if f.session_id != sessions[0].id {
        return Err(format!(
            "flow session_id {} != session id {}",
            f.session_id, sessions[0].id
        ));
    }

    // Stopping the share tears the session down; the SessionLog guard records
    // the end and the writer thread (plain std thread) flushes it.
    client.stop();
    sharer.stop();
    poll_db("session row gains end_ms after stop", DB_TIMEOUT, || {
        let sessions = query_all_sessions(&dir)?;
        Ok(sessions.first().and_then(|s| s.end_ms))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. udp_flow_recorded

/// A UDP echo through the tunnel: one NAT-entry-delimited UDP "connection"
/// (the driver sends every datagram from one inner source port) must land as
/// a proto-17 flow row to the echo service with payload bytes counted both
/// ways. UDP flows close on idle (30s) or session end; the suite stops the
/// peers instead of waiting out the idle timer, so the bytes (persisted at
/// close) appear via the `session_end` path.
fn udp_flow_recorded() -> Result<(), String> {
    let dir = fresh_log_dir("udp")?;
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;
    let (sharer, client) = start_logged_peers(&topo, &wan, &dir, false)?;

    const COUNT: usize = 10;
    const LEN: usize = 200;
    let stats = client.udp_echo(svc(ECHO_UDP_PORT), COUNT, LEN, Duration::from_secs(30))?;
    if stats.received != COUNT {
        return Err(format!("udp echo lost packets: {stats:?}"));
    }

    // The open row (no bytes yet) appears as soon as the first datagram
    // builds the NAT entry — assert the destination is right before teardown.
    poll_db("open udp flow row", DB_TIMEOUT, || {
        let flows = query_flows_to(&dir, ECHO_UDP_PORT)?;
        Ok(flows.iter().any(|f| f.proto == PROTO_UDP).then_some(()))
    })?;

    client.stop();
    sharer.stop();

    let flows = poll_db("closed udp flow row with bytes", DB_TIMEOUT, || {
        let flows = query_flows_to(&dir, ECHO_UDP_PORT)?;
        Ok(flows.iter().any(|f| f.end_reason.is_some()).then_some(flows))
    })?;
    if flows.len() != 1 {
        return Err(format!(
            "expected exactly one UDP flow row to {}:{ECHO_UDP_PORT}, got {flows:#?}",
            svc_ip()
        ));
    }
    let f = &flows[0];
    if f.proto != PROTO_UDP {
        return Err(format!("flow proto {} != UDP: {f:#?}", f.proto));
    }
    if f.src != CLIENT_INNER_IP.to_string() {
        return Err(format!("flow src {} is not the inner client address: {f:#?}", f.src));
    }
    if !f.established || !f.confirmed {
        return Err(format!("UDP netstack flow must be established+confirmed: {f:#?}"));
    }
    if f.egress_addr.is_none() {
        return Err(format!("UDP netstack flow must record an egress address: {f:#?}"));
    }
    // Payload bytes, counted at the NAT entry: COUNT x LEN in each direction
    // (zero echo loss was asserted above).
    let expect = (COUNT * LEN) as u64;
    if f.bytes_up != expect || f.bytes_down != expect {
        return Err(format!(
            "byte counts up={} down={} != {expect} each way: {f:#?}",
            f.bytes_up, f.bytes_down
        ));
    }
    match f.end_reason.as_deref() {
        Some("session_end") | Some("idle") | Some("closed") => {}
        other => return Err(format!("end_reason {other:?} is not a close: {f:#?}")),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. punch_addrs_recorded

/// A successful direct upgrade must leave address-validated evidence in the
/// session's address records. FullCone x FullCone punches deterministically
/// at the lab's sub-ms RTT (endpoint-independent filtering delivers every
/// punch; no port-steal sensitivity — see docs/lab.md), so after
/// `DirectUpgradeSucceeded` on both sides the sharer's log must hold a
/// `punch_verified` (learned from the peer's actual punch packets) or
/// `verified` (established direct QUIC) address — not just the
/// client-asserted `reported` one.
fn punch_addrs_recorded() -> Result<(), String> {
    let dir = fresh_log_dir("punch")?;
    let topo = Topology::build(&TopologySpec::new(NatKind::FullCone, NatKind::FullCone))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;
    let (mut sharer, mut client) = start_logged_peers(&topo, &wan, &dir, true)?;

    client
        .wait_event(is_upgrade_success, UPGRADE_TIMEOUT)
        .map_err(|e| format!("client never saw DirectUpgradeSucceeded: {e}"))?;
    sharer
        .wait_event(is_upgrade_success, SESSION_TIMEOUT)
        .map_err(|e| format!("sharer never saw DirectUpgradeSucceeded: {e}"))?;

    let addrs = poll_db("punch-verified session addr", DB_TIMEOUT, || {
        let sessions = query_all_sessions(&dir)?;
        Ok(sessions
            .iter()
            .find(|s| {
                s.addrs
                    .iter()
                    .any(|(_, kind, _)| kind == "punch_verified" || kind == "verified")
            })
            .map(|s| s.addrs.clone()))
    })?;
    log::info!("punch_addrs_recorded: session addrs {addrs:?}");

    client.stop();
    sharer.stop();
    Ok(())
}
