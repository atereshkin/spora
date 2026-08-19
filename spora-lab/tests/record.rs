//! The diagnostic record, checked against real sessions.
//!
//! Unit tests can prove the record format round-trips; only a real tunnel can
//! prove the record is *true* — that the steps it names actually happened, in
//! that order, with those verdicts. That is what this suite is for, and it is
//! the reason the vocabulary lives in the core rather than in the lab: both
//! labs and the shipping product read the same records.
//!
//! Scenarios:
//! - `a_working_session_is_recorded`: both ends of a healthy relay-via
//!   session write a record that says so, with the steps in the order they
//!   happened and a closing summary that agrees with them.
//! - `a_relay_that_never_answers_is_recorded_as_such`: a client pointed at a
//!   black hole records a failed dial with a code — and an outcome of
//!   `never_connected` rather than silence.
//! - `a_direct_upgrade_is_recorded`: when the punch works, the record shows
//!   every stage of it and the moment traffic moved onto the direct path.
//! - `a_redial_resolves_the_relays_again`: a reconnect re-derives the relay
//!   list rather than reusing the addresses resolved at startup — the record
//!   is what makes that observable.
//!
//! Records are written from the peers' own (namespaced) threads into a
//! per-scenario temp directory; /tmp is shared with the suite process, so the
//! main thread reads exactly what they wrote — the same arrangement the
//! connlog suite uses.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use spora_core::TunnelEvent;
use spora_core::record::{Outcome, Reason, Record, RecordConfig, Role, StepKind, StepOutcome};
use spora_lab::peers::{self, LabPeerOpts};
use spora_lab::services;
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{ECHO_UDP_PORT, NatKind, WAN_SERVICES_IP};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "record",
        spora_lab::scenarios![
            a_working_session_is_recorded,
            a_relay_that_never_answers_is_recorded_as_such,
            a_direct_upgrade_is_recorded,
            a_redial_resolves_the_relays_again,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// helpers

const SESSION_TIMEOUT: Duration = Duration::from_secs(15);
/// Records are written by a thread of their own, so every assertion polls.
const RECORD_TIMEOUT: Duration = Duration::from_secs(15);
/// Fast enough that a short scenario still collects a few samples.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

fn svc(port: u16) -> std::net::SocketAddrV4 {
    std::net::SocketAddrV4::new(
        WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses"),
        port,
    )
}

/// A fresh record directory per peer per scenario. A leftover directory from
/// a previous run would make "the newest record" ambiguous.
fn fresh_dir(scenario: &str, who: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("spora-lab-record-{scenario}-{who}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("remove {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn record_config(dir: &Path) -> RecordConfig {
    let mut cfg = RecordConfig::in_dir(dir);
    cfg.sample_interval = SAMPLE_INTERVAL;
    cfg
}

/// Poll `dir` until one record satisfies `want`, or the deadline passes.
fn wait_for_record(
    dir: &Path,
    what: &str,
    want: impl Fn(&Record) -> bool,
) -> Result<Record, String> {
    let deadline = Instant::now() + RECORD_TIMEOUT;
    let mut last: Option<Record> = None;
    loop {
        let records = Record::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
        for (_, rec) in records {
            if want(&rec) {
                return Ok(rec);
            }
            last = Some(rec);
        }
        if Instant::now() >= deadline {
            return Err(match last {
                Some(rec) => format!(
                    "no record in {} {what}; newest has steps [{}] and outcome {}",
                    dir.display(),
                    summarize(&rec),
                    rec.outcome()
                ),
                None => format!("no records at all in {} ({what})", dir.display()),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn summarize(rec: &Record) -> String {
    rec.steps
        .iter()
        .map(|s| format!("{}:{}", s.kind, s.outcome))
        .collect::<Vec<_>>()
        .join(" ")
}

fn has(rec: &Record, kind: StepKind, outcome: StepOutcome) -> bool {
    rec.steps
        .iter()
        .any(|s| s.kind == kind && s.outcome == outcome)
}

fn require(rec: &Record, kind: StepKind, outcome: StepOutcome) -> Result<(), String> {
    if has(rec, kind, outcome) {
        return Ok(());
    }
    Err(format!(
        "expected a {kind} step that came out {outcome}; got [{}]",
        summarize(rec)
    ))
}

// ---------------------------------------------------------------------------
// 1. a working session

fn a_working_session_is_recorded() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;

    let client_dir = fresh_dir("working", "client")?;
    let exit_dir = fresh_dir("working", "exit")?;

    let mut share_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    share_opts.enable_direct_upgrade = false; // this scenario is about the relay path
    share_opts.record = Some(record_config(&exit_dir));
    let mut client_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    client_opts.enable_direct_upgrade = false;
    client_opts.record = Some(record_config(&client_dir));

    let mut sharer = peers::start_sharer(&topo.sharer, &share_opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &client_opts)?;
    client.wait_event(
        |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
        SESSION_TIMEOUT,
    )?;
    sharer.wait_event(
        |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
        SESSION_TIMEOUT,
    )?;

    // Carry real traffic, and long enough for the sampler to fire at least
    // once: a record with no quality samples cannot answer "how well".
    let echo = client.udp_echo(svc(ECHO_UDP_PORT), 20, 200, Duration::from_secs(30))?;
    if echo.received != 20 {
        return Err(format!("udp echo lost packets: {echo:?}"));
    }
    std::thread::sleep(SAMPLE_INTERVAL * 3);

    let client_rec = wait_for_record(&client_dir, "for a client session", |r| {
        has(r, StepKind::SessionUp, StepOutcome::Ok)
    })?;
    if client_rec.open.role != Role::Client {
        return Err(format!("client wrote a {} record", client_rec.open.role));
    }
    require(&client_rec, StepKind::TokenParse, StepOutcome::Ok)?;
    require(&client_rec, StepKind::RelayResolve, StepOutcome::Ok)?;
    require(&client_rec, StepKind::RelayDial, StepOutcome::Ok)?;
    require(&client_rec, StepKind::Handshake, StepOutcome::Ok)?;
    require(&client_rec, StepKind::SessionUp, StepOutcome::Ok)?;
    // The upgrade was off, and that is recorded as a decision, not a failure.
    let skipped = client_rec.steps.iter().any(|s| {
        s.kind == StepKind::PathSwap
            && s.outcome == StepOutcome::Skipped
            && s.reason == Some(Reason::UpgradeDisabled)
    });
    if !skipped {
        return Err(format!(
            "expected the disabled upgrade to be recorded as skipped; got [{}]",
            summarize(&client_rec)
        ));
    }
    // The steps must read as a timeline.
    let mut previous = 0;
    for step in &client_rec.steps {
        if step.at_ms < previous {
            return Err(format!(
                "steps out of order: {} at {}ms follows {}ms",
                step.kind, step.at_ms, previous
            ));
        }
        previous = step.at_ms;
    }
    if client_rec.samples.is_empty() {
        return Err("no quality samples in the client record".into());
    }
    let carried = client_rec
        .samples
        .iter()
        .any(|s| s.tx_bytes > 0 && s.rx_bytes > 0);
    if !carried {
        return Err(format!(
            "samples show no traffic in either direction: {:?}",
            client_rec.samples.last()
        ));
    }

    let exit_rec = wait_for_record(&exit_dir, "for an exit session", |r| {
        has(r, StepKind::SessionUp, StepOutcome::Ok)
    })?;
    if exit_rec.open.role != Role::Exit {
        return Err(format!("sharer wrote a {} record", exit_rec.open.role));
    }
    require(&exit_rec, StepKind::ListenerBind, StepOutcome::Ok)?;
    require(&exit_rec, StepKind::Register, StepOutcome::Ok)?;
    require(&exit_rec, StepKind::Accept, StepOutcome::Ok)?;
    require(&exit_rec, StepKind::SessionUp, StepOutcome::Ok)?;
    require(&exit_rec, StepKind::ExitStart, StepOutcome::Ok)?;
    // Both ends name the same identity, which is what pairs their records.
    if exit_rec.open.routing_key != client_rec.open.routing_key {
        return Err(format!(
            "the two ends disagree about the identity: exit {:?}, client {:?}",
            exit_rec.open.routing_key, client_rec.open.routing_key
        ));
    }

    client.stop();
    sharer.stop();

    // Stopping closes the client's record, and the summary must agree with
    // the steps that produced it.
    let closed = wait_for_record(&client_dir, "closed after the client stopped", |r| {
        r.close.is_some()
    })?;
    let close = closed.close.as_ref().expect("closed");
    if close.sessions < 1 {
        return Err(format!(
            "closing summary counts {} sessions",
            close.sessions
        ));
    }
    if close.first_connect_ms.is_none() {
        return Err("closing summary has no time-to-first-connect".into());
    }
    if closed.truncated {
        return Err("a cleanly stopped client left a truncated record".into());
    }
    log::info!(
        "record: client {} steps / {} samples, exit {} steps; connected after {:?}ms",
        closed.steps.len(),
        closed.samples.len(),
        exit_rec.steps.len(),
        close.first_connect_ms
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. a relay that never answers

fn a_relay_that_never_answers_is_recorded_as_such() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;

    // A sharer only so we have a well-formed URL to dial; the client is then
    // pointed at a port nothing is listening on, which is what a censored or
    // dead relay looks like from the inside: silence.
    let sharer = peers::start_sharer(
        &topo.sharer,
        &LabPeerOpts::new(wan.relay_addr(), wan.stun_server()),
    )?;
    let url = sharer.url().clone();

    let client_dir = fresh_dir("blackhole", "client")?;
    let mut black_hole = wan.relay_addr();
    black_hole.set_port(black_hole.port().wrapping_add(1));
    let mut opts = LabPeerOpts::new(black_hole, wan.stun_server());
    // Keep the scenario short: one dial attempt, timed out fast.
    opts.timings.relay_dial_timeout = Duration::from_secs(3);
    opts.record = Some(record_config(&client_dir));

    // The URL carries the sharer's real relay, so override the client's view
    // of where to dial by rebuilding the URL against the black hole.
    let token = spora_core::identity::Token::from_url(&url)?;
    let mut dead_token = token.clone();
    dead_token.relays = vec![spora_core::identity::RelayEndpoint::new(
        black_hole.ip().to_string(),
        black_hole.port(),
    )];
    let dead_url = dead_token.to_url();

    match peers::start_client(&topo.client, dead_url, &opts) {
        Ok(client) => {
            client.stop();
            sharer.stop();
            return Err("connect() succeeded against a black hole".into());
        }
        Err(e) => log::info!("record: connect failed as expected: {e}"),
    }

    let rec = wait_for_record(&client_dir, "for the failed dial", |r| r.close.is_some())?;
    require(&rec, StepKind::RelayDial, StepOutcome::Failed)?;
    let failure = rec
        .first_failure()
        .ok_or_else(|| "no failing step recorded".to_string())?;
    // Which timeout wins is a timing detail; that it is a *timeout*, named
    // from the closed vocabulary, is the point.
    let expected = [
        Reason::ConnectTimeout,
        Reason::HandshakeTimeout,
        Reason::NoResponse,
    ];
    if !failure.reason.is_some_and(|r| expected.contains(&r)) {
        return Err(format!(
            "expected a timeout-shaped reason, got {:?} ({})",
            failure.reason,
            summarize(&rec)
        ));
    }
    let close = rec.close.as_ref().expect("closed");
    if close.outcome != Outcome::NeverConnected {
        return Err(format!("expected never_connected, got {}", close.outcome));
    }
    // Silence must not be mistakable for success.
    if has(&rec, StepKind::SessionUp, StepOutcome::Ok) {
        return Err("a black-holed dial recorded a session coming up".into());
    }
    sharer.stop();
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. the direct upgrade

fn a_direct_upgrade_is_recorded() -> Result<(), String> {
    // Full-cone both sides: the punch this scenario is about has to succeed
    // for the record of it to be checkable (the NAT matrix is where punching
    // itself is exercised).
    let topo = Topology::build(&TopologySpec::new(NatKind::FullCone, NatKind::FullCone))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;

    let client_dir = fresh_dir("upgrade", "client")?;
    let mut share_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    share_opts.enable_direct_upgrade = true;
    let mut client_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    client_opts.enable_direct_upgrade = true;
    client_opts.record = Some(record_config(&client_dir));

    let sharer = peers::start_sharer(&topo.sharer, &share_opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &client_opts)?;
    client.wait_event(
        |e| matches!(e, TunnelEvent::DirectUpgradeSucceeded { .. }),
        Duration::from_secs(30),
    )?;

    let rec = wait_for_record(&client_dir, "showing a completed upgrade", |r| {
        has(r, StepKind::PathSwap, StepOutcome::Ok)
    })?;
    require(&rec, StepKind::Stun, StepOutcome::Ok)?;
    require(&rec, StepKind::EndpointExchange, StepOutcome::Ok)?;
    require(&rec, StepKind::Punch, StepOutcome::Ok)?;
    require(&rec, StepKind::DirectHandshake, StepOutcome::Ok)?;
    require(&rec, StepKind::PathSwap, StepOutcome::Ok)?;

    // The punch step names the address that actually answered — the thing a
    // relay-via record can never know.
    let punch = rec
        .steps_of(StepKind::Punch)
        .find(|s| s.outcome == StepOutcome::Ok)
        .ok_or_else(|| "no successful punch step".to_string())?;
    if punch.peer.is_none() {
        return Err("the punch step recorded no peer address".into());
    }

    client.stop();
    sharer.stop();
    let closed = wait_for_record(&client_dir, "closed with a direct path", |r| {
        r.close.as_ref().is_some_and(|c| c.direct_ms.is_some())
    })?;
    log::info!(
        "record: direct path after {:?}ms",
        closed.close.as_ref().and_then(|c| c.direct_ms)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. a redial re-resolves

/// Relay names are re-derived on every (re)dial, not resolved once at
/// startup. It matters for exactly the case this project exists for: a relay
/// that moves, a hostname whose records change, and a censor that starts
/// poisoning one name are all invisible to a client holding addresses it
/// looked up an hour ago. The record is what makes the behaviour observable —
/// a `relay_resolve` step tagged with the redial cycle it belongs to.
fn a_redial_resolves_the_relays_again() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    // Short relay timeouts + short protocol timings so the death of the path
    // is detected and redialled in seconds rather than half a minute.
    let wan = services::start_wan(&topo.wan, || {
        relay::State::with_timeouts(
            Duration::from_secs(6),
            Duration::from_secs(3),
            Duration::from_millis(500),
        )
    })?;
    let timings = spora_core::Timings {
        register_interval: Duration::from_secs(1),
        quic_idle_timeout: Duration::from_secs(3),
        quic_keep_alive: Duration::from_secs(1),
        reconnect_delay: Duration::from_millis(500),
        ..Default::default()
    };

    let client_dir = fresh_dir("redial", "client")?;
    let mut share_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    share_opts.timings = timings.clone();
    share_opts.enable_direct_upgrade = false;
    let mut client_opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    client_opts.timings = timings;
    client_opts.enable_direct_upgrade = false;
    client_opts.record = Some(record_config(&client_dir));

    let sharer = peers::start_sharer(&topo.sharer, &share_opts)?;
    let mut client = peers::start_client(&topo.client, sharer.url().clone(), &client_opts)?;
    // An active client redials a dead path; a dormant one parks instead.
    client.set_keepalive(1);
    client.wait_event(
        |e| matches!(e, TunnelEvent::RelaySessionEstablished { .. }),
        SESSION_TIMEOUT,
    )?;

    // Fresh relay socket and state: the path is dead and the client must
    // start a new dial cycle.
    wan.restart_relay()?;
    client.discard_events();
    client
        .wait_event(
            |e| matches!(e, TunnelEvent::Reconnected),
            Duration::from_secs(30),
        )
        .map_err(|e| format!("client never reconnected after the relay restart: {e}"))?;

    let rec = wait_for_record(&client_dir, "showing a completed redial", |r| {
        r.steps
            .iter()
            .any(|s| s.kind == StepKind::Reconnect && s.cycle.is_some_and(|c| c >= 1))
    })?;
    let resolved_again = rec
        .steps_of(StepKind::RelayResolve)
        .any(|s| s.cycle.is_some_and(|c| c >= 1));
    if !resolved_again {
        return Err(format!(
            "the redial reused the addresses resolved at startup: no relay_resolve step in a \
             redial cycle; got [{}]",
            summarize(&rec)
        ));
    }
    // And the dial that followed belongs to the same cycle, so a reader can
    // tell which resolution fed which attempt.
    let dialled_again = rec
        .steps_of(StepKind::RelayDial)
        .any(|s| s.cycle.is_some_and(|c| c >= 1));
    if !dialled_again {
        return Err("no relay_dial step in a redial cycle".into());
    }

    client.stop();
    sharer.stop();
    Ok(())
}
