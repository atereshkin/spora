//! The exit's DNS forwarder end to end (spora-core `dns`): a client that
//! points its resolver at the synthetic address `100.64.0.53` has its
//! queries answered by the sharer's OWN upstreams — over UDP and over TCP,
//! byte for byte — with failover from an upstream that refuses (ICMP port
//! unreachable) inside the very query that hit it, and from one that stays
//! silent after it has struck out; and it gets nothing at all when the
//! forwarder is off, because the synthetic address is then just another
//! private destination the exit drops.
//!
//! The upstreams are wan-side: the stub resolver at
//! `WAN_SERVICES_IP:53` ([`spora_lab::services::dns_stub_answer`] is the
//! exact reply to expect), a port nobody listens on (the wan kernel refuses
//! it), and a port an iptables DROP swallows. The sharer reaches them
//! through its NAT like any egress, so a refusal has to travel back through
//! conntrack as a related ICMP error for the failover to be immediate.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use spora_core::dns::{self, DnsForwarder, DnsUpstream};
use spora_lab::peers::{self, DnsExit, LabPeerOpts};
use spora_lab::services::{self, DNS_PORT, dns_stub_answer};
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{NatKind, WAN_SERVICES_IP};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "dns",
        spora_lab::scenarios![
            udp_query_answered_by_the_sharers_upstream,
            tcp_query_answered_by_the_sharers_upstream,
            refused_upstream_fails_over_within_the_query,
            silent_upstream_strikes_out,
            forwarder_off_drops_the_query,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

/// A wan port with no listener: the wan kernel answers ICMP port
/// unreachable, which the exit's connected socket sees as a refusal.
const REFUSED_PORT: u16 = 5399;
/// A wan port behind an iptables DROP: queries vanish without a trace.
const SILENT_PORT: u16 = 5398;
/// How long a client waits for an answer that must come.
const GRACE: Duration = Duration::from_secs(3);

fn svc(port: u16) -> SocketAddr {
    SocketAddr::from((
        WAN_SERVICES_IP
            .parse::<Ipv4Addr>()
            .expect("WAN_SERVICES_IP parses"),
        port,
    ))
}

/// A recursion-desired A query for `example.com` with transaction `id`.
fn query(id: u16) -> Vec<u8> {
    let mut q = vec![0u8; 12];
    q[..2].copy_from_slice(&id.to_be_bytes());
    q[2] = 0x01; // RD
    q[5] = 1; // QDCOUNT
    q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    q
}

/// A forwarder with exactly these upstreams and no public fallback (the
/// lab has no internet; a fallback would only add a timeout).
fn forwarder(upstreams: &[SocketAddr]) -> Arc<DnsForwarder> {
    DnsForwarder::with_fallback(DnsUpstream::Servers(upstreams.to_vec()), Vec::new())
}

struct Rig {
    _topo: Topology,
    _wan: services::WanHandle,
    _sharer: peers::SharerHandle,
    client: peers::ClientHandle,
}

/// Sharer and client behind port-restricted NATs, pinned to the relay path
/// (the forwarder is path-independent; the upgrade would only add
/// nondeterminism), with the given forwarder setting on the sharer.
fn rig(dns: DnsExit, silent_port: bool) -> Result<Rig, String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let wan = services::start_wan(&topo.wan, relay::State::default)?;
    if silent_port {
        topo.wan.run(&format!(
            "iptables -A INPUT -p udp --dport {SILENT_PORT} -j DROP"
        ))?;
    }
    let mut opts = LabPeerOpts::new(wan.relay_addr(), wan.stun_server());
    opts.enable_direct_upgrade = false;
    opts.dns = dns;
    let sharer = peers::start_sharer(&topo.sharer, &opts)?;
    let client = peers::start_client(&topo.client, sharer.url().clone(), &opts)?;
    Ok(Rig {
        _topo: topo,
        _wan: wan,
        _sharer: sharer,
        client,
    })
}

/// The reply must be exactly what the stub resolver answers: the forwarder
/// changes nothing on the way back.
fn expect_stub_answer(reply: Option<Vec<u8>>, q: &[u8], what: &str) -> Result<(), String> {
    let reply = reply.ok_or_else(|| format!("{what}: no answer within {GRACE:?}"))?;
    let want = dns_stub_answer(q).expect("the lab query is well-formed");
    if reply != want {
        return Err(format!(
            "{what}: reply is not the stub's answer\n got {reply:02x?}\nwant {want:02x?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. udp_query_answered_by_the_sharers_upstream

fn udp_query_answered_by_the_sharers_upstream() -> Result<(), String> {
    let fwd = forwarder(&[svc(DNS_PORT)]);
    let rig = rig(DnsExit::Forwarder(fwd.clone()), false)?;
    for id in [0x0001u16, 0xBEEF, 0xFFFF] {
        let q = query(id);
        let reply = rig
            .client
            .udp_query(dns::proxy_socket(), q.clone(), GRACE)?;
        expect_stub_answer(reply, &q, &format!("udp query {id:#06x}"))?;
    }
    if fwd.pick(&[]) != Some(svc(DNS_PORT)) {
        return Err("the answering upstream must stay first in line".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. tcp_query_answered_by_the_sharers_upstream

fn tcp_query_answered_by_the_sharers_upstream() -> Result<(), String> {
    let rig = rig(DnsExit::Forwarder(forwarder(&[svc(DNS_PORT)])), false)?;
    let q = query(0x7C90);
    // RFC 7766 framing: a two-byte length prefix on both sides.
    let mut request = (q.len() as u16).to_be_bytes().to_vec();
    request.extend_from_slice(&q);
    let reply = rig
        .client
        .tcp_request(dns::proxy_socket(), request, GRACE)?;
    let want = dns_stub_answer(&q).expect("well-formed");
    let mut framed = (want.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&want);
    if reply != framed {
        return Err(format!(
            "tcp reply is not the stub's framed answer\n got {reply:02x?}\nwant {framed:02x?}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. refused_upstream_fails_over_within_the_query

fn refused_upstream_fails_over_within_the_query() -> Result<(), String> {
    let fwd = forwarder(&[svc(REFUSED_PORT), svc(DNS_PORT)]);
    let rig = rig(DnsExit::Forwarder(fwd.clone()), false)?;
    let q = query(0x0BAD);
    let started = Instant::now();
    let reply = rig
        .client
        .udp_query(dns::proxy_socket(), q.clone(), GRACE)?;
    let elapsed = started.elapsed();
    expect_stub_answer(reply, &q, "query while the first upstream refuses")?;
    // The refusal is an ICMP error, not a timeout: the retry on the second
    // upstream happens inside the same query, well under the 2s attempt
    // timeout the forwarder would otherwise have waited out.
    if elapsed > Duration::from_millis(1500) {
        return Err(format!(
            "answer took {elapsed:?}: the refused upstream cost an attempt timeout instead of failing over at once"
        ));
    }
    if fwd.pick(&[]) != Some(svc(DNS_PORT)) {
        return Err("the refused upstream must be quarantined".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. silent_upstream_strikes_out

fn silent_upstream_strikes_out() -> Result<(), String> {
    let fwd = forwarder(&[svc(SILENT_PORT), svc(DNS_PORT)]);
    let attempt = Duration::from_millis(300);
    fwd.set_attempt_timeout(attempt);
    let rig = rig(DnsExit::Forwarder(fwd.clone()), true)?;
    // Three strikes: each of these is answered by the second upstream after
    // the first one's attempt timeout.
    for id in 1..=3u16 {
        let q = query(id);
        let started = Instant::now();
        let reply = rig
            .client
            .udp_query(dns::proxy_socket(), q.clone(), GRACE)?;
        let elapsed = started.elapsed();
        expect_stub_answer(
            reply,
            &q,
            &format!("query {id} (silent upstream still live)"),
        )?;
        if elapsed < attempt {
            return Err(format!(
                "query {id} answered in {elapsed:?}, before the {attempt:?} attempt timeout — was the silent upstream even tried?"
            ));
        }
    }
    if fwd.pick(&[]) != Some(svc(DNS_PORT)) {
        return Err(
            "after three unanswered attempts the silent upstream must be quarantined".into(),
        );
    }
    // Out: the next query goes straight to the live one.
    let q = query(4);
    let started = Instant::now();
    let reply = rig
        .client
        .udp_query(dns::proxy_socket(), q.clone(), GRACE)?;
    let elapsed = started.elapsed();
    expect_stub_answer(reply, &q, "query 4 (silent upstream quarantined)")?;
    if elapsed >= attempt {
        return Err(format!(
            "query 4 took {elapsed:?}: the quarantined upstream was tried again"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. forwarder_off_drops_the_query

fn forwarder_off_drops_the_query() -> Result<(), String> {
    let rig = rig(DnsExit::Off, false)?;
    let q = query(0x0FF0);
    if let Some(reply) = rig
        .client
        .udp_query(dns::proxy_socket(), q, Duration::from_secs(1))?
    {
        return Err(format!(
            "the synthetic address answered with the forwarder off: {reply:02x?}"
        ));
    }
    // The tunnel itself is fine: the same client reaches the stub directly.
    let q = query(0x0FF1);
    let reply = rig.client.udp_query(svc(DNS_PORT), q.clone(), GRACE)?;
    expect_stub_answer(reply, &q, "direct query to the wan stub")?;
    Ok(())
}
