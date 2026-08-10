//! Passive flow meter for `ExitMode::Custom`.
//!
//! The netstack exit logs flows at its own re-origination points; a custom
//! exit (e.g. the CLI's `--os-routing` TUN pump) only moves opaque IP
//! packets. This wrapper sits between the composed session transport and the
//! `SessionHandler` and derives NetFlow-style flow records from the packet
//! stream itself: 5-tuples at fixed header offsets, TCP flags for
//! established/end-reason, idle timeouts to delimit UDP "connections".
//!
//! What it sees is traffic *offered to* the tunnel, not confirmed egress —
//! records are written with `confirmed = false` (the handler may still drop
//! or locally answer a packet). The egress source port the kernel's NAT
//! picked is not visible here either; `ConnLogConfig::egress_lookup` exists
//! so a privileged handler can resolve it out-of-band (conntrack).
//!
//! Hot-path cost is one fixed-offset parse plus one LRU-map operation per
//! packet — the same order of work the os_route pump's `classify()` already
//! does per packet.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{Sink, Stream};
use lru::LruCache;

use crate::connlog::{FlowGuard, SessionLog};
use crate::server::is_local_address;
use crate::transport::IpTransport;

/// Per-protocol flow-table caps. Bounds memory under tuple-spray; eviction
/// closes the victim's record (reason `evicted`), so a flood costs precision,
/// not correctness.
const TCP_FLOW_CAP: usize = 2048;
const OTHER_FLOW_CAP: usize = 2048;
/// In-flight fragment trains we can attribute (first-fragment carries the
/// ports; later fragments are matched by IP id). Tiny on purpose: legitimate
/// fragment trains are rare and short-lived.
const FRAG_CAP: usize = 256;
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    /// Inner client source (canonical client→world direction).
    src: SocketAddr,
    dst: SocketAddr,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
}

enum FlowState {
    Open {
        fin_up: bool,
        fin_down: bool,
    },
    /// Closed by FIN/RST or policy-blocked: the entry lingers (until idle
    /// sweep) so retransmits and local echo replies don't reopen a record.
    Done,
}

struct MeterFlow {
    guard: Option<FlowGuard>,
    state: FlowState,
    established: bool,
    last_seen: Instant,
}

impl MeterFlow {
    fn close(&mut self, reason: &'static str, idle_for: Duration) {
        if let Some(g) = self.guard.take() {
            g.close(reason, idle_for);
        }
        self.state = FlowState::Done;
    }
}

enum Direction {
    /// Client → world (the transport's Stream side on the share).
    Up,
    /// World → client (the transport's Sink side on the share).
    Down,
}

enum FragPos {
    None,
    First(u32),
    Later(u32),
}

struct Parsed {
    proto: u8,
    src: SocketAddr,
    dst: SocketAddr,
    tcp_flags: u8,
    frag: FragPos,
}

pub struct MeteredTransport {
    inner: IpTransport,
    slog: Arc<SessionLog>,
    keepalive_pair: (Ipv4Addr, Ipv4Addr),
    tcp_flows: LruCache<FlowKey, MeterFlow>,
    other_flows: LruCache<FlowKey, MeterFlow>,
    frags: LruCache<FragKey, FlowKey>,
    udp_idle: Duration,
    tcp_idle: Duration,
    next_sweep: Instant,
}

impl MeteredTransport {
    pub(crate) fn new(
        inner: IpTransport,
        slog: Arc<SessionLog>,
        keepalive_pair: (Ipv4Addr, Ipv4Addr),
    ) -> Self {
        let udp_idle = slog.udp_idle;
        let tcp_idle = slog.tcp_idle;
        Self {
            inner,
            slog,
            keepalive_pair,
            tcp_flows: LruCache::new(NonZeroUsize::new(TCP_FLOW_CAP).unwrap()),
            other_flows: LruCache::new(NonZeroUsize::new(OTHER_FLOW_CAP).unwrap()),
            frags: LruCache::new(NonZeroUsize::new(FRAG_CAP).unwrap()),
            udp_idle,
            tcp_idle,
            next_sweep: Instant::now() + SWEEP_INTERVAL,
        }
    }

    fn observe(&mut self, dir: Direction, pkt: &[u8]) {
        let Some(p) = parse(pkt) else { return };

        // The synthetic keepalive ping pair rides the tunnel both ways
        // (requests, replies, and locally crafted answers) — never a flow.
        if (p.proto == PROTO_ICMP || p.proto == PROTO_ICMPV6)
            && is_keepalive_pair(&p, self.keepalive_pair)
        {
            return;
        }

        let bytes = pkt.len() as u64;

        // Non-first fragments carry no ports; attribute by the IP id the
        // first fragment registered.
        if let FragPos::Later(id) = p.frag {
            let fkey = FragKey {
                src: p.src.ip(),
                dst: p.dst.ip(),
                id,
            };
            if let Some(key) = self.frags.get(&fkey).copied()
                && let Some(flow) =
                    table_for(&mut self.tcp_flows, &mut self.other_flows, key.proto).get_mut(&key)
                && let Some(g) = &flow.guard
            {
                match dir {
                    Direction::Up => g.add_up(bytes),
                    Direction::Down => g.add_down(bytes),
                }
                flow.last_seen = Instant::now();
            }
            return;
        }

        // Canonical key is client→world; a down-direction packet belongs to
        // the flow keyed by its reversed addresses.
        let key = match dir {
            Direction::Up => FlowKey {
                proto: p.proto,
                src: p.src,
                dst: p.dst,
            },
            Direction::Down => FlowKey {
                proto: p.proto,
                src: p.dst,
                dst: p.src,
            },
        };

        if let FragPos::First(id) = p.frag {
            self.frags.put(
                FragKey {
                    src: p.src.ip(),
                    dst: p.dst.ip(),
                    id,
                },
                key,
            );
        }

        let table = table_for(&mut self.tcp_flows, &mut self.other_flows, key.proto);

        if let Some(flow) = table.get_mut(&key) {
            flow.last_seen = Instant::now();
            if matches!(flow.state, FlowState::Done) {
                return;
            }
            if let Some(g) = &flow.guard {
                match dir {
                    Direction::Up => g.add_up(bytes),
                    Direction::Down => g.add_down(bytes),
                }
                // First world→client packet ≈ the destination answered.
                if !flow.established && matches!(dir, Direction::Down) {
                    flow.established = true;
                    g.established(None);
                }
            }
            if key.proto == PROTO_TCP {
                if p.tcp_flags & TCP_RST != 0 {
                    flow.close("rst", Duration::ZERO);
                } else if p.tcp_flags & TCP_FIN != 0
                    && let FlowState::Open { fin_up, fin_down } = &mut flow.state
                {
                    match dir {
                        Direction::Up => *fin_up = true,
                        Direction::Down => *fin_down = true,
                    }
                    if *fin_up && *fin_down {
                        flow.close("fin", Duration::ZERO);
                    }
                }
            }
            return;
        }

        // Only client-originated packets open flows; an unmatched
        // world→client packet has nothing to be attributed to.
        if matches!(dir, Direction::Down) {
            return;
        }

        let blocked = is_local_address(key.dst.ip());
        let guard = if blocked {
            self.slog.flow_blocked(key.proto, key.src, key.dst);
            None
        } else {
            // None when throttled or flow logging is off — the flow is still
            // tracked so the table state machine works, just unrecorded.
            self.slog.flow_open(key.proto, key.src, key.dst, false)
        };
        if let Some(g) = &guard {
            g.add_up(bytes);
        }
        let flow = MeterFlow {
            guard,
            state: if blocked {
                FlowState::Done
            } else {
                FlowState::Open {
                    fin_up: false,
                    fin_down: false,
                }
            },
            established: false,
            last_seen: Instant::now(),
        };
        let table = table_for(&mut self.tcp_flows, &mut self.other_flows, key.proto);
        // Invariant: `key` is absent here (the get_mut above returned None),
        // so anything push() hands back is a genuine LRU eviction — never
        // this key's own previous value (which push() would also return).
        if let Some((_, mut evicted)) = table.push(key, flow) {
            let idle = evicted.last_seen.elapsed();
            evicted.close("evicted", idle);
        }
    }

    fn maybe_sweep(&mut self) {
        let now = Instant::now();
        if now < self.next_sweep {
            return;
        }
        self.next_sweep = now + SWEEP_INTERVAL;
        sweep(&mut self.tcp_flows, self.tcp_idle);
        sweep(&mut self.other_flows, self.udp_idle);
    }
}

/// LRU order is last-activity order (both directions promote), so expiring
/// from the cold end visits exactly the idle entries.
fn sweep(table: &mut LruCache<FlowKey, MeterFlow>, idle: Duration) {
    while let Some((_, flow)) = table.peek_lru() {
        let idle_for = flow.last_seen.elapsed();
        if idle_for <= idle {
            break;
        }
        if let Some((_, mut flow)) = table.pop_lru() {
            flow.close("idle", idle_for);
        }
    }
}

fn table_for<'t>(
    tcp: &'t mut LruCache<FlowKey, MeterFlow>,
    other: &'t mut LruCache<FlowKey, MeterFlow>,
    proto: u8,
) -> &'t mut LruCache<FlowKey, MeterFlow> {
    if proto == PROTO_TCP { tcp } else { other }
}

fn is_keepalive_pair(p: &Parsed, pair: (Ipv4Addr, Ipv4Addr)) -> bool {
    let ips = [p.src.ip(), p.dst.ip()];
    let a = IpAddr::V4(pair.0);
    let b = IpAddr::V4(pair.1);
    ips.iter().all(|ip| *ip == a || *ip == b)
}

/// Fixed-offset IPv4/IPv6 + TCP/UDP/ICMP header parse. Returns `None` for
/// anything it can't attribute (truncated, unknown protocol, ESP, ...) —
/// unparseable packets are simply not metered.
fn parse(pkt: &[u8]) -> Option<Parsed> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => parse_v4(pkt),
        6 => parse_v6(pkt),
        _ => None,
    }
}

fn parse_v4(pkt: &[u8]) -> Option<Parsed> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let proto = pkt[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let more_fragments = flags_frag & 0x2000 != 0;
    let frag_offset = flags_frag & 0x1fff;
    let id = u16::from_be_bytes([pkt[4], pkt[5]]) as u32;

    if frag_offset != 0 {
        return Some(Parsed {
            proto,
            src: SocketAddr::new(src_ip, 0),
            dst: SocketAddr::new(dst_ip, 0),
            tcp_flags: 0,
            frag: FragPos::Later(id),
        });
    }
    let frag = if more_fragments {
        FragPos::First(id)
    } else {
        FragPos::None
    };
    l4(pkt, ihl, proto, src_ip, dst_ip, frag)
}

fn parse_v6(pkt: &[u8]) -> Option<Parsed> {
    if pkt.len() < 40 {
        return None;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    let src_ip = IpAddr::V6(src.into());
    let dst_ip = IpAddr::V6(dst.into());

    let mut next = pkt[6];
    let mut off = 40usize;
    let mut frag = FragPos::None;
    // Walk the extension chain (bounded — a hostile chain can't loop us).
    for _ in 0..8 {
        match next {
            PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => {
                return l4(pkt, off, next, src_ip, dst_ip, frag);
            }
            // Hop-by-hop, routing, destination options.
            0 | 43 | 60 => {
                if pkt.len() < off + 8 {
                    return None;
                }
                let len = (pkt[off + 1] as usize + 1) * 8;
                next = pkt[off];
                off += len;
            }
            // Fragment header (RFC 8200): fixed 8 bytes.
            44 => {
                if pkt.len() < off + 8 {
                    return None;
                }
                let frag_off = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) >> 3;
                let id =
                    u32::from_be_bytes([pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7]]);
                if frag_off != 0 {
                    return Some(Parsed {
                        proto: pkt[off],
                        src: SocketAddr::new(src_ip, 0),
                        dst: SocketAddr::new(dst_ip, 0),
                        tcp_flags: 0,
                        frag: FragPos::Later(id),
                    });
                }
                frag = FragPos::First(id);
                next = pkt[off];
                off += 8;
            }
            _ => return None,
        }
    }
    None
}

fn l4(
    pkt: &[u8],
    off: usize,
    proto: u8,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    frag: FragPos,
) -> Option<Parsed> {
    match proto {
        PROTO_TCP => {
            if pkt.len() < off + 14 {
                return None;
            }
            Some(Parsed {
                proto,
                src: SocketAddr::new(src_ip, u16::from_be_bytes([pkt[off], pkt[off + 1]])),
                dst: SocketAddr::new(dst_ip, u16::from_be_bytes([pkt[off + 2], pkt[off + 3]])),
                tcp_flags: pkt[off + 13],
                frag,
            })
        }
        PROTO_UDP => {
            if pkt.len() < off + 8 {
                return None;
            }
            Some(Parsed {
                proto,
                src: SocketAddr::new(src_ip, u16::from_be_bytes([pkt[off], pkt[off + 1]])),
                dst: SocketAddr::new(dst_ip, u16::from_be_bytes([pkt[off + 2], pkt[off + 3]])),
                tcp_flags: 0,
                frag,
            })
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            if pkt.len() < off + 4 {
                return None;
            }
            Some(Parsed {
                proto,
                src: SocketAddr::new(src_ip, 0),
                dst: SocketAddr::new(dst_ip, 0),
                tcp_flags: 0,
                frag,
            })
        }
        _ => None,
    }
}

impl Stream for MeteredTransport {
    type Item = std::io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.maybe_sweep();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(pkt))) => {
                this.observe(Direction::Up, &pkt);
                Poll::Ready(Some(Ok(pkt)))
            }
            other => other,
        }
    }
}

impl Sink<Vec<u8>> for MeteredTransport {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.observe(Direction::Down, &item);
        Pin::new(&mut this.inner).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

// Dropping the meter drops every remaining FlowGuard, which records each
// open flow as closed by "session_end" with the counts so far — teardown
// flush is structural, not a coordination step.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connlog::{ConnLog, ConnLogConfig, FlowQuery, open_readonly, query_flows};
    use crate::identity::Identity;
    use crate::transport::mock::mock_transport;
    use futures_util::{SinkExt, StreamExt};
    use std::path::Path;

    fn tcp_pkt(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        flags: (bool, bool, bool), // (syn, fin, rst)
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = etherparse::TcpHeader::new(sport, dport, 0, 64);
        tcp.syn = flags.0;
        tcp.fin = flags.1;
        tcp.rst = flags.2;
        tcp.ack = !flags.0;
        let builder = etherparse::PacketBuilder::ipv4(src, dst, 64).tcp_header(tcp);
        let mut pkt = Vec::new();
        builder.write(&mut pkt, payload).unwrap();
        pkt
    }

    fn udp_pkt(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4(src, dst, 64)
            .udp(sport, dport)
            .write(&mut pkt, payload)
            .unwrap();
        pkt
    }

    fn icmp_echo(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4(src, dst, 64)
            .icmpv4_echo_request(7, 1)
            .write(&mut pkt, b"ping")
            .unwrap();
        pkt
    }

    struct Rig {
        meter: MeteredTransport,
        handle: crate::transport::mock::MockTransportHandle,
        _log: ConnLog,
        session: Arc<SessionLog>,
    }

    fn rig(dir: &Path) -> Rig {
        let mut cfg = ConnLogConfig::in_dir(dir);
        cfg.flush_interval = Duration::from_millis(20);
        let identity = Identity::generate();
        let log = ConnLog::open(cfg, &identity, None).unwrap();
        let session = log.session("203.0.113.1:443".parse().unwrap());
        let (mock, handle) = mock_transport();
        let meter = MeteredTransport::new(
            Box::new(mock),
            session.clone(),
            (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)),
        );
        Rig {
            meter,
            handle,
            _log: log,
            session,
        }
    }

    fn wait_flows(dir: &Path, q: &FlowQuery, want: usize) -> Vec<crate::connlog::FlowRow> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(db) = open_readonly(dir)
                && let Ok(rows) = query_flows(&db, q)
                && rows.len() == want
            {
                return rows;
            }
            assert!(Instant::now() < deadline, "expected {} flow rows", want);
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[tokio::test]
    async fn tcp_flow_metered_through_full_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rig(dir.path());
        let client = [10, 0, 85, 2];
        let server = [93, 184, 216, 34];

        // SYN up.
        r.handle
            .send(tcp_pkt(
                client,
                50000,
                server,
                443,
                (true, false, false),
                b"",
            ))
            .unwrap();
        let syn = r.meter.next().await.unwrap().unwrap();
        let syn_len = syn.len() as u64;
        // SYN-ACK down (establishes).
        r.meter
            .send(tcp_pkt(
                server,
                443,
                client,
                50000,
                (true, false, false),
                b"",
            ))
            .await
            .unwrap();
        // Data up, then FIN both ways.
        r.handle
            .send(tcp_pkt(
                client,
                50000,
                server,
                443,
                (false, false, false),
                b"hello",
            ))
            .unwrap();
        r.meter.next().await.unwrap().unwrap();
        r.handle
            .send(tcp_pkt(
                client,
                50000,
                server,
                443,
                (false, true, false),
                b"",
            ))
            .unwrap();
        r.meter.next().await.unwrap().unwrap();
        r.meter
            .send(tcp_pkt(
                server,
                443,
                client,
                50000,
                (false, true, false),
                b"",
            ))
            .await
            .unwrap();

        let rows = wait_flows(
            dir.path(),
            &FlowQuery {
                ip: Some("93.184.216.34".parse().unwrap()),
                ..Default::default()
            },
            1,
        );
        // The close lands asynchronously; poll until end_reason appears.
        let deadline = Instant::now() + Duration::from_secs(5);
        let row = loop {
            let rows = wait_flows(
                dir.path(),
                &FlowQuery {
                    ip: Some("93.184.216.34".parse().unwrap()),
                    ..Default::default()
                },
                1,
            );
            if rows[0].end_reason.is_some() {
                break rows.into_iter().next().unwrap();
            }
            assert!(Instant::now() < deadline, "flow never closed");
            std::thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(row.dst_port, 443);
        assert_eq!(row.end_reason.as_deref(), Some("fin"));
        assert!(row.established);
        assert!(
            !row.confirmed,
            "meter flows are offered-traffic, not confirmed egress"
        );
        assert!(row.bytes_up > syn_len, "SYN + data + FIN counted");
        assert!(row.bytes_down > 0);
        drop(rows);
    }

    #[tokio::test]
    async fn udp_flow_and_keepalive_filtering() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rig(dir.path());

        // Keepalive ping + reply between the synthetic pair: never logged.
        r.handle
            .send(icmp_echo([10, 0, 0, 1], [10, 0, 0, 2]))
            .unwrap();
        r.meter.next().await.unwrap().unwrap();
        r.meter
            .send(icmp_echo([10, 0, 0, 2], [10, 0, 0, 1]))
            .await
            .unwrap();

        // Real UDP flow.
        r.handle
            .send(udp_pkt([10, 0, 85, 2], 40000, [8, 8, 8, 8], 53, b"query"))
            .unwrap();
        r.meter.next().await.unwrap().unwrap();
        r.meter
            .send(udp_pkt(
                [8, 8, 8, 8],
                53,
                [10, 0, 85, 2],
                40000,
                b"answer-bytes",
            ))
            .await
            .unwrap();

        // Blocked destination (RFC1918): recorded as blocked, not as egress.
        r.handle
            .send(udp_pkt([10, 0, 85, 2], 40001, [192, 168, 1, 1], 53, b"x"))
            .unwrap();
        r.meter.next().await.unwrap().unwrap();

        // Session teardown closes the open UDP flow via guard Drop.
        let session = r.session.clone();
        drop(r.meter);
        session.end("ended");
        drop(session);
        drop(r._log);

        let rows = wait_flows(
            dir.path(),
            &FlowQuery {
                ip: Some("8.8.8.8".parse().unwrap()),
                ..Default::default()
            },
            1,
        );
        assert_eq!(rows[0].end_reason.as_deref(), Some("session_end"));
        assert!(rows[0].established, "a reply marks the flow established");
        assert!(rows[0].bytes_up > 0 && rows[0].bytes_down > 0);

        let blocked = wait_flows(
            dir.path(),
            &FlowQuery {
                ip: Some("192.168.1.1".parse().unwrap()),
                ..Default::default()
            },
            1,
        );
        assert_eq!(blocked[0].end_reason.as_deref(), Some("blocked"));

        // No ICMP keepalive flow rows at all.
        let db = open_readonly(dir.path()).unwrap();
        let all = query_flows(&db, &FlowQuery::default()).unwrap();
        assert_eq!(all.len(), 2, "keepalive traffic must not appear: {:?}", all);
    }

    #[tokio::test]
    async fn rst_closes_flow() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rig(dir.path());
        let client = [10, 0, 85, 2];
        let server = [203, 0, 113, 80];

        r.handle
            .send(tcp_pkt(
                client,
                50000,
                server,
                80,
                (true, false, false),
                b"",
            ))
            .unwrap();
        r.meter.next().await.unwrap().unwrap();
        // RST from the server side.
        r.meter
            .send(tcp_pkt(
                server,
                80,
                client,
                50000,
                (false, false, true),
                b"",
            ))
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let rows = wait_flows(
                dir.path(),
                &FlowQuery {
                    ip: Some("203.0.113.80".parse().unwrap()),
                    ..Default::default()
                },
                1,
            );
            if rows[0].end_reason.as_deref() == Some("rst") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "expected rst close, got {:?}",
                rows[0].end_reason
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[test]
    fn parser_handles_v6_and_fragments() {
        // IPv6 UDP.
        let mut v6 = Vec::new();
        etherparse::PacketBuilder::ipv6([1u8; 16], [2u8; 16], 64)
            .udp(1000, 2000)
            .write(&mut v6, b"x")
            .unwrap();
        let p = parse(&v6).unwrap();
        assert_eq!(p.proto, PROTO_UDP);
        assert_eq!(p.src.port(), 1000);
        assert_eq!(p.dst.port(), 2000);

        // IPv4 non-first fragment: no ports, attributed by id.
        let mut frag = vec![
            0x45, 0x00, 0x00, 0x1c, // v4, ihl 5, len 28
            0xab, 0xcd, 0x00, 0xb9, // id 0xabcd, offset 0xb9 (non-zero)
            0x40, 0x11, 0x00, 0x00, // ttl, UDP, csum
            10, 0, 85, 2, // src
            8, 8, 8, 8, // dst
        ];
        frag.extend_from_slice(&[0u8; 8]);
        let p = parse(&frag).unwrap();
        assert!(matches!(p.frag, FragPos::Later(0xabcd)));

        // Truncated garbage.
        assert!(parse(&[0x45, 0x00]).is_none());
        assert!(parse(&[]).is_none());
    }
}
