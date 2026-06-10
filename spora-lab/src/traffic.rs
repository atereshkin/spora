//! Traffic drivers over the client's composed `IpTransport`.
//!
//! The pump OWNS the transport (single consumer): one task select-loops over
//! { commands, transport.next(), outbound queue } and dispatches inbound
//! packets — UDP to the in-flight echo session (match on inner dst port),
//! TCP into the smoltcp ingress queue, ICMP ignored (keepalive replies; the
//! share-side netstack answers pings locally).
//!
//! Drivers:
//! - **UDP echo**: crafts IPv4+UDP via etherparse from
//!   [`crate::CLIENT_INNER_IP`]:&lt;per-session port starting 40000&gt; to the
//!   server; the share netstack verifies lengths but not checksums
//!   client→share; replies arrive src=server, dst=our addr, TTL 20, valid
//!   checksums. Sends with light pacing (a few ms) — the share-side UDP NAT
//!   entry refreshes on outbound only. Echoes are matched by a 12-byte
//!   payload tag (sequence number + nonce) **prefix**, so responders that
//!   pad their replies (used to provoke share→client fragmentation) still
//!   match. Per-packet RTT min/avg/max and loss are reported in
//!   [`EchoStats`].
//! - **TCP bulk**: a smoltcp `Interface` over a custom in-memory device
//!   (rx = queue fed by the pump, tx = drained straight into the transport
//!   sink after every `iface.poll`). Medium::Ip, device MTU 1100 (stays
//!   under the QUIC datagram floor ≈1162 so client→share packets never need
//!   IP fragmentation, which the share netstack cannot reassemble). Default
//!   `ChecksumCapabilities` (smoltcp computes/verifies — required by the
//!   share-side smoltcp). One socket, 64 KiB buffers, connect → send
//!   `bytes` while reading the echo back until all bytes round-trip →
//!   close. `iface.poll` is driven from the pump loop with
//!   `poll_delay`-based timers.
//!
//! Both drivers tolerate unrelated inbound packets interleaving (keepalive
//! ICMP, stale echo replies, ...): everything inbound flows through an IPv4
//! [`Reassembler`] first — large UDP replies (share→client) arrive as IPv4
//! FRAGMENTS because the tunnel fragments datagrams larger than the QUIC
//! datagram budget and there is no kernel on this side to reassemble them —
//! and is then matched against the in-flight session or dropped.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use smoltcp::time::Instant as SmolInstant;
use spora_core::IpTransport;

use crate::CLIENT_INNER_IP;

/// Default gateway the smoltcp iface routes through — any address on the
/// inner /24 works (Medium::Ip has no neighbor resolution).
const INNER_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// First inner source port; one fresh port per traffic command so stale
/// share-side NAT entries from a previous session can never match.
const BASE_PORT: u16 = 40000;

/// Bytes of (sequence ‖ nonce) tag at the start of every echo payload.
const ECHO_TAG_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct EchoStats {
    pub sent: usize,
    pub received: usize,
    pub rtt_min: std::time::Duration,
    pub rtt_avg: std::time::Duration,
    pub rtt_max: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct BulkStats {
    pub bytes: usize,
    pub elapsed: std::time::Duration,
}

impl BulkStats {
    pub fn throughput_mbps(&self) -> f64 {
        (self.bytes as f64 * 8.0) / self.elapsed.as_secs_f64() / 1_000_000.0
    }
}

/// Commands handled by the pump task (constructed in `peers::start_client`).
pub enum TrafficCmd {
    UdpEcho {
        server: std::net::SocketAddrV4,
        count: usize,
        payload_len: usize,
        respond: tokio::sync::oneshot::Sender<Result<EchoStats, String>>,
    },
    TcpBulk {
        server: std::net::SocketAddrV4,
        bytes: usize,
        respond: tokio::sync::oneshot::Sender<Result<BulkStats, String>>,
    },
}

/// The pump: owns the transport, serves `TrafficCmd`s. Runs inside the
/// client host runtime.
pub struct TrafficPump {
    transport: IpTransport,
    cmds: tokio::sync::mpsc::UnboundedReceiver<TrafficCmd>,
    next_port: u16,
    /// Set when the transport stream ends. The production client composition
    /// (ReconnectTransport) redials forever and never ends, so this only
    /// trips for bare compositions; commands then fail fast instead of
    /// timing out.
    dead: bool,
}

impl TrafficPump {
    pub fn new(
        transport: spora_core::IpTransport,
        cmds: tokio::sync::mpsc::UnboundedReceiver<TrafficCmd>,
    ) -> Self {
        Self {
            transport,
            cmds,
            next_port: BASE_PORT,
            dead: false,
        }
    }

    /// Run until the command channel closes or the transport dies.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.cmds.recv() => {
                    let Some(cmd) = cmd else { return };
                    self.handle_cmd(cmd).await;
                }
                pkt = self.transport.next(), if !self.dead => {
                    match pkt {
                        // Idle inbound (keepalive echo replies, share-side
                        // pings, late echo replies): ignore.
                        Some(Ok(_)) => {}
                        Some(Err(e)) => log::warn!("pump: transport error while idle: {e}"),
                        None => {
                            log::warn!("pump: transport stream ended");
                            self.dead = true;
                        }
                    }
                }
            }
        }
    }

    async fn handle_cmd(&mut self, cmd: TrafficCmd) {
        match cmd {
            TrafficCmd::UdpEcho {
                server,
                count,
                payload_len,
                respond,
            } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.udp_echo(server, count, payload_len).await
                };
                let _ = respond.send(result);
            }
            TrafficCmd::TcpBulk {
                server,
                bytes,
                respond,
            } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.tcp_bulk(server, bytes).await
                };
                let _ = respond.send(result);
            }
        }
    }

    fn alloc_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = self.next_port.wrapping_add(1).max(BASE_PORT);
        port
    }

    /// Send `count` UDP datagrams of `payload_len` bytes (min 12, the tag)
    /// to `server` and collect the echoes. Finishes when every echo is in,
    /// or 3s pass without progress after the last send.
    async fn udp_echo(
        &mut self,
        server: SocketAddrV4,
        count: usize,
        payload_len: usize,
    ) -> Result<EchoStats, String> {
        const PACING: Duration = Duration::from_millis(5);
        const REPLY_GRACE: Duration = Duration::from_secs(3);

        let local_port = self.alloc_port();
        let nonce = fresh_nonce();
        let mut reasm = Reassembler::default();

        let mut sent_at: Vec<Option<std::time::Instant>> = vec![None; count];
        let mut got = vec![false; count];
        let mut rtts: Vec<Duration> = Vec::with_capacity(count);
        let mut sent = 0usize;
        let mut received = 0usize;

        let mut pace = tokio::time::interval(PACING);
        pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut grace_deadline = tokio::time::Instant::now() + REPLY_GRACE;

        while received < count {
            let mut send_now = false;
            tokio::select! {
                _ = pace.tick(), if sent < count => send_now = true,
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && let Some(seq) = match_echo_reply(&full, server, local_port, nonce)
                        {
                            let seq = seq as usize;
                            if seq < count && !got[seq] {
                                got[seq] = true;
                                received += 1;
                                if let Some(at) = sent_at[seq] {
                                    rtts.push(at.elapsed());
                                }
                                grace_deadline = tokio::time::Instant::now() + REPLY_GRACE;
                            }
                        }
                    }
                    Some(Err(e)) => log::warn!("udp echo: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err(format!(
                            "transport closed mid-echo ({received}/{count} replies in)"
                        ));
                    }
                },
                _ = tokio::time::sleep_until(grace_deadline), if sent >= count => break,
            }
            if send_now {
                let pkt = build_echo_request(local_port, server, sent as u32, nonce, payload_len);
                self.transport
                    .send(pkt)
                    .await
                    .map_err(|e| format!("udp echo send: {e}"))?;
                sent_at[sent] = Some(std::time::Instant::now());
                sent += 1;
                grace_deadline = tokio::time::Instant::now() + REPLY_GRACE;
            }
        }

        let rtt_min = rtts.iter().min().copied().unwrap_or(Duration::ZERO);
        let rtt_max = rtts.iter().max().copied().unwrap_or(Duration::ZERO);
        let rtt_avg = if rtts.is_empty() {
            Duration::ZERO
        } else {
            rtts.iter().sum::<Duration>() / rtts.len() as u32
        };
        Ok(EchoStats {
            sent,
            received,
            rtt_min,
            rtt_avg,
            rtt_max,
        })
    }

    /// Run a real TCP connection (smoltcp) against `server`, write `bytes`
    /// of a deterministic pattern and read the echo back, verifying content.
    async fn tcp_bulk(&mut self, server: SocketAddrV4, bytes: usize) -> Result<BulkStats, String> {
        use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
        use smoltcp::socket::tcp;
        use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

        /// Abort if neither direction makes progress for this long.
        const PROGRESS_TIMEOUT: Duration = Duration::from_secs(20);
        /// After all data round-tripped, wait at most this long for the
        /// close handshake before declaring victory anyway.
        const CLOSE_GRACE: Duration = Duration::from_secs(1);
        /// Floor for the poll_delay-based sleep so the progress timeout and
        /// retransmit timers are always re-checked.
        const MAX_IDLE: Duration = Duration::from_millis(20);

        let started = std::time::Instant::now();
        let local_port = self.alloc_port();

        let mut device = SmolDevice::default();
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = fresh_nonce();
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::now());
        // Mirror a host that owns CLIENT_INNER_IP: the address on a /24,
        // a default route, and any-ip (parity with the share-side stack).
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(CLIENT_INNER_IP), 24))
                .expect("first interface address always fits");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(INNER_GATEWAY)
            .map_err(|e| format!("default route: {e}"))?;

        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
        ));
        sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(
                iface.context(),
                (IpAddress::Ipv4(*server.ip()), server.port()),
                local_port,
            )
            .map_err(|e| format!("tcp connect: {e}"))?;

        let data: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
        let mut scratch = vec![0u8; 16 * 1024];
        let mut written = 0usize;
        let mut echoed = 0usize;
        let mut fin_sent = false;
        let mut close_deadline: Option<tokio::time::Instant> = None;
        let mut reasm = Reassembler::default();
        let mut last_progress = std::time::Instant::now();

        loop {
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);

            // tx: push everything smoltcp produced straight into the tunnel.
            while let Some(frame) = device.tx.pop_front() {
                self.transport
                    .send(frame)
                    .await
                    .map_err(|e| format!("tcp bulk: transport send: {e}"))?;
            }

            {
                let sock = sockets.get_mut::<tcp::Socket>(handle);

                while sock.can_recv() && echoed < bytes {
                    let n = sock
                        .recv_slice(&mut scratch)
                        .map_err(|e| format!("tcp recv: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    let end = echoed + n;
                    if end > bytes || scratch[..n] != data[echoed..end] {
                        return Err(format!("tcp echo mismatch at offset {echoed}"));
                    }
                    echoed = end;
                    last_progress = std::time::Instant::now();
                }

                while sock.can_send() && written < bytes {
                    let n = sock
                        .send_slice(&data[written..])
                        .map_err(|e| format!("tcp send: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    written += n;
                    last_progress = std::time::Instant::now();
                }

                if echoed >= bytes && !fin_sent {
                    sock.close();
                    fin_sent = true;
                    close_deadline = Some(tokio::time::Instant::now() + CLOSE_GRACE);
                }

                let state = sock.state();
                if fin_sent && matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
                    break;
                }
                if !fin_sent && state == tcp::State::Closed {
                    return Err(format!(
                        "tcp connection closed early (wrote {written}, echoed {echoed} of {bytes})"
                    ));
                }
            }

            if let Some(d) = close_deadline
                && tokio::time::Instant::now() >= d
            {
                break; // all data verified; don't sweat the FIN handshake
            }
            if last_progress.elapsed() > PROGRESS_TIMEOUT {
                return Err(format!(
                    "tcp bulk stalled (wrote {written}, echoed {echoed} of {bytes})"
                ));
            }

            // Anything smoltcp scheduled (retransmits, delayed ACKs) bounds
            // the sleep; MAX_IDLE bounds it from above so the progress and
            // close deadlines are re-checked.
            let delay = iface
                .poll_delay(SmolInstant::now(), &sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(MAX_IDLE)
                .min(MAX_IDLE);
            if delay.is_zero() {
                continue; // smoltcp wants an immediate re-poll
            }

            tokio::select! {
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && is_session_tcp(&full, server, local_port)
                        {
                            device.rx.push_back(full);
                        }
                    }
                    Some(Err(e)) => log::warn!("tcp bulk: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err(format!(
                            "transport closed mid-bulk (echoed {echoed}/{bytes})"
                        ));
                    }
                },
                _ = tokio::time::sleep(delay) => {}
            }
        }

        Ok(BulkStats {
            bytes: echoed,
            elapsed: started.elapsed(),
        })
    }
}

/// A random-enough u64 without a rand dependency: `RandomState` is seeded
/// from the OS per instance.
fn fresh_nonce() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// IPv4+UDP echo request from CLIENT_INNER_IP:`local_port` to `server`,
/// payload = [seq:4][nonce:8][0xA5 padding] (min 12 bytes).
fn build_echo_request(
    local_port: u16,
    server: SocketAddrV4,
    seq: u32,
    nonce: u64,
    payload_len: usize,
) -> Vec<u8> {
    let payload_len = payload_len.max(ECHO_TAG_LEN);
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.resize(payload_len, 0xA5);

    let mut pkt = Vec::with_capacity(28 + payload.len());
    etherparse::PacketBuilder::ipv4(CLIENT_INNER_IP.octets(), server.ip().octets(), 64)
        .udp(local_port, server.port())
        .write(&mut pkt, &payload)
        .expect("writing a UDP packet into a Vec cannot fail");
    pkt
}

/// If `pkt` is a (whole) IPv4/UDP reply from `server` to our echo session,
/// return the sequence number from its payload tag. Matching is on the
/// 12-byte tag prefix so padded replies still count.
fn match_echo_reply(
    pkt: &[u8],
    server: SocketAddrV4,
    local_port: u16,
    nonce: u64,
) -> Option<u32> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 + ECHO_TAG_LEN {
        return None;
    }
    if pkt[12..16] != server.ip().octets() || pkt[16..20] != CLIENT_INNER_IP.octets() {
        return None;
    }
    if u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) != server.port()
        || u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]) != local_port
    {
        return None;
    }
    let payload = &pkt[ihl + 8..];
    if payload[4..12] != nonce.to_be_bytes() {
        return None;
    }
    Some(u32::from_be_bytes(payload[0..4].try_into().unwrap()))
}

/// True if `pkt` is an IPv4/TCP segment belonging to the in-flight bulk
/// session (src = server, dst = CLIENT_INNER_IP:local_port).
fn is_session_tcp(pkt: &[u8], server: SocketAddrV4, local_port: u16) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 4 {
        return false;
    }
    pkt[12..16] == server.ip().octets()
        && pkt[16..20] == CLIENT_INNER_IP.octets()
        && u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) == server.port()
        && u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]) == local_port
}

// ---------------------------------------------------------------------------
// IPv4 fragment reassembly

/// Reassembles IPv4 fragments back into whole packets.
///
/// The tunnel IPv4-fragments any IP packet larger than the QUIC datagram
/// budget (`fragment_ipv4` in spora-core's QuicPeerTransport), and there is
/// no kernel on this side of the transport to reassemble — so large UDP
/// replies (share→client) arrive as fragments. Fragments are grouped by the
/// RFC 791 key (src, dst, protocol, identification), ordered by fragment
/// offset, and completed once the no-MF tail is present and every byte up to
/// it is covered. Non-fragments pass straight through.
#[derive(Default)]
pub struct Reassembler {
    partial: HashMap<FragKey, Partial>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FragKey {
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    id: u16,
}

struct Partial {
    /// payload chunks keyed by byte offset
    chunks: BTreeMap<usize, Vec<u8>>,
    /// total payload length, known once the no-MF tail arrives
    total: Option<usize>,
    /// IP header from the offset-0 fragment
    header: Option<Vec<u8>>,
    created: std::time::Instant,
}

/// Partial reassemblies older than this are evicted.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

impl Reassembler {
    /// Feed one inbound IP packet. Returns a complete packet — the input
    /// itself when it isn't a fragment, or the reassembled datagram when
    /// `pkt` completes one — or `None` while fragments are still pending.
    pub fn push(&mut self, pkt: Vec<u8>) -> Option<Vec<u8>> {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return Some(pkt); // not IPv4: pass through, callers ignore it
        }
        let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
        let more_fragments = flags_frag & 0x2000 != 0;
        let offset = ((flags_frag & 0x1fff) as usize) * 8;
        if !more_fragments && offset == 0 {
            return Some(pkt); // not fragmented
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        if ihl < 20 || pkt.len() < ihl {
            return Some(pkt); // malformed: pass through, callers ignore it
        }
        let total_field = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let end = total_field.clamp(ihl, pkt.len());
        let data = pkt[ihl..end].to_vec();

        self.partial
            .retain(|_, p| p.created.elapsed() < REASSEMBLY_TIMEOUT);

        let key = FragKey {
            src: pkt[12..16].try_into().unwrap(),
            dst: pkt[16..20].try_into().unwrap(),
            proto: pkt[9],
            id: u16::from_be_bytes([pkt[4], pkt[5]]),
        };
        let partial = self.partial.entry(key.clone()).or_insert_with(|| Partial {
            chunks: BTreeMap::new(),
            total: None,
            header: None,
            created: std::time::Instant::now(),
        });
        if offset == 0 {
            partial.header = Some(pkt[..ihl].to_vec());
        }
        if !more_fragments {
            partial.total = Some(offset + data.len());
        }
        partial.chunks.insert(offset, data);

        let assembled = partial.try_assemble();
        if assembled.is_some() {
            self.partial.remove(&key);
        }
        assembled
    }
}

impl Partial {
    /// Build the whole packet if the tail has arrived and coverage from 0 to
    /// the tail is contiguous. The header comes from the offset-0 fragment
    /// with total length fixed up, MF/offset cleared, and a recomputed
    /// checksum.
    fn try_assemble(&self) -> Option<Vec<u8>> {
        let total = self.total?;
        let header = self.header.as_ref()?;

        let mut covered = 0usize;
        for (&off, data) in &self.chunks {
            if off > covered {
                return None; // hole
            }
            covered = covered.max(off + data.len());
        }
        if covered < total {
            return None;
        }

        let mut payload = vec![0u8; total];
        for (&off, data) in &self.chunks {
            let end = (off + data.len()).min(total);
            if off < end {
                payload[off..end].copy_from_slice(&data[..end - off]);
            }
        }

        let ihl = header.len();
        let mut pkt = Vec::with_capacity(ihl + total);
        pkt.extend_from_slice(header);
        pkt.extend_from_slice(&payload);
        let total_len = (ihl + total) as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[6] &= 0x40; // keep only DF; clear MF + offset high bits
        pkt[7] = 0;
        pkt[10] = 0;
        pkt[11] = 0;
        let cks = ipv4_header_checksum(&pkt[..ihl]);
        pkt[10..12].copy_from_slice(&cks.to_be_bytes());
        Some(pkt)
    }
}

/// RFC 1071 ones'-complement header checksum (checksum field must be zero).
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// smoltcp device

/// In-memory smoltcp device: rx is fed by the pump from the transport, tx is
/// drained into the transport sink right after every `iface.poll`.
///
/// MTU 1100 keeps every client→share TCP segment under the tunnel's QUIC
/// datagram floor (≈1162 at the 1200-byte initial MTU), so client→share
/// packets are never IP-fragmented — the share-side netstack cannot
/// reassemble fragments. It also bounds the share→client segments: the SYN
/// advertises MSS = 1100 - 40 = 1060, which the share-side smoltcp clamps to.
const SMOL_DEVICE_MTU: usize = 1100;

#[derive(Default)]
struct SmolDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct SmolRxToken(Vec<u8>);

impl smoltcp::phy::RxToken for SmolRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct SmolTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::TxToken for SmolTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

impl smoltcp::phy::Device for SmolDevice {
    type RxToken<'a> = SmolRxToken;
    type TxToken<'a> = SmolTxToken<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(SmolRxToken, SmolTxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((SmolRxToken(pkt), SmolTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<SmolTxToken<'_>> {
        Some(SmolTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = SMOL_DEVICE_MTU;
        // checksum: ChecksumCapabilities::default() — smoltcp computes AND
        // verifies all checksums, as the share-side smoltcp requires.
        caps
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A full IPv4/UDP packet as the share-side netstack would build it
    /// (fresh header, TTL 20, valid checksums).
    fn udp_packet(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 253) as u8).collect();
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([203, 0, 113, 100], [10, 200, 0, 2], 20)
            .udp(7, 40000)
            .write(&mut pkt, &payload)
            .unwrap();
        pkt
    }

    /// Split `pkt` into IPv4 fragments carrying `chunk` payload bytes each
    /// (must be a multiple of 8), mimicking spora-core's `fragment_ipv4`:
    /// each fragment copies the IP header with MF set (except the tail),
    /// adjusted total length / fragment offset, and a valid checksum.
    fn split_fragments(pkt: &[u8], chunk: usize, id: u16) -> Vec<Vec<u8>> {
        assert_eq!(chunk % 8, 0);
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        let payload = &pkt[ihl..];
        let mut frags = Vec::new();
        let mut off = 0usize;
        while off < payload.len() {
            let end = (off + chunk).min(payload.len());
            let mf = end < payload.len();
            let mut frag = Vec::with_capacity(ihl + end - off);
            frag.extend_from_slice(&pkt[..ihl]);
            frag.extend_from_slice(&payload[off..end]);
            frag[2..4].copy_from_slice(&((ihl + end - off) as u16).to_be_bytes());
            frag[4..6].copy_from_slice(&id.to_be_bytes());
            let flags_frag = (if mf { 0x2000u16 } else { 0 }) | (off / 8) as u16;
            frag[6..8].copy_from_slice(&flags_frag.to_be_bytes());
            frag[10] = 0;
            frag[11] = 0;
            let cks = ipv4_header_checksum(&frag[..ihl]);
            frag[10..12].copy_from_slice(&cks.to_be_bytes());
            frags.push(frag);
            off = end;
        }
        frags
    }

    #[test]
    fn unfragmented_packet_passes_through() {
        let mut r = Reassembler::default();
        let pkt = udp_packet(64);
        assert_eq!(r.push(pkt.clone()), Some(pkt));
    }

    #[test]
    fn non_ipv4_passes_through() {
        let mut r = Reassembler::default();
        let junk = vec![0x60u8; 48]; // IPv6 version nibble
        assert_eq!(r.push(junk.clone()), Some(junk));
    }

    #[test]
    fn reassembles_out_of_order_fragments() {
        let mut r = Reassembler::default();
        let pkt = udp_packet(1400); // 1428-byte IP packet
        let frags = split_fragments(&pkt, 512, 0xBEEF);
        assert_eq!(frags.len(), 3);

        // Feed tail first, then head, then the middle completes it.
        assert_eq!(r.push(frags[2].clone()), None);
        assert_eq!(r.push(frags[0].clone()), None);
        let full = r.push(frags[1].clone()).expect("complete on last piece");

        // Payload and addressing survive; header checksum is valid.
        let ihl = ((full[0] & 0x0f) as usize) * 4;
        assert_eq!(&full[ihl..], &pkt[20..], "reassembled IP payload");
        assert_eq!(&full[12..20], &pkt[12..20], "addresses");
        assert_eq!(full[9], 17, "protocol");
        assert_eq!(
            u16::from_be_bytes([full[2], full[3]]) as usize,
            full.len(),
            "total length"
        );
        let flags_frag = u16::from_be_bytes([full[6], full[7]]);
        assert_eq!(flags_frag & 0x3fff, 0, "MF and offset cleared");
        let mut hdr = full[..ihl].to_vec();
        hdr[10] = 0;
        hdr[11] = 0;
        assert_eq!(
            ipv4_header_checksum(&hdr),
            u16::from_be_bytes([full[10], full[11]]),
            "recomputed header checksum"
        );

        // The reassembled packet matches the echo session it belongs to.
        let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 100), 7);
        assert!(is_complete_udp_for(&full, server, 40000));
    }

    /// Sanity helper for the test above: dst/ports parse out of the
    /// reassembled packet like any other whole UDP packet.
    fn is_complete_udp_for(pkt: &[u8], server: SocketAddrV4, local_port: u16) -> bool {
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        pkt[9] == 17
            && pkt[12..16] == server.ip().octets()
            && u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) == server.port()
            && u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]) == local_port
    }

    #[test]
    fn interleaved_fragment_trains_reassemble_independently() {
        let mut r = Reassembler::default();
        let a = udp_packet(900);
        let b = udp_packet(1200);
        let fa = split_fragments(&a, 488, 0x0001);
        let fb = split_fragments(&b, 488, 0x0002);
        assert_eq!(fa.len(), 2);
        assert_eq!(fb.len(), 3);

        assert_eq!(r.push(fa[0].clone()), None);
        assert_eq!(r.push(fb[1].clone()), None);
        assert_eq!(r.push(fb[0].clone()), None);
        let full_a = r.push(fa[1].clone()).expect("train A completes");
        let full_b = r.push(fb[2].clone()).expect("train B completes");
        assert_eq!(&full_a[20..], &a[20..]);
        assert_eq!(&full_b[20..], &b[20..]);
    }

    #[test]
    fn incomplete_train_stays_pending() {
        let mut r = Reassembler::default();
        let pkt = udp_packet(1400);
        let frags = split_fragments(&pkt, 512, 0x7777);
        // Head and tail but no middle: never completes.
        assert_eq!(r.push(frags[0].clone()), None);
        assert_eq!(r.push(frags[2].clone()), None);
    }

    #[test]
    fn echo_request_and_reply_match() {
        let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 100), 7);
        let req = build_echo_request(40000, server, 3, 0xDEAD_BEEF_CAFE_F00D, 200);
        assert_eq!(req.len(), 20 + 8 + 200);

        // Reflect it the way the echo path does: same payload, swapped
        // addressing.
        let payload = &req[28..];
        let mut reply = Vec::new();
        etherparse::PacketBuilder::ipv4([203, 0, 113, 100], [10, 200, 0, 2], 20)
            .udp(7, 40000)
            .write(&mut reply, payload)
            .unwrap();
        assert_eq!(
            match_echo_reply(&reply, server, 40000, 0xDEAD_BEEF_CAFE_F00D),
            Some(3)
        );
        // Wrong nonce, wrong port: no match.
        assert_eq!(match_echo_reply(&reply, server, 40000, 1), None);
        assert_eq!(match_echo_reply(&reply, server, 40001, 0xDEAD_BEEF_CAFE_F00D), None);
        // A padded reply still matches on the tag prefix.
        let mut padded = Vec::new();
        let mut big = payload.to_vec();
        big.resize(1400, 0x5A);
        etherparse::PacketBuilder::ipv4([203, 0, 113, 100], [10, 200, 0, 2], 20)
            .udp(7, 40000)
            .write(&mut padded, &big)
            .unwrap();
        assert_eq!(
            match_echo_reply(&padded, server, 40000, 0xDEAD_BEEF_CAFE_F00D),
            Some(3)
        );
    }
}
