//! The `nz` (Noise UDP) carrier data plane.
//!
//! A [`NoisePeerTransport`] carries tunnel IP packets as end-to-end Noise
//! datagrams over a UDP socket — the non-QUIC-shaped alternative for networks
//! that fingerprint or throttle QUIC. The handshake crypto lives in
//! [`crate::e2e_noise`]; this module is the wire framing and the socket driver.
//!
//! Wire image (all high-entropy; nothing a passive DPI box can pattern-match on
//! a per-flow basis except the public `routing_key`, exactly as the QUIC DCID is
//! today):
//!
//! ```text
//! handshake msg1 (B->A, the only relay-read packet):
//!   routing_key[20] | idx_B[4] | <noise NNpsk0 msg1>          (>= NZ_MSG1_MIN)
//! handshake msg2 (A->B, 5-tuple routed):
//!   idx_B[4] | idx_A[4] | <noise NNpsk0 msg2>
//! data / auth (either direction, 5-tuple routed):
//!   recv_index[4] | counter[8, header-protected] | AEAD(channel[1] | payload)
//! ```
//!
//! - `recv_index` is the destination's session index (cleartext, random per
//!   session — the demux key, like a QUIC connection id).
//! - `counter` is the per-packet AEAD nonce, **header-protected** (masked with a
//!   keystream sampled from the ciphertext) so no fixed-offset incrementing
//!   counter or zero-run appears on the wire — the WireGuard-family tell the
//!   adversarial review flagged as fatal.
//! - `channel` (inside the AEAD): `0x00` IP packet, `0x01` signal (hole-punch,
//!   Stage 2), `0x02` cert-auth (A's first message), `0x03` close.
//!
//! Stage 1b: relay-only, no direct upgrade, no pacer (nz is functional-but-slow
//! under load and MUST NOT be made a default carrier until a tunnel pacer lands).

// Signal handling, roaming, and the multi-client dispatcher land in later
// commits; until then a few constants/fields are only used by tests.
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Sink, Stream};
use log::warn;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::frag::{fragment_ipv4, fragment_ipv6};
use crate::e2e_noise::{
    NOISE_TAG_LEN, NoiseHandshake, NoiseSession, build_cert_auth, verify_cert_auth,
};
use crate::identity::{Identity, ROUTING_KEY_LEN, SECRET_LEN};

/// In-band channel tags (inside the AEAD, invisible on the wire).
const CH_IP: u8 = 0x00;
const CH_SIGNAL: u8 = 0x01;
const CH_AUTH: u8 = 0x02;
const CH_CLOSE: u8 = 0x03;

const INDEX_LEN: usize = 4;
const COUNTER_LEN: usize = 8;
/// Header bytes before the AEAD ciphertext on a data packet.
const DATA_HEADER_LEN: usize = INDEX_LEN + COUNTER_LEN;
/// Bytes of ciphertext sampled to derive the header-protection mask.
const HP_SAMPLE_LEN: usize = 16;
/// Smallest legal data packet: header + 1-byte channel + AEAD tag.
const DATA_MIN_LEN: usize = DATA_HEADER_LEN + 1 + NOISE_TAG_LEN;

/// The relay recognises an nz handshake by a `routing_key` prefix on a packet at
/// least this long (routing_key + idx + a full NNpsk0 msg1 = 20 + 4 + 48).
pub(crate) const NZ_MSG1_MIN: usize = ROUTING_KEY_LEN + INDEX_LEN + 48;

/// Fixed tunnel MTU reported to the netstack. A Noise datagram adds
/// `header(12) + channel(1) + tag(16) = 29` over the inner IP packet; keeping
/// the inner packet <= this leaves the datagram inside a conservative 1200-byte
/// path even over IPv6 (1120 + 29 + 40 + 8 = 1197). Oversized inner packets are
/// fragmented at the tunnel layer to fit.
pub(crate) const NZ_TUNNEL_MTU: u16 = 1120;

/// How long a session driver waits with no packet before declaring the path
/// dead (surfaced as `Stream` end so the outer `ReconnectTransport` re-dials).
const DEFAULT_IDLE: Duration = Duration::from_secs(30);

// ---- header protection ----------------------------------------------------

/// Per-session header-protection key, derived from the Noise channel binding so
/// both peers agree without any extra exchange. Not a confidentiality key — its
/// only job is to hide the packet counter's structure from a passive observer.
fn derive_hp_key(handshake_hash: &[u8; 32]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"spora-noise-hp-v1");
    ctx.update(handshake_hash);
    let mut k = [0u8; 32];
    k.copy_from_slice(ctx.finish().as_ref());
    k
}

/// The 8-byte counter mask = HMAC-SHA256(hp_key, ciphertext_sample)[..8]. The
/// sample is at a fixed offset in the ciphertext (independent of the counter),
/// so the receiver reproduces the mask before it needs the counter — the same
/// shape as QUIC header protection.
fn hp_mask(hp_key: &[u8; 32], sample: &[u8]) -> [u8; COUNTER_LEN] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, hp_key);
    let tag = ring::hmac::sign(&key, sample);
    let mut m = [0u8; COUNTER_LEN];
    m.copy_from_slice(&tag.as_ref()[..COUNTER_LEN]);
    m
}

/// Build one data packet: `recv_index | protected_counter | AEAD(channel|payload)`.
fn frame_data(
    session: &NoiseSession,
    hp_key: &[u8; 32],
    recv_index: u32,
    counter: u64,
    channel: u8,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(channel);
    plaintext.extend_from_slice(payload);
    let ciphertext = session.encrypt(counter, &plaintext)?;
    // ciphertext is >= 1 + NOISE_TAG_LEN = 17 bytes, so the sample always exists.
    let mask = hp_mask(hp_key, &ciphertext[..HP_SAMPLE_LEN]);
    let mut ctr = counter.to_be_bytes();
    for (b, m) in ctr.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
    let mut out = Vec::with_capacity(DATA_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&recv_index.to_be_bytes());
    out.extend_from_slice(&ctr);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Parse + decrypt a data packet. Returns `(counter, channel, payload)`. Fails
/// on a wrong index, short buffer, or AEAD failure (wrong key, tamper, or a
/// counter the header protection couldn't have produced).
fn deframe_data(
    session: &NoiseSession,
    hp_key: &[u8; 32],
    local_index: u32,
    buf: &[u8],
) -> Result<(u64, u8, Vec<u8>), String> {
    if buf.len() < DATA_MIN_LEN {
        return Err("nz: short data packet".into());
    }
    let idx = u32::from_be_bytes(buf[0..INDEX_LEN].try_into().unwrap());
    if idx != local_index {
        return Err("nz: index mismatch".into());
    }
    let ciphertext = &buf[DATA_HEADER_LEN..];
    let mask = hp_mask(hp_key, &ciphertext[..HP_SAMPLE_LEN]);
    let mut ctr = [0u8; COUNTER_LEN];
    ctr.copy_from_slice(&buf[INDEX_LEN..DATA_HEADER_LEN]);
    for (b, m) in ctr.iter_mut().zip(mask.iter()) {
        *b ^= *m;
    }
    let counter = u64::from_be_bytes(ctr);
    let plaintext = session.decrypt(counter, ciphertext)?;
    if plaintext.is_empty() {
        return Err("nz: empty plaintext".into());
    }
    Ok((counter, plaintext[0], plaintext[1..].to_vec()))
}

// ---- replay window (RFC 6479 sliding bitmap) ------------------------------

const REPLAY_WINDOW: u64 = 2048;

/// Anti-replay for the peer's monotonic-ish counter. Tolerates reordering
/// within the window (inner TCP reorders); rejects duplicates and anything
/// older than the window. AEAD verification happens *before* this, so it only
/// ever sees authentic counters.
struct ReplayWindow {
    highest: u64,
    seen_any: bool,
    bits: Vec<u64>,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            seen_any: false,
            bits: vec![0u64; (REPLAY_WINDOW / 64) as usize],
        }
    }

    fn get(&self, counter: u64) -> bool {
        let idx = (counter % REPLAY_WINDOW) as usize;
        self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    fn set(&mut self, counter: u64) {
        let idx = (counter % REPLAY_WINDOW) as usize;
        self.bits[idx / 64] |= 1u64 << (idx % 64);
    }

    fn clear(&mut self, counter: u64) {
        let idx = (counter % REPLAY_WINDOW) as usize;
        self.bits[idx / 64] &= !(1u64 << (idx % 64));
    }

    /// Returns true if `counter` is fresh (and records it); false on replay or
    /// too-old.
    fn check_and_set(&mut self, counter: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = counter;
            self.set(counter);
            return true;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift >= REPLAY_WINDOW {
                self.bits.iter_mut().for_each(|w| *w = 0);
            } else {
                for c in (self.highest + 1)..=counter {
                    self.clear(c);
                }
            }
            self.highest = counter;
            self.set(counter);
            true
        } else if self.highest - counter >= REPLAY_WINDOW {
            false // too old
        } else if self.get(counter) {
            false // replay
        } else {
            self.set(counter);
            true
        }
    }
}

// ---- socket pump ----------------------------------------------------------

/// Forward every datagram on `socket` into a channel as `(bytes, src)`. Used by
/// the client side (whose socket only ever talks to one relay) and by tests; the
/// share-side multi-client dispatcher (a later commit) replaces it.
pub(crate) fn spawn_socket_pump(
    socket: Arc<UdpSocket>,
) -> (mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>, JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    if tx.send((buf[..n].to_vec(), src)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    (rx, handle)
}

async fn recv_dgram(
    rx: &mut mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    within: Duration,
) -> Result<(Vec<u8>, SocketAddr), String> {
    match timeout(within, rx.recv()).await {
        Ok(Some(x)) => Ok(x),
        Ok(None) => Err("nz: datagram source closed".into()),
        Err(_) => Err("nz: handshake timed out".into()),
    }
}

// ---- handshake drivers ----------------------------------------------------

/// Client (B) side: run the NNpsk0 handshake to the sharer (through the relay at
/// `relay_addr`, or directly), verify A's cert-auth, and return the data-plane
/// transport. B owns its socket, so it pumps it internally.
pub(crate) async fn noise_connect(
    socket: Arc<UdpSocket>,
    relay_addr: SocketAddr,
    routing_key: &[u8; ROUTING_KEY_LEN],
    secret: &[u8; SECRET_LEN],
    hs_timeout: Duration,
    idle: Duration,
) -> Result<NoisePeerTransport, String> {
    let (mut rx, pump) = spawn_socket_pump(socket.clone());

    let mut hs = NoiseHandshake::initiator(routing_key, secret)?;
    let idx_b: u32 = rand::random();
    let noise_msg1 = hs.write_message(&[])?;
    let mut msg1 = Vec::with_capacity(ROUTING_KEY_LEN + INDEX_LEN + noise_msg1.len());
    msg1.extend_from_slice(routing_key);
    msg1.extend_from_slice(&idx_b.to_be_bytes());
    msg1.extend_from_slice(&noise_msg1);
    socket
        .send_to(&msg1, relay_addr)
        .await
        .map_err(|e| format!("nz send msg1: {e}"))?;

    // msg2: idx_B | idx_A | noise_msg2
    let (msg2, _src) = recv_dgram(&mut rx, hs_timeout).await?;
    if msg2.len() < 2 * INDEX_LEN {
        return Err("nz: short msg2".into());
    }
    let idx_b_echo = u32::from_be_bytes(msg2[0..INDEX_LEN].try_into().unwrap());
    if idx_b_echo != idx_b {
        return Err("nz: msg2 session-index mismatch".into());
    }
    let idx_a = u32::from_be_bytes(msg2[INDEX_LEN..2 * INDEX_LEN].try_into().unwrap());
    hs.read_message(&msg2[2 * INDEX_LEN..])?;
    if !hs.is_finished() {
        return Err("nz: handshake unfinished after msg2".into());
    }
    let session = Arc::new(hs.into_session()?);
    let hp_key = derive_hp_key(&session.handshake_hash);

    // cert-auth: A's first transport message (counter 0).
    let (auth, _src) = recv_dgram(&mut rx, hs_timeout).await?;
    let (_c, channel, auth_pt) = deframe_data(&session, &hp_key, idx_b, &auth)?;
    if channel != CH_AUTH {
        return Err("nz: expected cert-auth, got another frame".into());
    }
    verify_cert_auth(&auth_pt, routing_key, &session.handshake_hash)?;

    Ok(NoisePeerTransport::spawn(NoiseChannelInit {
        socket,
        peer_addr: relay_addr,
        session,
        hp_key,
        local_index: idx_b,
        peer_index: idx_a,
        send_counter_start: 0,
        recv_seen: vec![0], // A's cert-auth already consumed counter 0
        rx,
        pump,
        idle,
    }))
}

/// Sharer (A) side: given the incoming-datagram channel for one client (msg1
/// arrives first), run the responder handshake, send the cert-auth, and return
/// the transport. The caller (the share-side dispatcher, or a test) owns the
/// socket and feeds `rx`.
pub(crate) async fn noise_accept(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    pump: JoinHandle<()>,
    identity: &Identity,
    hs_timeout: Duration,
    idle: Duration,
) -> Result<NoisePeerTransport, String> {
    let (msg1, peer_addr) = recv_dgram(&mut rx, hs_timeout).await?;
    if msg1.len() < NZ_MSG1_MIN {
        return Err("nz: short msg1".into());
    }
    if msg1[0..ROUTING_KEY_LEN] != identity.routing_key {
        return Err("nz: msg1 routing-key mismatch".into());
    }
    let idx_b = u32::from_be_bytes(msg1[ROUTING_KEY_LEN..ROUTING_KEY_LEN + INDEX_LEN].try_into().unwrap());

    let mut hs = NoiseHandshake::responder(identity)?;
    hs.read_message(&msg1[ROUTING_KEY_LEN + INDEX_LEN..])?; // wrong secret fails here
    let idx_a: u32 = rand::random();
    let noise_msg2 = hs.write_message(&[])?;
    let mut msg2 = Vec::with_capacity(2 * INDEX_LEN + noise_msg2.len());
    msg2.extend_from_slice(&idx_b.to_be_bytes());
    msg2.extend_from_slice(&idx_a.to_be_bytes());
    msg2.extend_from_slice(&noise_msg2);
    socket
        .send_to(&msg2, peer_addr)
        .await
        .map_err(|e| format!("nz send msg2: {e}"))?;
    if !hs.is_finished() {
        return Err("nz: handshake unfinished after msg2".into());
    }
    let session = Arc::new(hs.into_session()?);
    let hp_key = derive_hp_key(&session.handshake_hash);

    // cert-auth to B as transport message #0 (recv_index = B's index).
    let auth = build_cert_auth(identity, &session.handshake_hash)?;
    let auth_pkt = frame_data(&session, &hp_key, idx_b, 0, CH_AUTH, &auth)?;
    socket
        .send_to(&auth_pkt, peer_addr)
        .await
        .map_err(|e| format!("nz send cert-auth: {e}"))?;

    Ok(NoisePeerTransport::spawn(NoiseChannelInit {
        socket,
        peer_addr,
        session,
        hp_key,
        local_index: idx_a,
        peer_index: idx_b,
        send_counter_start: 1, // counter 0 was the cert-auth
        recv_seen: vec![],
        rx,
        pump,
        idle,
    }))
}

// ---- transport ------------------------------------------------------------

struct NoiseChannelInit {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session: Arc<NoiseSession>,
    hp_key: [u8; 32],
    local_index: u32,
    peer_index: u32,
    send_counter_start: u64,
    recv_seen: Vec<u64>,
    rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    pump: JoinHandle<()>,
    idle: Duration,
}

/// A `Transport` carrying tunnel IP packets as Noise datagrams over UDP.
pub(crate) struct NoisePeerTransport {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session: Arc<NoiseSession>,
    hp_key: [u8; 32],
    peer_index: u32,
    send_counter: u64,
    ip_id_ctr: u32,
    dec_rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    reader: JoinHandle<()>,
    pump: JoinHandle<()>,
}

impl NoisePeerTransport {
    fn spawn(init: NoiseChannelInit) -> Self {
        let NoiseChannelInit {
            socket,
            peer_addr,
            session,
            hp_key,
            local_index,
            peer_index,
            send_counter_start,
            recv_seen,
            mut rx,
            pump,
            idle,
        } = init;

        let (dec_tx, dec_rx) = mpsc::unbounded_channel();
        let reader_session = session.clone();
        let reader = tokio::spawn(async move {
            let mut replay = ReplayWindow::new();
            for c in recv_seen {
                replay.check_and_set(c);
            }
            loop {
                let next = timeout(idle, rx.recv()).await;
                let (buf, _src) = match next {
                    Err(_) => {
                        let _ = dec_tx.send(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "nz: idle timeout",
                        )));
                        break;
                    }
                    Ok(None) => break, // socket source gone -> Stream end
                    Ok(Some(x)) => x,
                };
                match deframe_data(&reader_session, &hp_key, local_index, &buf) {
                    Ok((counter, channel, payload)) => {
                        if !replay.check_and_set(counter) {
                            continue; // replay or too old
                        }
                        match channel {
                            CH_IP => {
                                if dec_tx.send(Ok(payload)).is_err() {
                                    break;
                                }
                            }
                            CH_CLOSE => break, // peer closed -> Stream end
                            // CH_SIGNAL is wired in Stage 2; CH_AUTH shouldn't recur.
                            _ => {}
                        }
                    }
                    Err(_) => {} // malformed / not ours — drop
                }
            }
        });

        Self {
            socket,
            peer_addr,
            session,
            hp_key,
            peer_index,
            send_counter: send_counter_start,
            ip_id_ctr: 0,
            dec_rx,
            reader,
            pump,
        }
    }

    /// Remote address of the bootstrap path (the relay, or the peer when direct).
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Frame + send one payload on `channel` under the next counter. A full
    /// socket buffer drops the datagram (like QUIC's datagram path) rather than
    /// blocking the tunnel; the inner protocol recovers.
    fn send_on(&mut self, channel: u8, payload: &[u8]) -> io::Result<()> {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);
        let pkt = frame_data(
            &self.session,
            &self.hp_key,
            self.peer_index,
            counter,
            channel,
            payload,
        )
        .map_err(io::Error::other)?;
        match self.socket.try_send_to(&pkt, self.peer_addr) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Stream for NoisePeerTransport {
    type Item = io::Result<Vec<u8>>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.dec_rx.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for NoisePeerTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let cap = NZ_TUNNEL_MTU as usize;
        if item.len() > cap {
            // Oversized inner packet (e.g. an inbound UDP datagram a NATing
            // sharer re-originates and can't MSS-clamp): fragment at the tunnel
            // layer so the far side reassembles. Same policy as the QUIC carrier.
            let id = this.frag_id();
            let frags = match item.first().map(|b| b >> 4) {
                Some(4) => fragment_ipv4(&item, cap, id as u16),
                Some(6) => fragment_ipv6(&item, cap, id),
                _ => None,
            };
            match frags {
                Some(frags) => {
                    for f in frags {
                        this.send_on(CH_IP, &f)?;
                    }
                }
                None => warn!(
                    "nz: dropping oversized unfragmentable datagram: {} > {}",
                    item.len(),
                    cap
                ),
            }
            Ok(())
        } else {
            this.send_on(CH_IP, &item)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let _ = self.send_on(CH_CLOSE, &[]);
        Poll::Ready(Ok(()))
    }
}

impl NoisePeerTransport {
    fn frag_id(&mut self) -> u32 {
        let id = self.ip_id_ctr;
        self.ip_id_ctr = self.ip_id_ctr.wrapping_add(1);
        id
    }
}

impl Drop for NoisePeerTransport {
    fn drop(&mut self) {
        // Best-effort close so a superseded relay-via session's flow falls idle
        // promptly (the direct-upgrade swap and reconnect rely on it), then stop
        // the reader/pump tasks so nothing keeps refreshing the relay flow.
        let _ = self.send_on(CH_CLOSE, &[]);
        self.reader.abort();
        self.pump.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use futures_util::{SinkExt, StreamExt};

    async fn udp(addr: &str) -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind(addr).await.unwrap())
    }

    /// Stand up a connected B<->A nz pair over two loopback UDP sockets.
    async fn connected_pair(identity: Identity) -> (NoisePeerTransport, NoisePeerTransport) {
        let a_sock = udp("127.0.0.1:0").await;
        let b_sock = udp("127.0.0.1:0").await;
        let a_addr = a_sock.local_addr().unwrap();

        let (rx_a, pump_a) = spawn_socket_pump(a_sock.clone());
        let id = identity.clone();
        let accept = tokio::spawn(async move {
            noise_accept(a_sock, rx_a, pump_a, &id, Duration::from_secs(5), DEFAULT_IDLE).await
        });
        let rk = identity.routing_key;
        let secret = identity.secret;
        let connect = noise_connect(
            b_sock,
            a_addr,
            &rk,
            &secret,
            Duration::from_secs(5),
            DEFAULT_IDLE,
        );
        let (b_res, a_res) = tokio::join!(connect, accept);
        (a_res.unwrap().expect("accept"), b_res.expect("connect"))
    }

    fn ipv4_udp(payload_len: usize) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(1234, 5678)
            .write(&mut pkt, &vec![0xABu8; payload_len])
            .unwrap();
        pkt
    }

    #[tokio::test]
    async fn carries_ip_packets_both_directions() {
        let (mut a, mut b) = connected_pair(Identity::generate()).await;

        let p1 = ipv4_udp(64);
        b.send(p1.clone()).await.unwrap();
        let got = timeout(Duration::from_secs(2), a.next())
            .await
            .expect("A receives")
            .expect("stream open")
            .expect("no error");
        assert_eq!(got, p1, "B->A packet arrives intact");

        let p2 = ipv4_udp(128);
        a.send(p2.clone()).await.unwrap();
        let got = timeout(Duration::from_secs(2), b.next())
            .await
            .expect("B receives")
            .expect("stream open")
            .expect("no error");
        assert_eq!(got, p2, "A->B packet arrives intact");
    }

    #[tokio::test]
    async fn oversized_packet_fragments_and_reassembles_at_the_far_side() {
        let (mut a, mut b) = connected_pair(Identity::generate()).await;
        // A 3000-byte IPv4 packet is far larger than NZ_TUNNEL_MTU -> multiple
        // datagrams, each an IPv4 fragment the receiver's stack reassembles. We
        // observe the fragments here.
        let pkt = ipv4_udp(3000 - 28);
        assert!(pkt.len() > NZ_TUNNEL_MTU as usize);
        b.send(pkt.clone()).await.unwrap();

        let mut got = 0usize;
        let mut frags = 0;
        while got < pkt.len() - 20 {
            let f = timeout(Duration::from_secs(2), a.next())
                .await
                .expect("fragment arrives")
                .expect("open")
                .expect("no error");
            assert!(f.len() <= NZ_TUNNEL_MTU as usize, "fragment fits the tunnel MTU");
            got += f.len() - ((f[0] & 0x0f) as usize) * 4;
            frags += 1;
        }
        assert!(frags >= 2, "should have split into multiple fragments");
    }

    #[test]
    fn replay_window_rejects_duplicates_and_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(0), "first counter accepted");
        assert!(!w.check_and_set(0), "duplicate rejected");
        assert!(w.check_and_set(5), "advance accepted");
        assert!(w.check_and_set(3), "in-window reorder accepted");
        assert!(!w.check_and_set(3), "replayed reorder rejected");
        assert!(w.check_and_set(1), "in-window reorder accepted");
        assert!(w.check_and_set(REPLAY_WINDOW + 10), "big jump accepted");
        assert!(!w.check_and_set(5), "now far below window -> rejected");
    }

    #[test]
    fn header_protection_hides_the_counter_and_round_trips() {
        // Two packets with adjacent counters must not differ by a fixed +1 in
        // the on-wire counter field, and must still deframe correctly.
        let identity = Identity::generate();
        let mut hs_b = NoiseHandshake::initiator(&identity.routing_key, &identity.secret).unwrap();
        let mut hs_a = NoiseHandshake::responder(&identity).unwrap();
        let m1 = hs_b.write_message(&[]).unwrap();
        hs_a.read_message(&m1).unwrap();
        let m2 = hs_a.write_message(&[]).unwrap();
        hs_b.read_message(&m2).unwrap();
        let a_sess = hs_a.into_session().unwrap();
        let b_sess = hs_b.into_session().unwrap();
        let hp = derive_hp_key(&a_sess.handshake_hash);

        let idx = 0x1234_5678u32;
        let p0 = frame_data(&a_sess, &hp, idx, 0, CH_IP, b"hello").unwrap();
        let p1 = frame_data(&a_sess, &hp, idx, 1, CH_IP, b"hello").unwrap();
        // On-wire counter bytes differ by the header-protection mask, not +1.
        let c0 = &p0[INDEX_LEN..DATA_HEADER_LEN];
        let c1 = &p1[INDEX_LEN..DATA_HEADER_LEN];
        assert_ne!(c0, c1, "counters masked to different bytes");
        assert_ne!(c1, &1u64.to_be_bytes()[..], "counter 1 not in the clear");

        // And both deframe to the right counter/payload.
        let (ctr0, ch0, pl0) = deframe_data(&b_sess, &hp, idx, &p0).unwrap();
        let (ctr1, _, _) = deframe_data(&b_sess, &hp, idx, &p1).unwrap();
        assert_eq!((ctr0, ch0, pl0.as_slice()), (0, CH_IP, b"hello".as_slice()));
        assert_eq!(ctr1, 1);
    }
}
