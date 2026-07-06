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
//! Send path: each datagram goes straight out (`try_send_to`), no tunnel-layer
//! pacer. A feedback pacer was tried and reverted — with the ring-accelerated
//! snow backend the AEAD is asm-fast and nz reaches QUIC parity on a shaped link
//! unpaced (the earlier ~half-speed measurement was a debug-only pure-Rust-crypto
//! artifact); pacing only added overhead and hurt throughput in every case.

// Signal handling, roaming, and the multi-client dispatcher land in later
// commits; until then a few constants/fields are only used by tests.
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
pub(crate) const DATA_MIN_LEN: usize = DATA_HEADER_LEN + 1 + NOISE_TAG_LEN;

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

/// Precompute the per-session header-protection HMAC key from the Noise channel
/// binding, **once**. Both peers derive the same key; caching the `ring::hmac::Key`
/// (which precomputes the HMAC ipad/opad) rather than rebuilding it per packet
/// keeps header protection cheap on the hot path.
fn derive_hp_key(handshake_hash: &[u8; 32]) -> ring::hmac::Key {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"spora-noise-hp-v1");
    ctx.update(handshake_hash);
    let mut k = [0u8; 32];
    k.copy_from_slice(ctx.finish().as_ref());
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &k)
}

/// The 8-byte counter mask = HMAC-SHA256(hp_key, ciphertext_sample)[..8]. The
/// sample is at a fixed offset in the ciphertext (independent of the counter),
/// so the receiver reproduces the mask before it needs the counter — the same
/// shape as QUIC header protection.
fn hp_mask(hp_key: &ring::hmac::Key, sample: &[u8]) -> [u8; COUNTER_LEN] {
    let tag = ring::hmac::sign(hp_key, sample);
    let mut m = [0u8; COUNTER_LEN];
    m.copy_from_slice(&tag.as_ref()[..COUNTER_LEN]);
    m
}

/// Build one data packet: `recv_index | protected_counter | AEAD(channel|payload)`.
fn frame_data(
    session: &NoiseSession,
    hp_key: &ring::hmac::Key,
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
    hp_key: &ring::hmac::Key,
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
        } else if self.highest - counter >= REPLAY_WINDOW || self.get(counter) {
            false // too old, or a replay within the window
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
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            if tx.send((buf[..n].to_vec(), src)).is_err() {
                break;
            }
        }
    });
    (rx, handle)
}

/// Receive the first datagram matching `pred`, skipping any that don't — so a
/// handshake tolerates stray packets sharing the socket (on the direct path the
/// punched socket still carries in-flight hole-punch/verify markers, and a relay
/// may briefly mingle flows). Skipped packets are cheap to discard; a match is
/// validated by the caller. Times out if none matches in `within`.
async fn recv_matching<F: Fn(&[u8]) -> bool>(
    rx: &mut mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    within: Duration,
    pred: F,
) -> Result<(Vec<u8>, SocketAddr), String> {
    timeout(within, async {
        loop {
            match rx.recv().await {
                Some((d, src)) if pred(&d) => return Ok((d, src)),
                Some(_) => continue, // stray (punch leftover / other flow) — skip
                None => return Err("nz: datagram source closed".to_string()),
            }
        }
    })
    .await
    .map_err(|_| "nz: handshake timed out".to_string())?
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
    // Retransmit msg1 until msg2 arrives or hs_timeout elapses — a lost first
    // packet (a relay-registration race, or plain loss) must not fail the dial,
    // just as QUIC retransmits its Initial. msg2 is filtered by our idx_B echoed
    // back, so a stray punch/verify packet on a shared socket isn't misread.
    const MSG1_RESEND: Duration = Duration::from_millis(250);
    let idx_b_bytes = idx_b.to_be_bytes();
    let deadline = tokio::time::Instant::now() + hs_timeout;
    let msg2 = loop {
        socket
            .send_to(&msg1, relay_addr)
            .await
            .map_err(|e| format!("nz send msg1: {e}"))?;
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err("nz: handshake timed out (no msg2)".to_string());
        }
        let wait = MSG1_RESEND.min(deadline - now);
        let attempt = tokio::time::timeout(wait, async {
            loop {
                match rx.recv().await {
                    Some((d, _src))
                        if d.len() >= 2 * INDEX_LEN && d[0..INDEX_LEN] == idx_b_bytes =>
                    {
                        return Some(d);
                    }
                    Some(_) => continue,     // stray — skip
                    None => return None,     // datagram source closed
                }
            }
        })
        .await;
        match attempt {
            Ok(Some(m)) => break m,
            Ok(None) => return Err("nz: datagram source closed".to_string()),
            Err(_) => {} // this attempt timed out — resend msg1 and keep waiting
        }
    };
    let idx_a = u32::from_be_bytes(msg2[INDEX_LEN..2 * INDEX_LEN].try_into().unwrap());
    hs.read_message(&msg2[2 * INDEX_LEN..])?;
    if !hs.is_finished() {
        return Err("nz: handshake unfinished after msg2".into());
    }
    let session = Arc::new(hs.into_session()?);
    let hp_key = derive_hp_key(&session.handshake_hash);

    // cert-auth: A's first transport message (counter 0). Skip strays until a
    // datagram deframes as an AUTH frame under our index.
    let auth_pt = timeout(hs_timeout, async {
        loop {
            let (d, _) = match rx.recv().await {
                Some(x) => x,
                None => return Err("nz: datagram source closed".to_string()),
            };
            if let Ok((_c, CH_AUTH, pt)) = deframe_data(&session, &hp_key, idx_b, &d) {
                return Ok(pt);
            }
        }
    })
    .await
    .map_err(|_| "nz: timed out waiting for cert-auth".to_string())??;
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
        pump: Some(pump),
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
    local_index: u32,
    pump: Option<JoinHandle<()>>,
    identity: &Identity,
    hs_timeout: Duration,
    idle: Duration,
) -> Result<NoisePeerTransport, String> {
    // Filter to our own msg1 (routing_key prefix), skipping strays — on the
    // direct path the punched socket still carries in-flight punch markers.
    let (msg1, peer_addr) = recv_matching(&mut rx, hs_timeout, |d| {
        d.len() >= NZ_MSG1_MIN && d[0..ROUTING_KEY_LEN] == identity.routing_key
    })
    .await?;
    let idx_b = u32::from_be_bytes(msg1[ROUTING_KEY_LEN..ROUTING_KEY_LEN + INDEX_LEN].try_into().unwrap());

    let mut hs = NoiseHandshake::responder(identity)?;
    hs.read_message(&msg1[ROUTING_KEY_LEN + INDEX_LEN..])?; // wrong secret fails here
    // The caller (the share-side dispatcher) assigns idx_a so it can route this
    // session's later data packets by their recv_index without a decrypt.
    let idx_a: u32 = local_index;
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
    hp_key: ring::hmac::Key,
    local_index: u32,
    peer_index: u32,
    send_counter_start: u64,
    recv_seen: Vec<u64>,
    rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    pump: Option<JoinHandle<()>>,
    idle: Duration,
}

/// A `Transport` carrying tunnel IP packets as Noise datagrams over UDP.
pub(crate) struct NoisePeerTransport {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session: Arc<NoiseSession>,
    hp_key: ring::hmac::Key,
    peer_index: u32,
    /// Shared with the [`NoiseSignal`] so data (`CH_IP`) and signal (`CH_SIGNAL`)
    /// frames drawn from the same cipher never reuse an AEAD nonce.
    send_counter: Arc<AtomicU64>,
    ip_id_ctr: u32,
    dec_rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    reader: JoinHandle<()>,
    /// The in-band hole-punch signal channel, taken by the direct-upgrade task
    /// (`take_signal`). Present until taken; dropped with the transport if unused.
    signal: Option<NoiseSignal>,
    /// Some when this session owns its socket pump (client / test); None when a
    /// shared dispatcher feeds it (the share side).
    pump: Option<JoinHandle<()>>,
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

        let send_counter = Arc::new(AtomicU64::new(send_counter_start));
        let (dec_tx, dec_rx) = mpsc::unbounded_channel();
        // Incoming hole-punch signaling (CH_SIGNAL) is split off to the signal
        // channel; the reader forwards payloads and never blocks on it.
        let (sig_tx, sig_rx) = mpsc::unbounded_channel();
        let reader_session = session.clone();
        let reader_hp = hp_key.clone();
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
                // Malformed / not-ours packets deframe to Err and are dropped.
                if let Ok((counter, channel, payload)) =
                    deframe_data(&reader_session, &reader_hp, local_index, &buf)
                {
                    if !replay.check_and_set(counter) {
                        continue; // replay or too old
                    }
                    match channel {
                        CH_IP => {
                            if dec_tx.send(Ok(payload)).is_err() {
                                break;
                            }
                        }
                        CH_SIGNAL => {
                            // Best-effort: a dropped receiver (no upgrade task)
                            // just discards it; never breaks the data path.
                            let _ = sig_tx.send(payload);
                        }
                        CH_CLOSE => break, // peer closed -> Stream end
                        _ => {}            // CH_AUTH shouldn't recur
                    }
                }
            }
        });

        let signal = NoiseSignal {
            sig_rx,
            session: session.clone(),
            hp_key: hp_key.clone(),
            peer_index,
            socket: socket.clone(),
            peer_addr,
            send_counter: send_counter.clone(),
        };

        Self {
            socket,
            peer_addr,
            session,
            hp_key,
            peer_index,
            send_counter,
            ip_id_ctr: 0,
            dec_rx,
            reader,
            signal: Some(signal),
            pump,
        }
    }

    /// Take the in-band signal channel for the direct-upgrade task. Returns
    /// `None` if already taken.
    pub(crate) fn take_signal(&mut self) -> Option<NoiseSignal> {
        self.signal.take()
    }

    /// Remote address of the bootstrap path (the relay, or the peer when direct).
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Frame + send one payload on `channel` under the next counter. A full
    /// socket buffer drops the datagram (like QUIC's datagram path) rather than
    /// blocking the tunnel; the inner protocol recovers.
    fn send_on(&mut self, channel: u8, payload: &[u8]) -> io::Result<()> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
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

/// The in-band hole-punch signal channel for an nz session: length-implicit
/// messages carried as `CH_SIGNAL` data frames over the same E2E cipher as the
/// tunnel. It shares the transport's `send_counter` (so the two never collide on
/// an AEAD nonce) and receives via the transport reader's `CH_SIGNAL` split.
/// The API mirrors [`crate::signal::SignalChannel`] so the direct-upgrade code
/// treats both carriers alike.
pub struct NoiseSignal {
    sig_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    session: Arc<NoiseSession>,
    hp_key: ring::hmac::Key,
    peer_index: u32,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    send_counter: Arc<AtomicU64>,
}

impl NoiseSignal {
    /// Send one signal message (a full-send, not the data path's drop-on-full —
    /// signaling is low-rate and wants delivery).
    pub(crate) async fn send_signal(&mut self, data: &[u8]) -> io::Result<()> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let pkt = frame_data(
            &self.session,
            &self.hp_key,
            self.peer_index,
            counter,
            CH_SIGNAL,
            data,
        )
        .map_err(io::Error::other)?;
        self.socket.send_to(&pkt, self.peer_addr).await.map(|_| ())
    }

    /// Receive one signal message. Returns `None` only when the session driver
    /// dies (the reader dropped its sender) — never on a single lost datagram,
    /// which the upgrade loop's own timeout handles by retrying the round.
    pub(crate) async fn recv_signal(&mut self) -> Option<Vec<u8>> {
        self.sig_rx.recv().await
    }

    /// Point the signal channel's sends at a new peer address — used when the
    /// session migrates from the relay to a punched direct socket.
    pub(crate) fn set_peer_addr(&mut self, addr: SocketAddr) {
        self.peer_addr = addr;
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
        if let Some(pump) = &self.pump {
            pump.abort();
        }
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
            noise_accept(
                a_sock,
                rx_a,
                rand::random(),
                Some(pump_a),
                &id,
                Duration::from_secs(5),
                DEFAULT_IDLE,
            )
            .await
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

    /// Crypto-backend guard: per-packet frame+deframe throughput. This is a
    /// regression test for the snow `ring-accelerated` feature — without it,
    /// snow's pure-Rust AEAD runs at ~19 Mbit/s in a debug build (which left nz
    /// CPU-bound at half of QUIC); ring's asm does ~1 Gbit/s. The 200 Mbit/s
    /// floor sits far above pure-Rust-debug and far below ring, so it fails only
    /// if the fast backend is lost, not from machine noise.
    #[test]
    fn crypto_backend_is_fast_enough() {
        let identity = Identity::generate();
        let mut hs_b = NoiseHandshake::initiator(&identity.routing_key, &identity.secret).unwrap();
        let mut hs_a = NoiseHandshake::responder(&identity).unwrap();
        let m1 = hs_b.write_message(&[]).unwrap();
        hs_a.read_message(&m1).unwrap();
        let m2 = hs_a.write_message(&[]).unwrap();
        hs_b.read_message(&m2).unwrap();
        let a = hs_a.into_session().unwrap();
        let b = hs_b.into_session().unwrap();
        let hp = derive_hp_key(&a.handshake_hash);
        let payload = vec![0x5au8; 1120];
        let n = 8_000u64;
        let t = std::time::Instant::now();
        for i in 0..n {
            let f = frame_data(&a, &hp, 0x1122_3344, i, CH_IP, &payload).unwrap();
            deframe_data(&b, &hp, 0x1122_3344, &f).unwrap();
        }
        let mbps = (n as f64 * 1120.0 * 8.0) / t.elapsed().as_secs_f64() / 1e6;
        println!("nz frame+deframe: {mbps:.0} Mbit/s");
        assert!(mbps > 200.0, "nz crypto only {mbps:.0} Mbit/s — is snow ring-accelerated?");
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

    /// DPI wire-image: the bytes that actually go on the wire carry neither a
    /// QUIC fingerprint nor a WireGuard-style counter tell — the whole point of
    /// the nz carrier. (A full on-path capture is a lab/DPI-harness follow-up;
    /// this asserts the properties on the exact bytes the framing emits.)
    #[test]
    fn wire_image_carries_no_quic_or_counter_fingerprint() {
        let identity = Identity::generate();
        let mut hs_b = NoiseHandshake::initiator(&identity.routing_key, &identity.secret).unwrap();
        let idx_b: u32 = 0xDEAD_BEEF;
        let noise_msg1 = hs_b.write_message(&[]).unwrap();

        // Reconstruct the on-wire msg1 exactly as noise_connect frames it.
        let mut msg1 = Vec::new();
        msg1.extend_from_slice(&identity.routing_key);
        msg1.extend_from_slice(&idx_b.to_be_bytes());
        msg1.extend_from_slice(&noise_msg1);

        // A QUIC v1 long-header Initial has the fixed bit set and version
        // 0x00000001 at bytes 1..5. An on-path QUIC classifier keys on that
        // version; nz's bytes there are the routing key's, so they are not it.
        assert_ne!(
            &msg1[1..5],
            &[0x00, 0x00, 0x00, 0x01],
            "msg1 must not present QUIC v1's version field"
        );
        // No leading Spora relay-control magic either (that is 0x80 'spR' 0x01).
        assert_ne!(&msg1[0..4], b"\x80spR", "msg1 must not look like a control packet");

        // Across many data packets with sequential counters, the on-wire counter
        // field must never appear in the clear and must not advance by a constant
        // delta (the WireGuard-family tell the design review flagged as fatal).
        let mut hs_a = NoiseHandshake::responder(&identity).unwrap();
        hs_a.read_message(&noise_msg1).unwrap();
        let m2 = hs_a.write_message(&[]).unwrap();
        hs_b.read_message(&m2).unwrap();
        let a_sess = hs_a.into_session().unwrap();
        let hp = derive_hp_key(&a_sess.handshake_hash);

        let idx = 0x0102_0304u32;
        let mut wire_counters: Vec<[u8; COUNTER_LEN]> = Vec::new();
        for counter in 0u64..16 {
            let pkt = frame_data(&a_sess, &hp, idx, counter, CH_IP, b"payload").unwrap();
            let mut cf = [0u8; COUNTER_LEN];
            cf.copy_from_slice(&pkt[INDEX_LEN..DATA_HEADER_LEN]);
            assert_ne!(cf, counter.to_be_bytes(), "counter {counter} appears in the clear");
            wire_counters.push(cf);
        }
        // No two on-wire counter fields collide, and no constant stride links
        // them (a masked counter is pseudo-random, not counter+k).
        for i in 1..wire_counters.len() {
            assert_ne!(wire_counters[i], wire_counters[i - 1], "adjacent counters collide");
            let delta_prev = u64::from_be_bytes(wire_counters[1]).wrapping_sub(u64::from_be_bytes(wire_counters[0]));
            let delta_i = u64::from_be_bytes(wire_counters[i]).wrapping_sub(u64::from_be_bytes(wire_counters[i - 1]));
            if i > 1 {
                assert_ne!(delta_i, delta_prev, "counter field advances by a constant stride");
            }
        }
    }

    #[tokio::test]
    async fn in_band_signal_round_trips_both_directions() {
        let (mut a, mut b) = connected_pair(Identity::generate()).await;
        let mut a_sig = a.take_signal().expect("A has a signal channel");
        let mut b_sig = b.take_signal().expect("B has a signal channel");

        // A -> B (a hole-punch endpoint blob, as neg.rs would send).
        a_sig.send_signal(b"203.0.113.7:41000").await.unwrap();
        let got = timeout(Duration::from_secs(2), b_sig.recv_signal())
            .await
            .expect("B receives")
            .expect("a message, not driver death");
        assert_eq!(got, b"203.0.113.7:41000");

        // B -> A, on the same session (shares the data cipher + counter).
        b_sig.send_signal(b"198.51.100.9:42000").await.unwrap();
        let got = timeout(Duration::from_secs(2), a_sig.recv_signal())
            .await
            .expect("A receives")
            .expect("a message");
        assert_eq!(got, b"198.51.100.9:42000");

        // Signals interleave with tunnel data without nonce collision (shared
        // counter): a data packet still deframes after the signals.
        b.send(ipv4_udp(64)).await.unwrap();
        let pkt = timeout(Duration::from_secs(2), a.next())
            .await
            .expect("A receives data")
            .expect("open")
            .expect("no error");
        assert_eq!(pkt.len(), ipv4_udp(64).len());

        // take_signal is once-only.
        assert!(a.take_signal().is_none());
    }
}
