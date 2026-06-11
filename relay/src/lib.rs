//! Dumb UDP relay library. The binary in `main.rs` is a thin wrapper around
//! [`serve`].
//!
//! Wire protocol (see also `relay_client::protocol`):
//!   - A (sharer) sends a signed `REGISTER` (routing key + timestamp + cert +
//!     signature) to the relay every ~30s. The relay verifies the signature
//!     and the `routing_key == SHA-256(cert)[..20]` commitment, enforces a
//!     strictly-increasing timestamp (replay guard), and stores
//!     `routing_key -> A's UDP addr`. It holds no secret — it only verifies.
//!   - B (client) sends a QUIC Initial with DCID = `routing_key`. The relay
//!     reads the DCID out of the long header, looks up A's addr, installs
//!     a bidirectional flow `(B_addr <-> A_addr)`, and forwards.
//!   - Subsequent packets (long or short header) from either flow endpoint
//!     are forwarded by source-address lookup.
//!   - Idle entries time out (registrations ~120s, flows ~60s).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::net::UdpSocket;

use relay_client::protocol::{self, Classified, ROUTING_KEY_LEN};

pub const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(120);
pub const FLOW_TIMEOUT: Duration = Duration::from_secs(60);
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
pub const RECV_BUF: usize = 4096;

pub type RoutingKey = [u8; ROUTING_KEY_LEN];

pub struct State {
    /// `routing_key -> (sharer addr, last-seen Instant, last-accepted signed
    /// timestamp)`. The timestamp is the replay guard: a REGISTER is only
    /// accepted if its signed timestamp strictly exceeds the stored one, so a
    /// captured registration replayed (e.g. from another source) is rejected
    /// while the genuine sharer keeps refreshing.
    registrations: HashMap<RoutingKey, (SocketAddr, Instant, u64)>,
    flows: HashMap<SocketAddr, (SocketAddr, Instant)>,
    registration_timeout: Duration,
    flow_timeout: Duration,
    sweep_interval: Duration,
}

impl Default for State {
    fn default() -> Self {
        Self::with_timeouts(REGISTRATION_TIMEOUT, FLOW_TIMEOUT, SWEEP_INTERVAL)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Forward(SocketAddr),
    Drop,
}

/// Addresses the relay refuses to register or forward to. Unspecified,
/// multicast, and broadcast are never legitimate peer addresses; forwarding to
/// them turns the relay into a reflector/amplifier (one inbound packet → a
/// multicast group, etc.). Loopback is intentionally allowed so the unit/lab
/// tests and local development can run every peer on 127.0.0.1.
fn is_relayable(addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_broadcast(),
        std::net::IpAddr::V6(_) => true,
    }
}

impl State {
    /// Build a `State` with custom expiry timeouts and sweep cadence
    /// (defaults: 120s / 60s / 5s). Used by tests and the e2e lab to make
    /// expiry scenarios run in seconds of wall time.
    pub fn with_timeouts(
        registration_timeout: Duration,
        flow_timeout: Duration,
        sweep_interval: Duration,
    ) -> State {
        State {
            registrations: HashMap::new(),
            flows: HashMap::new(),
            registration_timeout,
            flow_timeout,
            sweep_interval,
        }
    }

    /// Decide what to do with a packet from `src`. Updates internal state
    /// (registrations, flow timestamps) and returns the address to forward
    /// the bytes to, or `Drop`.
    pub fn handle_packet(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Action {
        let classified = protocol::classify(pkt);

        if let Classified::Control { ty, body } = classified {
            self.handle_control(src, ty, body, now);
            return Action::Drop;
        }

        // Existing flow? Forward by source-address lookup. This covers both
        // long- and short-header packets after the first match.
        if let Some((dst, ts)) = self.flows.get_mut(&src) {
            *ts = now;
            return Action::Forward(*dst);
        }

        // Unmatched source — only QUIC long-header packets with a DCID equal
        // to a registered routing key can install a new flow.
        if let Classified::QuicLongHeader { dcid } = classified
            && dcid.len() == ROUTING_KEY_LEN
        {
            let mut rk: RoutingKey = [0u8; ROUTING_KEY_LEN];
            rk.copy_from_slice(dcid);
            if let Some((sharer_addr, reg_ts, _)) = self.registrations.get(&rk).copied() {
                // Refuse a self-referential or non-relayable flow *before* the
                // one-at-a-time check, so a spoofed packet can neither bootstrap
                // a self-sustaining loop nor occupy the sharer's flow slot.
                // flows.insert(src, ...) and flows.insert(sharer_addr, ...)
                // collapse to flows[X] = (X) when src == sharer_addr, which
                // would make the relay forward every packet from X back to X
                // forever from a single (spoofed) packet.
                if src == sharer_addr || !is_relayable(&src) {
                    debug!(
                        "refusing self-referential/non-relayable flow for {} (rk {:x?})",
                        src,
                        &rk[..4]
                    );
                    return Action::Drop;
                }
                // Sweep only runs when packets arrive, so a quiet relay can
                // still hold a registration well past its timeout. Treat an
                // expired one as absent (and drop it now) — otherwise we'd
                // forward to a dead sharer and, worse, install a flow keyed
                // to its address that blocks its one-flow slot until the
                // flow itself times out.
                if now.duration_since(reg_ts) >= self.registration_timeout {
                    self.registrations.remove(&rk);
                    debug!("ignoring expired registration rk {:x?} for client {}", &rk[..4], src);
                    return Action::Drop;
                }
                // One-at-a-time: if the sharer is already in a flow, drop the
                // new attempt. The first client's flow has to time out (or
                // its QUIC connection has to end) before another client can
                // be routed to the same sharer.
                if self.flows.contains_key(&sharer_addr) {
                    debug!(
                        "dropping new client {} for already-serving sharer {} (rk {:x?})",
                        src,
                        sharer_addr,
                        &rk[..4]
                    );
                    return Action::Drop;
                }
                self.flows.insert(src, (sharer_addr, now));
                self.flows.insert(sharer_addr, (src, now));
                info!(
                    "matched client {} <-> sharer {} on rk {:x?}",
                    src,
                    sharer_addr,
                    &rk[..4]
                );
                return Action::Forward(sharer_addr);
            }
        }

        Action::Drop
    }

    fn handle_control(&mut self, src: SocketAddr, ty: u8, body: &[u8], now: Instant) {
        match ty {
            protocol::ctrl::REGISTER => {
                // Cheap source check before spending a signature verification.
                if !is_relayable(&src) {
                    warn!("ignoring REGISTER from non-relayable source {}", src);
                    return;
                }
                // Verify the signature and that the routing key commits to the
                // presented cert. We hold no secret — this only proves the
                // registration was authorized by the key the routing key pins.
                let (rk, ts) = match protocol::verify_signed_register(body) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("rejecting REGISTER from {}: {:?}", src, e);
                        return;
                    }
                };
                // Replay guard: the signed timestamp must strictly exceed the
                // last one accepted for this key. A captured registration
                // replayed (e.g. from an attacker's address) carries an
                // already-seen timestamp and is dropped; the genuine sharer's
                // next refresh always carries a fresh higher one.
                if let Some((_, _, last_ts)) = self.registrations.get(&rk)
                    && ts <= *last_ts
                {
                    debug!(
                        "rejecting stale/replayed REGISTER for rk {:x?} from {} (ts {} <= {})",
                        &rk[..4], src, ts, last_ts
                    );
                    return;
                }
                let is_new = !self.registrations.contains_key(&rk);
                self.registrations.insert(rk, (src, now, ts));
                if is_new {
                    info!("REGISTER rk {:x?} from {}", &rk[..4], src);
                } else {
                    debug!("REGISTER refresh rk {:x?} from {}", &rk[..4], src);
                }
            }
            other => warn!("unknown control type 0x{:02x} from {}", other, src),
        }
    }

    /// Drop expired registrations and flows.
    pub fn sweep(&mut self, now: Instant) {
        let before_reg = self.registrations.len();
        let before_flows = self.flows.len();
        let registration_timeout = self.registration_timeout;
        let flow_timeout = self.flow_timeout;
        self.registrations
            .retain(|_, (_, ts, _)| now.duration_since(*ts) < registration_timeout);
        self.flows
            .retain(|_, (_, ts)| now.duration_since(*ts) < flow_timeout);
        let reg_removed = before_reg - self.registrations.len();
        let flow_removed = before_flows - self.flows.len();
        if reg_removed + flow_removed > 0 {
            debug!(
                "sweep: removed {} registrations, {} flow entries",
                reg_removed, flow_removed
            );
        }
    }

    pub fn registration_count(&self) -> usize {
        self.registrations.len()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Main recv/forward loop. Runs forever.
pub async fn serve(socket: UdpSocket, mut state: State) {
    let mut buf = vec![0u8; RECV_BUF];
    let mut last_sweep = Instant::now();
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("recv error: {}", e);
                continue;
            }
        };
        let now = Instant::now();
        if let Action::Forward(dst) = state.handle_packet(src, &buf[..n], now)
            && let Err(e) = socket.send_to(&buf[..n], dst).await
        {
            warn!("send_to {} ({} bytes) failed: {}", dst, n, e);
        }
        if now.duration_since(last_sweep) >= state.sweep_interval {
            state.sweep(now);
            last_sweep = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_client::protocol::RegisterSigner;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A sharer-side signer with a fresh random ECDSA-P256 cert. Its
    /// `routing_key()` is the SHA-256 commitment the relay verifies, and
    /// `next_register_packet()` produces a valid signed REGISTER each call.
    fn registrar() -> RegisterSigner {
        let ck = rcgen::generate_simple_self_signed(vec!["spora.peer".to_string()]).unwrap();
        RegisterSigner::new(&ck.cert.der().to_vec(), &ck.key_pair.serialize_der()).unwrap()
    }

    fn initial_with_dcid(dcid: &[u8]) -> Vec<u8> {
        // Minimal QUIC long-header shape: 0xC0, version(4), dcid_len, dcid
        let mut pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, dcid.len() as u8];
        pkt.extend_from_slice(dcid);
        pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        pkt
    }

    fn short_header() -> Vec<u8> {
        vec![0x40, 0x11, 0x22, 0x33, 0x44]
    }

    fn rk(seed: u8) -> RoutingKey {
        [seed; ROUTING_KEY_LEN]
    }

    #[test]
    fn register_then_match_installs_bidirectional_flow() {
        let mut s = State::default();
        let now = Instant::now();
        let a_addr = addr("10.0.0.1:1111");
        let b_addr = addr("10.0.0.2:2222");

        let mut a = registrar();
        let key = a.routing_key();
        assert_eq!(s.handle_packet(a_addr, &a.next_register_packet(), now), Action::Drop);
        assert_eq!(s.registration_count(), 1);

        let initial = initial_with_dcid(&key);
        assert_eq!(s.handle_packet(b_addr, &initial, now), Action::Forward(a_addr));
        assert_eq!(s.flow_count(), 2);

        let pkt = short_header();
        assert_eq!(s.handle_packet(a_addr, &pkt, now), Action::Forward(b_addr));
        assert_eq!(s.handle_packet(b_addr, &pkt, now), Action::Forward(a_addr));
    }

    #[test]
    fn unregistered_dcid_is_dropped() {
        let mut s = State::default();
        let initial = initial_with_dcid(&rk(0xCC));
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &initial, Instant::now()),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn short_header_from_unknown_src_is_dropped() {
        let mut s = State::default();
        let pkt = short_header();
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &pkt, Instant::now()),
            Action::Drop
        );
    }

    #[test]
    fn second_client_dropped_while_first_flow_active() {
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b1 = addr("10.0.0.2:2222");
        let b2 = addr("10.0.0.3:3333");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);
        s.handle_packet(b1, &initial_with_dcid(&key), now);
        assert_eq!(s.flow_count(), 2);

        assert_eq!(
            s.handle_packet(b2, &initial_with_dcid(&key), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 2);

        assert_eq!(s.handle_packet(b1, &short_header(), now), Action::Forward(a));
    }

    #[test]
    fn self_referential_flow_is_refused() {
        // A client whose source address equals the registered sharer address
        // (achievable by spoofing the source) must not install a flow: it would
        // collapse to flows[X] = (X) and self-forward forever. Reproduces the
        // single-packet relay loop from the review.
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);
        assert_eq!(
            s.handle_packet(a, &initial_with_dcid(&key), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 0, "no self-referential flow installed");
        // And the sharer's slot is still free for a genuine client afterwards.
        let b = addr("10.0.0.2:2222");
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(a)
        );
    }

    #[test]
    fn register_from_non_relayable_source_is_ignored() {
        let mut s = State::default();
        let now = Instant::now();
        let mut reg = registrar();
        // 0.0.0.0 (unspecified) and a multicast address must not be bound, even
        // with an otherwise-valid signature.
        assert_eq!(
            s.handle_packet(addr("0.0.0.0:9"), &reg.next_register_packet(), now),
            Action::Drop
        );
        assert_eq!(
            s.handle_packet(addr("224.0.0.1:9"), &reg.next_register_packet(), now),
            Action::Drop
        );
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn non_relayable_client_source_installs_no_flow() {
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);
        // A client Initial whose (spoofed) source is multicast must be dropped,
        // so the relay never reflects/amplifies to a multicast group.
        assert_eq!(
            s.handle_packet(addr("224.0.0.5:7"), &initial_with_dcid(&key), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn flow_timestamp_refreshes_on_traffic() {
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b = addr("10.0.0.2:2222");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), t0);
        s.handle_packet(b, &initial_with_dcid(&key), t0);

        let t1 = t0 + Duration::from_secs(50);
        s.handle_packet(b, &short_header(), t1);
        s.sweep(t1 + Duration::from_secs(5));
        assert_eq!(s.flow_count(), 2, "flow should still be alive");

        s.sweep(t1 + Duration::from_secs(70));
        assert_eq!(s.flow_count(), 0);
    }

    #[test]
    fn registration_expires_after_timeout() {
        let mut s = State::default();
        let t0 = Instant::now();
        let mut reg = registrar();
        s.handle_packet(addr("10.0.0.1:1"), &reg.next_register_packet(), t0);
        assert_eq!(s.registration_count(), 1);
        s.sweep(t0 + REGISTRATION_TIMEOUT - Duration::from_secs(1));
        assert_eq!(s.registration_count(), 1);
        s.sweep(t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn expired_registration_does_not_match_even_without_a_sweep() {
        // A quiet relay never sweeps; a client arriving after the timeout
        // must NOT be forwarded to the stale sharer (and no flow installed).
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b = addr("10.0.0.2:2222");
        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), t0);

        let late = t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1);
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), late),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 0, "no flow installed off a stale registration");
        assert_eq!(s.registration_count(), 0, "stale registration dropped on access");
    }

    #[test]
    fn registration_refresh_extends_timestamp() {
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1");
        let mut reg = registrar();
        s.handle_packet(a, &reg.next_register_packet(), t0);
        let t1 = t0 + REGISTRATION_TIMEOUT - Duration::from_secs(5);
        // A refresh carries a strictly-greater signed timestamp, so the relay
        // accepts it and extends the registration.
        s.handle_packet(a, &reg.next_register_packet(), t1);
        s.sweep(t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(s.registration_count(), 1);
    }

    #[test]
    fn replayed_register_from_other_source_does_not_rebind() {
        // The #2 fix: an on-path attacker who captures a valid REGISTER cannot
        // rebind the key by replaying it from its own address — the replayed
        // copy carries an already-seen timestamp and is refused.
        let mut s = State::default();
        let now = Instant::now();
        let sharer = addr("10.0.0.1:1111");
        let attacker = addr("10.9.9.9:9999");
        let mut reg = registrar();
        let key = reg.routing_key();

        let pkt = reg.next_register_packet();
        assert_eq!(s.handle_packet(sharer, &pkt, now), Action::Drop);
        // Attacker replays the identical bytes from its own source.
        assert_eq!(s.handle_packet(attacker, &pkt, now), Action::Drop);

        // A client is still routed to the genuine sharer, not the attacker.
        let b = addr("10.0.0.2:2222");
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(sharer)
        );
    }

    #[test]
    fn forged_register_for_known_routing_key_is_rejected() {
        // Knowing the (public) routing key is not enough: an attacker using
        // their own cert/key cannot register someone else's routing key,
        // because it no longer commits to the presented cert.
        let mut s = State::default();
        let now = Instant::now();
        let victim_key = registrar().routing_key();

        let mut attacker = registrar();
        let pkt = attacker.next_register_packet();
        let mut body = pkt[protocol::CTRL_MAGIC.len() + 1..].to_vec();
        body[..ROUTING_KEY_LEN].copy_from_slice(&victim_key);
        s.handle_control(addr("10.9.9.9:9"), protocol::ctrl::REGISTER, &body, now);
        assert_eq!(s.registration_count(), 0, "forged register must not bind");
    }

    #[test]
    fn malformed_register_is_ignored() {
        let mut s = State::default();
        let mut bad = protocol::CTRL_MAGIC.to_vec();
        bad.push(protocol::ctrl::REGISTER);
        bad.extend_from_slice(&[0xFFu8; 5]);
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &bad, Instant::now()),
            Action::Drop
        );
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn empty_packet_is_dropped() {
        let mut s = State::default();
        assert_eq!(
            s.handle_packet(addr("1.2.3.4:5"), &[], Instant::now()),
            Action::Drop
        );
    }

    #[tokio::test]
    async fn end_to_end_forwarding_via_real_sockets() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let _serve = tokio::spawn(serve(relay_sock, State::default()));

        let a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut reg = registrar();
        let key = reg.routing_key();

        a_sock
            .send_to(&reg.next_register_packet(), relay_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let initial = initial_with_dcid(&key);
        b_sock.send_to(&initial, relay_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let recv = tokio::time::timeout(Duration::from_secs(1), a_sock.recv_from(&mut buf))
            .await
            .expect("A should receive B's initial")
            .unwrap();
        assert_eq!(&buf[..recv.0], &initial[..]);
        assert_eq!(recv.1, relay_addr);

        let reply = vec![0x40, 0x00, 0xCA, 0xFE];
        a_sock.send_to(&reply, relay_addr).await.unwrap();
        let recv = tokio::time::timeout(Duration::from_secs(1), b_sock.recv_from(&mut buf))
            .await
            .expect("B should receive A's reply")
            .unwrap();
        assert_eq!(&buf[..recv.0], &reply[..]);
        assert_eq!(recv.1, relay_addr);
    }
}
