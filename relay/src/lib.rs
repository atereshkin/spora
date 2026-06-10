//! Dumb UDP relay library. The binary in `main.rs` is a thin wrapper around
//! [`serve`].
//!
//! Wire protocol (see also `relay_client::protocol`):
//!   - A (sharer) sends `[CTRL_MAGIC | REGISTER | routing_key(20)]` to the
//!     relay every ~30s. The relay stores `routing_key -> A's UDP addr`.
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
    registrations: HashMap<RoutingKey, (SocketAddr, Instant)>,
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
            if let Some((sharer_addr, _)) = self.registrations.get(&rk).copied() {
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
                if body.len() != ROUTING_KEY_LEN {
                    warn!(
                        "REGISTER from {} has wrong body length {}, expected {}",
                        src,
                        body.len(),
                        ROUTING_KEY_LEN
                    );
                    return;
                }
                let mut rk = [0u8; ROUTING_KEY_LEN];
                rk.copy_from_slice(body);
                let is_new = !self.registrations.contains_key(&rk);
                self.registrations.insert(rk, (src, now));
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
            .retain(|_, (_, ts)| now.duration_since(*ts) < registration_timeout);
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
    use relay_client::protocol::build_register;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
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

        let reg = build_register(&rk(0xAA));
        assert_eq!(s.handle_packet(a_addr, &reg, now), Action::Drop);
        assert_eq!(s.registration_count(), 1);

        let initial = initial_with_dcid(&rk(0xAA));
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

        s.handle_packet(a, &build_register(&rk(0x11)), now);
        s.handle_packet(b1, &initial_with_dcid(&rk(0x11)), now);
        assert_eq!(s.flow_count(), 2);

        assert_eq!(
            s.handle_packet(b2, &initial_with_dcid(&rk(0x11)), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 2);

        assert_eq!(s.handle_packet(b1, &short_header(), now), Action::Forward(a));
    }

    #[test]
    fn flow_timestamp_refreshes_on_traffic() {
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b = addr("10.0.0.2:2222");

        s.handle_packet(a, &build_register(&rk(0x22)), t0);
        s.handle_packet(b, &initial_with_dcid(&rk(0x22)), t0);

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
        s.handle_packet(addr("10.0.0.1:1"), &build_register(&rk(0x33)), t0);
        assert_eq!(s.registration_count(), 1);
        s.sweep(t0 + REGISTRATION_TIMEOUT - Duration::from_secs(1));
        assert_eq!(s.registration_count(), 1);
        s.sweep(t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn registration_refresh_extends_timestamp() {
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1");
        s.handle_packet(a, &build_register(&rk(0x44)), t0);
        let t1 = t0 + REGISTRATION_TIMEOUT - Duration::from_secs(5);
        s.handle_packet(a, &build_register(&rk(0x44)), t1);
        s.sweep(t0 + REGISTRATION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(s.registration_count(), 1);
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

        let key = rk(0x77);

        a_sock
            .send_to(&build_register(&key), relay_addr)
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
