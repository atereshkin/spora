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
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::net::UdpSocket;

use relay_client::authz::{self, ISSUER_PUBKEY_LEN};
use relay_client::protocol::{self, Classified, ROUTING_KEY_LEN};

pub mod sessionlog;
use sessionlog::{SessionLog, SessionState};

pub const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(120);
pub const FLOW_TIMEOUT: Duration = Duration::from_secs(60);
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
pub const RECV_BUF: usize = 4096;

/// How long after the sharer last sent toward its client the flow still counts
/// as "actively serving" (and so blocks a new client). Must exceed the sharer's
/// QUIC keep-alive cadence (10s) so a live but idle session stays protected
/// between keep-alive PINGs; short enough that a rejected/abandoned connection
/// frees the slot quickly. See the one-at-a-time logic in `handle_packet`.
pub const REVERSE_ACTIVITY_GRACE: Duration = Duration::from_secs(20);

pub type RoutingKey = [u8; ROUTING_KEY_LEN];

/// A forwarding-table entry. Stored under both endpoints of a flow.
#[derive(Clone)]
struct Flow {
    /// Where to forward packets arriving from this entry's key address.
    dst: SocketAddr,
    /// Last time any packet refreshed this entry (for idle expiry).
    ts: Instant,
    /// `true` for the entry keyed by the sharer's address (so its `dst` is the
    /// client). Lets the forwarder record return traffic only for the real
    /// sharer→client direction.
    from_sharer: bool,
    /// On the sharer-keyed entry only: when the sharer last sent toward the
    /// client. `None` until the sharer responds. Drives the "actively serving"
    /// check that protects an established client from being displaced.
    reverse: Option<Instant>,
    /// Shared session accounting for the connection log, present on BOTH of a
    /// flow's entries (so either direction's bytes land in the same totals).
    /// `None` when session logging is disabled — keeps the no-log path free.
    session: Option<Arc<SessionState>>,
}

pub struct State {
    /// `routing_key -> (sharer addr, last-seen Instant, last-accepted signed
    /// timestamp)`. The timestamp is the replay guard: a REGISTER is only
    /// accepted if its signed timestamp strictly exceeds the stored one, so a
    /// captured registration replayed (e.g. from another source) is rejected
    /// while the genuine sharer keeps refreshing.
    registrations: HashMap<RoutingKey, (SocketAddr, Instant, u64)>,
    flows: HashMap<SocketAddr, Flow>,
    registration_timeout: Duration,
    flow_timeout: Duration,
    sweep_interval: Duration,
    /// Trusted capability-token issuer public keys. **Empty means open mode**:
    /// any validly self-signed registration is accepted (today's behavior).
    /// When non-empty, a registration must carry a capability token that is
    /// signed by one of these issuers, marked allowed, and bound to the routing
    /// key being registered — see [`authz`].
    issuer_keys: Vec<[u8; ISSUER_PUBKEY_LEN]>,
    /// Optional persistent session log (off by default; the deployed binary
    /// attaches one). Records each matched flow for operator accountability —
    /// see [`sessionlog`].
    session_log: Option<SessionLog>,
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
///
/// The IP is canonicalized for the *policy check only*: on a dual-stack
/// socket v4 peers appear as v4-mapped (`::ffff:a.b.c.d`), and without
/// canonicalization `::ffff:224.0.0.1` / `::ffff:255.255.255.255` /
/// `::ffff:0.0.0.0` would walk past the v6 arm. The stored/forwarded
/// `SocketAddr` keeps its kernel-reported (mapped) form — send_to with a
/// plain V4 address on an AF_INET6 socket fails.
fn is_relayable(addr: &SocketAddr) -> bool {
    let ip = addr.ip().to_canonical();
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
            issuer_keys: Vec::new(),
            session_log: None,
        }
    }

    /// Attach a persistent session log (the deployed binary does this; tests
    /// and the lab leave it off). Builder-style so `State::default()` stays
    /// the logging-free path.
    pub fn with_session_log(mut self, log: SessionLog) -> State {
        self.session_log = Some(log);
        self
    }

    /// Require capability-token authorization, trusting the given issuer public
    /// keys. Builder-style; passing an empty set leaves the relay in open mode.
    /// See [`authz`] and [`State::handle_control`].
    pub fn with_issuer_keys(mut self, keys: Vec<[u8; ISSUER_PUBKEY_LEN]>) -> State {
        self.issuer_keys = keys;
        self
    }

    /// Whether the relay requires capability-token authorization (i.e. it has at
    /// least one trusted issuer key configured).
    pub fn requires_authorization(&self) -> bool {
        !self.issuer_keys.is_empty()
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
        if let Some(flow) = self.flows.get_mut(&src) {
            flow.ts = now;
            let from_sharer = flow.from_sharer;
            // Record sharer→client return traffic so we can tell an actively
            // served client (protected) from an idle/abandoned flow.
            if from_sharer {
                flow.reverse = Some(now);
            }
            // Session accounting (hot path: one atomic add per direction).
            if let Some(s) = &flow.session {
                if from_sharer {
                    s.add_s2c(pkt.len() as u64);
                } else {
                    s.add_c2s(pkt.len() as u64);
                }
            }
            return Action::Forward(flow.dst);
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
                // One-at-a-time, but only against an *actively serving* sharer.
                // A flow counts as serving only while the sharer is returning
                // traffic to its current client (within REVERSE_ACTIVITY_GRACE).
                // A party that merely knows the (public) routing key can install
                // a flow and keep sending client→sharer packets, but the sharer
                // never returns sustained traffic to an unauthenticated peer (it
                // closes the QUIC connection on auth failure/timeout), so that
                // flow falls idle and a genuine client can displace it. Without
                // this, a single Initial-shaped packet refreshed every <60s would
                // hold the slot and lock out every real client.
                let mut preserved_reverse = None;
                let mut reused_session: Option<Arc<SessionState>> = None;
                if let Some(existing) = self.flows.get(&sharer_addr).cloned() {
                    if existing.dst == src {
                        // Same client re-sending (e.g. an Initial retransmit):
                        // keep its established serving state AND its session, so
                        // a retransmit refreshes rather than opening a duplicate.
                        preserved_reverse = existing.reverse;
                        reused_session = existing.session.clone();
                    } else {
                        let serving = existing
                            .reverse
                            .is_some_and(|t| now.duration_since(t) < REVERSE_ACTIVITY_GRACE);
                        if serving {
                            debug!(
                                "dropping client {} for actively-serving sharer {} (rk {:x?})",
                                src, sharer_addr, &rk[..4]
                            );
                            return Action::Drop;
                        }
                        // Idle/abandoned incumbent — close its session and
                        // displace it for this client.
                        if let (Some(log), Some(s)) = (&self.session_log, &existing.session) {
                            log.close_session(s, "displaced");
                        }
                        self.flows.remove(&existing.dst);
                    }
                }
                // Open (or reuse, on retransmit) the session for this flow. Only
                // allocated when logging is on, so the no-log path stays free.
                let session = match (reused_session, &self.session_log) {
                    (Some(s), _) => Some(s),
                    (None, Some(log)) => Some(log.open_session(&rk, src, sharer_addr)),
                    (None, None) => None,
                };
                if let Some(s) = &session {
                    // Count the client Initial that installed the flow.
                    s.add_c2s(pkt.len() as u64);
                }
                self.flows.insert(
                    src,
                    Flow {
                        dst: sharer_addr,
                        ts: now,
                        from_sharer: false,
                        reverse: None,
                        session: session.clone(),
                    },
                );
                self.flows.insert(
                    sharer_addr,
                    Flow {
                        dst: src,
                        ts: now,
                        from_sharer: true,
                        reverse: preserved_reverse,
                        session,
                    },
                );
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
                let (rk, ts, token) = match protocol::verify_signed_register(body) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("rejecting REGISTER from {}: {:?}", src, e);
                        return;
                    }
                };
                // Authorization: in authorized mode (issuer keys configured) the
                // registration must carry a valid capability token bound to this
                // routing key. The registration signature above already proved
                // possession of the key, so a token that names this routing key
                // is non-transferable. In open mode (no issuer keys) any token
                // (including none) is accepted — today's behavior.
                if !self.issuer_keys.is_empty()
                    && let Err(e) = authz::verify_token(token, &rk, &self.issuer_keys)
                {
                    warn!(
                        "rejecting unauthorized REGISTER for rk {:x?} from {}: {:?}",
                        &rk[..4], src, e
                    );
                    return;
                }
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
        // Close the session log entry for each expired flow before dropping it.
        // The shared `SessionState` makes the close idempotent, so the flow's
        // two entries (which may expire in different sweeps) emit exactly one
        // close. Borrow the log separately from `flows` (disjoint fields).
        let log = self.session_log.as_ref();
        self.flows.retain(|_, flow| {
            let alive = now.duration_since(flow.ts) < flow_timeout;
            if !alive
                && let (Some(log), Some(s)) = (log, &flow.session)
            {
                log.close_session(s, "idle");
            }
            alive
        });
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

    /// A registrar carrying a valid "allowed" capability token issued for its
    /// own routing key by `issuer`.
    fn authorized_registrar(issuer: &authz::IssuerKeyPair) -> RegisterSigner {
        let signer = registrar();
        let token = issuer.issue(&signer.routing_key());
        signer.with_token(Some(token))
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
        // The sharer returns traffic to b1, so the flow is actively serving.
        assert_eq!(s.handle_packet(a, &short_header(), now), Action::Forward(b1));

        // A second client is now dropped while b1 is actively served.
        assert_eq!(
            s.handle_packet(b2, &initial_with_dcid(&key), now),
            Action::Drop
        );
        assert_eq!(s.flow_count(), 2);

        assert_eq!(s.handle_packet(b1, &short_header(), now), Action::Forward(a));
    }

    #[test]
    fn idle_flow_is_displaced_by_a_new_client() {
        // The #3 fix: a flow with no return traffic from the sharer (an
        // attacker who knows the routing key but can't get served) does not
        // lock out a genuine client.
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let attacker = addr("10.9.9.9:9999");
        let client = addr("10.0.0.2:2222");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);

        // Attacker installs a flow but the sharer never returns traffic to it.
        assert_eq!(s.handle_packet(attacker, &initial_with_dcid(&key), now), Action::Forward(a));
        // A genuine client displaces the idle flow.
        assert_eq!(s.handle_packet(client, &initial_with_dcid(&key), now), Action::Forward(a));
        // The sharer now routes to the genuine client, and the attacker's stale
        // entry is gone (its packets no longer match a flow).
        assert_eq!(s.handle_packet(a, &short_header(), now), Action::Forward(client));
        assert_eq!(s.handle_packet(attacker, &short_header(), now), Action::Drop);
    }

    #[test]
    fn actively_served_flow_becomes_displaceable_after_grace() {
        // An actively-served client is protected, but once the sharer stops
        // returning traffic (e.g. the connection ended) the slot frees up after
        // REVERSE_ACTIVITY_GRACE so a new client is not blocked forever.
        let mut s = State::default();
        let t0 = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b1 = addr("10.0.0.2:2222");
        let b2 = addr("10.0.0.3:3333");

        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), t0);
        s.handle_packet(b1, &initial_with_dcid(&key), t0);
        s.handle_packet(a, &short_header(), t0); // sharer serves b1

        // Within the grace window, b2 is refused.
        let mid = t0 + REVERSE_ACTIVITY_GRACE / 2;
        assert_eq!(s.handle_packet(b2, &initial_with_dcid(&key), mid), Action::Drop);

        // After the grace window with no further return traffic, b2 displaces b1.
        let late = t0 + REVERSE_ACTIVITY_GRACE + Duration::from_secs(1);
        assert_eq!(s.handle_packet(b2, &initial_with_dcid(&key), late), Action::Forward(a));
        assert_eq!(s.handle_packet(a, &short_header(), late), Action::Forward(b2));
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
    fn v6_and_mixed_family_flows_forward() {
        // The state machine is family-agnostic: a v6 sharer serves a
        // v4-mapped client (the dual-stack-socket shape) without any
        // normalization of the stored addresses.
        let mut s = State::default();
        let now = Instant::now();
        let a = addr("[2001:db8::1]:1111");
        let b = addr("[::ffff:203.0.113.6]:2222");

        let mut reg = registrar();
        let key = reg.routing_key();
        assert_eq!(s.handle_packet(a, &reg.next_register_packet(), now), Action::Drop);
        assert_eq!(s.registration_count(), 1);

        assert_eq!(s.handle_packet(b, &initial_with_dcid(&key), now), Action::Forward(a));
        assert_eq!(s.handle_packet(a, &short_header(), now), Action::Forward(b));
        assert_eq!(s.handle_packet(b, &short_header(), now), Action::Forward(a));
    }

    #[test]
    fn v4_mapped_non_relayable_sources_are_refused() {
        // On a dual-stack socket, v4 junk arrives in ::ffff: form — the
        // policy must see through the mapping (multicast/broadcast/
        // unspecified have no v6-arm equivalents).
        let mut s = State::default();
        let now = Instant::now();
        let mut reg = registrar();
        let key = reg.routing_key();
        s.handle_packet(addr("[2001:db8::1]:1111"), &reg.next_register_packet(), now);

        for src in [
            "[::ffff:224.0.0.1]:9",
            "[::ffff:255.255.255.255]:9",
            "[::ffff:0.0.0.0]:9",
            "[ff02::1]:9",
        ] {
            assert_eq!(
                s.handle_packet(addr(src), &initial_with_dcid(&key), now),
                Action::Drop,
                "must refuse flow from {src}"
            );
            // A REGISTER (with a valid signature and fresh timestamp) from a
            // non-relayable source must not rebind the key. Control packets
            // always return Drop, so assert on the binding instead.
            s.handle_packet(addr(src), &reg.next_register_packet(), now);
        }
        assert_eq!(s.flow_count(), 0);
        // The genuine sharer still owns the binding: a real client is
        // forwarded to it, not to any of the junk sources.
        let b = addr("[2001:db8::b]:2222");
        assert_eq!(
            s.handle_packet(b, &initial_with_dcid(&key), now),
            Action::Forward(addr("[2001:db8::1]:1111"))
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

    // --- Capability-token authorization ---

    #[test]
    fn open_mode_accepts_tokenless_registration() {
        // No issuer keys configured => open mode: a plain (tokenless) signed
        // registration is accepted, exactly as before authz existed.
        let mut s = State::default();
        assert!(!s.requires_authorization());
        let mut reg = registrar();
        s.handle_packet(addr("10.0.0.1:1"), &reg.next_register_packet(), Instant::now());
        assert_eq!(s.registration_count(), 1);
    }

    #[test]
    fn authorized_mode_rejects_tokenless_registration() {
        let issuer = authz::IssuerKeyPair::generate().unwrap();
        let mut s = State::default().with_issuer_keys(vec![issuer.public_key()]);
        assert!(s.requires_authorization());
        // A perfectly valid signed registration, but with no capability token.
        let mut reg = registrar();
        s.handle_packet(addr("10.0.0.1:1"), &reg.next_register_packet(), Instant::now());
        assert_eq!(s.registration_count(), 0, "tokenless register must be refused when gated");
    }

    #[test]
    fn authorized_mode_accepts_valid_token_and_routes() {
        let issuer = authz::IssuerKeyPair::generate().unwrap();
        let mut s = State::default().with_issuer_keys(vec![issuer.public_key()]);
        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let b = addr("10.0.0.2:2222");

        let mut reg = authorized_registrar(&issuer);
        let key = reg.routing_key();
        s.handle_packet(a, &reg.next_register_packet(), now);
        assert_eq!(s.registration_count(), 1, "valid token must be accepted");

        // ...and the authorized sharer routes a client normally.
        assert_eq!(s.handle_packet(b, &initial_with_dcid(&key), now), Action::Forward(a));
    }

    #[test]
    fn authorized_mode_rejects_token_from_untrusted_issuer() {
        let trusted = authz::IssuerKeyPair::generate().unwrap();
        let rogue = authz::IssuerKeyPair::generate().unwrap();
        let mut s = State::default().with_issuer_keys(vec![trusted.public_key()]);
        // Token signed by an issuer the relay does not trust.
        let mut reg = authorized_registrar(&rogue);
        s.handle_packet(addr("10.0.0.1:1"), &reg.next_register_packet(), Instant::now());
        assert_eq!(s.registration_count(), 0, "untrusted-issuer token must be refused");
    }

    #[test]
    fn authorized_mode_rejects_token_bound_to_a_different_key() {
        // A token is bound to a routing key (its subject). Attaching a token
        // issued for someone else's key to my own registration is refused, so a
        // token cannot be transplanted onto a different identity.
        let issuer = authz::IssuerKeyPair::generate().unwrap();
        let mut s = State::default().with_issuer_keys(vec![issuer.public_key()]);
        // A token issued for a foreign routing key, attached to our signer.
        let foreign_key = registrar().routing_key();
        let token = issuer.issue(&foreign_key);
        let mut reg = registrar().with_token(Some(token));
        assert_ne!(reg.routing_key(), foreign_key);
        s.handle_packet(addr("10.0.0.1:1"), &reg.next_register_packet(), Instant::now());
        assert_eq!(s.registration_count(), 0, "token bound to another key must be refused");
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

    // --- Session logging ---

    use crate::sessionlog::{SessionLog, SessionLogConfig};

    fn fast_log(path: &std::path::Path) -> SessionLog {
        let mut cfg = SessionLogConfig::at(path);
        cfg.flush_interval = Duration::from_millis(20);
        SessionLog::open(cfg).unwrap()
    }

    /// Poll the (async-written) session DB until `pred` passes or 5s elapse.
    fn wait_session<F>(path: &std::path::Path, pred: F)
    where
        F: Fn(&rusqlite::Connection) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(db) = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) && pred(&db)
            {
                return;
            }
            assert!(Instant::now() < deadline, "session log condition not met within 5s");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[test]
    fn session_log_records_matched_flow_with_counts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.sqlite");
        let mut s = State::default().with_session_log(fast_log(&path));

        let now = Instant::now();
        let a = addr("10.0.0.1:1111"); // sharer
        let b = addr("10.0.0.2:2222"); // client
        let mut reg = registrar();
        let key = reg.routing_key();

        s.handle_packet(a, &reg.next_register_packet(), now);
        // Client Initial installs the flow (counted as the first c2s packet).
        assert_eq!(s.handle_packet(b, &initial_with_dcid(&key), now), Action::Forward(a));
        // One sharer→client packet (s2c) and one more client→sharer (c2s).
        s.handle_packet(a, &short_header(), now);
        s.handle_packet(b, &short_header(), now);
        // Idle past the flow timeout → session closed as 'idle' on sweep.
        s.sweep(now + FLOW_TIMEOUT + Duration::from_secs(1));
        // Dropping State drops the SessionLog → writer flushes and exits.
        drop(s);

        let key_hex: String = key.iter().map(|x| format!("{:02x}", x)).collect();
        wait_session(&path, |db| {
            db.query_row(
                "SELECT client_addr, sharer_addr, pkts_c2s, pkts_s2c, end_reason
                 FROM sessions WHERE routing_key=?1",
                [&key_hex],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .map(|(client, sharer, c2s, s2c, reason)| {
                client == "10.0.0.2:2222"
                    && sharer == "10.0.0.1:1111"
                    && c2s == 2 // Initial + one short-header
                    && s2c == 1
                    && reason.as_deref() == Some("idle")
            })
            .unwrap_or(false)
        });
    }

    #[test]
    fn session_log_records_displacement() {
        // An idle incumbent (a peer that installed a flow but the sharer never
        // returned traffic to) is closed as 'displaced' when a real client
        // takes the slot.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.sqlite");
        let mut s = State::default().with_session_log(fast_log(&path));

        let now = Instant::now();
        let a = addr("10.0.0.1:1111");
        let attacker = addr("10.9.9.9:9999");
        let client = addr("10.0.0.2:2222");
        let mut reg = registrar();
        let key = reg.routing_key();

        s.handle_packet(a, &reg.next_register_packet(), now);
        // Attacker installs a flow; the sharer never serves it (stays idle).
        assert_eq!(s.handle_packet(attacker, &initial_with_dcid(&key), now), Action::Forward(a));
        // A genuine client displaces the idle incumbent.
        assert_eq!(s.handle_packet(client, &initial_with_dcid(&key), now), Action::Forward(a));
        drop(s);

        wait_session(&path, |db| {
            let displaced: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE client_addr='10.9.9.9:9999' AND end_reason='displaced'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let client_open: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE client_addr='10.0.0.2:2222' AND end_ms IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            displaced == 1 && client_open == 1
        });
    }
}
