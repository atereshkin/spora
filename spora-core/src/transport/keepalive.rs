use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use futures_util::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use log::{debug, info, trace, warn};
use tokio::time::{sleep, Sleep};
use std::net::Ipv4Addr;
use tokio::time::Instant;
use crate::IpTransport;

/// How the keepalive layer decides when to probe.
#[derive(Clone)]
pub enum KeepAliveMode {
    /// Periodic pings. Used by share/server side.
    Periodic {
        interval: std::time::Duration,
        recv_timeout: std::time::Duration,
    },
    /// Externally controlled via a shared atomic.
    /// Value 0 = on-demand (probe only after idle gap when traffic resumes).
    /// Value >0 = always probe at that interval in seconds.
    Adaptive {
        knob: Arc<AtomicU64>,
    },
}

/// Configuration for the ICMP keepalive layer.
///
/// Note: `src_ip`/`dst_ip` are the *inner* (tunneled) IPv4 addresses used to craft an ICMP Echo.
/// For now these can be arbitrary private addresses as long as the remote side doesn't drop them.
#[derive(Clone)]
pub struct KeepAliveConfig {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub icmp_id: u16,
    pub mode: KeepAliveMode,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            icmp_id: 0x5350, // 'SP'
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(10),
                recv_timeout: std::time::Duration::from_secs(30),
            },
        }
    }
}

enum KeepAliveSendState {
    Idle,
    Sending(Vec<u8>),
}

// --- Adaptive mode constants ---
const IDLE_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(20);
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const INBOUND_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

enum ProbeState {
    Dormant,
    Probing {
        ping_timer: Pin<Box<Sleep>>,
        response_deadline: Pin<Box<Sleep>>,
    },
}

struct AdaptiveState {
    last_real_outbound: Instant,
    last_inbound: Instant,
    /// True once we've received at least one real inbound packet.
    /// Until this is set, we never declare the peer dead — the connection
    /// hasn't been proven alive yet (relay handshake may still be in progress).
    ever_received: bool,
    /// Set when we send a "rescue ping" after the deadline fires with no inbound.
    /// If the NEXT deadline also fires with no inbound, we declare dead.
    /// This handles transport upgrades where the underlying connection changes
    /// and the old ping/response cycle is no longer relevant.
    rescue_sent: bool,
    probe: ProbeState,
}

/// Inner state that differs between Periodic and Adaptive mode.
enum ModeState {
    Periodic {
        timer: Pin<Box<Sleep>>,
        recv_timer: Pin<Box<Sleep>>,
        interval: std::time::Duration,
        recv_timeout: std::time::Duration,
    },
    Adaptive {
        knob: Arc<AtomicU64>,
        state: AdaptiveState,
    },
}

// Free function to build ICMP echo — avoids &mut self borrow conflicts.
fn build_icmp_echo(cfg: &KeepAliveConfig, seq: &mut u16) -> Vec<u8> {
    let payload: [u8; 4] = *b"spka";
    let mut pkt = Vec::with_capacity(64);
    let builder = etherparse::PacketBuilder::ipv4(
        cfg.src_ip.octets(),
        cfg.dst_ip.octets(),
        64,
    )
    .icmpv4_echo_request(cfg.icmp_id, *seq);

    *seq = seq.wrapping_add(1);

    builder
        .write(&mut pkt, &payload)
        .expect("writing into Vec should not fail");

    pkt
}

/// Try to flush a pending keepalive packet through the inner sink.
/// Free function to avoid borrow conflicts.
fn flush_send_state(inner: &mut IpTransport, send_state: &mut KeepAliveSendState, cx: &mut Context<'_>) -> Poll<()> {
    loop {
        match send_state {
            KeepAliveSendState::Idle => return Poll::Ready(()),
            KeepAliveSendState::Sending(pkt) => {
                match Pin::new(&mut **inner).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => {
                        warn!("Keepalive poll_ready failed: {}", e);
                        *send_state = KeepAliveSendState::Idle;
                        return Poll::Ready(());
                    }
                    Poll::Pending => return Poll::Pending,
                }

                let pkt = std::mem::take(pkt);
                if let Err(e) = Pin::new(&mut **inner).start_send(pkt) {
                    warn!("Keepalive start_send failed: {}", e);
                    *send_state = KeepAliveSendState::Idle;
                    return Poll::Ready(());
                }

                match Pin::new(&mut **inner).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        trace!("Keepalive sent");
                        *send_state = KeepAliveSendState::Idle;
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        warn!("Keepalive poll_flush failed: {}", e);
                        *send_state = KeepAliveSendState::Idle;
                        return Poll::Ready(());
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

/// Check if a packet is an ICMP Echo Reply matching our keepalive id.
fn is_icmp_echo_reply(pkt: &[u8], expected_id: u16) -> bool {
    if let Some((1, icmp)) = parse_icmp(pkt) {
        // Type 0 = Echo Reply
        icmp[0] == 0 && icmp[1] == 0 && u16::from_be_bytes([icmp[4], icmp[5]]) == expected_id
    } else {
        false
    }
}

/// Check if a packet is an ICMP Echo Request matching our keepalive id.
fn is_icmp_echo_request(pkt: &[u8], expected_id: u16) -> bool {
    if let Some((1, icmp)) = parse_icmp(pkt) {
        // Type 8 = Echo Request
        icmp[0] == 8 && icmp[1] == 0 && u16::from_be_bytes([icmp[4], icmp[5]]) == expected_id
    } else {
        false
    }
}

/// Parse an IPv4 packet and return (protocol, icmp_slice) if it's ICMP.
fn parse_icmp(pkt: &[u8]) -> Option<(u8, &[u8])> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let proto = pkt[9];
    if proto != 1 || pkt.len() < ihl + 8 {
        return None;
    }
    Some((proto, &pkt[ihl..]))
}

/// Build an ICMP Echo Reply from an incoming Echo Request.
/// Swaps src/dst IPs and changes type 8→0, recalculating the ICMP checksum.
fn build_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 28 {
        return None;
    }
    let ihl = ((request[0] & 0x0F) as usize) * 4;
    if request.len() < ihl + 8 {
        return None;
    }

    let mut reply = request.to_vec();

    // Swap src and dst IP addresses (bytes 12-15 and 16-19).
    // Must copy dst first (from original request) since reply starts as a clone.
    reply[12..16].copy_from_slice(&request[16..20]); // src ← old dst
    reply[16..20].copy_from_slice(&request[12..16]); // dst ← old src

    // Change ICMP type from 8 (Echo Request) to 0 (Echo Reply).
    reply[ihl] = 0;

    // Recalculate ICMP checksum.
    // Zero out the checksum field first.
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let icmp_data = &reply[ihl..];
    let checksum = internet_checksum(icmp_data);
    reply[ihl + 2] = (checksum >> 8) as u8;
    reply[ihl + 3] = (checksum & 0xFF) as u8;

    // Recalculate IPv4 header checksum.
    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = internet_checksum(&reply[..ihl]);
    reply[10] = (ip_checksum >> 8) as u8;
    reply[11] = (ip_checksum & 0xFF) as u8;

    Some(reply)
}

/// Standard internet checksum (RFC 1071).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// A best-effort keepalive wrapper that periodically injects an IPv4+ICMP Echo Request packet
/// into the inner transport to keep NAT bindings alive.
///
/// Supports two modes:
/// - **Periodic** (share/server side): timer-based pings when idle, recv_timeout for dead peer.
/// - **Adaptive** (client/use side): externally controlled via atomic knob. On-demand probing
///   that activates when traffic resumes after an idle gap, or always-on at a configurable interval.
pub struct KeepAliveTransport {
    inner: IpTransport,
    cfg: KeepAliveConfig,
    seq: u16,
    send_state: KeepAliveSendState,
    mode_state: ModeState,
}

impl KeepAliveTransport {
    pub fn new(inner: IpTransport, cfg: KeepAliveConfig) -> Self {
        let mode_state = match &cfg.mode {
            KeepAliveMode::Periodic { interval, recv_timeout } => {
                info!("Keepalive: Periodic mode (interval={:?}, recv_timeout={:?})", interval, recv_timeout);
                ModeState::Periodic {
                    timer: Box::pin(sleep(*interval)),
                    recv_timer: Box::pin(sleep(*recv_timeout)),
                    interval: *interval,
                    recv_timeout: *recv_timeout,
                }
            }
            KeepAliveMode::Adaptive { knob } => {
                let initial = knob.load(Ordering::Relaxed);
                info!("Keepalive: Adaptive mode (initial knob={})", initial);
                ModeState::Adaptive {
                    knob: knob.clone(),
                    state: AdaptiveState {
                        last_real_outbound: Instant::now(),
                        last_inbound: Instant::now(),
                        ever_received: false,
                        rescue_sent: false,
                        probe: ProbeState::Dormant,
                    },
                }
            }
        };

        Self {
            inner,
            seq: 0,
            send_state: KeepAliveSendState::Idle,
            mode_state,
            cfg,
        }
    }

    fn poll_maybe_probe(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match &mut self.mode_state {
            ModeState::Periodic { timer, interval, .. } => {
                if matches!(self.send_state, KeepAliveSendState::Idle) {
                    if let Poll::Ready(()) = timer.as_mut().poll(cx) {
                        let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                        debug!("Keepalive: periodic ping (seq={})", self.seq);
                        self.send_state = KeepAliveSendState::Sending(pkt);
                        timer.as_mut().reset(Instant::now() + *interval);
                    }
                }
                flush_send_state(&mut self.inner, &mut self.send_state, cx)
            }
            ModeState::Adaptive { knob, state } => {
                let knob_val = knob.load(Ordering::Relaxed);

                match &mut state.probe {
                    ProbeState::Dormant => {
                        if knob_val > 0 {
                            let interval = std::time::Duration::from_secs(knob_val);
                            let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                            info!("Keepalive: Dormant -> Probing (knob={}s)", knob_val);
                            self.send_state = KeepAliveSendState::Sending(pkt);
                            state.probe = ProbeState::Probing {
                                ping_timer: Box::pin(sleep(interval)),
                                response_deadline: Box::pin(sleep(RESPONSE_TIMEOUT)),
                            };
                        }
                    }
                    ProbeState::Probing { ping_timer, response_deadline } => {
                        // knob == 0 means screen OFF — go dormant immediately.
                        if knob_val == 0 {
                            info!("Keepalive: Probing -> Dormant (knob set to 0)");
                            state.probe = ProbeState::Dormant;
                            return flush_send_state(&mut self.inner, &mut self.send_state, cx);
                        }

                        if matches!(self.send_state, KeepAliveSendState::Idle) {
                            if let Poll::Ready(()) = ping_timer.as_mut().poll(cx) {
                                let interval = std::time::Duration::from_secs(knob_val);
                                let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                                debug!("Keepalive: ping timer fired, sending ICMP echo");
                                self.send_state = KeepAliveSendState::Sending(pkt);
                                ping_timer.as_mut().reset(Instant::now() + interval);
                                response_deadline.as_mut().reset(Instant::now() + RESPONSE_TIMEOUT);
                            }
                        }
                    }
                }

                flush_send_state(&mut self.inner, &mut self.send_state, cx)
            }
        }
    }

    fn on_outbound(&mut self) {
        match &mut self.mode_state {
            ModeState::Periodic { timer, interval, .. } => {
                timer.as_mut().reset(Instant::now() + *interval);
            }
            ModeState::Adaptive { knob, state } => {
                let was_idle = Instant::now().duration_since(state.last_real_outbound) > IDLE_THRESHOLD;
                state.last_real_outbound = Instant::now();

                if matches!(state.probe, ProbeState::Dormant) && was_idle {
                    let knob_val = knob.load(Ordering::Relaxed);
                    let interval = if knob_val > 0 {
                        std::time::Duration::from_secs(knob_val)
                    } else {
                        IDLE_THRESHOLD
                    };
                    info!("Keepalive: Dormant -> Probing (outbound after idle gap)");
                    if matches!(self.send_state, KeepAliveSendState::Idle) {
                        let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                        self.send_state = KeepAliveSendState::Sending(pkt);
                    }
                    state.probe = ProbeState::Probing {
                        ping_timer: Box::pin(sleep(interval)),
                        response_deadline: Box::pin(sleep(RESPONSE_TIMEOUT)),
                    };
                }
            }
        }
    }

    fn on_inbound(&mut self) {
        match &mut self.mode_state {
            ModeState::Periodic { timer, recv_timer, interval, recv_timeout } => {
                timer.as_mut().reset(Instant::now() + *interval);
                recv_timer.as_mut().reset(Instant::now() + *recv_timeout);
            }
            ModeState::Adaptive { state, .. } => {
                state.last_inbound = Instant::now();
                state.rescue_sent = false;
                if !state.ever_received {
                    info!("Keepalive: first inbound packet received, connection proven alive");
                    state.ever_received = true;
                }
                // Don't reset response_deadline here — the next ping_timer fire
                // will set it properly. Resetting to RESPONSE_TIMEOUT here would
                // create a 3s polling cycle between pings.
            }
        }
    }

    /// Check if peer appears dead. Returns true if we should yield None.
    fn check_dead(&mut self, cx: &mut Context<'_>) -> Option<Poll<Option<io::Result<Vec<u8>>>>> {
        match &mut self.mode_state {
            ModeState::Periodic { recv_timer, recv_timeout, .. } => {
                match recv_timer.as_mut().poll(cx) {
                    Poll::Ready(_) => {
                        warn!("No inbound traffic for {:?}, peer appears dead", recv_timeout);
                        Some(Poll::Ready(None))
                    }
                    Poll::Pending => None,
                }
            }
            ModeState::Adaptive { state, .. } => {
                if let ProbeState::Probing { response_deadline, .. } = &mut state.probe {
                    if let Poll::Ready(()) = response_deadline.as_mut().poll(cx) {
                        if !state.ever_received {
                            // Connection not yet proven alive — keep probing but don't
                            // declare dead. The relay handshake may still be in progress.
                            debug!("Keepalive: response deadline fired but no inbound yet, waiting");
                            response_deadline.as_mut().reset(Instant::now() + RESPONSE_TIMEOUT);
                        } else if Instant::now().duration_since(state.last_inbound) > INBOUND_GRACE {
                            if !state.rescue_sent {
                                // First miss — send a rescue ping through the current transport.
                                // This handles transport upgrades where the inner connection
                                // changed and old pings are no longer relevant.
                                info!("Keepalive: no response, sending rescue ping");
                                if matches!(self.send_state, KeepAliveSendState::Idle) {
                                    let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                                    self.send_state = KeepAliveSendState::Sending(pkt);
                                }
                                state.rescue_sent = true;
                                response_deadline.as_mut().reset(Instant::now() + RESPONSE_TIMEOUT);
                            } else {
                                warn!("Keepalive: peer dead (no response to rescue ping, no inbound for {:?})", INBOUND_GRACE);
                                return Some(Poll::Ready(None));
                            }
                        } else {
                            // Peer responded to our ping (last_inbound is recent).
                            // Park the deadline until the next ping_timer fires and
                            // resets it — don't keep re-checking every 3s.
                            response_deadline.as_mut().reset(Instant::now() + std::time::Duration::from_secs(3600));
                        }
                    }
                }
                None
            }
        }
    }
}

impl Stream for KeepAliveTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        let _ = this.poll_maybe_probe(cx);

        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(pkt))) => {
                if is_icmp_echo_reply(&pkt, this.cfg.icmp_id) {
                    debug!("Keepalive: received ICMP echo reply (ping response)");
                } else if is_icmp_echo_request(&pkt, this.cfg.icmp_id) {
                    // Peer's keepalive ping — auto-reply so the peer knows we're alive.
                    // Don't forward to TUN (the kernel may not respond to these IPs).
                    debug!("Keepalive: received peer's ICMP echo request, auto-replying");
                    this.on_inbound();
                    if let Some(reply) = build_echo_reply(&pkt) {
                        if matches!(this.send_state, KeepAliveSendState::Idle) {
                            this.send_state = KeepAliveSendState::Sending(reply);
                        }
                    }
                    // Re-poll to flush the reply and check for more packets.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                } else {
                    trace!("Keepalive: inbound packet ({} bytes)", pkt.len());
                }
                this.on_inbound();
                Poll::Ready(Some(Ok(pkt)))
            }
            Poll::Pending => {
                if let Some(dead) = this.check_dead(cx) {
                    dead
                } else {
                    Poll::Pending
                }
            }
            other => other,
        }
    }
}

impl Sink<Vec<u8>> for KeepAliveTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let _ = this.poll_maybe_probe(cx);
        Pin::new(&mut this.inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.on_outbound();
        Pin::new(&mut this.inner).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let _ = this.poll_maybe_probe(cx);
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::{mock_transport, mock_transport_pair, is_icmp_echo_request};
    use futures_util::{SinkExt, StreamExt};

    // =====================================================================
    // Periodic mode tests (existing behavior)
    // =====================================================================

    fn periodic_config(interval_secs: u64) -> KeepAliveConfig {
        KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(interval_secs),
                recv_timeout: std::time::Duration::from_secs(30),
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn keepalive_injects_icmp_after_interval() {
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let cfg = periodic_config(5);
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            let _ = futures_util::future::poll_fn(|cx| {
                let _ = Pin::new(&mut ka).poll_next(cx);
                Poll::Ready(())
            })
            .await;
        })
        .await
        .unwrap();

        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), remote.next())
            .await
            .expect("should receive keepalive packet")
            .unwrap()
            .unwrap();
        assert!(is_icmp_echo_request(&pkt), "expected ICMP echo request, got {:?}", &pkt[..pkt.len().min(24)]);
    }

    #[tokio::test]
    async fn inbound_traffic_resets_keepalive_timer() {
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let cfg = periodic_config(5);
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        remote.send(vec![10, 20, 30]).await.unwrap();
        let pkt = ka.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![10, 20, 30]);

        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(10), remote.next()).await;
        assert!(result.is_err(), "should not have received keepalive yet (timer was reset)");

        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        let _ = futures_util::future::poll_fn(|cx| {
            let _ = Pin::new(&mut ka).poll_next(cx);
            Poll::Ready(())
        })
        .await;

        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), remote.next())
            .await
            .expect("should receive keepalive after full interval since reset")
            .unwrap()
            .unwrap();
        assert!(is_icmp_echo_request(&pkt));
    }

    #[tokio::test]
    async fn outbound_traffic_resets_keepalive_timer() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let cfg = periodic_config(5);
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        Pin::new(&mut ka).send(vec![10, 20, 30]).await.unwrap();
        let pkt = handle.recv().await.unwrap();
        assert_eq!(pkt, vec![10, 20, 30]);

        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(result.is_err(), "should not have received keepalive yet (timer was reset by outbound)");

        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        let _ = futures_util::future::poll_fn(|cx| {
            let _ = Pin::new(&mut ka).poll_next(cx);
            Poll::Ready(())
        })
        .await;

        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("should receive keepalive after full interval since outbound reset")
            .unwrap();
        assert!(is_icmp_echo_request(&pkt));
    }

    #[tokio::test]
    async fn recv_timeout_yields_none_when_peer_is_silent() {
        tokio::time::pause();

        let (local, _remote) = mock_transport_pair();
        let cfg = KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(5),
                recv_timeout: std::time::Duration::from_secs(15),
            },
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        tokio::time::advance(std::time::Duration::from_secs(16)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        match result {
            Ok(None) => {}
            other => panic!("expected None (peer dead), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn recv_timeout_resets_on_inbound_traffic() {
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let cfg = KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(5),
                recv_timeout: std::time::Duration::from_secs(15),
            },
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        remote.send(vec![1, 2, 3]).await.unwrap();
        let pkt = ka.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(10), ka.next()).await;
        assert!(result.is_err(), "should still be pending (recv timer was reset)");

        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        match result {
            Ok(None) => {}
            other => panic!("expected None after recv_timeout, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn recv_timeout_not_reset_by_outbound_traffic() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let cfg = KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(5),
                recv_timeout: std::time::Duration::from_secs(15),
            },
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        Pin::new(&mut ka).send(vec![1, 2, 3]).await.unwrap();
        let _ = handle.recv().await;

        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        match result {
            Ok(None) => {}
            other => panic!("expected None (outbound shouldn't reset recv timer), got {:?}", other),
        }
    }

    // =====================================================================
    // Adaptive mode tests
    // =====================================================================

    fn adaptive_config(knob: Arc<AtomicU64>) -> KeepAliveConfig {
        KeepAliveConfig {
            mode: KeepAliveMode::Adaptive { knob },
            ..Default::default()
        }
    }

    /// Helper: poll the transport once to drive keepalive logic.
    async fn drive_poll(ka: &mut KeepAliveTransport) {
        futures_util::future::poll_fn(|cx| {
            let _ = Pin::new(&mut *ka).poll_next(cx);
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn adaptive_dormant_sends_no_pings() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let knob = Arc::new(AtomicU64::new(0));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance a long time — should stay dormant, no pings.
        tokio::time::advance(std::time::Duration::from_secs(120)).await;
        drive_poll(&mut ka).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(result.is_err(), "should not receive any pings while dormant");
    }

    #[tokio::test]
    async fn adaptive_outbound_after_idle_triggers_ping() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let knob = Arc::new(AtomicU64::new(0));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance past IDLE_THRESHOLD so that the next outbound triggers activation.
        tokio::time::advance(IDLE_THRESHOLD + std::time::Duration::from_secs(1)).await;

        // Send outbound traffic.
        Pin::new(&mut ka).send(vec![1, 2, 3]).await.unwrap();
        // Consume the user packet.
        let pkt = handle.recv().await.unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Drive poll to flush the scheduled ping.
        drive_poll(&mut ka).await;

        // Should receive the ICMP ping.
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("should receive ping after outbound-after-idle")
            .unwrap();
        assert!(is_icmp_echo_request(&pkt), "expected ICMP echo request");
    }

    #[tokio::test]
    async fn adaptive_deactivates_when_idle() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let knob = Arc::new(AtomicU64::new(0));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Activate by sending after idle gap.
        tokio::time::advance(IDLE_THRESHOLD + std::time::Duration::from_secs(1)).await;
        Pin::new(&mut ka).send(vec![1, 2, 3]).await.unwrap();
        let _ = handle.recv().await; // user pkt

        // Drive to flush the activation ping.
        drive_poll(&mut ka).await;
        // Consume the ICMP ping.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv()).await;

        // Now stop sending. Advance past IDLE_THRESHOLD → goes dormant (knob=0).
        tokio::time::advance(IDLE_THRESHOLD + std::time::Duration::from_secs(1)).await;
        drive_poll(&mut ka).await;

        // Further time passes — no more pings (dormant).
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        drive_poll(&mut ka).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(result.is_err(), "should not receive pings after going dormant");
    }

    #[tokio::test]
    async fn adaptive_returns_none_when_no_response() {
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let knob = Arc::new(AtomicU64::new(20));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // knob > 0 should immediately activate. Drive poll to send initial ping.
        drive_poll(&mut ka).await;

        // Prove the connection is alive with one inbound packet.
        remote.send(vec![1]).await.unwrap();
        let pkt = ka.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![1]);

        // Advance past INBOUND_GRACE so the first response_deadline fires → rescue ping.
        tokio::time::advance(INBOUND_GRACE + std::time::Duration::from_secs(1)).await;
        // Drive poll to trigger the rescue ping.
        drive_poll(&mut ka).await;

        // Advance past RESPONSE_TIMEOUT so the second deadline fires → peer dead.
        tokio::time::advance(RESPONSE_TIMEOUT + std::time::Duration::from_secs(1)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        match result {
            Ok(None) => {} // expected — peer dead after rescue ping unanswered
            other => panic!("expected None (peer dead), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn adaptive_rescue_ping_saves_connection() {
        // Simulates a transport upgrade: after the first ping cycle, inbound
        // stops (old transport gone). The rescue ping goes through the new
        // transport and the peer responds — connection should survive.
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let knob = Arc::new(AtomicU64::new(20));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Activate and prove alive.
        drive_poll(&mut ka).await;
        remote.send(vec![1]).await.unwrap();
        let _ = ka.next().await.unwrap().unwrap();

        // Advance past INBOUND_GRACE → rescue ping sent.
        tokio::time::advance(INBOUND_GRACE + std::time::Duration::from_secs(1)).await;
        drive_poll(&mut ka).await;

        // Peer responds to the rescue ping — connection saved.
        remote.send(vec![2]).await.unwrap();
        let pkt = ka.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![2]);

        // Advance a bit more — should still be alive.
        tokio::time::advance(RESPONSE_TIMEOUT + std::time::Duration::from_secs(1)).await;
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), ka.next()).await;
        assert!(result.is_err(), "should still be alive after rescue ping was answered");
    }

    #[tokio::test]
    async fn adaptive_no_death_before_first_inbound() {
        tokio::time::pause();

        let (local, _remote) = mock_transport_pair();
        let knob = Arc::new(AtomicU64::new(20));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Activate probing (knob > 0).
        drive_poll(&mut ka).await;

        // Advance WAY past RESPONSE_TIMEOUT + INBOUND_GRACE without any inbound.
        // The transport must NOT declare peer dead because we haven't received
        // even one packet yet (connection not proven alive).
        tokio::time::advance(std::time::Duration::from_secs(60)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        assert!(result.is_err(), "should NOT declare peer dead before first inbound packet");
    }

    #[tokio::test]
    async fn adaptive_stays_alive_with_inbound() {
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let knob = Arc::new(AtomicU64::new(20));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Drive poll to activate (knob > 0).
        drive_poll(&mut ka).await;

        // Advance close to the deadline.
        tokio::time::advance(RESPONSE_TIMEOUT - std::time::Duration::from_millis(100)).await;

        // Send inbound traffic — this should reset the response deadline.
        remote.send(vec![42]).await.unwrap();
        let pkt = ka.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![42]);

        // Advance past what would have been the original deadline.
        tokio::time::advance(std::time::Duration::from_secs(2)).await;

        // Should still be alive since we got inbound traffic.
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), ka.next()).await;
        assert!(result.is_err(), "should still be pending (inbound traffic reset deadline)");
    }

    #[tokio::test]
    async fn adaptive_knob_positive_keeps_probing() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let knob = Arc::new(AtomicU64::new(5));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Initial activation ping.
        drive_poll(&mut ka).await;
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("should get initial ping")
            .unwrap();
        assert!(is_icmp_echo_request(&pkt));

        // Simulate inbound response to keep alive.
        if let ModeState::Adaptive { state, .. } = &mut ka.mode_state {
            state.last_inbound = Instant::now();
        }

        // Advance 6s (past the 5s knob interval) and poll again.
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        drive_poll(&mut ka).await;

        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("should get second ping after interval")
            .unwrap();
        assert!(is_icmp_echo_request(&pkt));
    }

    #[tokio::test]
    async fn adaptive_knob_zero_to_positive_triggers_immediate_ping() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let knob = Arc::new(AtomicU64::new(0));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Dormant initially — no pings.
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        drive_poll(&mut ka).await;
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(result.is_err(), "should be dormant");

        // Switch knob to 20 (screen on).
        knob.store(20, Ordering::Relaxed);

        // Next poll should send an immediate ping.
        drive_poll(&mut ka).await;

        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("should get immediate ping after knob 0→20")
            .unwrap();
        assert!(is_icmp_echo_request(&pkt));
    }

    #[tokio::test]
    async fn adaptive_knob_positive_to_zero_goes_on_demand() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let knob = Arc::new(AtomicU64::new(5));
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Activate — consume initial ping.
        drive_poll(&mut ka).await;
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv()).await;

        // Switch to on-demand (screen off).
        knob.store(0, Ordering::Relaxed);

        // Next poll should immediately go dormant.
        drive_poll(&mut ka).await;

        // Further time — no pings.
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        drive_poll(&mut ka).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(result.is_err(), "should not ping after switching to on-demand and going idle");
    }

    #[tokio::test]
    async fn auto_replies_to_peer_keepalive_ping() {
        // When the peer (server) sends an ICMP echo request with our keepalive ID,
        // we should auto-reply without forwarding to TUN.
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let knob = Arc::new(AtomicU64::new(0)); // dormant
        let cfg = adaptive_config(knob.clone());
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Build an ICMP echo request as if from the peer's keepalive.
        // Use the default keepalive IPs and ID.
        let peer_ping = {
            let payload: [u8; 4] = *b"spka";
            let mut pkt = Vec::with_capacity(64);
            // Peer sends from its src_ip (10.0.0.1) to its dst_ip (10.0.0.2).
            // But from our perspective, the packet arrives with src=10.0.0.1, dst=10.0.0.2.
            let builder = etherparse::PacketBuilder::ipv4(
                [10, 0, 0, 1], // peer's src
                [10, 0, 0, 2], // peer's dst
                64,
            )
            .icmpv4_echo_request(0x5350, 42); // our keepalive ID
            builder.write(&mut pkt, &payload).unwrap();
            pkt
        };

        // Peer sends the ping.
        remote.send(peer_ping).await.unwrap();

        // Drive poll — should intercept the ping and auto-reply.
        // The ping should NOT be yielded to the caller (not forwarded to TUN).
        drive_poll(&mut ka).await;

        // Drive again to flush the reply.
        drive_poll(&mut ka).await;

        // Remote should receive an ICMP echo reply.
        let reply = tokio::time::timeout(std::time::Duration::from_millis(100), remote.next())
            .await
            .expect("should receive auto-reply")
            .unwrap()
            .unwrap();

        // Verify it's an echo reply (type 0) with swapped IPs.
        assert!(reply.len() >= 28, "reply too short");
        let ihl = ((reply[0] & 0x0F) as usize) * 4;
        assert_eq!(reply[9], 1, "should be ICMP");
        assert_eq!(reply[ihl], 0, "should be Echo Reply (type 0)");
        // src should be 10.0.0.2 (was dst), dst should be 10.0.0.1 (was src)
        assert_eq!(&reply[12..16], &[10, 0, 0, 2], "reply src should be swapped");
        assert_eq!(&reply[16..20], &[10, 0, 0, 1], "reply dst should be swapped");
    }
}
