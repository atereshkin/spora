use crate::IpTransport;
use crate::record::{Reason, Recorder, StepKind};
use futures_util::{Sink, Stream};
use log::{debug, info, trace, warn};
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::time::Instant;
use tokio::time::{Sleep, sleep};

/// Traffic and liveness-probe counters, maintained by the keepalive layer.
///
/// This layer sits on every carrier and on both sides of a direct upgrade, so
/// it is the only vantage point that can produce a single continuous series
/// across a path swap — which is why the counters live here rather than in a
/// carrier.
///
/// What is counted is **tunnel payload**: the packets the application handed
/// over or received. Deliberately not the same quantity as a carrier's wire
/// bytes (which include its framing and its retransmissions), nor as the
/// exit's post-netstack goodput. Probes are counted separately and never
/// folded into the traffic counters, so an idle tunnel reads as idle.
#[derive(Debug, Default)]
pub struct LinkCounters {
    pub tx_pkts: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_pkts: AtomicU64,
    pub rx_bytes: AtomicU64,
    /// Liveness probes sent, and the ones that came back. Their ratio is the
    /// only loss figure available on every carrier.
    pub probes_sent: AtomicU64,
    pub probes_answered: AtomicU64,
    /// Round trip of the most recently answered probe, in microseconds. This
    /// one includes the tunnel itself, unlike a carrier's own estimate.
    pub last_rtt_us: AtomicU64,
}

impl LinkCounters {
    /// Round trip of the most recently answered probe, if there has been one.
    pub fn last_rtt(&self) -> Option<std::time::Duration> {
        match self.last_rtt_us.load(Ordering::Relaxed) {
            0 => None,
            us => Some(std::time::Duration::from_micros(us)),
        }
    }
}

/// How the keepalive layer decides when to probe.
#[derive(Clone)]
pub enum KeepAliveMode {
    /// Periodic pings. Used by share/server side.
    /// `recv_timeout`: if `Some`, declare peer dead after this long without inbound.
    /// If `None`, pings are sent for NAT maintenance only — never declare dead.
    Periodic {
        interval: std::time::Duration,
        recv_timeout: Option<std::time::Duration>,
    },
    /// Externally controlled via a shared atomic.
    /// Value 0 = on-demand (probe only after idle gap when traffic resumes).
    /// Value >0 = always probe at that interval in seconds.
    /// The `waker` is shared with the FFI layer so that `set_keepalive()` can
    /// wake the transport task when the knob changes (otherwise a Dormant
    /// transport with no timers would never notice the knob change).
    Adaptive {
        knob: Arc<AtomicU64>,
        waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
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
    /// Adaptive mode: an outbound packet after this much send-silence
    /// re-activates probing (and is the on-demand probe interval at knob 0).
    pub idle_threshold: std::time::Duration,
    /// Adaptive mode: how long after a ping to wait for any inbound before
    /// the response deadline fires.
    pub response_timeout: std::time::Duration,
    /// Adaptive mode: inbound within this window keeps the peer alive when
    /// the response deadline fires.
    pub inbound_grace: std::time::Duration,
    /// Periodic mode only: if `Some`, suppress proactive pings once inbound
    /// has been silent for this long, and resume on the next inbound. This
    /// is how the share side becomes dormancy-aware WITHOUT a protocol
    /// signal: an active client always pings (its Adaptive knob is on), so
    /// the share side keeps hearing from it and keeps the return path warm;
    /// a dormant client goes silent, so after `active_window` the share side
    /// goes quiet too — no pings to a dormant peer means it isn't forced to
    /// ACK, giving true radio silence. `None` = always ping (legacy).
    pub active_window: Option<std::time::Duration>,
    /// Where to accumulate traffic and probe counters, for whoever is keeping
    /// a diagnostic record. `None` skips the bookkeeping entirely.
    pub counters: Option<Arc<LinkCounters>>,
    /// Where to write the verdicts this layer reaches — chiefly the peer
    /// going quiet. Nobody else can see that one: from the outside, a tunnel
    /// killed by silence and one killed by an error look identical.
    pub recorder: Option<Recorder>,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            icmp_id: 0x5350, // 'SP'
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(10),
                recv_timeout: None,
            },
            idle_threshold: IDLE_THRESHOLD,
            response_timeout: RESPONSE_TIMEOUT,
            inbound_grace: INBOUND_GRACE,
            active_window: None,
            counters: None,
            recorder: None,
        }
    }
}

enum KeepAliveSendState {
    Idle,
    Sending(Vec<u8>),
}

// --- Adaptive mode defaults (see KeepAliveConfig fields) ---
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
        recv_timer: Option<Pin<Box<Sleep>>>,
        interval: std::time::Duration,
        recv_timeout: Option<std::time::Duration>,
        /// Last time an inbound packet arrived — gates `active_window`.
        last_inbound: Instant,
    },
    Adaptive {
        knob: Arc<AtomicU64>,
        waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
        state: AdaptiveState,
    },
}

// Free function to build ICMP echo — avoids &mut self borrow conflicts.
fn build_icmp_echo(cfg: &KeepAliveConfig, seq: &mut u16) -> Vec<u8> {
    let payload: [u8; 4] = *b"spka";
    let mut pkt = Vec::with_capacity(64);
    let builder = etherparse::PacketBuilder::ipv4(cfg.src_ip.octets(), cfg.dst_ip.octets(), 64)
        .icmpv4_echo_request(cfg.icmp_id, *seq);

    *seq = seq.wrapping_add(1);

    builder
        .write(&mut pkt, &payload)
        .expect("writing into Vec should not fail");

    pkt
}

/// Try to flush a pending keepalive packet through the inner sink.
/// Free function to avoid borrow conflicts.
fn flush_send_state(
    inner: &mut IpTransport,
    send_state: &mut KeepAliveSendState,
    counters: &Option<Arc<LinkCounters>>,
    sent_at: &mut Option<Instant>,
    cx: &mut Context<'_>,
) -> Poll<()> {
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
                        *sent_at = Some(Instant::now());
                        if let Some(c) = counters {
                            c.probes_sent.fetch_add(1, Ordering::Relaxed);
                        }
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
    if pkt.len() < 20 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt[9] != 1 || pkt.len() < ihl + 8 {
        return false;
    }
    let icmp = &pkt[ihl..];
    // Type 0 = Echo Reply, code 0
    icmp[0] == 0 && icmp[1] == 0 && u16::from_be_bytes([icmp[4], icmp[5]]) == expected_id
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
    /// When the probe currently awaiting an answer went out. Taken by the
    /// reply that matches it, which is where the round trip comes from.
    probe_sent_at: Option<Instant>,
}

impl KeepAliveTransport {
    pub fn new(inner: IpTransport, cfg: KeepAliveConfig) -> Self {
        let mode_state = match &cfg.mode {
            KeepAliveMode::Periodic {
                interval,
                recv_timeout,
            } => {
                info!(
                    "Keepalive: Periodic mode (interval={:?}, recv_timeout={:?})",
                    interval, recv_timeout
                );
                ModeState::Periodic {
                    timer: Box::pin(sleep(*interval)),
                    recv_timer: recv_timeout.map(|d| Box::pin(sleep(d))),
                    interval: *interval,
                    recv_timeout: *recv_timeout,
                    last_inbound: Instant::now(),
                }
            }
            KeepAliveMode::Adaptive { knob, waker } => {
                let initial = knob.load(Ordering::Relaxed);
                info!("Keepalive: Adaptive mode (initial knob={})", initial);
                ModeState::Adaptive {
                    knob: knob.clone(),
                    waker: waker.clone(),
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
            probe_sent_at: None,
        }
    }

    fn poll_maybe_probe(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match &mut self.mode_state {
            ModeState::Periodic {
                timer,
                interval,
                last_inbound,
                ..
            } => {
                if matches!(self.send_state, KeepAliveSendState::Idle) {
                    if let Poll::Ready(()) = timer.as_mut().poll(cx) {
                        timer.as_mut().reset(Instant::now() + *interval);
                        // Dormancy-aware: stay quiet while the peer has been
                        // silent longer than active_window (it's dormant, so
                        // pinging it would only force ACKs and break its radio
                        // silence). The next inbound resets last_inbound and
                        // proactive pinging resumes.
                        let quiet = self
                            .cfg
                            .active_window
                            .is_some_and(|w| Instant::now().duration_since(*last_inbound) > w);
                        if quiet {
                            trace!("Keepalive: periodic ping suppressed (peer quiet)");
                        } else {
                            let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                            debug!("Keepalive: periodic ping (seq={})", self.seq);
                            self.send_state = KeepAliveSendState::Sending(pkt);
                        }
                    }
                }
                flush_send_state(
                    &mut self.inner,
                    &mut self.send_state,
                    &self.cfg.counters,
                    &mut self.probe_sent_at,
                    cx,
                )
            }
            ModeState::Adaptive { knob, waker, state } => {
                let knob_val = knob.load(Ordering::Relaxed);

                match &mut state.probe {
                    ProbeState::Dormant => {
                        if knob_val > 0 {
                            let interval = std::time::Duration::from_secs(knob_val);
                            let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                            info!("Keepalive: Dormant -> Probing (knob={}s)", knob_val);
                            if let Some(rec) = self.cfg.recorder.as_ref() {
                                rec.mark(StepKind::Wake)
                                    .detail(format!("probing every {knob_val}s"))
                                    .ok();
                            }
                            self.send_state = KeepAliveSendState::Sending(pkt);
                            state.probe = ProbeState::Probing {
                                ping_timer: Box::pin(sleep(interval)),
                                response_deadline: Box::pin(sleep(self.cfg.response_timeout)),
                            };
                        } else {
                            // Park the task — set_keepalive() will wake us via the
                            // shared waker when the knob changes.
                            *waker.lock().unwrap() = Some(cx.waker().clone());
                        }
                    }
                    ProbeState::Probing {
                        ping_timer,
                        response_deadline,
                    } => {
                        // knob == 0 means screen OFF — go dormant immediately.
                        if knob_val == 0 {
                            info!("Keepalive: Probing -> Dormant (knob set to 0)");
                            // Radio silence is deliberate, so it is recorded
                            // as a decision: a tunnel that goes quiet because
                            // the screen went off must not read like one that
                            // went quiet because the network did.
                            if let Some(rec) = self.cfg.recorder.as_ref() {
                                rec.mark(StepKind::Dormant)
                                    .detail("probing stopped: the application went dormant")
                                    .ok();
                            }
                            state.probe = ProbeState::Dormant;
                            // Re-arm the knob waker. The set_keepalive(0) call
                            // that just flipped the knob consumed the previous
                            // waker to wake us; without re-registering here, a
                            // Dormant task with no other timers (a dead TCP
                            // carrier) would miss the next set_keepalive(N>0)
                            // and never resume probing.
                            *waker.lock().unwrap() = Some(cx.waker().clone());
                            return flush_send_state(
                                &mut self.inner,
                                &mut self.send_state,
                                &self.cfg.counters,
                                &mut self.probe_sent_at,
                                cx,
                            );
                        }

                        if matches!(self.send_state, KeepAliveSendState::Idle) {
                            if let Poll::Ready(()) = ping_timer.as_mut().poll(cx) {
                                let interval = std::time::Duration::from_secs(knob_val);
                                let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                                debug!("Keepalive: ping timer fired, sending ICMP echo");
                                self.send_state = KeepAliveSendState::Sending(pkt);
                                ping_timer.as_mut().reset(Instant::now() + interval);
                                response_deadline
                                    .as_mut()
                                    .reset(Instant::now() + self.cfg.response_timeout);
                            }
                        }
                    }
                }

                flush_send_state(
                    &mut self.inner,
                    &mut self.send_state,
                    &self.cfg.counters,
                    &mut self.probe_sent_at,
                    cx,
                )
            }
        }
    }

    fn on_outbound(&mut self) {
        match &mut self.mode_state {
            ModeState::Periodic {
                timer, interval, ..
            } => {
                timer.as_mut().reset(Instant::now() + *interval);
            }
            ModeState::Adaptive { knob, state, .. } => {
                let was_idle = Instant::now().duration_since(state.last_real_outbound)
                    > self.cfg.idle_threshold;
                state.last_real_outbound = Instant::now();

                if matches!(state.probe, ProbeState::Dormant) && was_idle {
                    let knob_val = knob.load(Ordering::Relaxed);
                    let interval = if knob_val > 0 {
                        std::time::Duration::from_secs(knob_val)
                    } else {
                        self.cfg.idle_threshold
                    };
                    info!("Keepalive: Dormant -> Probing (outbound after idle gap)");
                    if let Some(rec) = self.cfg.recorder.as_ref() {
                        rec.mark(StepKind::Wake).detail("traffic resumed").ok();
                    }
                    if matches!(self.send_state, KeepAliveSendState::Idle) {
                        let pkt = build_icmp_echo(&self.cfg, &mut self.seq);
                        self.send_state = KeepAliveSendState::Sending(pkt);
                    }
                    state.probe = ProbeState::Probing {
                        ping_timer: Box::pin(sleep(interval)),
                        response_deadline: Box::pin(sleep(self.cfg.response_timeout)),
                    };
                }
            }
        }
    }

    fn on_inbound(&mut self) {
        match &mut self.mode_state {
            ModeState::Periodic {
                timer,
                recv_timer,
                interval,
                recv_timeout,
                last_inbound,
            } => {
                *last_inbound = Instant::now();
                timer.as_mut().reset(Instant::now() + *interval);
                if let (Some(rt), Some(timeout)) = (recv_timer.as_mut(), recv_timeout) {
                    rt.as_mut().reset(Instant::now() + *timeout);
                }
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
        let recorder = self.cfg.recorder.clone();
        let inbound_grace = self.cfg.inbound_grace;
        match &mut self.mode_state {
            ModeState::Periodic {
                recv_timer,
                recv_timeout,
                ..
            } => {
                if let Some(rt) = recv_timer.as_mut() {
                    match rt.as_mut().poll(cx) {
                        Poll::Ready(_) => {
                            warn!(
                                "No inbound traffic for {:?}, peer appears dead",
                                recv_timeout
                            );
                            // Nobody else can see this: a tunnel killed by
                            // silence and one killed by an error look
                            // identical from the outside.
                            if let Some(rec) = recorder.as_ref() {
                                rec.mark(StepKind::Liveness).fail(
                                    Reason::KeepaliveTimeout,
                                    format!("nothing inbound for {recv_timeout:?}"),
                                );
                            }
                            Some(Poll::Ready(None))
                        }
                        Poll::Pending => None,
                    }
                } else {
                    None
                }
            }
            ModeState::Adaptive { state, .. } => {
                if let ProbeState::Probing {
                    response_deadline, ..
                } = &mut state.probe
                {
                    if let Poll::Ready(()) = response_deadline.as_mut().poll(cx) {
                        if !state.ever_received {
                            // Connection not yet proven alive — keep probing but don't
                            // declare dead. The relay handshake may still be in progress.
                            debug!(
                                "Keepalive: response deadline fired but no inbound yet, waiting"
                            );
                            response_deadline
                                .as_mut()
                                .reset(Instant::now() + self.cfg.response_timeout);
                        } else if Instant::now().duration_since(state.last_inbound)
                            > self.cfg.inbound_grace
                        {
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
                                response_deadline
                                    .as_mut()
                                    .reset(Instant::now() + self.cfg.response_timeout);
                            } else {
                                warn!(
                                    "Keepalive: peer dead (no response to rescue ping, no inbound for {:?})",
                                    inbound_grace
                                );
                                if let Some(rec) = recorder.as_ref() {
                                    rec.mark(StepKind::Liveness).fail(
                                        Reason::KeepaliveTimeout,
                                        format!(
                                            "no answer to the rescue probe, nothing inbound for {inbound_grace:?}"
                                        ),
                                    );
                                }
                                return Some(Poll::Ready(None));
                            }
                        } else {
                            // Peer responded to our ping (last_inbound is recent).
                            // Park the deadline until the next ping_timer fires and
                            // resets it — don't keep re-checking every 3s.
                            response_deadline
                                .as_mut()
                                .reset(Instant::now() + std::time::Duration::from_secs(3600));
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
                let reply = is_icmp_echo_reply(&pkt, this.cfg.icmp_id);
                if reply {
                    debug!("Keepalive: received ICMP echo reply (ping response)");
                } else {
                    trace!("Keepalive: inbound packet ({} bytes)", pkt.len());
                }
                if let Some(c) = this.cfg.counters.as_ref() {
                    if reply {
                        c.probes_answered.fetch_add(1, Ordering::Relaxed);
                        // Only the probe still outstanding measures anything;
                        // a duplicate or late reply is counted, not timed.
                        if let Some(t0) = this.probe_sent_at.take() {
                            let us = t0.elapsed().as_micros().min(u64::MAX as u128) as u64;
                            c.last_rtt_us.store(us.max(1), Ordering::Relaxed);
                        }
                    } else {
                        c.rx_pkts.fetch_add(1, Ordering::Relaxed);
                        c.rx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    }
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
        if let Some(c) = this.cfg.counters.as_ref() {
            c.tx_pkts.fetch_add(1, Ordering::Relaxed);
            c.tx_bytes.fetch_add(item.len() as u64, Ordering::Relaxed);
        }
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
    use crate::transport::mock::{is_icmp_echo_request, mock_transport, mock_transport_pair};
    use futures_util::{SinkExt, StreamExt};

    // =====================================================================
    // Periodic mode tests (existing behavior)
    // =====================================================================

    fn periodic_config(interval_secs: u64) -> KeepAliveConfig {
        KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(interval_secs),
                recv_timeout: Some(std::time::Duration::from_secs(30)),
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
        assert!(
            is_icmp_echo_request(&pkt),
            "expected ICMP echo request, got {:?}",
            &pkt[..pkt.len().min(24)]
        );
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

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), remote.next()).await;
        assert!(
            result.is_err(),
            "should not have received keepalive yet (timer was reset)"
        );

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

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(
            result.is_err(),
            "should not have received keepalive yet (timer was reset by outbound)"
        );

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
                recv_timeout: Some(std::time::Duration::from_secs(15)),
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
                recv_timeout: Some(std::time::Duration::from_secs(15)),
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
        assert!(
            result.is_err(),
            "should still be pending (recv timer was reset)"
        );

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
                recv_timeout: Some(std::time::Duration::from_secs(15)),
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
            other => panic!(
                "expected None (outbound shouldn't reset recv timer), got {:?}",
                other
            ),
        }
    }

    // =====================================================================
    // Adaptive mode tests
    // =====================================================================

    fn adaptive_config(knob: Arc<AtomicU64>) -> KeepAliveConfig {
        KeepAliveConfig {
            mode: KeepAliveMode::Adaptive {
                knob,
                waker: Arc::new(std::sync::Mutex::new(None)),
            },
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

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(
            result.is_err(),
            "should not receive any pings while dormant"
        );
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

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(
            result.is_err(),
            "should not receive pings after going dormant"
        );
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
        assert!(
            result.is_err(),
            "should still be alive after rescue ping was answered"
        );
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
        assert!(
            result.is_err(),
            "should NOT declare peer dead before first inbound packet"
        );
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
        assert!(
            result.is_err(),
            "should still be pending (inbound traffic reset deadline)"
        );
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
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
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
    async fn adaptive_knob_zero_then_positive_after_probing_wakes() {
        // Regression: set_keepalive(0) while Probing must re-arm the waker so a
        // following set_keepalive(N>0) is seen even on a transport with no
        // timers of its own. Before the fix the Probing->Dormant branch dropped
        // the waker and the knob change was lost.
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let knob = Arc::new(AtomicU64::new(5));
        let waker_slot: Arc<std::sync::Mutex<Option<std::task::Waker>>> =
            Arc::new(std::sync::Mutex::new(None));
        let cfg = KeepAliveConfig {
            mode: KeepAliveMode::Adaptive {
                knob: knob.clone(),
                waker: waker_slot.clone(),
            },
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Activate (Probing) and consume the initial ping.
        drive_poll(&mut ka).await;
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv()).await;

        // set_keepalive(0): go dormant. This poll must leave a waker registered.
        knob.store(0, Ordering::Relaxed);
        drive_poll(&mut ka).await;
        assert!(
            waker_slot.lock().unwrap().is_some(),
            "Probing->Dormant must re-arm the knob waker"
        );

        // set_keepalive(20): the app can now wake the parked task.
        knob.store(20, Ordering::Relaxed);
        let w = waker_slot.lock().unwrap().take();
        assert!(w.is_some(), "waker should still be there to wake");
        w.unwrap().wake();

        // Next poll sends a ping (proving the knob change took effect).
        drive_poll(&mut ka).await;
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("should ping after 5->0->20 knob dance")
            .unwrap();
        assert!(is_icmp_echo_request(&pkt));
    }

    #[tokio::test]
    async fn periodic_active_window_suppresses_pings_when_peer_quiet() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let cfg = KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(5),
                recv_timeout: None,
            },
            active_window: Some(std::time::Duration::from_secs(12)),
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Within active_window (no inbound yet, but last_inbound = start): the
        // first couple of intervals still ping.
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        drive_poll(&mut ka).await;
        let first = tokio::time::timeout(std::time::Duration::from_millis(50), handle.recv()).await;
        assert!(first.is_ok(), "should ping while within active_window");

        // Advance well past active_window with NO inbound → pings suppressed.
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        drive_poll(&mut ka).await;
        let suppressed =
            tokio::time::timeout(std::time::Duration::from_millis(50), handle.recv()).await;
        assert!(
            suppressed.is_err(),
            "should suppress pings once peer has been silent past active_window"
        );
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

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(
            result.is_err(),
            "should not ping after switching to on-demand and going idle"
        );
    }
}
