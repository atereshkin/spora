use std::future::Future;
use futures_util::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use log::{trace, warn};
use tokio::time::{sleep, Sleep};
use std::net::Ipv4Addr;
use tokio::time::Instant;
use crate::IpTransport;

/// Configuration for the ICMP keepalive layer.
///
/// Note: `src_ip`/`dst_ip` are the *inner* (tunneled) IPv4 addresses used to craft an ICMP Echo.
/// For now these can be arbitrary private addresses as long as the remote side doesn't drop them.
#[derive(Clone, Copy, Debug)]
pub struct KeepAliveConfig {
    pub interval: std::time::Duration,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub icmp_id: u16,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            interval: std::time::Duration::from_secs(10),
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            icmp_id: 0x5350, // 'SP'
        }
    }
}

enum KeepAliveSendState {
    Idle,
    Sending(Vec<u8>),
}

/// A best-effort keepalive wrapper that periodically injects an IPv4+ICMP Echo Request packet
/// into the inner transport to keep NAT bindings alive.
///
/// Policy:
/// - Timer is reset on any inbound/outbound traffic (i.e. "only when idle").
/// - No parsing/filtering: inbound packets are passed through untouched.
/// - Keepalive injection is best-effort: failures trigger a warning and we try again later.
pub struct KeepAliveTransport {
    inner: IpTransport,
    cfg: KeepAliveConfig,
    seq: u16,
    timer: Pin<Box<Sleep>>,
    send_state: KeepAliveSendState,
}

impl KeepAliveTransport {
    pub fn new(inner: IpTransport, cfg: KeepAliveConfig) -> Self {
        Self {
            inner,
            cfg,
            seq: 0,
            timer: Box::pin(sleep(cfg.interval)),
            send_state: KeepAliveSendState::Idle,
        }
    }

    fn reset_timer(&mut self) {
        self.timer
            .as_mut()
            .reset(Instant::now() + self.cfg.interval);
    }

    fn build_icmp_echo(&mut self) -> Vec<u8> {
        // ICMP Echo Request payload can be tiny; we include a simple magic tag.
        // If you later want RTT, include a timestamp and match echo replies.
        let payload: [u8; 4] = *b"spka";

        // Uses `etherparse` which is already in your dependency tree.
        let mut pkt = Vec::with_capacity(64);
        let builder = etherparse::PacketBuilder::ipv4(
            self.cfg.src_ip.octets(),
            self.cfg.dst_ip.octets(),
            64, // ttl
        )
        .icmpv4_echo_request(self.cfg.icmp_id, self.seq);

        self.seq = self.seq.wrapping_add(1);

        builder
            .write(&mut pkt, &payload)
            .expect("writing into Vec should not fail");

        pkt
    }

    fn poll_maybe_send_keepalive(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // If timer fired and we're idle, schedule a new keepalive packet.
        if matches!(self.send_state, KeepAliveSendState::Idle) {
            if let Poll::Ready(()) = self.timer.as_mut().poll(cx) {
                let pkt = self.build_icmp_echo();
                trace!("Keepalive timer fired; scheduling ICMP echo ({} bytes)", pkt.len());
                self.send_state = KeepAliveSendState::Sending(pkt);
                // Reset timer immediately so repeated polls don't enqueue more.
                self.reset_timer();
            }
        }

        loop {
            match &mut self.send_state {
                KeepAliveSendState::Idle => return Poll::Ready(()),
                KeepAliveSendState::Sending(pkt) => {
                    // Drive sending via Sink poll methods (non-async).
                    match Pin::new(&mut self.inner).poll_ready(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => {
                            warn!("Keepalive poll_ready failed: {}", e);
                            self.send_state = KeepAliveSendState::Idle;
                            return Poll::Ready(());
                        }
                        Poll::Pending => return Poll::Pending,
                    }

                    // Take ownership and attempt to start_send.
                    let pkt = std::mem::take(pkt);
                    if let Err(e) = Pin::new(&mut self.inner).start_send(pkt) {
                        warn!("Keepalive start_send failed: {}", e);
                        self.send_state = KeepAliveSendState::Idle;
                        return Poll::Ready(());
                    }

                    match Pin::new(&mut self.inner).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            trace!("Keepalive sent");
                            self.send_state = KeepAliveSendState::Idle;
                            continue;
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("Keepalive poll_flush failed: {}", e);
                            self.send_state = KeepAliveSendState::Idle;
                            return Poll::Ready(());
                        }
                        Poll::Pending => {
                            // We already started the send; now wait for flush completion.
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }
}

impl Stream for KeepAliveTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Opportunistically send keepalive when polled (outermost layer should be polled often).
        let _ = this.poll_maybe_send_keepalive(cx);

        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(pkt))) => {
                this.reset_timer();
                Poll::Ready(Some(Ok(pkt)))
            }
            other => other,
        }
    }
}

impl Sink<Vec<u8>> for KeepAliveTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        // While user is active, we still allow keepalive to be driven by polls,
        // but it's "idle-only" due to reset_timer calls.
        let _ = this.poll_maybe_send_keepalive(cx);

        Pin::new(&mut this.inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.reset_timer();
        Pin::new(&mut this.inner).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let _ = this.poll_maybe_send_keepalive(cx);
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
    use crate::transport::mock::mock_transport_pair;
    use futures_util::{SinkExt, StreamExt};

    fn is_icmp_echo_request(pkt: &[u8]) -> bool {
        // Minimal check: IPv4 (version nibble == 4), protocol == 1 (ICMP), ICMP type == 8 (echo request)
        pkt.len() >= 24 && (pkt[0] >> 4) == 4 && pkt[9] == 1 && pkt[20] == 8
    }

    #[tokio::test]
    async fn keepalive_injects_icmp_after_interval() {
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance past the keepalive interval
        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        // Poll the keepalive transport — it should inject an ICMP packet
        // We need to poll ka (as Stream) to trigger the keepalive send
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            // poll_next on ka drives poll_maybe_send_keepalive internally
            let _ = futures_util::future::poll_fn(|cx| {
                let _ = Pin::new(&mut ka).poll_next(cx);
                Poll::Ready(())
            })
            .await;
        })
        .await
        .unwrap();

        // The remote side should have received the ICMP echo
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
        let cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance 3 seconds (not yet past the 5s interval)
        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        // Send inbound traffic which should reset the timer
        remote.send(vec![10, 20, 30]).await.unwrap();
        let pkt = ka.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![10, 20, 30]);

        // Advance another 3 seconds (6s total, but only 3s since reset)
        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        // Poll — timer should NOT have fired yet (only 3s since reset, need 5s)
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), remote.next()).await;
        assert!(result.is_err(), "should not have received keepalive yet (timer was reset)");

        // Advance past the interval from the reset point
        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        // Now poll ka to trigger the keepalive
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
}

