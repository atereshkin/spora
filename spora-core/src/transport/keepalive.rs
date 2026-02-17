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
    /// If no inbound packet arrives within this duration, yield `None` to signal
    /// the peer is gone. This is separate from `interval` because the keepalive
    /// timer resets on both inbound and outbound traffic, so it can't detect a
    /// dead peer on its own.
    pub recv_timeout: std::time::Duration,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub icmp_id: u16,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            interval: std::time::Duration::from_secs(10),
            recv_timeout: std::time::Duration::from_secs(30),
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
    /// Fires when no inbound packet has arrived for `cfg.recv_timeout`.
    /// Only reset on inbound traffic — outbound/keepalive packets don't count.
    recv_timer: Pin<Box<Sleep>>,
    send_state: KeepAliveSendState,
}

impl KeepAliveTransport {
    pub fn new(inner: IpTransport, cfg: KeepAliveConfig) -> Self {
        Self {
            inner,
            seq: 0,
            timer: Box::pin(sleep(cfg.interval)),
            recv_timer: Box::pin(sleep(cfg.recv_timeout)),
            send_state: KeepAliveSendState::Idle,
            cfg,
        }
    }

    fn reset_timer(&mut self) {
        self.timer
            .as_mut()
            .reset(Instant::now() + self.cfg.interval);
    }

    fn reset_recv_timer(&mut self) {
        self.recv_timer
            .as_mut()
            .reset(Instant::now() + self.cfg.recv_timeout);
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
                this.reset_recv_timer();
                Poll::Ready(Some(Ok(pkt)))
            }
            Poll::Pending => {
                // No data from inner — check if recv timeout fired (peer is gone).
                match this.recv_timer.as_mut().poll(cx) {
                    Poll::Ready(_) => {
                        warn!("No inbound traffic for {:?}, peer appears dead", this.cfg.recv_timeout);
                        Poll::Ready(None)
                    }
                    Poll::Pending => Poll::Pending,
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
    use crate::transport::mock::{mock_transport, mock_transport_pair, is_icmp_echo_request};
    use futures_util::{SinkExt, StreamExt};

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

    #[tokio::test]
    async fn outbound_traffic_resets_keepalive_timer() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance 3 seconds (not yet past the 5s interval)
        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        // Send outbound traffic which should reset the timer via start_send
        Pin::new(&mut ka).send(vec![10, 20, 30]).await.unwrap();
        let pkt = handle.recv().await.unwrap();
        assert_eq!(pkt, vec![10, 20, 30]);

        // Advance another 3 seconds (6s total, but only 3s since outbound reset)
        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        // Poll — timer should NOT have fired yet (only 3s since reset, need 5s)
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), handle.recv()).await;
        assert!(result.is_err(), "should not have received keepalive yet (timer was reset by outbound)");

        // Advance past the interval from the reset point
        tokio::time::advance(std::time::Duration::from_secs(3)).await;

        // Now poll ka to trigger the keepalive
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
            interval: std::time::Duration::from_secs(5),
            recv_timeout: std::time::Duration::from_secs(15),
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance past the recv_timeout (no inbound traffic)
        tokio::time::advance(std::time::Duration::from_secs(16)).await;

        // poll_next should return None (peer dead)
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        match result {
            Ok(None) => {} // expected — stream ended
            other => panic!("expected None (peer dead), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn recv_timeout_resets_on_inbound_traffic() {
        tokio::time::pause();

        let (local, mut remote) = mock_transport_pair();
        let cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(5),
            recv_timeout: std::time::Duration::from_secs(15),
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance 10 seconds (within the 15s recv_timeout)
        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        // Inbound traffic resets the recv timer
        remote.send(vec![1, 2, 3]).await.unwrap();
        let pkt = ka.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Advance another 10 seconds (20s total, but only 10s since last inbound)
        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        // Should still be alive — recv timer was reset at t=10
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), ka.next()).await;
        assert!(result.is_err(), "should still be pending (recv timer was reset)");

        // Advance past the recv_timeout from the reset point
        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        match result {
            Ok(None) => {} // expected — peer dead
            other => panic!("expected None after recv_timeout, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn recv_timeout_not_reset_by_outbound_traffic() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();
        let cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(5),
            recv_timeout: std::time::Duration::from_secs(15),
            ..Default::default()
        };
        let mut ka = KeepAliveTransport::new(Box::new(local), cfg);

        // Advance 10 seconds, then send outbound traffic
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        Pin::new(&mut ka).send(vec![1, 2, 3]).await.unwrap();
        let _ = handle.recv().await; // consume the packet

        // Advance past recv_timeout from start (outbound should NOT have reset it)
        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        let result = tokio::time::timeout(std::time::Duration::from_millis(100), ka.next()).await;
        match result {
            Ok(None) => {} // expected — outbound didn't reset recv timer
            other => panic!("expected None (outbound shouldn't reset recv timer), got {:?}", other),
        }
    }
}

