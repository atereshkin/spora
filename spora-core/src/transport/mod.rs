pub mod frag;
pub mod keepalive;
pub mod meter;
#[cfg(test)]
pub mod mock;
pub mod noise;
pub mod quic;
pub mod shaper;
pub mod stream;
pub mod upgradable;

use futures_util::{Sink, Stream};
use log::{debug, info, warn};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll::Ready;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::net::UdpSocket;
use tokio::time::{Sleep, sleep};

pub type IpTransport = Box<dyn Transport + Send + Unpin>;

pub trait Transport: Stream<Item = io::Result<Vec<u8>>> + Sink<Vec<u8>, Error = io::Error> {}

impl<T> Transport for T where
    T: Stream<Item = io::Result<Vec<u8>>> + Sink<Vec<u8>, Error = io::Error> + Send + Unpin
{
}

const UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    recv_buffer: Vec<u8>,
    inner_sink: Pin<Box<dyn Sink<Vec<u8>, Error = io::Error> + Send>>,
    timeout_timer: Pin<Box<Sleep>>,
}

impl UdpTransport {
    pub fn new(socket: Arc<UdpSocket>, peer_addr: SocketAddr) -> Self {
        let socket_clone = socket.clone();
        let transport_sink =
            futures_util::sink::unfold(socket_clone, move |s, pkt: Vec<u8>| async move {
                s.send_to(&pkt, peer_addr).await?;
                Ok::<_, io::Error>(s)
            });

        Self {
            socket,
            peer_addr,
            recv_buffer: vec![0u8; 1500],
            inner_sink: Box::pin(transport_sink),
            timeout_timer: Box::pin(sleep(UDP_TIMEOUT)),
        }
    }
}

impl Stream for UdpTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // it's only in a loop to repeat polling the socket if we get a packet from the wrong peer
            let mut buf = tokio::io::ReadBuf::new(&mut this.recv_buffer);
            match this.socket.poll_recv_from(cx, &mut buf) {
                Poll::Ready(Ok(addr)) => {
                    if addr == this.peer_addr {
                        this.timeout_timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + UDP_TIMEOUT);
                        return Poll::Ready(Some(Ok(buf.filled().to_vec())));
                    }
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => {}
            }
            return match this.timeout_timer.as_mut().poll(cx) {
                Poll::Ready(_) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            };
        }
    }
}

impl Sink<Vec<u8>> for UdpTransport {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_sink.as_mut().poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.inner_sink.as_mut().start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_sink.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_sink.as_mut().poll_close(cx)
    }
}

/// Default sleep after a failed dial (see `Timings::reconnect_delay`).
pub(crate) const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) type DialFuture = Pin<Box<dyn Future<Output = io::Result<IpTransport>> + Send>>;
type Dialer = Box<dyn FnMut() -> DialFuture + Send>;

/// The client's dormancy knob + its wake channel, shared with the keepalive
/// layer. Knob 0 = dormant (screen off); the reconnect loop parks instead of
/// redialing, and `set_keepalive(N>0)` wakes it.
pub(crate) type Dormancy = (Arc<AtomicU64>, Arc<Mutex<Option<Waker>>>);

enum ReconnectState {
    Connected(IpTransport),
    Sleeping(Pin<Box<Sleep>>),
    /// Parked because the app is dormant (knob 0): a dead tunnel while the
    /// screen is off must NOT spin the radio redialing. Waits for the knob
    /// to go positive (set_keepalive wakes us via the shared waker).
    DormantPark,
    Dialing(DialFuture),
}

/// A `Transport` wrapper that transparently reconnects by swapping the inner `IpTransport`.
///
/// Policy:
/// - retry forever
/// - when inner yields `None` or `Err`, sleep `delay` then reconnect — pacing
///   *every* reconnect, not just retries after a failed dial. A successful but
///   short-lived session (e.g. a client repeatedly evicted by the share side's
///   single-session policy) would otherwise redial instantly and, with the peer
///   doing the same, spin in a tight mutual-eviction storm.
/// - while the app is dormant (knob 0) a dead tunnel parks instead of
///   redialing — cooperate-with-sleep, so a screen-off phone is radio-silent;
///   the redial fires on wake. Per-port sessions make that wake-redial cheap.
/// - outbound packets are *dropped* while reconnecting
pub struct ReconnectTransport {
    dialer: Dialer,
    state: ReconnectState,
    delay: std::time::Duration,
    dormancy: Option<Dormancy>,
}

impl ReconnectTransport {
    pub fn new(
        initial: IpTransport,
        dialer: Dialer,
        delay: std::time::Duration,
        dormancy: Option<Dormancy>,
    ) -> Self {
        Self {
            dialer,
            state: ReconnectState::Connected(initial),
            delay,
            dormancy,
        }
    }

    fn begin_sleep(&mut self) {
        debug!(
            "Sleeping for {} seconds before reconnecting.",
            self.delay.as_secs()
        );
        self.state = ReconnectState::Sleeping(Box::pin(sleep(self.delay)));
    }

    fn is_dormant(&self) -> bool {
        self.dormancy
            .as_ref()
            .is_some_and(|(knob, _)| knob.load(Ordering::Relaxed) == 0)
    }

    /// Register this task's waker (so `set_keepalive(N>0)` re-polls us) and
    /// then RE-CHECK the knob, returning whether we should stay parked. The
    /// re-check after registering closes the store-vs-register race: a
    /// `set_keepalive(N)` that ran between an earlier `is_dormant()` and this
    /// registration stores knob>0 but finds no waker to wake — the re-read
    /// here sees that knob>0 and reports "don't park". Sharing the keepalive
    /// layer's waker slot is safe: while parked we do not poll the inner
    /// keepalive layer, so nothing else writes the slot.
    fn stay_parked(&mut self, cx: &Context<'_>) -> bool {
        if let Some((_, waker)) = &self.dormancy {
            *waker.lock().unwrap() = Some(cx.waker().clone());
        }
        self.is_dormant()
    }

    /// After the reconnect delay: dial, unless the app is dormant — then park.
    fn dial_or_park(&mut self, cx: &Context<'_>) {
        if self.is_dormant() && self.stay_parked(cx) {
            debug!("Dormant (knob 0): parking reconnect instead of dialing.");
            self.state = ReconnectState::DormantPark;
        } else {
            self.begin_dial();
        }
    }

    fn begin_dial(&mut self) {
        debug!("Dialing...");
        let fut = (self.dialer)();
        self.state = ReconnectState::Dialing(fut);
    }
}

impl Stream for ReconnectTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                ReconnectState::Connected(inner) => {
                    let mut pinned = Pin::new(inner);
                    match pinned.as_mut().poll_next(cx) {
                        Poll::Ready(Some(Ok(pkt))) => return Poll::Ready(Some(Ok(pkt))),
                        Poll::Ready(Some(Err(e))) => {
                            warn!("Inner transport error, reconnecting: {}", e);
                            this.begin_sleep();
                            continue;
                        }
                        Poll::Ready(None) => {
                            info!("Inner transport stream ended, reconnecting");
                            this.begin_sleep();
                            continue;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReconnectState::Sleeping(timer) => match timer.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.dial_or_park(cx);
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::DormantPark => {
                    // Re-register our waker and re-read the knob atomically
                    // enough to close the race with set_keepalive.
                    if this.stay_parked(cx) {
                        return Poll::Pending;
                    }
                    this.begin_dial();
                    continue;
                }
                ReconnectState::Dialing(fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(new_inner)) => {
                        info!("Reconnected successfully");
                        this.state = ReconnectState::Connected(new_inner);
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        debug!("Dial failed: {}", e);
                        // Dial failed => sleep then try again forever.
                        this.begin_sleep();
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

impl Sink<Vec<u8>> for ReconnectTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let ret = match &mut this.state {
            ReconnectState::Connected(inner) => Pin::new(inner).poll_ready(cx),
            ReconnectState::Sleeping(_) | ReconnectState::DormantPark | ReconnectState::Dialing(_) => {
                Poll::Ready(Ok(()))
            } // drop policy
        };
        ret
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        match &mut this.state {
            ReconnectState::Connected(inner) => {
                if let Err(e) = Pin::new(inner).start_send(item) {
                    warn!("start_send failed: {}. Reconnecting...", e);
                    this.begin_sleep();
                }
                Ok(())
            }
            ReconnectState::Sleeping(_) | ReconnectState::DormantPark | ReconnectState::Dialing(_) => {
                Ok(())
            } // drop policy
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match &mut this.state {
            ReconnectState::Connected(inner) => match Pin::new(inner).poll_flush(cx) {
                Ready(Err(e)) => {
                    warn!("poll_flush failed: {}. Reconnecting...", e);
                    // begin_sleep (not begin_dial) so this reconnect path also
                    // honors the dormancy park + reconnect-delay pacing that
                    // the Sleeping->dial_or_park transition applies. (Latent:
                    // the current inner chain never errors on flush/close.)
                    this.begin_sleep();
                    Ready(Ok(()))
                }
                p => p,
            },
            ReconnectState::Sleeping(_) | ReconnectState::DormantPark | ReconnectState::Dialing(_) => {
                Poll::Ready(Ok(()))
            } // drop policy
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match &mut this.state {
            ReconnectState::Connected(inner) => match Pin::new(inner).poll_close(cx) {
                Ready(Err(e)) => {
                    warn!("poll_close failed: {}. Reconnecting...", e);
                    this.begin_sleep(); // see poll_flush
                    Ready(Ok(()))
                }
                p => p,
            },
            ReconnectState::Sleeping(_) | ReconnectState::DormantPark | ReconnectState::Dialing(_) => {
                Poll::Ready(Ok(()))
            } // drop policy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{
        MockTransportHandle, is_icmp_echo_request, mock_transport, mock_transport_pair,
    };
    use super::*;
    use crate::transport::keepalive::{KeepAliveConfig, KeepAliveMode, KeepAliveTransport};
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn reconnect_passes_packets_through() {
        let (local, mut remote) = mock_transport_pair();
        let dialer: Dialer = Box::new(|| Box::pin(async { unreachable!("should not dial") }));
        let mut rt = ReconnectTransport::new(Box::new(local), dialer, RECONNECT_DELAY, None);

        // Send from remote, receive on reconnect transport
        remote.send(vec![1, 2, 3]).await.unwrap();
        let pkt = rt.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Send through reconnect transport, receive on remote
        Pin::new(&mut rt).send(vec![4, 5, 6]).await.unwrap();
        let pkt = remote.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn reconnect_redials_on_inner_close() {
        tokio::time::pause();
        let (local, handle) = mock_transport();
        handle.close(); // close the channel so local yields None

        let dial_count = Arc::new(AtomicUsize::new(0));
        let dc = dial_count.clone();
        let handles: Arc<Mutex<Vec<MockTransportHandle>>> = Arc::new(Mutex::new(Vec::new()));
        let handles_clone = handles.clone();

        let dialer: Dialer = Box::new(move || {
            let dc = dc.clone();
            let handles = handles_clone.clone();
            Box::pin(async move {
                dc.fetch_add(1, Ordering::SeqCst);
                let (new_local, new_handle) = mock_transport();
                handles.lock().unwrap().push(new_handle);
                Ok(Box::new(new_local) as IpTransport)
            })
        });

        let mut rt = ReconnectTransport::new(Box::new(local), dialer, RECONNECT_DELAY, None);

        // First poll sees None and enters the paced sleep — it must NOT dial yet.
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();
        assert_eq!(
            dial_count.load(Ordering::SeqCst),
            0,
            "must not redial before the reconnect delay elapses"
        );

        // After the delay, the dial fires.
        tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_millis(100)).await;
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();
        assert!(
            dial_count.load(Ordering::SeqCst) >= 1,
            "dialer should have been called"
        );
    }

    #[tokio::test]
    async fn reconnect_redials_on_stream_error() {
        // The inner stream yielding Some(Err) (a transport error, not a clean
        // close) must also trigger a paced reconnect. Exercises the
        // Poll::Ready(Some(Err)) arm, which the close()/None tests don't cover.
        tokio::time::pause();
        let (local, handle) = mock_transport();
        handle.inject_error(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "inner transport error",
        ));

        let dial_count = Arc::new(AtomicUsize::new(0));
        let dc = dial_count.clone();
        let dialer: Dialer = Box::new(move || {
            let dc = dc.clone();
            Box::pin(async move {
                dc.fetch_add(1, Ordering::SeqCst);
                let (new_local, _new_handle) = mock_transport();
                Ok(Box::new(new_local) as IpTransport)
            })
        });

        let mut rt = ReconnectTransport::new(Box::new(local), dialer, RECONNECT_DELAY, None);

        // The stream error enters the paced sleep — no immediate redial.
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();
        assert_eq!(
            dial_count.load(Ordering::SeqCst),
            0,
            "a stream error must pace the reconnect, not dial immediately"
        );

        // After the delay, it redials.
        tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_millis(100)).await;
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();
        assert!(
            dial_count.load(Ordering::SeqCst) >= 1,
            "dialer should have been called after a stream error"
        );
        drop(handle);
    }

    #[tokio::test]
    async fn reconnect_retries_after_dial_failure() {
        tokio::time::pause();

        let (local, handle) = mock_transport();
        handle.close(); // close channel to trigger reconnect

        let dial_count = Arc::new(AtomicUsize::new(0));
        let dc = dial_count.clone();
        let handles: Arc<Mutex<Vec<MockTransportHandle>>> = Arc::new(Mutex::new(Vec::new()));
        let handles_clone = handles.clone();

        let dialer: Dialer = Box::new(move || {
            let dc = dc.clone();
            let handles = handles_clone.clone();
            Box::pin(async move {
                let n = dc.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "test failure",
                    ))
                } else {
                    let (new_local, new_handle) = mock_transport();
                    handles.lock().unwrap().push(new_handle);
                    Ok(Box::new(new_local) as IpTransport)
                }
            })
        });

        let mut rt = ReconnectTransport::new(Box::new(local), dialer, RECONNECT_DELAY, None);

        // Drive the transport: it should fail twice, sleep between, then succeed
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if dial_count.load(Ordering::SeqCst) >= 3 {
                    break;
                }
                // Advance time past the reconnect delay
                tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_millis(100)).await;
                // Poll to drive state machine
                tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
                    .await
                    .ok();
            }
        })
        .await
        .expect("should complete within timeout");

        assert!(
            dial_count.load(Ordering::SeqCst) >= 3,
            "dialer should have been called at least 3 times"
        );
    }

    // --- Sink tests ---

    #[tokio::test]
    async fn reconnect_sink_error_triggers_redial() {
        tokio::time::pause();
        let (local, handle) = mock_transport();
        // Close the handle so the inner transport's Sink returns BrokenPipe
        handle.close();

        let dial_count = Arc::new(AtomicUsize::new(0));
        let dc = dial_count.clone();
        let handles: Arc<Mutex<Vec<MockTransportHandle>>> = Arc::new(Mutex::new(Vec::new()));
        let handles_clone = handles.clone();

        let dialer: Dialer = Box::new(move || {
            let dc = dc.clone();
            let handles = handles_clone.clone();
            Box::pin(async move {
                dc.fetch_add(1, Ordering::SeqCst);
                let (new_local, new_handle) = mock_transport();
                handles.lock().unwrap().push(new_handle);
                Ok(Box::new(new_local) as IpTransport)
            })
        });

        let mut rt = ReconnectTransport::new(Box::new(local), dialer, RECONNECT_DELAY, None);

        // Drive past the None; the redial is paced, so advance past the delay.
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();
        tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_millis(100)).await;
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();
        assert!(
            dial_count.load(Ordering::SeqCst) >= 1,
            "dialer should have been called from stream close"
        );

        // Now close the new handle to make the Sink fail
        {
            let mut h = handles.lock().unwrap();
            let new_handle = h.pop().unwrap();
            new_handle.close();
        }

        // Reset dial count
        dial_count.store(0, Ordering::SeqCst);

        // Send through the ReconnectTransport — start_send should hit BrokenPipe and trigger redial
        Pin::new(&mut rt).send(vec![1, 2, 3]).await.unwrap();

        // The sink-error reconnect is paced too: advance past the delay, then dial.
        tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_millis(100)).await;
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();

        assert!(
            dial_count.load(Ordering::SeqCst) >= 1,
            "dialer should have been called after sink error"
        );
    }

    #[tokio::test]
    async fn reconnect_drops_packets_while_sleeping() {
        tokio::time::pause();

        let (local, handle) = mock_transport();
        handle.close(); // trigger reconnect

        // Dialer always fails, so we stay in Sleeping state
        let dialer: Dialer = Box::new(|| {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "always fails",
                ))
            })
        });

        let mut rt = ReconnectTransport::new(Box::new(local), dialer, RECONNECT_DELAY, None);

        // Poll to drive: None → Sleeping (the paced reconnect delay)
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();

        // Now in Sleeping state — send should succeed (drop policy)
        let result = Pin::new(&mut rt).send(vec![1, 2, 3]).await;
        assert!(
            result.is_ok(),
            "send should succeed (drop policy) while sleeping"
        );
    }

    #[tokio::test]
    async fn reconnect_drops_packets_while_dialing() {
        tokio::time::pause();
        let (local, handle) = mock_transport();
        handle.close(); // trigger reconnect

        // Dialer hangs forever
        let dialer: Dialer = Box::new(|| Box::pin(futures_util::future::pending()));

        let mut rt = ReconnectTransport::new(Box::new(local), dialer, RECONNECT_DELAY, None);

        // None → Sleeping → (advance past the delay) → begin_dial → Dialing (hangs)
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();
        tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_millis(100)).await;
        tokio::time::timeout(std::time::Duration::from_millis(10), rt.next())
            .await
            .ok();

        // Now in Dialing state — send should succeed (drop policy)
        let result = Pin::new(&mut rt).send(vec![1, 2, 3]).await;
        assert!(
            result.is_ok(),
            "send should succeed (drop policy) while dialing"
        );
    }

    // --- Full transport stack integration tests ---

    #[tokio::test]
    async fn full_stack_passes_packets_and_injects_keepalives() {
        tokio::time::pause();

        let (local, mut handle) = mock_transport();

        let dialer: Dialer = Box::new(|| Box::pin(async { unreachable!("should not dial") }));
        let reconnect = Box::new(ReconnectTransport::new(
            Box::new(local),
            dialer,
            RECONNECT_DELAY,
            None,
        )) as IpTransport;

        let ka_cfg = KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(5),
                recv_timeout: Some(std::time::Duration::from_secs(30)),
            },
            ..Default::default()
        };
        let mut stack = KeepAliveTransport::new(reconnect, ka_cfg);

        // Data flows inbound: handle → stack
        handle.send(vec![10, 20]).unwrap();
        let pkt = stack.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![10, 20]);

        // Data flows outbound: stack → handle
        Pin::new(&mut stack).send(vec![30, 40]).await.unwrap();
        let pkt = handle.recv().await.unwrap();
        assert_eq!(pkt, vec![30, 40]);

        // Advance past keepalive interval
        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        // Poll to trigger keepalive injection
        let _ = futures_util::future::poll_fn(|cx| {
            let _ = Pin::new(&mut stack).poll_next(cx);
            Poll::Ready(())
        })
        .await;

        // Remote should receive the ICMP keepalive
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), handle.recv())
            .await
            .expect("should receive keepalive")
            .unwrap();
        assert!(is_icmp_echo_request(&pkt), "expected ICMP echo request");
    }

    #[tokio::test]
    async fn full_stack_reconnects_on_close_and_resumes() {
        tokio::time::pause();

        let (local, handle) = mock_transport();

        let handles: Arc<Mutex<Vec<MockTransportHandle>>> = Arc::new(Mutex::new(Vec::new()));
        let handles_clone = handles.clone();
        let dial_count = Arc::new(AtomicUsize::new(0));
        let dc = dial_count.clone();

        let dialer: Dialer = Box::new(move || {
            let dc = dc.clone();
            let handles = handles_clone.clone();
            Box::pin(async move {
                dc.fetch_add(1, Ordering::SeqCst);
                let (new_local, new_handle) = mock_transport();
                handles.lock().unwrap().push(new_handle);
                Ok(Box::new(new_local) as IpTransport)
            })
        });

        let reconnect = Box::new(ReconnectTransport::new(
            Box::new(local),
            dialer,
            RECONNECT_DELAY,
            None,
        )) as IpTransport;

        let ka_cfg = KeepAliveConfig {
            mode: KeepAliveMode::Periodic {
                interval: std::time::Duration::from_secs(5),
                recv_timeout: Some(std::time::Duration::from_secs(30)),
            },
            ..Default::default()
        };
        let mut stack = KeepAliveTransport::new(reconnect, ka_cfg);

        // Initial passthrough works
        handle.send(vec![1, 2, 3]).unwrap();
        let pkt = stack.next().await.unwrap().unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Close the handle to trigger reconnect
        handle.close();

        // Drive the state machine: poll_next sees None and enters the paced
        // sleep; advance past the reconnect delay so the dial fires.
        tokio::time::timeout(std::time::Duration::from_millis(10), stack.next())
            .await
            .ok();
        tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_secs(1)).await;
        tokio::time::timeout(std::time::Duration::from_millis(100), stack.next())
            .await
            .ok();

        assert!(
            dial_count.load(Ordering::SeqCst) >= 1,
            "dialer should have been called"
        );

        // Send data via the new handle's transport
        {
            let h = handles.lock().unwrap();
            h[0].send(vec![7, 8, 9]).unwrap();
        }

        // Data should flow through the new connection
        let pkt = tokio::time::timeout(std::time::Duration::from_millis(100), stack.next())
            .await
            .expect("should receive on new connection")
            .unwrap()
            .unwrap();
        assert_eq!(pkt, vec![7, 8, 9]);
    }
}
