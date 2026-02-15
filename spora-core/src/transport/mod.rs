pub mod keepalive;
#[cfg(test)]
pub mod mock;

use std::future::Future;
use futures_util::{Sink, Stream};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::task::Poll::Ready;
use log::{debug, trace, warn};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Sleep};

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
        loop { // it's only in a loop to repeat polling the socket if we get a packet from the wrong peer
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
                Poll::Ready(_) => {
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
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


const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) type DialFuture = Pin<Box<dyn Future<Output = io::Result<IpTransport>> + Send>>;
type Dialer = Box<dyn FnMut() -> DialFuture + Send>;

enum ReconnectState {
    Connected(IpTransport),
    Sleeping(Pin<Box<Sleep>>),
    Dialing(DialFuture),
}

/// A `Transport` wrapper that transparently reconnects by swapping the inner `IpTransport`.
///
/// Policy:
/// - retry forever
/// - when inner yields `None` or `Err`, start reconnect
/// - outbound packets are *dropped* while reconnecting
pub struct ReconnectTransport {
    dialer: Dialer,
    state: ReconnectState,
}

impl ReconnectTransport {
    pub fn new(initial: IpTransport, dialer: Dialer) -> Self {
        Self {
            dialer,
            state: ReconnectState::Connected(initial),
        }
    }

    fn begin_sleep(&mut self) {
        debug!("Sleeping for {} seconds before reconnecting.", RECONNECT_DELAY.as_secs());
        self.state = ReconnectState::Sleeping(Box::pin(sleep(RECONNECT_DELAY)));
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
                        Poll::Ready(Some(Err(_e))) => {
                            // Underlying transport errored => reconnect.
                            this.begin_dial();
                            continue;
                        }
                        Poll::Ready(None) => {
                            // Underlying transport ended => reconnect.
                            this.begin_dial();
                            continue;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReconnectState::Sleeping(timer) => match timer.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.begin_dial();
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Dialing(fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(new_inner)) => {
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
            ReconnectState::Sleeping(_) | ReconnectState::Dialing(_) => Poll::Ready(Ok(())), // drop policy
        };
        trace!("poll_ready: {:?}", ret);
        ret
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let ret = match &mut this.state {
            ReconnectState::Connected(inner) => {
                if let Err(e) = Pin::new(inner).start_send(item) {
                    warn!("start_send failed: {}. Reconnecting...", e);
                    this.begin_dial();
                }
                Ok(())
            },
            ReconnectState::Sleeping(_) | ReconnectState::Dialing(_) => Ok(()), // drop policy
        };
        trace!("start_send: {:?}", ret);
        ret
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match &mut this.state {
            ReconnectState::Connected(inner) => {
                match Pin::new(inner).poll_flush(cx) {
                    Ready(Err(e)) => {
                        warn!("poll_flush failed: {}. Reconnecting...", e);
                        this.begin_dial();
                        Ready(Ok(()))
                    },
                    p => p
                }
            },
            ReconnectState::Sleeping(_) | ReconnectState::Dialing(_) => Poll::Ready(Ok(())), // drop policy
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match &mut this.state {
            ReconnectState::Connected(inner) => {
                match Pin::new(inner).poll_close(cx) {
                    Ready(Err(e)) => {
                        warn!("poll_close failed: {}. Reconnecting...", e);
                        this.begin_dial();
                        Ready(Ok(()))
                    },
                    p => p
                }
            },
            ReconnectState::Sleeping(_) | ReconnectState::Dialing(_) => Poll::Ready(Ok(())), // drop policy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::mock::mock_transport_pair;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn reconnect_passes_packets_through() {
        let (local, mut remote) = mock_transport_pair();
        let dialer: Dialer = Box::new(|| Box::pin(async { unreachable!("should not dial") }));
        let mut rt = ReconnectTransport::new(Box::new(local), dialer);

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
        let (local, remote) = mock_transport_pair();
        drop(remote); // close the channel so local yields None

        let dial_count = Arc::new(AtomicUsize::new(0));
        let dc = dial_count.clone();

        let dialer: Dialer = Box::new(move || {
            let dc = dc.clone();
            Box::pin(async move {
                dc.fetch_add(1, Ordering::SeqCst);
                let (new_local, _keep) = mock_transport_pair();
                // Leak _keep so the new transport doesn't close immediately
                Box::leak(Box::new(_keep));
                Ok(Box::new(new_local) as IpTransport)
            })
        });

        let mut rt = ReconnectTransport::new(Box::new(local), dialer);

        // The first poll should see None from the dead inner, dial, and then pend (new transport is idle)
        tokio::time::timeout(std::time::Duration::from_millis(100), rt.next()).await.ok();

        assert!(dial_count.load(Ordering::SeqCst) >= 1, "dialer should have been called");
    }

    #[tokio::test]
    async fn reconnect_retries_after_dial_failure() {
        tokio::time::pause();

        let (local, remote) = mock_transport_pair();
        drop(remote); // close channel to trigger reconnect

        let dial_count = Arc::new(AtomicUsize::new(0));
        let dc = dial_count.clone();

        let dialer: Dialer = Box::new(move || {
            let dc = dc.clone();
            Box::pin(async move {
                let n = dc.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "test failure"))
                } else {
                    let (new_local, _keep) = mock_transport_pair();
                    Box::leak(Box::new(_keep));
                    Ok(Box::new(new_local) as IpTransport)
                }
            })
        });

        let mut rt = ReconnectTransport::new(Box::new(local), dialer);

        // Drive the transport: it should fail twice, sleep between, then succeed
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if dial_count.load(Ordering::SeqCst) >= 3 {
                    break;
                }
                // Advance time past the reconnect delay
                tokio::time::advance(RECONNECT_DELAY + std::time::Duration::from_millis(100)).await;
                // Poll to drive state machine
                tokio::time::timeout(std::time::Duration::from_millis(10), rt.next()).await.ok();
            }
        })
        .await
        .expect("should complete within timeout");

        assert!(dial_count.load(Ordering::SeqCst) >= 3, "dialer should have been called at least 3 times");
    }
}