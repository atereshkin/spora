use std::future::Future;
use futures_util::{Sink, Stream};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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
        loop {
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
            match this.timeout_timer.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    return Poll::Ready(None)
                }
                Poll::Pending => return Poll::Pending,
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
