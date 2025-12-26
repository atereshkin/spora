use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::UdpSocket;
use futures_util::{Stream, Sink};

// pub type IpTransport = Box<dyn Transport + Send + Unpin>;
//
// pub trait Transport:
//     Stream<Item = io::Result<Vec<u8>>> +
//     Sink<Vec<u8>, Error = io::Error>
// {}

pub type IpStream = Box<dyn Stream<Item = io::Result<Vec<u8>>> + Send + Unpin>;
pub type IpSink = Box<dyn Sink<Vec<u8>, Error = io::Error> + Send + Unpin>;


// impl<T> Transport for T
// where T: Stream<Item = io::Result<Vec<u8>>> +
//          Sink<Vec<u8>, Error = io::Error> +
//          Send + Unpin
// {}


pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    recv_buffer: Vec<u8>,
    inner_sink: Pin<Box<dyn Sink<Vec<u8>, Error = io::Error> + Send>>,
}

impl UdpTransport {
    pub fn new(socket: Arc<UdpSocket>, peer_addr: SocketAddr) -> Self {
        let socket_clone = socket.clone();
        let transport_sink = futures_util::sink::unfold(socket_clone, move |s, pkt: Vec<u8>| async move {
            s.send_to(&pkt, peer_addr).await?;
            Ok::<_, io::Error>(s)
        });

        Self {
            socket,
            peer_addr,
            recv_buffer: vec![0u8; 1500],
            inner_sink: Box::pin(transport_sink),
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
                        return Poll::Ready(Some(Ok(buf.filled().to_vec())));
                    }
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
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
