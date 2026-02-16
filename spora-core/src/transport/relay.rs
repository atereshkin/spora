use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use log::{debug, warn};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Prefix byte for signaling messages on the relay socket.
/// IPv4 packets start with 0x45–0x4F so there's no ambiguity.
pub const SIGNAL_PREFIX: u8 = 0xFE;

/// Split a relay `UdpSocket` into a `RelayTransport` (IP traffic) and a
/// `SignalChannel` (signaling messages). A background demux task reads from
/// the socket and dispatches by first byte.
pub fn relay_connection(
    socket: UdpSocket,
) -> (RelayTransport, SignalChannel, JoinHandle<()>) {
    let socket = Arc::new(socket);

    let (ip_tx, ip_rx) = mpsc::unbounded_channel();
    let (signal_tx, signal_rx) = mpsc::unbounded_channel();

    let recv_socket = socket.clone();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match recv_socket.recv(&mut buf).await {
                Ok(len) if len > 0 => {
                    if buf[0] == SIGNAL_PREFIX {
                        // Strip the prefix byte
                        if signal_tx.send(buf[1..len].to_vec()).is_err() {
                            debug!("Signal channel closed, demux task exiting");
                            break;
                        }
                    } else if ip_tx.send(buf[..len].to_vec()).is_err() {
                        debug!("IP channel closed, demux task exiting");
                        break;
                    }
                }
                Ok(_) => {} // empty packet, ignore
                Err(e) => {
                    warn!("Relay socket recv error: {}", e);
                    break;
                }
            }
        }
    });

    let send_socket = socket.clone();
    let transport_sink =
        futures_util::sink::unfold(send_socket, move |s, pkt: Vec<u8>| async move {
            s.send(&pkt).await?;
            Ok::<_, io::Error>(s)
        });

    let transport = RelayTransport {
        ip_rx,
        inner_sink: Box::pin(transport_sink),
    };

    let channel = SignalChannel {
        socket,
        signal_rx,
    };

    (transport, channel, handle)
}

/// Transport for IP traffic over the relay socket.
///
/// - `Stream`: yields IP packets from the demux channel
/// - `Sink`: sends raw bytes directly via the socket
pub struct RelayTransport {
    ip_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    inner_sink: Pin<Box<dyn Sink<Vec<u8>, Error = io::Error> + Send>>,
}

impl Stream for RelayTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.ip_rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for RelayTransport {
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

/// Channel for signaling messages over the relay socket.
///
/// Signaling messages are prefixed with `SIGNAL_PREFIX` (0xFE) on the wire.
pub struct SignalChannel {
    socket: Arc<UdpSocket>,
    signal_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl SignalChannel {
    /// Send a signaling message (automatically prepends `SIGNAL_PREFIX`).
    pub async fn send_signal(&self, data: &[u8]) -> io::Result<()> {
        let mut msg = Vec::with_capacity(1 + data.len());
        msg.push(SIGNAL_PREFIX);
        msg.extend_from_slice(data);
        self.socket.send(&msg).await?;
        Ok(())
    }

    /// Receive the next signaling message (prefix already stripped).
    pub async fn recv_signal(&mut self) -> Option<Vec<u8>> {
        self.signal_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    /// Helper: create a connected pair of UDP sockets on loopback.
    async fn loopback_pair() -> (UdpSocket, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn relay_demux_routes_ip_and_signal() {
        let (relay_sock, peer_sock) = loopback_pair().await;
        let (mut transport, mut signal, _handle) = relay_connection(relay_sock);

        // Send an IPv4-like packet from peer (first byte 0x45)
        let ip_pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        peer_sock.send(&ip_pkt).await.unwrap();

        // Send a signaling packet from peer
        let mut sig_pkt = vec![SIGNAL_PREFIX];
        sig_pkt.extend_from_slice(b"192.168.1.1:5000");
        peer_sock.send(&sig_pkt).await.unwrap();

        // IP packet arrives on transport
        use futures_util::StreamExt;
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.next(),
        )
        .await
        .expect("timeout")
        .unwrap()
        .unwrap();
        assert_eq!(received, ip_pkt);

        // Signal arrives on signal channel (prefix stripped)
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            signal.recv_signal(),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(received, b"192.168.1.1:5000");
    }

    #[tokio::test]
    async fn relay_transport_sends_raw() {
        let (relay_sock, peer_sock) = loopback_pair().await;
        let (transport, _signal, _handle) = relay_connection(relay_sock);

        use futures_util::SinkExt;
        let mut transport = transport;
        let data = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut transport).send(data.clone()).await.unwrap();

        let mut buf = [0u8; 1500];
        let len = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer_sock.recv(&mut buf),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(&buf[..len], &data);
    }

    #[tokio::test]
    async fn signal_channel_roundtrip() {
        let (relay_sock, peer_sock) = loopback_pair().await;
        let (_transport, signal, _handle) = relay_connection(relay_sock);

        // Send signal from our side
        signal.send_signal(b"hello").await.unwrap();

        // Peer receives it with prefix
        let mut buf = [0u8; 1500];
        let len = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer_sock.recv(&mut buf),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(buf[0], SIGNAL_PREFIX);
        assert_eq!(&buf[1..len], b"hello");
    }
}
