use futures_util::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

/// A channel-backed transport for use in tests.
///
/// Two `MockTransport`s linked via `mock_transport_pair()` can exchange packets
/// without any real networking.
pub struct MockTransport {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    error_rx: mpsc::UnboundedReceiver<io::Error>,
}

/// Handle for controlling a `MockTransport` from tests.
///
/// Created by `mock_transport()`. Lets you inject packets, receive packets,
/// inject errors, or close the transport.
pub struct MockTransportHandle {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    #[allow(dead_code)]
    error_tx: mpsc::UnboundedSender<io::Error>,
}

impl MockTransportHandle {
    /// Send a packet into the paired `MockTransport` (appears as inbound data).
    pub fn send(&self, pkt: Vec<u8>) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.tx.send(pkt)
    }

    /// Receive a packet that the paired `MockTransport` sent (via its `Sink` impl).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Inject an error so the next `Stream::poll_next` on the transport yields `Some(Err(...))`.
    #[allow(dead_code)]
    pub fn inject_error(&self, err: io::Error) {
        let _ = self.error_tx.send(err);
    }

    /// Close the transport by dropping the sender, causing the transport's `Stream` to yield `None`.
    pub fn close(self) {
        drop(self.tx);
    }
}

/// Create a `MockTransport` and a `MockTransportHandle` for controlling it.
pub fn mock_transport() -> (MockTransport, MockTransportHandle) {
    let (handle_tx, transport_rx) = mpsc::unbounded_channel();
    let (transport_tx, handle_rx) = mpsc::unbounded_channel();
    let (error_tx, error_rx) = mpsc::unbounded_channel();

    let transport = MockTransport {
        rx: transport_rx,
        tx: transport_tx,
        error_rx,
    };

    let handle = MockTransportHandle {
        tx: handle_tx,
        rx: handle_rx,
        error_tx,
    };

    (transport, handle)
}

/// Create a pair of linked `MockTransport`s: bytes sent on one appear as received on the other.
pub fn mock_transport_pair() -> (MockTransport, MockTransport) {
    let (tx_a, rx_b) = mpsc::unbounded_channel();
    let (tx_b, rx_a) = mpsc::unbounded_channel();
    let (_err_tx_a, err_rx_a) = mpsc::unbounded_channel();
    let (_err_tx_b, err_rx_b) = mpsc::unbounded_channel();
    (
        MockTransport { rx: rx_a, tx: tx_a, error_rx: err_rx_a },
        MockTransport { rx: rx_b, tx: tx_b, error_rx: err_rx_b },
    )
}

/// Check whether a packet looks like an IPv4 ICMP Echo Request.
///
/// Shared test utility used by keepalive and integration tests.
pub fn is_icmp_echo_request(pkt: &[u8]) -> bool {
    // Minimal check: IPv4 (version nibble == 4), protocol == 1 (ICMP), ICMP type == 8 (echo request)
    pkt.len() >= 24 && (pkt[0] >> 4) == 4 && pkt[9] == 1 && pkt[20] == 8
}

impl Stream for MockTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Check for injected errors first.
        match self.error_rx.try_recv() {
            Ok(err) => return Poll::Ready(Some(Err(err))),
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => {}
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for MockTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.tx
            .send(item)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "receiver dropped"))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
