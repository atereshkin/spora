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
}

/// Create a pair of linked `MockTransport`s: bytes sent on one appear as received on the other.
pub fn mock_transport_pair() -> (MockTransport, MockTransport) {
    let (tx_a, rx_b) = mpsc::unbounded_channel();
    let (tx_b, rx_a) = mpsc::unbounded_channel();
    (
        MockTransport { rx: rx_a, tx: tx_a },
        MockTransport { rx: rx_b, tx: tx_b },
    )
}

impl Stream for MockTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
