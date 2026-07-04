//! IP packets over a reliable, ordered byte stream — the E2E path of a
//! stream-native carrier (e.g. the TCP/TLS relay).
//!
//! QUIC carries IP packets as unreliable datagrams; a byte stream can't, so the
//! stream carrier frames each IP packet with a 2-byte big-endian length prefix
//! (`LengthDelimitedCodec`). Reliability and ordering come from the stream (TCP)
//! underneath; this layer only frames. The E2E *encryption* is the TLS session
//! the stream runs over (pinned to the routing key) — see `e2e_tls` — so this
//! type is deliberately agnostic to what `S` is (a TLS stream in production, an
//! in-memory duplex in tests).
//!
//! Deliberately NOT QUIC-over-a-stream: running QUIC's datagrams over TCP would
//! stack loss recovery and reintroduce head-of-line blocking against the inner
//! TCP. A stream carrier is stream-native end to end.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// The largest IP packet we frame. IPv4 total length is 16-bit, so 65535 covers
/// any single packet; tunnel packets are far smaller (MTU-sized).
const MAX_FRAME: usize = u16::MAX as usize;

/// A [`Transport`](super::Transport) over any `AsyncRead + AsyncWrite` stream:
/// length-delimited IP packets in and out.
pub struct StreamPeerTransport<S> {
    framed: Framed<S, LengthDelimitedCodec>,
}

impl<S: AsyncRead + AsyncWrite> StreamPeerTransport<S> {
    pub fn new(stream: S) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .length_field_length(2) // 2-byte BE length prefix
            .max_frame_length(MAX_FRAME)
            .new_framed(stream);
        Self { framed: codec }
    }
}

impl<S: AsyncRead + Unpin> Stream for StreamPeerTransport<S> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.framed).poll_next(cx) {
            Poll::Ready(Some(Ok(buf))) => Poll::Ready(Some(Ok(buf.to_vec()))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> Sink<Vec<u8>> for StreamPeerTransport<S> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.framed).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.framed).start_send(Bytes::from(item))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.framed).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.framed).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};

    #[tokio::test]
    async fn ip_packets_round_trip_over_a_duplex_stream() {
        // Two StreamPeerTransports back-to-back over an in-memory duplex.
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut ta = StreamPeerTransport::new(a);
        let mut tb = StreamPeerTransport::new(b);

        // A -> B, several packets, framing must preserve boundaries exactly.
        let p1 = vec![0x45, 0x00, 0x00, 0x14, 0xCA, 0xFE];
        let p2 = vec![0u8; 1400];
        ta.send(p1.clone()).await.unwrap();
        ta.send(p2.clone()).await.unwrap();
        assert_eq!(tb.next().await.unwrap().unwrap(), p1);
        assert_eq!(tb.next().await.unwrap().unwrap(), p2);

        // B -> A reverse direction.
        let p3 = vec![0x60, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        tb.send(p3.clone()).await.unwrap();
        assert_eq!(ta.next().await.unwrap().unwrap(), p3);
    }

    #[tokio::test]
    async fn stream_end_terminates_the_transport() {
        let (a, b) = tokio::io::duplex(1024);
        let mut ta = StreamPeerTransport::new(a);
        drop(b); // peer hangs up
        // A read must resolve to end-of-stream (None), which ReconnectTransport
        // treats as a reconnect trigger — never a hang.
        assert!(ta.next().await.is_none());
    }

    #[tokio::test]
    async fn max_size_packet_frames_ok_and_boundaries_are_kept() {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let mut ta = StreamPeerTransport::new(a);
        let mut tb = StreamPeerTransport::new(b);
        let big = vec![0xABu8; MAX_FRAME]; // 65535, the largest single IP packet
        let small = vec![0x11u8; 3];
        ta.send(big.clone()).await.unwrap();
        ta.send(small.clone()).await.unwrap();
        assert_eq!(tb.next().await.unwrap().unwrap().len(), MAX_FRAME);
        assert_eq!(tb.next().await.unwrap().unwrap(), small);
    }
}
