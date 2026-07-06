//! Carrier-agnostic signaling channel for the direct-upgrade probe.
//!
//! Once an end-to-end session is authenticated, the same channel carries the
//! out-of-band signaling between peers (currently: endpoint exchange for the
//! hole-punch upgrade). Two carriers back it, behind one API:
//!
//! - `Quic` — a QUIC bidi stream, length-prefixed (`u32` BE) messages.
//! - `Noise` — the nz in-band [`crate::transport::noise::NoiseSignal`]:
//!   `CH_SIGNAL` datagrams over the same E2E cipher as the tunnel.

use std::io;

use log::warn;

use crate::transport::noise::NoiseSignal;

const MAX_SIGNAL_MSG: usize = 64 * 1024;

pub enum SignalChannel {
    Quic {
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    Noise(NoiseSignal),
}

impl SignalChannel {
    /// A signaling channel over a QUIC bidi stream.
    pub fn quic(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self::Quic { send, recv }
    }

    /// A signaling channel over the nz in-band datagram channel.
    pub(crate) fn noise(inner: NoiseSignal) -> Self {
        Self::Noise(inner)
    }

    /// Whether this is the nz (Noise) carrier — the direct-upgrade rebuild
    /// dispatches on this instead of a separate carrier parameter.
    pub(crate) fn is_noise(&self) -> bool {
        matches!(self, Self::Noise(_))
    }

    /// Send one message.
    pub async fn send_signal(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Quic { send, .. } => {
                let len: u32 = data.len().try_into().map_err(|_| {
                    io::Error::other(format!("signal message too large: {} bytes", data.len()))
                })?;
                send.write_all(&len.to_be_bytes())
                    .await
                    .map_err(|e| io::Error::other(format!("signal write len: {}", e)))?;
                send.write_all(data)
                    .await
                    .map_err(|e| io::Error::other(format!("signal write data: {}", e)))?;
                Ok(())
            }
            Self::Noise(s) => s.send_signal(data).await,
        }
    }

    /// Read one message. Returns `None` on a clean close / driver death or any
    /// read error (matches the datagram-based channel's signature).
    pub async fn recv_signal(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Quic { recv, .. } => {
                let mut len_buf = [0u8; 4];
                if let Err(e) = recv.read_exact(&mut len_buf).await {
                    warn!("signal: recv len: {}", e);
                    return None;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_SIGNAL_MSG {
                    warn!("signal: incoming message too large: {} bytes", len);
                    return None;
                }
                let mut data = vec![0u8; len];
                if let Err(e) = recv.read_exact(&mut data).await {
                    warn!("signal: recv data: {}", e);
                    return None;
                }
                Some(data)
            }
            Self::Noise(s) => s.recv_signal().await,
        }
    }
}
