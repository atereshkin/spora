//! Length-framed message channel over a QUIC bidi stream.
//!
//! Once the end-to-end QUIC connection is established and authenticated, the
//! same bidi stream carries every out-of-band signaling message between
//! peers (currently: endpoint exchange for the direct-upgrade probe). Each
//! message is prefixed with a big-endian `u32` length.

use std::io;

use log::warn;

const MAX_SIGNAL_MSG: usize = 64 * 1024;

pub struct SignalChannel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl SignalChannel {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    /// Send one length-prefixed message.
    pub async fn send_signal(&mut self, data: &[u8]) -> io::Result<()> {
        let len: u32 = data.len().try_into().map_err(|_| {
            io::Error::other(format!("signal message too large: {} bytes", data.len()))
        })?;
        self.send
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| io::Error::other(format!("signal write len: {}", e)))?;
        self.send
            .write_all(data)
            .await
            .map_err(|e| io::Error::other(format!("signal write data: {}", e)))?;
        Ok(())
    }

    /// Read one length-prefixed message. Returns `None` on a clean close or
    /// any read error (matches the old datagram-based channel's signature).
    pub async fn recv_signal(&mut self) -> Option<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        if let Err(e) = self.recv.read_exact(&mut len_buf).await {
            warn!("signal: recv len: {}", e);
            return None;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_SIGNAL_MSG {
            warn!("signal: incoming message too large: {} bytes", len);
            return None;
        }
        let mut data = vec![0u8; len];
        if let Err(e) = self.recv.read_exact(&mut data).await {
            warn!("signal: recv data: {}", e);
            return None;
        }
        Some(data)
    }
}
