use std::net::SocketAddr;
use std::str::FromStr;
use log::error;
use crate::server::TunnelError;
use crate::server::TunnelError::ProtocolError;
use crate::signal::SignalChannel;

pub trait NegChannel {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError>;
    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError>;
}

pub struct SignalNegChannel<'a> {
    channel: &'a mut SignalChannel,
}

impl<'a> SignalNegChannel<'a> {
    pub fn new(channel: &'a mut SignalChannel) -> Self {
        SignalNegChannel { channel }
    }

}

impl<'a> NegChannel for SignalNegChannel<'a> {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError> {
        self.channel
            .send_signal(addr.to_string().as_bytes())
            .await
            .map_err(|e| {
                error!("failed to send endpoint via signal channel: {}", e);
                TunnelError::NegChannelClosed
            })?;
        Ok(())
    }

    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError> {
        let data = self.channel.recv_signal().await.ok_or_else(|| {
            error!("signal channel closed while receiving endpoint");
            TunnelError::NegChannelClosed
        })?;
        let line = std::str::from_utf8(&data).map_err(|e| {
            ProtocolError(format!("invalid UTF-8 in endpoint: {}", e))
        })?;
        SocketAddr::from_str(line.trim()).map_err(|e| {
            ProtocolError(format!("invalid peer address: {}", e))
        })
    }
}
