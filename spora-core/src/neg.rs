use std::net::SocketAddr;
use std::str::FromStr;
use log::error;
use tokio::net::UdpSocket;
use crate::server::TunnelError;
use crate::server::TunnelError::ProtocolError;

pub trait NegChannel {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError>;
    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError>;
}

pub struct UdpNegChannel<'a> {
    socket: &'a UdpSocket,
}

impl<'a> UdpNegChannel<'a> {
    pub fn new(socket: &'a UdpSocket) -> Self {
        UdpNegChannel { socket }
    }
}

impl<'a> NegChannel for UdpNegChannel<'a> {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError> {
        self.socket.send(addr.to_string().as_bytes()).await.map_err(|e| {
            error!("failed to send endpoint: {}", e);
            TunnelError::NegChannelClosed
        })?;
        Ok(())
    }

    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError> {
        let mut buf = [0u8; 256];
        let len = self.socket.recv(&mut buf).await.map_err(|e| {
            error!("failed to receive endpoint: {}", e);
            TunnelError::NegChannelClosed
        })?;
        let line = std::str::from_utf8(&buf[..len]).map_err(|e| {
            ProtocolError(format!("invalid UTF-8 in endpoint: {}", e))
        })?;
        SocketAddr::from_str(line.trim()).map_err(|e| {
            ProtocolError(format!("invalid peer address: {}", e))
        })
    }
}
