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
        let addr = SocketAddr::from_str(line.trim()).map_err(|e| {
            ProtocolError(format!("invalid peer address: {}", e))
        })?;
        // The peer controls this address and it becomes a send_to target during
        // hole punching. Refuse targets that could turn a punch into a
        // reflection at the sharer's own loopback services or a multicast group.
        // (A legitimate STUN-derived endpoint is a unicast address; same-LAN
        // peers with private reflexive addresses are still allowed.)
        if !is_valid_punch_target(&addr) {
            return Err(ProtocolError(format!("refusing punch target {}", addr)));
        }
        Ok(addr)
    }
}

/// Whether `addr` is acceptable as a hole-punch target. Rejects loopback,
/// unspecified, multicast, broadcast, and port 0 — none of which is ever a
/// real peer endpoint.
fn is_valid_punch_target(addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_broadcast(),
        std::net::IpAddr::V6(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_dangerous_punch_targets() {
        let bad = [
            "127.0.0.1:443",
            "[::1]:443",
            "0.0.0.0:443",
            "[::]:443",
            "224.0.0.1:443",
            "255.255.255.255:443",
            "203.0.113.5:0",
        ];
        for s in bad {
            assert!(
                !is_valid_punch_target(&s.parse().unwrap()),
                "should reject {s}"
            );
        }
    }

    #[test]
    fn accepts_real_unicast_endpoints() {
        // Public and same-LAN private reflexive addresses are both valid.
        for s in ["203.0.113.5:54321", "192.168.1.50:54321", "[2001:db8::1]:443"] {
            assert!(
                is_valid_punch_target(&s.parse().unwrap()),
                "should accept {s}"
            );
        }
    }
}
