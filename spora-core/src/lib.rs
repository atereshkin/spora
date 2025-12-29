mod neg;
mod server;
mod transport;

use log::{debug};
use server::{PeerPort, BASE_PORT};
use std::net::{SocketAddr, ToSocketAddrs};
use stunclient::StunClient;

const STUN_SERVER: &str = "stun.l.google.com:19302";

pub async fn share() -> Result<PeerPort, String> {
    let pp = match PeerPort::new().await {
        Ok(pp) => pp,
        Err(e) => return Err(format!("failed to start message subscription: {}", e)),
    };
    let clone = pp.clone();
    // TODO: error handling
    tokio::spawn(async move { clone.run().await });
    Ok(pp)
}

pub async fn pierce() -> Result<(SocketAddr, SocketAddr), String> {
    let stun_addr = STUN_SERVER
        .to_socket_addrs()
        .unwrap()
        .filter(|x| x.is_ipv4())
        .next()
        .unwrap();

    let mut local_port = BASE_PORT;
    while local_port < BASE_PORT + 10 {
        let local_addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], local_port));
        let udp = match tokio::net::UdpSocket::bind(&local_addr).await {
            Ok(udp) => udp,
            Err(_) => {
                local_port += 1;
                continue;
            }
        };
        debug!("Local addr: {}", udp.local_addr().unwrap());

        let c = StunClient::new(stun_addr);
        let f = c.query_external_address_async(&udp);
        match f.await {
            Ok(addr) => return Ok((local_addr, addr)),
            Err(_) => {
                local_port += 1;
                continue;
            }
        };
    }
    Err("failed to pierce".into())
}
