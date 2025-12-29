mod neg;
mod server;
mod transport;

pub use crate::transport::IpTransport;
use log::debug;
use pubsub_client::PubSubService;
use server::{PeerPort, BASE_PORT};
use std::error::Error;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use stunclient::StunClient;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::UdpSocket;
use url::Url;
use crate::neg::{FramedNegChannel, NegChannel};
use crate::transport::UdpTransport;

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

// TODO: needs better error handling
pub async fn connect(url: Url) -> Result<IpTransport, String> {
    let (local_addr, external_addr) = pierce().await?;
    let sock = UdpSocket::bind(local_addr).await.map_err(|_| "failed to bind socket")?;

    let mut stream = PubSubService::publish(
        url.host_str().unwrap(),
        url.port().unwrap(),
        url.path().strip_prefix("/").unwrap(),
    )
    .await.map_err(|_| "failed to publish to pubsub")?;
    let mut neg_chan = FramedNegChannel::from_tcp_stream(&mut stream);
    neg_chan.send_endpoint(external_addr).await.map_err(|_| "failed to send endpoint")?;
    dbg!("Sent external addr {} to sharer", external_addr);
    let other_end = neg_chan.recv_endpoint().await.map_err(|_| "could not receive endpoint")?;

    sock.connect(other_end).await.map_err(|_| "could not connect to peer")?;
    sock.send(&[123]).await.map_err(|_| "unable to send initial byte")?;
    Ok(Box::new(UdpTransport::new(Arc::new(sock), other_end)))
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
