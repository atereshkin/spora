mod neg;
mod server;
mod transport;
pub mod tun_util;

use crate::neg::{FramedNegChannel, NegChannel};
use crate::transport::keepalive::{KeepAliveConfig, KeepAliveTransport};
pub use crate::transport::IpTransport;
use crate::transport::{ReconnectTransport, UdpTransport};
use log::debug;
use pubsub_client::PubSubService;
use server::{PeerPort, BASE_PORT};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use stunclient::StunClient;
use tokio::net::UdpSocket;
use url::Url;

pub struct ConnectResult {
    pub transport: IpTransport,
    pub udp_socket: Arc<UdpSocket>,
}

#[derive(Clone)]
pub struct Config {
    pub stun_server: String,
    pub pubsub_host: String,
    pub pubsub_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stun_server: "stun.l.google.com:19302".into(),
            pubsub_host: "188.166.74.116".into(),
            pubsub_port: 2334,
        }
    }
}

pub async fn share(config: Config) -> Result<PeerPort, String> {
    let pp = match PeerPort::new(config).await {
        Ok(pp) => pp,
        Err(e) => return Err(format!("failed to start message subscription: {}", e)),
    };
    let clone = pp.clone();
    // TODO: error handling
    tokio::spawn(async move { clone.run().await });
    Ok(pp)
}

async fn connect_once(url: &Url, stun_server: &str) -> Result<(IpTransport, Arc<UdpSocket>), String> {
    let (local_addr, external_addr) = pierce(stun_server).await?;
    let sock = UdpSocket::bind(local_addr)
        .await
        .map_err(|_| "failed to bind socket")?;

    let mut stream = PubSubService::publish(
        url.host_str().unwrap(),
        url.port().unwrap(),
        url.path().strip_prefix("/").unwrap(),
    )
    .await
    .map_err(|_| "failed to publish to pubsub")?;

    let mut neg_chan = FramedNegChannel::from_tcp_stream(&mut stream);
    neg_chan
        .send_endpoint(external_addr)
        .await
        .map_err(|_| "failed to send endpoint")?;

    let other_end = neg_chan
        .recv_endpoint()
        .await
        .map_err(|_| "could not receive endpoint")?;

    sock.connect(other_end)
        .await
        .map_err(|_| "could not connect to peer")?;

    sock.send(&[123])
        .await
        .map_err(|_| "unable to send initial byte")?;

    let sock = Arc::new(sock);
    let sock_ref = sock.clone();
    Ok((Box::new(UdpTransport::new(sock, other_end)), sock_ref))
}

// TODO: needs better error handling
pub async fn connect(url: Url, config: &Config) -> Result<ConnectResult, String> {
    let (initial, udp_socket) = connect_once(&url, &config.stun_server).await?;

    // Dialer used by the reconnect wrapper: infinite retries; any `None`/`Err` triggers reconnect.
    let url_for_dialer = url.clone();
    let stun_for_dialer = config.stun_server.clone();
    let dialer = Box::new(move || {
        let url = url_for_dialer.clone();
        let stun = stun_for_dialer.clone();

        // Force `Pin<Box<impl Future>>` -> `Pin<Box<dyn Future>>` coercion.
        let fut: crate::transport::DialFuture = Box::pin(async move {
            let (transport, _) = connect_once(&url, &stun)
                .await
                .map_err(|s| io::Error::new(io::ErrorKind::Other, s))?;
            Ok(transport)
        });

        fut
    });

    let reconnect = Box::new(ReconnectTransport::new(initial, dialer)) as IpTransport;

    let keepalive_cfg = KeepAliveConfig::default();
    let transport = Box::new(KeepAliveTransport::new(reconnect, keepalive_cfg));
    Ok(ConnectResult { transport, udp_socket })
}

pub async fn pierce(stun_server: &str) -> Result<(SocketAddr, SocketAddr), String> {
    let Some(stun_addr) = stun_server
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve stun address: {}", e))?
        .filter(|x| x.is_ipv4())
        .next()
    else {
        return Err("stun address did not resolve into an IPv4".into());
    };

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
        debug!("Local addr: {}", &local_addr);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pierce_fails_on_unresolvable_stun() {
        let result = pierce("this.host.does.not.exist.invalid:19302").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("failed to resolve"),
            "expected 'failed to resolve' in error, got: {err}"
        );
    }

    #[tokio::test]
    async fn pierce_fails_on_unreachable_stun() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737), guaranteed non-routable
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            pierce("192.0.2.1:19302"),
        )
        .await;

        match result {
            Ok(Ok(_)) => panic!("should not succeed with unreachable STUN server"),
            Ok(Err(_)) => {} // pierce returned an error — expected
            Err(_) => {}     // timed out — also acceptable
        }
    }

    #[tokio::test]
    async fn connect_once_fails_on_bad_pubsub() {
        // Port 1 — nothing listening. pierce will try the real STUN server, so
        // we use an unreachable STUN to make it fail fast at the pierce stage,
        // OR we craft a URL that will fail at the pubsub stage.
        // Easiest: use a valid STUN but an unreachable pubsub host.
        let url = Url::parse("http://127.0.0.1:1/testkey").unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            connect_once(&url, "192.0.2.1:19302"),
        )
        .await;

        match result {
            Ok(Ok(_)) => panic!("should not succeed with bad pubsub/stun"),
            Ok(Err(_)) => {} // error — expected
            Err(_) => {}     // timed out — also acceptable
        }
    }
}
