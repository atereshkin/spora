mod neg;
pub mod server;
pub mod transport;
pub mod tun_util;

use crate::neg::{NegChannel, SignalNegChannel};
use crate::transport::keepalive::{KeepAliveConfig, KeepAliveTransport};
pub use crate::transport::IpTransport;
use crate::transport::relay::{relay_connection, SignalChannel};
use crate::transport::upgradable::{upgradable_transport, UpgradeSender};
use crate::transport::UdpTransport;
use log::{debug, info, warn};
use pubsub_client::PubSubService;
use server::PeerPort;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use stunclient::StunClient;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

pub struct ConnectResult {
    pub transport: IpTransport,
    pub relay_socket_fd: i32,
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

pub struct ShareSession {
    pub key: String,
    pub endpoint: String,
    pub cancel: CancellationToken,
    pub task: JoinHandle<()>,
}

impl ShareSession {
    /// Cancel the session and wait for the background task to finish.
    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }

    /// Cancel the session and abort the background task immediately.
    pub fn abort(self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

pub async fn share(config: Config) -> Result<ShareSession, String> {
    let pp = match PeerPort::new(config).await {
        Ok(pp) => pp,
        Err(e) => return Err(format!("failed to start message subscription: {}", e)),
    };
    let key = pp.key.clone();
    let endpoint = pp.endpoint.clone();
    let cancel = CancellationToken::new();
    let child = cancel.clone();
    let task = tokio::spawn(async move { pp.run(child).await });
    Ok(ShareSession { key, endpoint, cancel, task })
}

/// Connect to a peer via relay-first tunneling with background direct upgrade.
///
/// 1. Publishes to the relay to get a relay socket
/// 2. Creates a RelayTransport for immediate IP tunneling
/// 3. Wraps in UpgradableTransport + KeepAlive
/// 4. Spawns a background task that tries to establish a direct UDP connection
pub async fn connect(url: Url, config: &Config) -> Result<ConnectResult, String> {
    let relay_socket = PubSubService::publish(
        url.host_str().unwrap(),
        url.port().unwrap(),
        url.path().strip_prefix("/").unwrap(),
    )
    .await
    .map_err(|e| format!("failed to publish to pubsub: {}", e))?;

    #[cfg(unix)]
    let relay_fd = {
        use std::os::unix::io::AsRawFd;
        relay_socket.as_raw_fd()
    };
    #[cfg(not(unix))]
    let relay_fd = -1;

    let (relay_transport, signal_channel, demux_handle) = relay_connection(relay_socket);

    let (upgradable, upgrade_sender, router_handle) =
        upgradable_transport(Box::new(relay_transport));

    let keepalive_cfg = KeepAliveConfig::default();
    let transport = Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

    // Spawn background direct upgrade task.
    // Move demux_handle and router_handle into the task to keep them alive.
    let stun_server = config.stun_server.clone();
    tokio::spawn(async move {
        try_direct_upgrade(signal_channel, upgrade_sender, &stun_server).await;
        // Keep handles alive until upgrade task ends — dropping them aborts the
        // background tasks. The router/demux continue as long as this task runs.
        drop(demux_handle);
        drop(router_handle);
    });

    Ok(ConnectResult {
        transport,
        relay_socket_fd: relay_fd,
    })
}

/// Background task: repeatedly try to establish a direct UDP connection.
/// On success, send the new transport via `upgrade_sender`.
async fn try_direct_upgrade(
    mut signal: SignalChannel,
    upgrade_sender: UpgradeSender,
    stun_server: &str,
) {
    loop {
        match try_direct_connection(&mut signal, stun_server).await {
            Ok(transport) => {
                info!("Direct connection established, upgrading transport");
                if upgrade_sender.send(transport).is_err() {
                    warn!("Failed to send upgrade — tunnel already closed");
                }
                return;
            }
            Err(e) => {
                warn!("Direct connection attempt failed: {}. Retrying in 15s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            }
        }
    }
}

/// Try to establish a direct UDP connection with the peer.
///
/// 1. STUN to discover external address (keeping the socket)
/// 2. Exchange endpoints via signaling channel
/// 3. Send punch packet and wait for response
async fn try_direct_connection(
    signal: &mut SignalChannel,
    stun_server: &str,
) -> Result<IpTransport, String> {
    let (socket, external_addr) = pierce_keep_socket(stun_server).await?;

    let mut neg = SignalNegChannel::new(signal);
    neg.send_endpoint(external_addr)
        .await
        .map_err(|_| "failed to send endpoint via signal".to_string())?;

    let peer_addr = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        neg.recv_endpoint(),
    )
    .await
    .map_err(|_| "timed out waiting for peer endpoint".to_string())?
    .map_err(|e| format!("failed to receive peer endpoint: {:?}", e))?;

    debug!("Direct connection: sending punch to {}", peer_addr);
    socket
        .send_to(&[0u8; 1], peer_addr)
        .await
        .map_err(|e| format!("failed to send punch packet: {}", e))?;

    // Wait for a response from the peer to confirm the hole is punched
    let mut buf = [0u8; 1500];
    let recv_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((_len, addr)) if addr == peer_addr => return Ok(()),
                    Ok(_) => continue, // packet from someone else, keep waiting
                    Err(e) => return Err(format!("recv error: {}", e)),
                }
            }
        },
    )
    .await;

    match recv_result {
        Ok(Ok(())) => {
            debug!("Direct connection confirmed with {}", peer_addr);
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("timed out waiting for punch response".to_string()),
    }

    let socket = Arc::new(socket);
    Ok(Box::new(UdpTransport::new(socket, peer_addr)))
}

/// Like `pierce()` but returns the UDP socket along with the addresses,
/// so it can be reused for the direct connection (same port = same NAT mapping).
pub async fn pierce_keep_socket(
    stun_server: &str,
) -> Result<(UdpSocket, SocketAddr), String> {
    let Some(stun_addr) = stun_server
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve stun address: {}", e))?
        .find(|x| x.is_ipv4())
    else {
        return Err("stun address did not resolve into an IPv4".into());
    };

    let mut local_port = server::BASE_PORT;
    while local_port < server::BASE_PORT + 10 {
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
            Ok(external_addr) => return Ok((udp, external_addr)),
            Err(_) => {
                local_port += 1;
                continue;
            }
        };
    }
    Err("failed to pierce".into())
}

pub async fn pierce(stun_server: &str) -> Result<(SocketAddr, SocketAddr), String> {
    let (socket, external_addr) = pierce_keep_socket(stun_server).await?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local addr: {}", e))?;
    Ok((local_addr, external_addr))
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
    async fn connect_fails_on_bad_pubsub() {
        let url = Url::parse("http://192.0.2.1:1/testkey").unwrap();
        let config = Config {
            stun_server: "192.0.2.1:19302".into(),
            pubsub_host: "192.0.2.1".into(),
            pubsub_port: 1,
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            connect(url, &config),
        )
        .await;

        match result {
            Ok(Ok(_)) => panic!("should not succeed with bad pubsub"),
            Ok(Err(_)) => {} // error — expected
            Err(_) => {}     // timed out — also acceptable
        }
    }
}
