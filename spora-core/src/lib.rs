mod neg;
pub mod server;
pub mod transport;
pub mod tun_util;

use crate::neg::{NegChannel, SignalNegChannel};
use crate::transport::keepalive::{KeepAliveConfig, KeepAliveTransport};
use crate::transport::DialFuture;
pub use crate::transport::IpTransport;
use crate::transport::relay::{relay_connection, SignalChannel};
use crate::transport::upgradable::{upgradable_transport, UpgradeSender};
use crate::transport::ReconnectTransport;
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

pub type SocketProtector = Option<Arc<dyn Fn(i32) + Send + Sync>>;

/// Call the protector callback with the socket's raw fd (unix only).
pub fn protect_socket(protector: &SocketProtector, _socket: &UdpSocket) {
    #[cfg(unix)]
    if let Some(ref f) = protector {
        use std::os::unix::io::AsRawFd;
        f(_socket.as_raw_fd());
    }
}

pub struct ConnectResult {
    pub transport: IpTransport,
    pub cancel: CancellationToken,
}

#[derive(Clone)]
pub struct Config {
    pub stun_server: String,
    pub pubsub_host: String,
    pub pubsub_port: u16,
    pub protector: SocketProtector,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            stun_server: "stun.l.google.com:19302".into(),
            pubsub_host: "188.166.74.116".into(),
            pubsub_port: 2334,
            protector: None,
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

/// Generate a random secret key for use with `share()`.
pub fn make_secret_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..12).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect()
}

pub async fn share(key: String, config: Config) -> Result<ShareSession, String> {
    let pp = match PeerPort::new(key, config).await {
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

/// Build a relay-based client transport stack and spawn a background upgrade task.
///
/// Returns `KeepAlive(Upgradable(Relay))` with a background task attempting
/// direct UDP upgrade via STUN.
fn build_client_transport(relay_socket: UdpSocket, stun_server: &str, protector: &SocketProtector, cancel: CancellationToken) -> IpTransport {
    let (relay_transport, signal_channel, demux_handle) = relay_connection(relay_socket);

    let (upgradable, upgrade_sender, router_handle) =
        upgradable_transport(Box::new(relay_transport));

    let keepalive_cfg = KeepAliveConfig::default();
    let transport: IpTransport =
        Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

    // Spawn background direct upgrade task (client = initiator).
    // Move demux_handle and router_handle into the task to keep them alive.
    let stun_server = stun_server.to_string();
    let protector = protector.clone();
    tokio::spawn(async move {
        try_direct_upgrade(signal_channel, upgrade_sender, &stun_server, true, &protector, cancel).await;
        drop(demux_handle);
        drop(router_handle);
    });

    transport
}

/// Connect to a peer via relay-first tunneling with background direct upgrade.
///
/// 1. Publishes to the relay to get a relay socket
/// 2. Creates a RelayTransport for immediate IP tunneling
/// 3. Wraps in UpgradableTransport + KeepAlive
/// 4. Spawns a background task that tries to establish a direct UDP connection
/// 5. Wraps in ReconnectTransport to auto-reconnect if the relay connection drops
pub async fn connect(url: Url, config: &Config) -> Result<ConnectResult, String> {
    let cancel = CancellationToken::new();

    let relay_socket = PubSubService::publish(
        url.host_str().unwrap(),
        url.port().unwrap(),
        url.path().strip_prefix("/").unwrap(),
        &config.protector,
    )
    .await
    .map_err(|e| format!("failed to publish to pubsub: {}", e))?;

    let initial = build_client_transport(relay_socket, &config.stun_server, &config.protector, cancel.clone());

    let url_clone = url;
    let config_clone = config.clone();
    let dialer_cancel = cancel.clone();
    let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
        let url = url_clone.clone();
        let config = config_clone.clone();
        let cancel = dialer_cancel.clone();
        Box::pin(async move {
            let relay_socket = PubSubService::publish(
                url.host_str().unwrap(),
                url.port().unwrap(),
                url.path().strip_prefix("/").unwrap(),
                &config.protector,
            )
            .await?;
            Ok(build_client_transport(relay_socket, &config.stun_server, &config.protector, cancel))
        })
    });

    let transport = Box::new(ReconnectTransport::new(initial, dialer));

    Ok(ConnectResult {
        transport,
        cancel,
    })
}

/// Background task: repeatedly try to establish a direct UDP connection.
/// On success, send the new transport via `upgrade_sender`.
///
/// `initiator` controls the protocol order:
/// - `true` (client): STUN first, send endpoint, wait for peer. Retry with delay.
/// - `false` (server): Wait for peer endpoint first, then STUN and respond. No delay between retries.
pub(crate) async fn try_direct_upgrade(
    mut signal: SignalChannel,
    upgrade_sender: UpgradeSender,
    stun_server: &str,
    initiator: bool,
    protector: &SocketProtector,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            info!("Direct upgrade cancelled");
            return;
        }
        let result = if initiator {
            try_direct_as_initiator(&mut signal, stun_server, protector).await
        } else {
            try_direct_as_responder(&mut signal, stun_server, protector).await
        };
        match result {
            Ok(transport) => {
                info!("Direct connection established, upgrading transport");
                if upgrade_sender.send(transport).is_err() {
                    warn!("Failed to send upgrade — tunnel already closed");
                }
                return;
            }
            Err(e) => {
                warn!("Direct connection attempt failed: {}.", e);
                if initiator {
                    warn!("Retrying in 15s...");
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            info!("Direct upgrade cancelled during retry wait");
                            return;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {}
                    }
                }
                // Responder loops back immediately to wait for the next signal.
            }
        }
    }
}

/// Client-initiated: STUN first, send our endpoint, wait for peer's.
async fn try_direct_as_initiator(
    signal: &mut SignalChannel,
    stun_server: &str,
    protector: &SocketProtector,
) -> Result<IpTransport, String> {
    let (socket, external_addr) = pierce_keep_socket(stun_server, protector).await?;

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

    punch_and_confirm(socket, peer_addr).await
}

/// Server-side: wait for client's endpoint first, then STUN and respond.
async fn try_direct_as_responder(
    signal: &mut SignalChannel,
    stun_server: &str,
    protector: &SocketProtector,
) -> Result<IpTransport, String> {
    let mut neg = SignalNegChannel::new(signal);

    // Block until the client sends its endpoint — this is the trigger.
    let peer_addr = neg
        .recv_endpoint()
        .await
        .map_err(|e| format!("failed to receive peer endpoint: {:?}", e))?;

    let (socket, external_addr) = pierce_keep_socket(stun_server, protector).await?;

    neg.send_endpoint(external_addr)
        .await
        .map_err(|_| "failed to send endpoint via signal".to_string())?;

    punch_and_confirm(socket, peer_addr).await
}

/// Marker for bidirectional verification packets.
const VERIFY_MARKER: &[u8; 7] = b"SPORA_V";

/// Punch through NAT and verify *bidirectional* connectivity before upgrading.
///
/// Phase 1 — punch exchange: send punch packets repeatedly while waiting for the
/// peer's punch. Repeated sends handle the timing window where one peer's NAT
/// mapping hasn't been created yet when the other's punch arrives.
///
/// Phase 2 — bidirectional verify: both sides send VERIFY packets. Receiving the
/// peer's VERIFY proves they also completed phase 1 (i.e. they received our
/// punch). Only if both phases succeed is the connection truly bidirectional.
async fn punch_and_confirm(
    socket: UdpSocket,
    peer_addr: SocketAddr,
) -> Result<IpTransport, String> {
    debug!("Direct connection: punching {}", peer_addr);

    // Phase 1: Exchange punch packets.
    let phase1 = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut buf = [0u8; 1500];
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = socket.send_to(&[0u8; 1], peer_addr).await;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((_, addr)) if addr == peer_addr => return Ok::<_, String>(()),
                        Ok(_) => continue,
                        Err(e) => return Err(format!("recv error: {}", e)),
                    }
                }
            }
        }
    })
    .await;

    match phase1 {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("timed out during punch exchange".to_string()),
    }

    debug!(
        "Punch received from {}, verifying bidirectional...",
        peer_addr
    );

    // Phase 2: Verify both directions. Send VERIFY repeatedly while waiting for
    // the peer's VERIFY. If the peer never completed phase 1 (because our punch
    // didn't reach them), they never enter phase 2 and we time out here — preventing
    // a one-sided upgrade that would break the relay tunnel.
    let phase2 = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut buf = [0u8; 1500];
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = socket.send_to(VERIFY_MARKER, peer_addr).await;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr))
                            if addr == peer_addr
                                && len == VERIFY_MARKER.len()
                                && &buf[..len] == VERIFY_MARKER =>
                        {
                            // Peer completed phase 1 too — both directions work.
                            // Send one more VERIFY so the peer also sees ours.
                            let _ = socket.send_to(VERIFY_MARKER, peer_addr).await;
                            return Ok::<_, String>(());
                        }
                        Ok(_) => continue, // stale punch or unrelated packet
                        Err(e) => return Err(format!("recv error: {}", e)),
                    }
                }
            }
        }
    })
    .await;

    match phase2 {
        Ok(Ok(())) => {
            debug!("Bidirectional direct connection confirmed with {}", peer_addr);
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err("direct connection is not bidirectional — not upgrading".to_string())
        }
    }

    let socket = Arc::new(socket);
    Ok(Box::new(UdpTransport::new(socket, peer_addr)))
}

/// Like `pierce()` but returns the UDP socket along with the addresses,
/// so it can be reused for the direct connection (same port = same NAT mapping).
pub async fn pierce_keep_socket(
    stun_server: &str,
    protector: &SocketProtector,
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
        protect_socket(protector, &udp);
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
    let (socket, external_addr) = pierce_keep_socket(stun_server, &None).await?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| format!("failed to get local addr: {}", e))?;
    Ok((local_addr, external_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::keepalive::{KeepAliveConfig, KeepAliveTransport};
    use crate::transport::relay::relay_connection;
    use crate::transport::upgradable::upgradable_transport;
    use futures_util::{SinkExt, StreamExt};
    use std::collections::HashMap;
    use std::pin::Pin;

    /// Minimal fake pubsub relay for integration tests.
    ///
    /// Implements the same protocol as the real relay:
    /// - SUB (0x01) + key → registers subscriber, replies with SUB_ACK + endpoint
    /// - PUB (0x02) + key → matches with subscriber, replies with PUB_ACK
    /// - After match: forwards all raw data between the two peers
    async fn fake_relay(socket: UdpSocket) {
        let mut subscribers: HashMap<Vec<u8>, SocketAddr> = HashMap::new();
        let mut routes: HashMap<SocketAddr, SocketAddr> = HashMap::new();
        let mut buf = [0u8; 65535];
        let endpoint = socket.local_addr().unwrap().to_string();

        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => break,
            };
            if len == 0 {
                continue;
            }

            // If this peer is already matched, forward raw
            if let Some(&dest) = routes.get(&src) {
                let _ = socket.send_to(&buf[..len], dest).await;
                continue;
            }

            match buf[0] {
                0x01 => {
                    // SUB
                    let key = buf[1..len].to_vec();
                    subscribers.insert(key, src);
                    let mut resp = vec![0x01];
                    resp.extend_from_slice(endpoint.as_bytes());
                    let _ = socket.send_to(&resp, src).await;
                }
                0x02 => {
                    // PUB
                    let key = buf[1..len].to_vec();
                    if let Some(sub_addr) = subscribers.remove(&key) {
                        routes.insert(src, sub_addr);
                        routes.insert(sub_addr, src);
                        let _ = socket.send_to(&[0x02], src).await;
                    } else {
                        let mut resp = vec![0xFF];
                        resp.extend_from_slice(b"unknown subscriber");
                        let _ = socket.send_to(&resp, src).await;
                    }
                }
                _ => {}
            }
        }
    }

    /// Helper: start a fake relay and return its address.
    async fn start_fake_relay() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(fake_relay(socket));
        addr
    }

    /// Helper: subscribe + publish through a fake relay, return matched socket pair.
    async fn matched_relay_pair(relay_addr: SocketAddr) -> (UdpSocket, UdpSocket) {
        let pubsub = PubSubService::new("127.0.0.1", relay_addr.port());
        let (server_sock, _endpoint) = pubsub.sub("testkey", &None).await.unwrap();
        let client_sock =
            PubSubService::publish("127.0.0.1", relay_addr.port(), "testkey", &None)
                .await
                .unwrap();
        (server_sock, client_sock)
    }

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    // --- Relay transport through fake relay ---

    #[tokio::test]
    async fn relay_pair_ip_data_flows_client_to_server() {
        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        let (mut server_transport, _server_signal, _sh) = relay_connection(server_sock);
        let (mut client_transport, _client_signal, _ch) = relay_connection(client_sock);

        let ip_pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_transport)
            .send(ip_pkt.clone())
            .await
            .unwrap();

        let received = tokio::time::timeout(TIMEOUT, server_transport.next())
            .await
            .expect("server should receive IP packet from client")
            .unwrap()
            .unwrap();
        assert_eq!(received, ip_pkt);
    }

    #[tokio::test]
    async fn relay_pair_ip_data_flows_server_to_client() {
        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        let (mut server_transport, _server_signal, _sh) = relay_connection(server_sock);
        let (mut client_transport, _client_signal, _ch) = relay_connection(client_sock);

        let ip_pkt = vec![0x45, 0x00, 0x00, 0x14, 9, 8, 7, 6];
        Pin::new(&mut server_transport)
            .send(ip_pkt.clone())
            .await
            .unwrap();

        let received = tokio::time::timeout(TIMEOUT, client_transport.next())
            .await
            .expect("client should receive IP packet from server")
            .unwrap()
            .unwrap();
        assert_eq!(received, ip_pkt);
    }

    #[tokio::test]
    async fn relay_pair_signal_flows_bidirectional() {
        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        let (_server_transport, mut server_signal, _sh) = relay_connection(server_sock);
        let (_client_transport, mut client_signal, _ch) = relay_connection(client_sock);

        // Client → Server signal
        client_signal.send_signal(b"10.0.0.1:5000").await.unwrap();
        let sig = tokio::time::timeout(TIMEOUT, server_signal.recv_signal())
            .await
            .expect("server should receive signal from client")
            .unwrap();
        assert_eq!(sig, b"10.0.0.1:5000");

        // Server → Client signal
        server_signal.send_signal(b"10.0.0.2:6000").await.unwrap();
        let sig = tokio::time::timeout(TIMEOUT, client_signal.recv_signal())
            .await
            .expect("client should receive signal from server")
            .unwrap();
        assert_eq!(sig, b"10.0.0.2:6000");
    }

    #[tokio::test]
    async fn relay_pair_ip_and_signal_dont_cross() {
        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        let (mut server_transport, mut server_signal, _sh) = relay_connection(server_sock);
        let (mut client_transport, client_signal, _ch) = relay_connection(client_sock);

        // Send IP data and signal from client simultaneously
        let ip_pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_transport)
            .send(ip_pkt.clone())
            .await
            .unwrap();
        client_signal.send_signal(b"endpoint-info").await.unwrap();

        // Server IP channel should get the IP packet, not the signal
        let received = tokio::time::timeout(TIMEOUT, server_transport.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();
        assert_eq!(received, ip_pkt, "IP channel got wrong data");

        // Server signal channel should get the signal, not the IP packet
        let sig = tokio::time::timeout(TIMEOUT, server_signal.recv_signal())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(sig, b"endpoint-info", "signal channel got wrong data");
    }

    // --- Full transport stack through fake relay ---

    #[tokio::test]
    async fn full_stack_relay_data_flows_bidirectional() {
        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        // Build full transport stack on both sides:
        // KeepAlive → Upgradable → Relay
        let (server_relay, _server_sig, _sh) = relay_connection(server_sock);
        let (server_upgradable, _server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60), // long interval to avoid noise
            ..Default::default()
        };
        let mut server_stack =
            KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let (client_relay, _client_sig, _crh) = relay_connection(client_sock);
        let (client_upgradable, _client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Client → Server
        let pkt1 = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack)
            .send(pkt1.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await
            .expect("server should receive data through full stack")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt1);

        // Server → Client
        let pkt2 = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut server_stack)
            .send(pkt2.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, client_stack.next())
            .await
            .expect("client should receive data through full stack")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt2);
    }

    #[tokio::test]
    async fn full_stack_relay_upgrade_switches_transport() {
        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        let (server_relay, _server_sig, _sh) = relay_connection(server_sock);
        let (server_upgradable, _server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack =
            KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let (client_relay, _client_sig, _ch) = relay_connection(client_sock);
        let (client_upgradable, client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Verify relay mode works first
        let pkt1 = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack)
            .send(pkt1.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await
            .expect("relay mode should work before upgrade")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt1);

        // Now simulate a "direct" upgrade on the client side using mock transports
        use crate::transport::mock::mock_transport;
        let (mock_direct, mut mock_handle) = mock_transport();
        client_upgrade_tx.send(Box::new(mock_direct)).unwrap();

        // Give the router time to switch
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Data sent by the "direct peer" should arrive at the client stack
        mock_handle.send(vec![0x45, 0, 0, 20, 9, 9, 9, 9]).unwrap();
        let received = tokio::time::timeout(TIMEOUT, client_stack.next())
            .await
            .expect("data should flow through upgraded transport")
            .unwrap()
            .unwrap();
        assert_eq!(received, vec![0x45, 0, 0, 20, 9, 9, 9, 9]);

        // Data from client stack should go to the mock handle (not the relay)
        Pin::new(&mut client_stack)
            .send(vec![0x45, 0, 0, 20, 7, 7, 7, 7])
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, mock_handle.recv())
            .await
            .expect("outbound should go through upgraded transport")
            .unwrap();
        assert_eq!(received, vec![0x45, 0, 0, 20, 7, 7, 7, 7]);
    }

    /// Regression test for asymmetric NAT traversal bug.
    ///
    /// When only ONE side upgrades to a direct transport (because its
    /// `punch_and_confirm` succeeded) while the other stays on relay:
    /// - The upgraded side drops the relay transport (router switches)
    /// - The non-upgraded side still sends via relay → upgraded side doesn't receive
    /// - The upgraded side sends via direct → non-upgraded side doesn't receive
    ///
    /// This test proves that one-sided upgrade breaks the tunnel, which is why
    /// `punch_and_confirm` must verify bidirectional connectivity before upgrading.
    #[tokio::test]
    async fn one_sided_upgrade_breaks_tunnel() {
        use crate::transport::mock::mock_transport;

        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        let (server_relay, _server_sig, _sh) = relay_connection(server_sock);
        let (server_upgradable, server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300),
            ..Default::default()
        };
        let mut server_transport =
            KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let (client_relay, _client_sig, _ch) = relay_connection(client_sock);
        let (client_upgradable, _client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Verify relay works initially
        let pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_transport)
            .send(pkt.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_transport.next())
            .await
            .expect("relay should work initially")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt);

        // Simulate asymmetric NAT: only the SERVER upgrades to "direct"
        // (its punch_and_confirm succeeded, but the client's didn't).
        let (mock_direct, _mock_handle) = mock_transport();
        server_upgrade_tx.send(Box::new(mock_direct)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Client sends via relay — server should NOT receive it because
        // the server's router switched away from the relay transport.
        let pkt2 = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut client_transport)
            .send(pkt2.clone())
            .await
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            server_transport.next(),
        )
        .await;
        assert!(
            result.is_err(),
            "after one-sided upgrade, client→server relay data must not arrive \
             (the server's router switched to the mock transport). \
             This is why punch_and_confirm must verify BOTH directions."
        );
    }

    // --- Tests that replicate the actual share/connect flow ---

    /// Server starts its transport stack BEFORE the client connects
    /// (this is what really happens — PeerPort::run starts the tunnel immediately).
    #[tokio::test]
    async fn server_starts_before_client_connects() {
        let relay_addr = start_fake_relay().await;

        // Server subscribes (like PeerPort::new)
        let pubsub = PubSubService::new("127.0.0.1", relay_addr.port());
        let (server_sock, _) = pubsub.sub("testkey", &None).await.unwrap();

        // Server immediately builds its full transport stack (like PeerPort::run)
        let (server_relay, _server_sig, _sh) = relay_connection(server_sock);
        let (server_upgradable, _server_up_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack =
            KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        // Delay — simulate real-world gap before client connects
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // NOW the client publishes (like connect())
        let client_sock =
            PubSubService::publish("127.0.0.1", relay_addr.port(), "testkey", &None)
                .await
                .unwrap();
        let (client_relay, _client_sig, _ch) = relay_connection(client_sock);
        let (client_upgradable, _client_up_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Client → Server
        let pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack)
            .send(pkt.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await
            .expect("server should receive data even though it started first")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt);
    }

    /// Both sides run try_direct_upgrade in the background (which will fail
    /// because STUN is unreachable). Relay mode must still work.
    #[tokio::test]
    async fn relay_works_while_direct_upgrade_fails() {
        let relay_addr = start_fake_relay().await;

        let pubsub = PubSubService::new("127.0.0.1", relay_addr.port());
        let (server_sock, _) = pubsub.sub("testkey", &None).await.unwrap();
        let client_sock =
            PubSubService::publish("127.0.0.1", relay_addr.port(), "testkey", &None)
                .await
                .unwrap();

        // Server side — like PeerPort::run
        let (server_relay, server_signal, _sh) = relay_connection(server_sock);
        let (server_upgradable, server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack =
            KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        // Server spawns upgrade responder
        let _server_upgrade = tokio::spawn(async move {
            try_direct_upgrade(
                server_signal,
                server_upgrade_tx,
                "192.0.2.1:19302", // unreachable — upgrade will fail
                false,
                &None,
                CancellationToken::new(),
            )
            .await;
        });

        // Client side — like connect()
        let (client_relay, client_signal, _ch) = relay_connection(client_sock);
        let (client_upgradable, client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Client spawns upgrade initiator
        let _client_upgrade = tokio::spawn(async move {
            try_direct_upgrade(
                client_signal,
                client_upgrade_tx,
                "192.0.2.1:19302",
                true,
                &None,
                CancellationToken::new(),
            )
            .await;
        });

        // Relay data should still flow despite background upgrade attempts
        let pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack)
            .send(pkt.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await
            .expect("relay mode should work while direct upgrade attempts are running")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt);

        // Also check server → client
        let pkt2 = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut server_stack)
            .send(pkt2.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, client_stack.next())
            .await
            .expect("server→client relay should also work")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt2);
    }

    /// Test the actual connect() function against a fake relay.
    /// The client's transport should be able to exchange data with a raw
    /// server-side relay transport.
    #[tokio::test]
    async fn connect_fn_produces_working_transport() {
        let relay_addr = start_fake_relay().await;

        // Server subscribes
        let pubsub = PubSubService::new("127.0.0.1", relay_addr.port());
        let (server_sock, _) = pubsub.sub("testkey", &None).await.unwrap();

        // Server builds its transport
        let (server_relay, _server_sig, _sh) = relay_connection(server_sock);
        let (server_upgradable, _server_up_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack =
            KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        // Client uses the actual connect() function
        let url = Url::parse(&format!(
            "spora://127.0.0.1:{}/testkey",
            relay_addr.port()
        ))
        .unwrap();
        let config = Config {
            stun_server: "192.0.2.1:19302".into(),
            pubsub_host: "127.0.0.1".into(),
            pubsub_port: relay_addr.port(),
            protector: None,
        };
        let mut result = connect(url, &config).await.unwrap();

        // Client → Server
        let pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut result.transport)
            .send(pkt.clone())
            .await
            .unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await
            .expect("server should receive data from connect()'s transport")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt);
    }

    // --- Client reconnect tests ---

    /// After the relay connection breaks, a client transport wrapped in
    /// ReconnectTransport re-publishes to the relay and resumes data flow.
    ///
    /// This tests the reconnect mechanism that connect() should use.
    /// Connection break is simulated by aborting the relay demux handle.
    #[tokio::test]
    async fn client_reconnects_through_relay_after_disconnect() {
        use crate::transport::{DialFuture, ReconnectTransport};

        let relay_addr = start_fake_relay().await;
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300),
            ..Default::default()
        };

        // --- Round 1: initial connection ---

        let pubsub = PubSubService::new("127.0.0.1", relay_addr.port());
        let (server_sock, _) = pubsub.sub("testkey", &None).await.unwrap();
        let client_sock =
            PubSubService::publish("127.0.0.1", relay_addr.port(), "testkey", &None)
                .await
                .unwrap();

        // Server transport
        let (server_relay, _, _sh) = relay_connection(server_sock);
        let (server_up, _, _sr) = upgradable_transport(Box::new(server_relay));
        let mut server1 = KeepAliveTransport::new(Box::new(server_up), ka_cfg);

        // Client transport with ReconnectTransport
        let (client_relay, _, client_demux) = relay_connection(client_sock);
        let (client_up, _, _cr) = upgradable_transport(Box::new(client_relay));
        let client_inner: IpTransport =
            Box::new(KeepAliveTransport::new(Box::new(client_up), ka_cfg));

        let relay_port = relay_addr.port();
        let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
            let port = relay_port;
            Box::pin(async move {
                let sock = PubSubService::publish("127.0.0.1", port, "testkey", &None).await?;
                let (relay, _, _) = relay_connection(sock);
                let (up, _, _) = upgradable_transport(Box::new(relay));
                let ka = KeepAliveConfig {
                    interval: std::time::Duration::from_secs(300),
                    ..Default::default()
                };
                Ok(Box::new(KeepAliveTransport::new(Box::new(up), ka)) as IpTransport)
            })
        });

        let mut client = ReconnectTransport::new(client_inner, dialer);

        // Data flows in round 1
        let pkt1 = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        Pin::new(&mut client).send(pkt1.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server1.next())
            .await
            .expect("round 1: server should receive data")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt1);

        // --- Break the connection, set up round 2 ---

        // Server re-subscribes FIRST (ready for client's re-publish)
        drop(server1);
        let (server_sock2, _) = pubsub.sub("testkey", &None).await.unwrap();
        let (server_relay2, _, _sh2) = relay_connection(server_sock2);
        let (server_up2, _, _sr2) = upgradable_transport(Box::new(server_relay2));
        let mut server2 = KeepAliveTransport::new(Box::new(server_up2), ka_cfg);

        // Break the client's relay connection
        client_demux.abort();

        // Drive the client to detect break and reconnect:
        // demux abort → relay None → upgradable None → keepalive None
        // → ReconnectTransport dials → re-publishes → new connection
        for _ in 0..5 {
            tokio::time::timeout(
                std::time::Duration::from_millis(200),
                client.next(),
            )
            .await
            .ok();
        }

        // --- Round 2: data flows through the new connection ---

        let pkt2 = vec![0x45, 0, 0, 20, 5, 6, 7, 8];
        Pin::new(&mut client).send(pkt2.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server2.next())
            .await
            .expect("round 2: server should receive data after reconnect")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt2);
    }

    /// Multiple disconnections and reconnections: the client keeps
    /// reconnecting and data keeps flowing each time.
    #[tokio::test]
    async fn client_survives_multiple_disconnections() {
        use crate::transport::{DialFuture, ReconnectTransport};

        let relay_addr = start_fake_relay().await;
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300),
            ..Default::default()
        };
        let relay_port = relay_addr.port();
        let pubsub = PubSubService::new("127.0.0.1", relay_port);

        // Server subscribes for round 1
        let (server_sock, _) = pubsub.sub("testkey", &None).await.unwrap();
        let client_sock =
            PubSubService::publish("127.0.0.1", relay_port, "testkey", &None)
                .await
                .unwrap();

        // Server transport
        let (server_relay, _, _sh) = relay_connection(server_sock);
        let (server_up, _, _sr) = upgradable_transport(Box::new(server_relay));
        let mut server = KeepAliveTransport::new(Box::new(server_up), ka_cfg);

        // Client transport with ReconnectTransport.
        // Store demux handles so we can break subsequent connections too.
        let demux_handles: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let (client_relay, _, initial_demux) = relay_connection(client_sock);
        let (client_up, _, _cr) = upgradable_transport(Box::new(client_relay));
        let client_inner: IpTransport =
            Box::new(KeepAliveTransport::new(Box::new(client_up), ka_cfg));

        let dh = demux_handles.clone();
        let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
            let dh = dh.clone();
            let port = relay_port;
            Box::pin(async move {
                let sock = PubSubService::publish("127.0.0.1", port, "testkey", &None).await?;
                let (relay, _, demux_h) = relay_connection(sock);
                dh.lock().unwrap().push(demux_h);
                let (up, _, _) = upgradable_transport(Box::new(relay));
                let ka = KeepAliveConfig {
                    interval: std::time::Duration::from_secs(300),
                    ..Default::default()
                };
                Ok(Box::new(KeepAliveTransport::new(Box::new(up), ka)) as IpTransport)
            })
        });

        let mut client = ReconnectTransport::new(client_inner, dialer);

        // Round 1: initial data exchange
        let pkt = vec![0x45, 0, 0, 20, 0, 0, 0, 1];
        Pin::new(&mut client).send(pkt.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server.next())
            .await
            .expect("round 1: server should receive data")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt);

        // Rounds 2 and 3: disconnect and reconnect
        let mut demux_to_abort = initial_demux;
        for round in 2..=3u8 {
            // Server re-subscribes
            drop(server);
            let (server_sock, _) = pubsub.sub("testkey", &None).await.unwrap();
            let (sr, _, _sh) = relay_connection(server_sock);
            let (su, _, _sr) = upgradable_transport(Box::new(sr));
            server = KeepAliveTransport::new(Box::new(su), ka_cfg);

            // Break the client's current connection
            demux_to_abort.abort();

            // Drive reconnection
            for _ in 0..5 {
                tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    client.next(),
                )
                .await
                .ok();
            }

            // Data should flow
            let pkt = vec![0x45, 0, 0, 20, 0, 0, 0, round];
            Pin::new(&mut client).send(pkt.clone()).await.unwrap();
            let received = tokio::time::timeout(TIMEOUT, server.next())
                .await
                .unwrap_or_else(|_| panic!("round {}: server should receive data", round))
                .unwrap()
                .unwrap();
            assert_eq!(received, pkt, "round {}", round);

            // Get the new demux handle for the next iteration
            demux_to_abort = demux_handles.lock().unwrap().pop().unwrap();
        }
    }

    // --- Netstack integration tests ---

    /// Helper: build a valid ICMP Echo Request packet using etherparse.
    fn build_icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(64);
        etherparse::PacketBuilder::ipv4(src, dst, 64)
            .icmpv4_echo_request(id, seq)
            .write(&mut pkt, b"test")
            .unwrap();
        pkt
    }

    /// Helper: check if a packet is an ICMP Echo Reply.
    fn is_icmp_echo_reply(pkt: &[u8]) -> bool {
        pkt.len() >= 24 && (pkt[0] >> 4) == 4 && pkt[9] == 1 && pkt[20] == 0
    }

    /// Most basic netstack test: feed an ICMP Echo Request directly via mock
    /// transport and check that the netstack responds with an Echo Reply.
    #[tokio::test]
    async fn netstack_responds_to_icmp_via_mock_transport() {
        use crate::transport::mock::mock_transport;

        let (mock, mut handle) = mock_transport();
        let transport: IpTransport = Box::new(mock);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            server::start_tunnel(transport, None, cancel_clone).await.unwrap();
        });

        // Give the netstack a moment to set up
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Build and send ICMP Echo Request
        let icmp_request = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0x1234, 1);
        handle.send(icmp_request).unwrap();

        // Wait for ICMP Echo Reply
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match handle.recv().await {
                        Some(pkt) if is_icmp_echo_reply(&pkt) => return pkt,
                        Some(_) => continue, // skip non-reply packets
                        None => panic!("mock transport closed unexpectedly"),
                    }
                }
            },
        )
        .await
        .expect("should receive ICMP echo reply from netstack");

        // Verify reply structure
        assert_eq!(reply[0] >> 4, 4, "should be IPv4");
        assert_eq!(reply[9], 1, "protocol should be ICMP");
        assert_eq!(reply[20], 0, "ICMP type should be Echo Reply (0)");

        cancel.cancel();
    }

    /// Full integration: relay transport → upgradable → keepalive → netstack.
    /// This replicates the exact production server-side stack.
    /// Client sends an ICMP Echo Request through the relay and expects a Reply.
    #[tokio::test]
    async fn netstack_responds_to_icmp_through_relay() {
        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        // Server side: full production stack
        let (server_relay, server_signal, _server_demux) = relay_connection(server_sock);
        let (server_upgradable, _server_upgrade_tx, _server_router) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300), // very long to avoid noise
            ..Default::default()
        };
        let server_transport: IpTransport =
            Box::new(KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg));

        // Start the tunnel with netstack
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let _tunnel_task = tokio::spawn(async move {
            server::start_tunnel(server_transport, None, cancel_clone).await.unwrap();
        });

        // Drop the signal channel to avoid the responder blocking on recv
        drop(server_signal);

        // Give the netstack a moment to set up
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client side: relay → upgradable → keepalive (no netstack)
        let (client_relay, _client_signal, _client_demux) = relay_connection(client_sock);
        let (client_upgradable, _client_upgrade_tx, _client_router) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Send ICMP Echo Request from client
        let icmp_request = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0x1234, 1);
        Pin::new(&mut client_transport)
            .send(icmp_request)
            .await
            .unwrap();

        // Wait for ICMP Echo Reply through the relay
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match client_transport.next().await {
                        Some(Ok(pkt)) if is_icmp_echo_reply(&pkt) => return pkt,
                        Some(Ok(_)) => continue, // skip keepalive or other packets
                        Some(Err(e)) => panic!("client transport error: {}", e),
                        None => panic!("client transport closed unexpectedly"),
                    }
                }
            },
        )
        .await
        .expect("should receive ICMP echo reply through relay");

        assert_eq!(reply[0] >> 4, 4, "should be IPv4");
        assert_eq!(reply[9], 1, "protocol should be ICMP");
        assert_eq!(reply[20], 0, "ICMP type should be Echo Reply (0)");

        cancel.cancel();
    }

    /// Full production scenario: relay + netstack + background upgrade attempts
    /// (upgrade will fail because STUN is unreachable). Uses default keepalive
    /// interval to test for interference from keepalive packets.
    #[tokio::test]
    async fn full_production_stack_icmp_with_failed_upgrades() {
        let relay_addr = start_fake_relay().await;

        // Server subscribes
        let pubsub = PubSubService::new("127.0.0.1", relay_addr.port());
        let (server_sock, _) = pubsub.sub("testkey", &None).await.unwrap();
        let client_sock =
            PubSubService::publish("127.0.0.1", relay_addr.port(), "testkey", &None)
                .await
                .unwrap();

        // Server side: exact same code path as PeerPort::run()
        let (server_relay, server_signal, _server_demux) = relay_connection(server_sock);
        let (server_upgradable, server_upgrade_tx, _server_router) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig::default(); // 10s keepalive
        let server_transport: IpTransport =
            Box::new(KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg));

        // Spawn upgrade responder (will fail — unreachable STUN)
        let _server_upgrade = tokio::spawn(async move {
            try_direct_upgrade(
                server_signal,
                server_upgrade_tx,
                "192.0.2.1:19302",
                false,
                &None,
                CancellationToken::new(),
            )
            .await;
        });

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let _tunnel_task = tokio::spawn(async move {
            server::start_tunnel(server_transport, None, cancel_clone).await.unwrap();
        });

        // Client side: exact same code path as connect()
        let (client_relay, client_signal, _client_demux) = relay_connection(client_sock);
        let (client_upgradable, client_upgrade_tx, _client_router) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Spawn upgrade initiator (will fail — unreachable STUN)
        let _client_upgrade = tokio::spawn(async move {
            try_direct_upgrade(
                client_signal,
                client_upgrade_tx,
                "192.0.2.1:19302",
                true,
                &None,
                CancellationToken::new(),
            )
            .await;
        });

        // Give everything time to start up
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Send multiple ICMP Echo Requests
        for seq in 0..5u16 {
            let icmp_request =
                build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0xABCD, seq);
            Pin::new(&mut client_transport)
                .send(icmp_request)
                .await
                .unwrap();
        }

        // Collect replies (may be interleaved with keepalive packets)
        let mut reply_count = 0;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match client_transport.next().await {
                        Some(Ok(pkt)) if is_icmp_echo_reply(&pkt) => {
                            reply_count += 1;
                            if reply_count >= 5 {
                                return;
                            }
                        }
                        Some(Ok(_)) => continue, // keepalive or other traffic
                        Some(Err(e)) => panic!("transport error: {}", e),
                        None => panic!("transport closed unexpectedly"),
                    }
                }
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "expected 5 ICMP echo replies, got {} before timeout",
            reply_count
        );

        cancel.cancel();
    }

    /// Test that a raw TCP SYN packet flows through the relay tunnel and
    /// the server's netstack generates a response (SYN-ACK or RST).
    /// This verifies TCP packet processing in the netstack via the relay path.
    #[tokio::test]
    async fn netstack_processes_tcp_syn_through_relay() {
        use tokio::net::TcpListener as TokioTcpListener;

        // Start a local TCP server so the netstack has something to connect to
        let tcp_server = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = tcp_server.local_addr().unwrap().port();
        // Accept one connection in background (don't need to do anything with it)
        tokio::spawn(async move {
            let _ = tcp_server.accept().await;
        });

        let relay_addr = start_fake_relay().await;
        let (server_sock, client_sock) = matched_relay_pair(relay_addr).await;

        // Server side with netstack
        let (server_relay, _server_signal, _server_demux) = relay_connection(server_sock);
        let (server_upgradable, _server_upgrade_tx, _server_router) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300),
            ..Default::default()
        };
        let server_transport: IpTransport =
            Box::new(KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg));

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let _tunnel_task = tokio::spawn(async move {
            server::start_tunnel(server_transport, None, cancel_clone).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client side: raw transport (no netstack)
        let (client_relay, _client_signal, _client_demux) = relay_connection(client_sock);
        let (client_upgradable, _client_upgrade_tx, _client_router) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport =
            KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        // Craft a TCP SYN packet to localhost:server_port
        let mut tcp_syn = Vec::new();
        etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 2],   // src
            [127, 0, 0, 1],  // dst (localhost — the echo server)
            64,
        )
        .tcp(12345, server_port, 1000, 65535) // src_port, dst_port, seq, window
        .syn()
        .write(&mut tcp_syn, &[])
        .unwrap();

        Pin::new(&mut client_transport)
            .send(tcp_syn)
            .await
            .unwrap();

        // The server's netstack should process the SYN and generate a TCP response
        // (either SYN-ACK if the real connection succeeds, or RST if it fails).
        // Either way, we expect SOME TCP packet back — proving the netstack
        // processed the SYN through the relay tunnel.
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match client_transport.next().await {
                        Some(Ok(pkt)) => {
                            // Check if it's a TCP packet (protocol 6)
                            if pkt.len() >= 20 && (pkt[0] >> 4) == 4 && pkt[9] == 6 {
                                return pkt;
                            }
                            // Skip non-TCP packets (keepalive ICMP, etc.)
                            continue;
                        }
                        Some(Err(e)) => panic!("transport error: {}", e),
                        None => panic!("transport closed unexpectedly"),
                    }
                }
            },
        )
        .await
        .expect("should receive a TCP response (SYN-ACK or RST) from netstack");

        // Verify it's a TCP response
        assert_eq!(response[0] >> 4, 4, "should be IPv4");
        assert_eq!(response[9], 6, "protocol should be TCP");
        // The IHL tells us the IP header length
        let ihl = (response[0] & 0x0F) as usize * 4;
        assert!(response.len() > ihl + 13, "packet too short for TCP header");
        let tcp_flags = response[ihl + 13];
        // SYN-ACK = 0x12, RST = 0x04, RST-ACK = 0x14
        assert!(
            tcp_flags & 0x12 == 0x12 || tcp_flags & 0x04 == 0x04,
            "expected SYN-ACK or RST, got flags: 0x{:02X}",
            tcp_flags
        );

        cancel.cancel();
    }

    /// End-to-end test using the actual share() and connect() functions.
    /// This exercises the complete production code path including PeerPort::run(),
    /// start_tunnel(), and the connect() relay setup.
    #[tokio::test]
    async fn end_to_end_share_and_connect() {
        let relay_addr = start_fake_relay().await;

        let config = Config {
            stun_server: "192.0.2.1:19302".into(), // unreachable — upgrade will fail
            pubsub_host: "127.0.0.1".into(),
            pubsub_port: relay_addr.port(),
            protector: None,
        };

        // Start sharing (server side) — this subscribes and spawns the tunnel
        let session = share("testkey".into(), config.clone()).await.unwrap();
        let key = session.key.clone();

        // Give the server a moment to set up
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Connect (client side) — this publishes and returns transport
        let url = Url::parse(&format!("spora://127.0.0.1:{}/{}", relay_addr.port(), key))
            .unwrap();
        let mut result = connect(url, &config).await.unwrap();

        // Give the tunnel a moment to stabilize
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Send ICMP Echo Request from client
        let icmp_request = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0x9999, 1);
        Pin::new(&mut result.transport)
            .send(icmp_request)
            .await
            .unwrap();

        // Wait for ICMP Echo Reply from the server's netstack
        let reply_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match result.transport.next().await {
                        Some(Ok(pkt)) if is_icmp_echo_reply(&pkt) => return pkt,
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => panic!("transport error: {}", e),
                        None => panic!("transport closed unexpectedly"),
                    }
                }
            },
        )
        .await;

        assert!(
            reply_result.is_ok(),
            "should receive ICMP echo reply through the full share/connect tunnel"
        );

        let reply = reply_result.unwrap();
        assert_eq!(reply[0] >> 4, 4, "should be IPv4");
        assert_eq!(reply[9], 1, "protocol should be ICMP");
        assert_eq!(reply[20], 0, "ICMP type should be Echo Reply (0)");

        // Clean up
        session.stop().await;
    }

    // --- Existing tests ---

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
            protector: None,
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
