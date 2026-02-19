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
use crate::transport::quic::{establish_quic_client, establish_quic_server, generate_self_signed_cert};
use log::{debug, info, warn};
use pubsub_client::PubSubService;
use quinn::Connection;
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
    let task = tokio::spawn(async move {
        info!("PeerPort::run task started");
        pp.run(child).await;
        info!("PeerPort::run task exited");
    });
    Ok(ShareSession { key, endpoint, cancel, task })
}

/// Build a relay-based client transport stack and spawn a background upgrade task.
///
/// Returns `KeepAlive(Upgradable(Relay))` with a background task attempting
/// direct UDP upgrade via STUN.
fn build_client_transport(relay_conn: Connection, stun_server: &str, protector: &SocketProtector, cancel: CancellationToken) -> IpTransport {
    let (relay_transport, signal_channel, demux_handle) = relay_connection(relay_conn);

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

    let relay_conn = PubSubService::publish(
        url.host_str().unwrap(),
        url.port().unwrap(),
        url.path().strip_prefix("/").unwrap(),
        &config.protector,
    )
    .await
    .map_err(|e| format!("failed to publish to pubsub: {}", e))?;

    let initial = build_client_transport(relay_conn, &config.stun_server, &config.protector, cancel.clone());

    let url_clone = url;
    let config_clone = config.clone();
    let dialer_cancel = cancel.clone();
    let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
        let url = url_clone.clone();
        let config = config_clone.clone();
        let cancel = dialer_cancel.clone();
        Box::pin(async move {
            let relay_conn = PubSubService::publish(
                url.host_str().unwrap(),
                url.port().unwrap(),
                url.path().strip_prefix("/").unwrap(),
                &config.protector,
            )
            .await?;
            Ok(build_client_transport(relay_conn, &config.stun_server, &config.protector, cancel))
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

/// Client-initiated (QUIC client): STUN first, send our endpoint, wait for peer's
/// endpoint and cert fingerprint, then establish QUIC connection.
async fn try_direct_as_initiator(
    signal: &mut SignalChannel,
    stun_server: &str,
    protector: &SocketProtector,
) -> Result<IpTransport, String> {
    let (socket, external_addr) = pierce_keep_socket(stun_server, protector).await?;

    let (peer_addr, fingerprint) = {
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

        let fingerprint = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            neg.recv_fingerprint(),
        )
        .await
        .map_err(|_| "timed out waiting for peer fingerprint".to_string())?
        .map_err(|e| format!("failed to receive peer fingerprint: {:?}", e))?;

        (peer_addr, fingerprint)
    };

    let socket = punch_and_verify(socket, peer_addr).await?;
    let transport = establish_quic_client(socket, peer_addr, &fingerprint).await?;
    Ok(Box::new(transport))
}

/// Server-side (QUIC server): wait for client's endpoint first, then STUN, respond
/// with our endpoint and cert fingerprint, then establish QUIC connection.
async fn try_direct_as_responder(
    signal: &mut SignalChannel,
    stun_server: &str,
    protector: &SocketProtector,
) -> Result<IpTransport, String> {
    let (cert, key, fingerprint) = generate_self_signed_cert();

    let (peer_addr, socket) = {
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

        neg.send_fingerprint(&fingerprint)
            .await
            .map_err(|_| "failed to send fingerprint via signal".to_string())?;

        (peer_addr, socket)
    };

    let socket = punch_and_verify(socket, peer_addr).await?;
    let transport = establish_quic_server(socket, cert, key).await?;
    Ok(Box::new(transport))
}

/// Marker for bidirectional verification packets.
const VERIFY_MARKER: &[u8; 7] = b"SPORA_V";

/// Punch through NAT and verify *bidirectional* connectivity.
///
/// Phase 1 — punch exchange: send punch packets repeatedly while waiting for the
/// peer's punch. Repeated sends handle the timing window where one peer's NAT
/// mapping hasn't been created yet when the other's punch arrives.
///
/// Phase 2 — bidirectional verify: both sides send VERIFY packets. Receiving the
/// peer's VERIFY proves they also completed phase 1 (i.e. they received our
/// punch). Only if both phases succeed is the connection truly bidirectional.
///
/// Returns the raw UDP socket for QUIC wrapping.
async fn punch_and_verify(
    socket: UdpSocket,
    peer_addr: SocketAddr,
) -> Result<UdpSocket, String> {
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

    Ok(socket)
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
    use pubsub_client::build_endpoint_with_crypto;
    use std::collections::HashMap;
    use std::pin::Pin;
    use tokio::sync::Mutex as TokioMutex;

    const ALPN: &[u8] = b"spora-relay/1";

    /// Generate ephemeral certs for testing and return (server_config, client_crypto).
    fn test_certs() -> (quinn::ServerConfig, rustls::ClientConfig) {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let relay_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut relay_params = rcgen::CertificateParams::default();
        relay_params.distinguished_name = rcgen::DistinguishedName::new();
        relay_params
            .subject_alt_names
            .push(rcgen::SanType::DnsName("relay.spora.dev".try_into().unwrap()));
        let relay_cert = relay_params
            .signed_by(&relay_key, &ca_cert, &ca_key)
            .unwrap();

        let cert = rustls::pki_types::CertificateDer::from(relay_cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(relay_key.serialize_der()).unwrap();

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![ALPN.to_vec()];

        (server_config, client_crypto)
    }

    struct FakeSubscriber {
        connection: Connection,
        send_stream: quinn::SendStream,
    }

    /// Minimal fake pubsub relay for integration tests (QUIC-based).
    async fn fake_relay(endpoint: quinn::Endpoint) {
        let subscribers: Arc<TokioMutex<HashMap<Vec<u8>, FakeSubscriber>>> =
            Arc::new(TokioMutex::new(HashMap::new()));

        while let Some(incoming) = endpoint.accept().await {
            let subscribers = subscribers.clone();
            let endpoint_str = endpoint.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let (mut send, mut recv) = match conn.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let handshake = match recv.read_to_end(65535).await {
                    Ok(h) => h,
                    Err(_) => return,
                };
                if handshake.is_empty() {
                    return;
                }

                let msg_type = handshake[0];
                let key = handshake[1..].to_vec();

                match msg_type {
                    0x01 => {
                        // SUB
                        let mut resp = vec![0x01];
                        resp.extend_from_slice(endpoint_str.as_bytes());
                        let _ = send.write_all(&resp).await;
                        // Don't finish - keep open for MATCH notification
                        subscribers.lock().await.insert(
                            key,
                            FakeSubscriber {
                                connection: conn,
                                send_stream: send,
                            },
                        );
                    }
                    0x02 => {
                        // PUB
                        let mut subs = subscribers.lock().await;
                        if let Some(mut sub) = subs.remove(&key) {
                            let _ = send.write_all(&[0x02]).await;
                            let _ = send.finish();
                            // Notify subscriber
                            let _ = sub.send_stream.write_all(&[0x03]).await;
                            let _ = sub.send_stream.finish();
                            // Forward datagrams bidirectionally
                            let a = conn;
                            let b = sub.connection;
                            let a2 = a.clone();
                            let b2 = b.clone();
                            tokio::spawn(async move {
                                loop {
                                    match a.read_datagram().await {
                                        Ok(d) => {
                                            if b.send_datagram(d).is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                            tokio::spawn(async move {
                                loop {
                                    match b2.read_datagram().await {
                                        Ok(d) => {
                                            if a2.send_datagram(d).is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                        } else {
                            let mut resp = vec![0xFF];
                            resp.extend_from_slice(b"unknown subscriber");
                            let _ = send.write_all(&resp).await;
                            let _ = send.finish();
                        }
                    }
                    _ => {}
                }
            });
        }
    }

    /// Helper: start a fake QUIC relay and return (port, client_crypto).
    fn start_fake_relay() -> (u16, rustls::ClientConfig) {
        let (server_config, client_crypto) = test_certs();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(fake_relay(endpoint));
        (port, client_crypto)
    }

    /// Helper: subscribe + publish through a fake relay, return matched connection pair.
    async fn matched_relay_pair(
        port: u16,
        client_crypto: &rustls::ClientConfig,
    ) -> (Connection, Connection) {
        let sub_ep = build_endpoint_with_crypto(client_crypto.clone(), &None).unwrap();
        let svc = PubSubService::new("127.0.0.1", port);
        let mut sub_conn = svc.sub_with_endpoint("testkey", &sub_ep).await.unwrap();

        let pub_ep = build_endpoint_with_crypto(client_crypto.clone(), &None).unwrap();
        let pub_conn =
            PubSubService::publish_with_endpoint("127.0.0.1", port, "testkey", &pub_ep)
                .await
                .unwrap();

        sub_conn.wait_for_match().await.unwrap();
        (sub_conn.connection, pub_conn)
    }

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

    // --- Relay transport through fake relay ---

    #[tokio::test]
    async fn relay_pair_ip_data_flows_client_to_server() {
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (mut server_transport, _server_signal, _sh) = relay_connection(server_conn);
        let (mut client_transport, _client_signal, _ch) = relay_connection(client_conn);

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
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (mut server_transport, _server_signal, _sh) = relay_connection(server_conn);
        let (mut client_transport, _client_signal, _ch) = relay_connection(client_conn);

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
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (_server_transport, mut server_signal, _sh) = relay_connection(server_conn);
        let (_client_transport, mut client_signal, _ch) = relay_connection(client_conn);

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
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (mut server_transport, mut server_signal, _sh) = relay_connection(server_conn);
        let (mut client_transport, client_signal, _ch) = relay_connection(client_conn);

        let ip_pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_transport)
            .send(ip_pkt.clone())
            .await
            .unwrap();
        client_signal.send_signal(b"endpoint-info").await.unwrap();

        let received = tokio::time::timeout(TIMEOUT, server_transport.next())
            .await
            .expect("timeout")
            .unwrap()
            .unwrap();
        assert_eq!(received, ip_pkt, "IP channel got wrong data");

        let sig = tokio::time::timeout(TIMEOUT, server_signal.recv_signal())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(sig, b"endpoint-info", "signal channel got wrong data");
    }

    // --- Full transport stack through fake relay ---

    #[tokio::test]
    async fn full_stack_relay_data_flows_bidirectional() {
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, _server_sig, _sh) = relay_connection(server_conn);
        let (server_upgradable, _server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack = KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let (client_relay, _client_sig, _crh) = relay_connection(client_conn);
        let (client_upgradable, _client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let pkt1 = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack).send(pkt1.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await.expect("server should receive").unwrap().unwrap();
        assert_eq!(received, pkt1);

        let pkt2 = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut server_stack).send(pkt2.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, client_stack.next())
            .await.expect("client should receive").unwrap().unwrap();
        assert_eq!(received, pkt2);
    }

    #[tokio::test]
    async fn full_stack_relay_upgrade_switches_transport() {
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, _server_sig, _sh) = relay_connection(server_conn);
        let (server_upgradable, _server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack = KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let (client_relay, _client_sig, _ch) = relay_connection(client_conn);
        let (client_upgradable, client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let pkt1 = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack).send(pkt1.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await.expect("relay mode should work").unwrap().unwrap();
        assert_eq!(received, pkt1);

        use crate::transport::mock::mock_transport;
        let (mock_direct, mut mock_handle) = mock_transport();
        client_upgrade_tx.send(Box::new(mock_direct)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        mock_handle.send(vec![0x45, 0, 0, 20, 9, 9, 9, 9]).unwrap();
        let received = tokio::time::timeout(TIMEOUT, client_stack.next())
            .await.expect("upgraded transport").unwrap().unwrap();
        assert_eq!(received, vec![0x45, 0, 0, 20, 9, 9, 9, 9]);

        Pin::new(&mut client_stack).send(vec![0x45, 0, 0, 20, 7, 7, 7, 7]).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, mock_handle.recv())
            .await.expect("outbound should go through upgraded").unwrap();
        assert_eq!(received, vec![0x45, 0, 0, 20, 7, 7, 7, 7]);
    }

    #[tokio::test]
    async fn one_sided_upgrade_breaks_tunnel() {
        use crate::transport::mock::mock_transport;

        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, _server_sig, _sh) = relay_connection(server_conn);
        let (server_upgradable, server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300),
            ..Default::default()
        };
        let mut server_transport = KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let (client_relay, _client_sig, _ch) = relay_connection(client_conn);
        let (client_upgradable, _client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_transport).send(pkt.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_transport.next())
            .await.expect("relay should work").unwrap().unwrap();
        assert_eq!(received, pkt);

        let (mock_direct, _mock_handle) = mock_transport();
        server_upgrade_tx.send(Box::new(mock_direct)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let pkt2 = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut client_transport).send(pkt2.clone()).await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            server_transport.next(),
        ).await;
        assert!(result.is_err(), "one-sided upgrade should break tunnel");
    }

    // --- Tests that replicate the actual share/connect flow ---

    #[tokio::test]
    async fn server_starts_before_client_connects() {
        let (port, crypto) = start_fake_relay();

        // Server subscribes and waits for match
        let sub_ep = build_endpoint_with_crypto(crypto.clone(), &None).unwrap();
        let svc = PubSubService::new("127.0.0.1", port);
        let mut sub_conn = svc.sub_with_endpoint("testkey", &sub_ep).await.unwrap();

        // Publish in background (will trigger match)
        let pub_ep = build_endpoint_with_crypto(crypto.clone(), &None).unwrap();
        let pub_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            PubSubService::publish_with_endpoint("127.0.0.1", port, "testkey", &pub_ep)
                .await
                .unwrap()
        });

        sub_conn.wait_for_match().await.unwrap();
        let server_conn = sub_conn.connection;

        let (server_relay, _server_sig, _sh) = relay_connection(server_conn);
        let (server_upgradable, _server_up_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack = KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let client_conn = pub_handle.await.unwrap();
        let (client_relay, _client_sig, _ch) = relay_connection(client_conn);
        let (client_upgradable, _client_up_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack).send(pkt.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await.expect("server should receive").unwrap().unwrap();
        assert_eq!(received, pkt);
    }

    #[tokio::test]
    async fn relay_works_while_direct_upgrade_fails() {
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, server_signal, _sh) = relay_connection(server_conn);
        let (server_upgradable, server_upgrade_tx, _sr) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(60),
            ..Default::default()
        };
        let mut server_stack = KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg);

        let _server_upgrade = tokio::spawn(async move {
            try_direct_upgrade(server_signal, server_upgrade_tx, "192.0.2.1:19302", false, &None, CancellationToken::new()).await;
        });

        let (client_relay, client_signal, _ch) = relay_connection(client_conn);
        let (client_upgradable, client_upgrade_tx, _cr) =
            upgradable_transport(Box::new(client_relay));
        let mut client_stack = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let _client_upgrade = tokio::spawn(async move {
            try_direct_upgrade(client_signal, client_upgrade_tx, "192.0.2.1:19302", true, &None, CancellationToken::new()).await;
        });

        let pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_stack).send(pkt.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_stack.next())
            .await.expect("relay should work").unwrap().unwrap();
        assert_eq!(received, pkt);

        let pkt2 = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut server_stack).send(pkt2.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, client_stack.next())
            .await.expect("server→client should work").unwrap().unwrap();
        assert_eq!(received, pkt2);
    }

    // --- Client reconnect tests ---

    #[tokio::test]
    async fn client_reconnects_through_relay_after_disconnect() {
        use crate::transport::{DialFuture, ReconnectTransport};

        let (port, crypto) = start_fake_relay();
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300),
            ..Default::default()
        };

        // --- Round 1 ---
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, _, _sh) = relay_connection(server_conn);
        let (server_up, _, _sr) = upgradable_transport(Box::new(server_relay));
        let mut server1 = KeepAliveTransport::new(Box::new(server_up), ka_cfg);

        let (client_relay, _, client_demux) = relay_connection(client_conn);
        let (client_up, _, _cr) = upgradable_transport(Box::new(client_relay));
        let client_inner: IpTransport = Box::new(KeepAliveTransport::new(Box::new(client_up), ka_cfg));

        let crypto_clone = crypto.clone();
        let dialer: Box<dyn FnMut() -> DialFuture + Send> = Box::new(move || {
            let crypto = crypto_clone.clone();
            Box::pin(async move {
                let ep = build_endpoint_with_crypto(crypto, &None)?;
                let conn = PubSubService::publish_with_endpoint("127.0.0.1", port, "testkey", &ep).await?;
                let (relay, _, _) = relay_connection(conn);
                let (up, _, _) = upgradable_transport(Box::new(relay));
                let ka = KeepAliveConfig { interval: std::time::Duration::from_secs(300), ..Default::default() };
                Ok(Box::new(KeepAliveTransport::new(Box::new(up), ka)) as IpTransport)
            })
        });

        let mut client = ReconnectTransport::new(client_inner, dialer);

        let pkt1 = vec![0x45, 0, 0, 20, 1, 2, 3, 4];
        Pin::new(&mut client).send(pkt1.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server1.next())
            .await.expect("round 1").unwrap().unwrap();
        assert_eq!(received, pkt1);

        // --- Break + Round 2 ---
        drop(server1);
        // Server re-subscribes
        let sub_ep = build_endpoint_with_crypto(crypto.clone(), &None).unwrap();
        let svc = PubSubService::new("127.0.0.1", port);
        let mut sub_conn = svc.sub_with_endpoint("testkey", &sub_ep).await.unwrap();

        // Break client's connection
        client_demux.abort();

        // Drive reconnect (client re-publishes, which triggers match)
        for _ in 0..5 {
            tokio::time::timeout(std::time::Duration::from_millis(200), client.next()).await.ok();
        }

        // Wait for match on server side
        tokio::time::timeout(TIMEOUT, sub_conn.wait_for_match()).await.ok();
        let (server_relay2, _, _sh2) = relay_connection(sub_conn.connection);
        let (server_up2, _, _sr2) = upgradable_transport(Box::new(server_relay2));
        let mut server2 = KeepAliveTransport::new(Box::new(server_up2), ka_cfg);

        let pkt2 = vec![0x45, 0, 0, 20, 5, 6, 7, 8];
        Pin::new(&mut client).send(pkt2.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server2.next())
            .await.expect("round 2").unwrap().unwrap();
        assert_eq!(received, pkt2);
    }

    // --- Netstack integration tests ---

    fn build_icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(64);
        etherparse::PacketBuilder::ipv4(src, dst, 64)
            .icmpv4_echo_request(id, seq)
            .write(&mut pkt, b"test")
            .unwrap();
        pkt
    }

    fn is_icmp_echo_reply(pkt: &[u8]) -> bool {
        pkt.len() >= 24 && (pkt[0] >> 4) == 4 && pkt[9] == 1 && pkt[20] == 0
    }

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

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let icmp_request = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0x1234, 1);
        handle.send(icmp_request).unwrap();

        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match handle.recv().await {
                        Some(pkt) if is_icmp_echo_reply(&pkt) => return pkt,
                        Some(_) => continue,
                        None => panic!("mock transport closed"),
                    }
                }
            },
        ).await.expect("should receive ICMP echo reply");

        assert_eq!(reply[0] >> 4, 4);
        assert_eq!(reply[9], 1);
        assert_eq!(reply[20], 0);
        cancel.cancel();
    }

    #[tokio::test]
    async fn netstack_responds_to_icmp_through_relay() {
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, server_signal, _server_demux) = relay_connection(server_conn);
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
        tokio::spawn(async move {
            server::start_tunnel(server_transport, None, cancel_clone).await.unwrap();
        });
        drop(server_signal);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let (client_relay, _client_signal, _client_demux) = relay_connection(client_conn);
        let (client_upgradable, _client_upgrade_tx, _client_router) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let icmp_request = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0x1234, 1);
        Pin::new(&mut client_transport).send(icmp_request).await.unwrap();

        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match client_transport.next().await {
                        Some(Ok(pkt)) if is_icmp_echo_reply(&pkt) => return pkt,
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => panic!("transport error: {}", e),
                        None => panic!("transport closed"),
                    }
                }
            },
        ).await.expect("should receive ICMP echo reply through relay");

        assert_eq!(reply[0] >> 4, 4);
        assert_eq!(reply[9], 1);
        assert_eq!(reply[20], 0);
        cancel.cancel();
    }

    #[tokio::test]
    async fn full_production_stack_icmp_with_failed_upgrades() {
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, server_signal, _server_demux) = relay_connection(server_conn);
        let (server_upgradable, server_upgrade_tx, _server_router) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig::default();
        let server_transport: IpTransport =
            Box::new(KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg));

        let _server_upgrade = tokio::spawn(async move {
            try_direct_upgrade(server_signal, server_upgrade_tx, "192.0.2.1:19302", false, &None, CancellationToken::new()).await;
        });

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            server::start_tunnel(server_transport, None, cancel_clone).await.unwrap();
        });

        let (client_relay, client_signal, _client_demux) = relay_connection(client_conn);
        let (client_upgradable, client_upgrade_tx, _client_router) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let _client_upgrade = tokio::spawn(async move {
            try_direct_upgrade(client_signal, client_upgrade_tx, "192.0.2.1:19302", true, &None, CancellationToken::new()).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        for seq in 0..5u16 {
            let icmp = build_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0xABCD, seq);
            Pin::new(&mut client_transport).send(icmp).await.unwrap();
        }

        let mut reply_count = 0;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match client_transport.next().await {
                        Some(Ok(pkt)) if is_icmp_echo_reply(&pkt) => {
                            reply_count += 1;
                            if reply_count >= 5 { return; }
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => panic!("transport error: {}", e),
                        None => panic!("transport closed"),
                    }
                }
            },
        ).await;

        assert!(result.is_ok(), "expected 5 ICMP echo replies, got {}", reply_count);
        cancel.cancel();
    }

    #[tokio::test]
    async fn netstack_processes_tcp_syn_through_relay() {
        use tokio::net::TcpListener as TokioTcpListener;

        let tcp_server = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = tcp_server.local_addr().unwrap().port();
        tokio::spawn(async move { let _ = tcp_server.accept().await; });

        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, _server_signal, _server_demux) = relay_connection(server_conn);
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
        tokio::spawn(async move {
            server::start_tunnel(server_transport, None, cancel_clone).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let (client_relay, _client_signal, _client_demux) = relay_connection(client_conn);
        let (client_upgradable, _client_upgrade_tx, _client_router) =
            upgradable_transport(Box::new(client_relay));
        let mut client_transport = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        let mut tcp_syn = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [127, 0, 0, 1], 64)
            .tcp(12345, server_port, 1000, 65535)
            .syn()
            .write(&mut tcp_syn, &[])
            .unwrap();

        Pin::new(&mut client_transport).send(tcp_syn).await.unwrap();

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                loop {
                    match client_transport.next().await {
                        Some(Ok(pkt)) if pkt.len() >= 20 && (pkt[0] >> 4) == 4 && pkt[9] == 6 => return pkt,
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => panic!("transport error: {}", e),
                        None => panic!("transport closed"),
                    }
                }
            },
        ).await.expect("should receive TCP response from netstack");

        assert_eq!(response[0] >> 4, 4);
        assert_eq!(response[9], 6);
        let ihl = (response[0] & 0x0F) as usize * 4;
        let tcp_flags = response[ihl + 13];
        assert!(tcp_flags & 0x12 == 0x12 || tcp_flags & 0x04 == 0x04);
        cancel.cancel();
    }

    // --- Relay tunnel setup helper ---

    struct TunnelPair {
        client_transport: KeepAliveTransport,
        server_cancel: CancellationToken,
        _handles: Vec<JoinHandle<()>>,
    }

    async fn setup_relay_tunnel() -> TunnelPair {
        let (port, crypto) = start_fake_relay();
        let (server_conn, client_conn) = matched_relay_pair(port, &crypto).await;

        let (server_relay, _server_signal, server_demux) = relay_connection(server_conn);
        let (server_upgradable, _server_upgrade_tx, server_router) =
            upgradable_transport(Box::new(server_relay));
        let ka_cfg = KeepAliveConfig {
            interval: std::time::Duration::from_secs(300),
            ..Default::default()
        };
        let server_transport: IpTransport =
            Box::new(KeepAliveTransport::new(Box::new(server_upgradable), ka_cfg));

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let tunnel_handle = tokio::spawn(async move {
            server::start_tunnel(server_transport, None, cancel_clone).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let (client_relay, _client_signal, client_demux) = relay_connection(client_conn);
        let (client_upgradable, _client_upgrade_tx, client_router) =
            upgradable_transport(Box::new(client_relay));
        let client_transport = KeepAliveTransport::new(Box::new(client_upgradable), ka_cfg);

        TunnelPair {
            client_transport,
            server_cancel: cancel,
            _handles: vec![tunnel_handle, server_demux, server_router, client_demux, client_router],
        }
    }

    // --- Raw TCP client for packet-level handshake + data ---

    struct RawTcpClient {
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
    }

    impl RawTcpClient {
        fn new(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Self {
            Self {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq: 1000,
                ack: 0,
            }
        }

        fn build_syn(&mut self) -> Vec<u8> {
            let mut pkt = Vec::new();
            etherparse::PacketBuilder::ipv4(self.src_ip, self.dst_ip, 64)
                .tcp(self.src_port, self.dst_port, self.seq, 65535)
                .syn()
                .write(&mut pkt, &[])
                .unwrap();
            self.seq += 1; // SYN consumes one sequence number
            pkt
        }

        fn process_syn_ack(&mut self, pkt: &[u8]) {
            let parsed = etherparse::SlicedPacket::from_ip(pkt).unwrap();
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport {
                self.ack = tcp.sequence_number() + 1;
            }
        }

        fn build_ack(&self) -> Vec<u8> {
            let mut pkt = Vec::new();
            etherparse::PacketBuilder::ipv4(self.src_ip, self.dst_ip, 64)
                .tcp(self.src_port, self.dst_port, self.seq, 65535)
                .ack(self.ack)
                .write(&mut pkt, &[])
                .unwrap();
            pkt
        }

        fn build_data(&mut self, payload: &[u8]) -> Vec<u8> {
            let mut pkt = Vec::new();
            etherparse::PacketBuilder::ipv4(self.src_ip, self.dst_ip, 64)
                .tcp(self.src_port, self.dst_port, self.seq, 65535)
                .ack(self.ack)
                .psh()
                .write(&mut pkt, payload)
                .unwrap();
            self.seq += payload.len() as u32;
            pkt
        }

        fn build_fin(&mut self) -> Vec<u8> {
            let mut pkt = Vec::new();
            etherparse::PacketBuilder::ipv4(self.src_ip, self.dst_ip, 64)
                .tcp(self.src_port, self.dst_port, self.seq, 65535)
                .ack(self.ack)
                .fin()
                .write(&mut pkt, &[])
                .unwrap();
            self.seq += 1; // FIN consumes one sequence number
            pkt
        }

        /// Parse a TCP response, update ack number, return payload bytes (if any).
        fn process_response(&mut self, pkt: &[u8]) -> Vec<u8> {
            let parsed = etherparse::SlicedPacket::from_ip(pkt).unwrap();
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport {
                let payload = tcp.payload().to_vec();
                let seg_len = payload.len() as u32
                    + if tcp.syn() { 1 } else { 0 }
                    + if tcp.fin() { 1 } else { 0 };
                if seg_len > 0 {
                    self.ack = tcp.sequence_number() + seg_len;
                }
                payload
            } else {
                Vec::new()
            }
        }
    }

    // --- Packet filter helpers ---

    async fn recv_tcp(transport: &mut KeepAliveTransport, timeout: std::time::Duration) -> Vec<u8> {
        tokio::time::timeout(timeout, async {
            loop {
                match transport.next().await {
                    Some(Ok(pkt)) if pkt.len() >= 20 && (pkt[0] >> 4) == 4 && pkt[9] == 6 => {
                        return pkt;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => panic!("transport error: {}", e),
                    None => panic!("transport closed"),
                }
            }
        })
        .await
        .expect("timed out waiting for TCP packet")
    }

    async fn recv_udp_pkt(transport: &mut KeepAliveTransport, timeout: std::time::Duration) -> Vec<u8> {
        tokio::time::timeout(timeout, async {
            loop {
                match transport.next().await {
                    Some(Ok(pkt)) if pkt.len() >= 20 && (pkt[0] >> 4) == 4 && pkt[9] == 17 => {
                        return pkt;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => panic!("transport error: {}", e),
                    None => panic!("transport closed"),
                }
            }
        })
        .await
        .expect("timed out waiting for UDP packet")
    }

    // --- End-to-end integration tests ---

    #[tokio::test]
    async fn tcp_echo_through_relay_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as TokioTcpListener;

        // Start a real TCP echo server
        let echo_server = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_server.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo_server.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => { let _ = stream.write_all(&buf[..n]).await; }
                        }
                    }
                });
            }
        });

        let mut tunnel = setup_relay_tunnel().await;
        let timeout = std::time::Duration::from_secs(5);

        // TCP 3-way handshake
        let mut tcp = RawTcpClient::new([10, 0, 0, 2], [127, 0, 0, 1], 40001, echo_port);

        // SYN
        let syn = tcp.build_syn();
        Pin::new(&mut tunnel.client_transport).send(syn).await.unwrap();

        // Receive SYN-ACK
        let syn_ack = recv_tcp(&mut tunnel.client_transport, timeout).await;
        let parsed = etherparse::SlicedPacket::from_ip(&syn_ack).unwrap();
        if let Some(etherparse::TransportSlice::Tcp(ref t)) = parsed.transport {
            assert!(t.syn() && t.ack(), "expected SYN-ACK, got flags: syn={} ack={}", t.syn(), t.ack());
        }
        tcp.process_syn_ack(&syn_ack);

        // ACK (completes handshake)
        let ack = tcp.build_ack();
        Pin::new(&mut tunnel.client_transport).send(ack).await.unwrap();

        // Send data
        let payload = b"Hello, tunnel!";
        let data_pkt = tcp.build_data(payload);
        Pin::new(&mut tunnel.client_transport).send(data_pkt).await.unwrap();

        // Receive echoed data
        let mut received_data = Vec::new();
        let result = tokio::time::timeout(timeout, async {
            while received_data.len() < payload.len() {
                let response = recv_tcp(&mut tunnel.client_transport, timeout).await;
                let data = tcp.process_response(&response);
                received_data.extend_from_slice(&data);
            }
        }).await;
        assert!(result.is_ok(), "timed out waiting for echo data");
        assert_eq!(&received_data[..payload.len()], payload);

        // ACK the received data
        let ack = tcp.build_ack();
        Pin::new(&mut tunnel.client_transport).send(ack).await.unwrap();

        // FIN
        let fin = tcp.build_fin();
        Pin::new(&mut tunnel.client_transport).send(fin).await.unwrap();

        // Wait for FIN-ACK from server (may be ACK or FIN+ACK)
        let fin_response = recv_tcp(&mut tunnel.client_transport, timeout).await;
        let parsed = etherparse::SlicedPacket::from_ip(&fin_response).unwrap();
        if let Some(etherparse::TransportSlice::Tcp(ref t)) = parsed.transport {
            assert!(t.ack(), "expected ACK in FIN response");
        }

        tunnel.server_cancel.cancel();
    }

    #[tokio::test]
    async fn udp_echo_through_relay_tunnel() {
        // Start a real UDP echo server
        let echo_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match echo_socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => { let _ = echo_socket.send_to(&buf[..n], addr).await; }
                    Err(_) => break,
                }
            }
        });

        let mut tunnel = setup_relay_tunnel().await;
        let timeout = std::time::Duration::from_secs(5);

        // Craft and send a UDP packet
        let payload = b"Hello, UDP tunnel!";
        let mut udp_pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [127, 0, 0, 1], 64)
            .udp(50001, echo_port)
            .write(&mut udp_pkt, payload)
            .unwrap();

        Pin::new(&mut tunnel.client_transport).send(udp_pkt).await.unwrap();

        // Receive echoed UDP response
        let response = recv_udp_pkt(&mut tunnel.client_transport, timeout).await;
        let parsed = etherparse::SlicedPacket::from_ip(&response).unwrap();
        if let Some(etherparse::TransportSlice::Udp(udp)) = parsed.transport {
            assert_eq!(udp.payload(), payload);
        } else {
            panic!("expected UDP transport slice");
        }

        tunnel.server_cancel.cancel();
    }

    #[tokio::test]
    async fn multiple_tcp_connections_through_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as TokioTcpListener;

        let echo_server = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_server.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo_server.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => { let _ = stream.write_all(&buf[..n]).await; }
                        }
                    }
                });
            }
        });

        let mut tunnel = setup_relay_tunnel().await;
        let timeout = std::time::Duration::from_secs(5);

        // Connection #1
        let mut tcp1 = RawTcpClient::new([10, 0, 0, 2], [127, 0, 0, 1], 40001, echo_port);
        Pin::new(&mut tunnel.client_transport).send(tcp1.build_syn()).await.unwrap();
        let syn_ack1 = recv_tcp(&mut tunnel.client_transport, timeout).await;
        tcp1.process_syn_ack(&syn_ack1);
        Pin::new(&mut tunnel.client_transport).send(tcp1.build_ack()).await.unwrap();

        let data1 = b"conn1-data";
        Pin::new(&mut tunnel.client_transport).send(tcp1.build_data(data1)).await.unwrap();

        let mut received1 = Vec::new();
        let result = tokio::time::timeout(timeout, async {
            while received1.len() < data1.len() {
                let resp = recv_tcp(&mut tunnel.client_transport, timeout).await;
                received1.extend_from_slice(&tcp1.process_response(&resp));
            }
        }).await;
        assert!(result.is_ok(), "conn1 echo timed out");
        assert_eq!(&received1[..data1.len()], data1);

        // Connection #2 (different src port)
        let mut tcp2 = RawTcpClient::new([10, 0, 0, 2], [127, 0, 0, 1], 40002, echo_port);
        Pin::new(&mut tunnel.client_transport).send(tcp2.build_syn()).await.unwrap();
        let syn_ack2 = recv_tcp(&mut tunnel.client_transport, timeout).await;
        tcp2.process_syn_ack(&syn_ack2);
        Pin::new(&mut tunnel.client_transport).send(tcp2.build_ack()).await.unwrap();

        let data2 = b"conn2-data";
        Pin::new(&mut tunnel.client_transport).send(tcp2.build_data(data2)).await.unwrap();

        let mut received2 = Vec::new();
        let result = tokio::time::timeout(timeout, async {
            while received2.len() < data2.len() {
                let resp = recv_tcp(&mut tunnel.client_transport, timeout).await;
                // Determine which connection this packet belongs to
                let parsed = etherparse::SlicedPacket::from_ip(&resp).unwrap();
                if let Some(etherparse::TransportSlice::Tcp(ref t)) = parsed.transport {
                    if t.source_port() == echo_port {
                        // Check destination port to route to correct client
                        if t.destination_port() == 40002 {
                            received2.extend_from_slice(&tcp2.process_response(&resp));
                        } else {
                            // Data for conn1, just process to keep ack updated
                            tcp1.process_response(&resp);
                        }
                    }
                }
            }
        }).await;
        assert!(result.is_ok(), "conn2 echo timed out");
        assert_eq!(&received2[..data2.len()], data2);

        tunnel.server_cancel.cancel();
    }

    #[tokio::test]
    async fn large_payload_tcp_through_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as TokioTcpListener;

        let echo_server = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_server.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo_server.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => { let _ = stream.write_all(&buf[..n]).await; }
                        }
                    }
                });
            }
        });

        let mut tunnel = setup_relay_tunnel().await;
        let timeout = std::time::Duration::from_secs(10);

        let mut tcp = RawTcpClient::new([10, 0, 0, 2], [127, 0, 0, 1], 40001, echo_port);

        // Handshake
        Pin::new(&mut tunnel.client_transport).send(tcp.build_syn()).await.unwrap();
        let syn_ack = recv_tcp(&mut tunnel.client_transport, timeout).await;
        tcp.process_syn_ack(&syn_ack);
        Pin::new(&mut tunnel.client_transport).send(tcp.build_ack()).await.unwrap();

        // Build a 4KB payload, send in ~500-byte segments to stay under MTU
        let total_size = 4096;
        let segment_size = 500;
        let full_payload: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

        for chunk in full_payload.chunks(segment_size) {
            let data_pkt = tcp.build_data(chunk);
            Pin::new(&mut tunnel.client_transport).send(data_pkt).await.unwrap();
            // Small delay to avoid overwhelming the netstack
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        // Collect echoed data
        let mut received = Vec::new();
        let result = tokio::time::timeout(timeout, async {
            while received.len() < total_size {
                let resp = recv_tcp(&mut tunnel.client_transport, timeout).await;
                let data = tcp.process_response(&resp);
                if !data.is_empty() {
                    received.extend_from_slice(&data);
                    // ACK the data
                    let ack = tcp.build_ack();
                    Pin::new(&mut tunnel.client_transport).send(ack).await.unwrap();
                }
            }
        }).await;

        assert!(result.is_ok(), "timed out, received {}/{} bytes", received.len(), total_size);
        assert_eq!(received.len(), total_size);
        assert_eq!(received, full_payload);

        tunnel.server_cancel.cancel();
    }

    // --- Certificate pinning tests ---

    /// Like `test_certs()` but allows specifying the SAN on the relay certificate.
    fn test_certs_with_san(san: &str) -> (quinn::ServerConfig, rustls::ClientConfig) {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let relay_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut relay_params = rcgen::CertificateParams::default();
        relay_params.distinguished_name = rcgen::DistinguishedName::new();
        relay_params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(san.try_into().unwrap()));
        let relay_cert = relay_params
            .signed_by(&relay_key, &ca_cert, &ca_key)
            .unwrap();

        let cert = rustls::pki_types::CertificateDer::from(relay_cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(relay_key.serialize_der()).unwrap();

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![ALPN.to_vec()];

        (server_config, client_crypto)
    }

    /// Start a fake relay with a specific server TLS config. Returns the port.
    fn start_fake_relay_with_config(server_config: quinn::ServerConfig) -> u16 {
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(fake_relay(endpoint));
        port
    }

    /// Try a raw QUIC connection to a relay, bypassing pubsub-client's retry loop.
    /// Returns Ok(Connection) on success, Err on TLS/handshake failure.
    async fn try_quic_connect(
        client_crypto: rustls::ClientConfig,
        port: u16,
    ) -> Result<quinn::Connection, quinn::ConnectionError> {
        let ep = build_endpoint_with_crypto(client_crypto, &None).unwrap();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let connecting = ep.connect(addr, "relay.spora.dev").unwrap();
        connecting.await
    }

    #[tokio::test]
    async fn relay_rejects_connection_with_wrong_ca() {
        // Server has cert signed by CA_A
        let (server_config, _correct_crypto) = test_certs();
        // Client trusts a completely different CA_B
        let (_, wrong_crypto) = test_certs();

        let port = start_fake_relay_with_config(server_config);
        let result = try_quic_connect(wrong_crypto, port).await;

        assert!(result.is_err(), "connection should fail when client trusts a different CA");
    }

    #[tokio::test]
    async fn relay_rejects_connection_with_wrong_san() {
        // Server cert has SAN "wrong.example.com" instead of "relay.spora.dev"
        // Client trusts the correct CA but connects with SNI "relay.spora.dev"
        let (server_config, correct_crypto) = test_certs_with_san("wrong.example.com");

        let port = start_fake_relay_with_config(server_config);
        let result = try_quic_connect(correct_crypto, port).await;

        assert!(result.is_err(), "connection should fail when server SAN doesn't match SNI");
    }

    #[tokio::test]
    async fn relay_rejects_self_signed_server_cert() {
        // Server uses a self-signed cert (acts as its own CA)
        let relay_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut relay_params = rcgen::CertificateParams::default();
        relay_params.distinguished_name = rcgen::DistinguishedName::new();
        relay_params
            .subject_alt_names
            .push(rcgen::SanType::DnsName("relay.spora.dev".try_into().unwrap()));
        let self_signed = relay_params.self_signed(&relay_key).unwrap();

        let cert = rustls::pki_types::CertificateDer::from(self_signed.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(relay_key.serialize_der()).unwrap();

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));

        // Client trusts a separate CA (not the self-signed cert)
        let (_, client_crypto) = test_certs();

        let port = start_fake_relay_with_config(server_config);
        let result = try_quic_connect(client_crypto, port).await;

        assert!(result.is_err(), "connection should fail with self-signed server cert");
    }

    #[tokio::test]
    async fn relay_accepts_connection_with_correct_pinned_ca() {
        // Positive control: matching CA, correct SAN → connection succeeds
        let (server_config, client_crypto) = test_certs();
        let port = start_fake_relay_with_config(server_config);

        let ep = build_endpoint_with_crypto(client_crypto, &None).unwrap();
        let svc = PubSubService::new("127.0.0.1", port);
        let result = svc.sub_with_endpoint("testkey", &ep).await;

        assert!(result.is_ok(), "connection should succeed with correct pinned CA: {:?}", result.err());
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
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            pierce("192.0.2.1:19302"),
        ).await;

        match result {
            Ok(Ok(_)) => panic!("should not succeed"),
            Ok(Err(_)) => {}
            Err(_) => {}
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
        ).await;

        match result {
            Ok(Ok(_)) => panic!("should not succeed"),
            Ok(Err(_)) => {}
            Err(_) => {}
        }
    }

    // --- QUIC P2P transport tests ---

    use crate::transport::quic::{
        cert_fingerprint, establish_quic_client, establish_quic_server, generate_self_signed_cert,
    };

    /// Helper: create a localhost UDP socket pair bound to ephemeral ports.
    async fn quic_socket_pair() -> (tokio::net::UdpSocket, tokio::net::UdpSocket, std::net::SocketAddr, std::net::SocketAddr) {
        let server_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        (server_sock, client_sock, server_addr, client_addr)
    }

    #[tokio::test]
    async fn quic_peer_transport_roundtrip() {
        let (server_sock, client_sock, server_addr, _client_addr) = quic_socket_pair().await;

        let (cert, key, fingerprint) = generate_self_signed_cert();

        let server_task = tokio::spawn(async move {
            establish_quic_server(server_sock, cert, key).await.unwrap()
        });

        let client_task = tokio::spawn(async move {
            establish_quic_client(client_sock, server_addr, &fingerprint).await.unwrap()
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        let mut server_transport = server_result.unwrap();
        let mut client_transport = client_result.unwrap();

        // Client → Server
        let pkt1 = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_transport).send(pkt1.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_transport.next())
            .await
            .expect("server should receive packet from client")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt1);

        // Server → Client
        let pkt2 = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut server_transport).send(pkt2.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, client_transport.next())
            .await
            .expect("client should receive packet from server")
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt2);
    }

    #[tokio::test]
    async fn quic_peer_rejects_wrong_fingerprint() {
        let (server_sock, client_sock, server_addr, _client_addr) = quic_socket_pair().await;

        let (cert, key, _correct_fp) = generate_self_signed_cert();

        // Generate a different cert to get a different fingerprint
        let (other_cert, _, _) = generate_self_signed_cert();
        let wrong_fingerprint = cert_fingerprint(other_cert.as_ref());

        let server_task = tokio::spawn(async move {
            establish_quic_server(server_sock, cert, key).await
        });

        let client_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            establish_quic_client(client_sock, server_addr, &wrong_fingerprint),
        ).await;

        // Client should fail due to fingerprint mismatch
        match client_result {
            Ok(Ok(_)) => panic!("client should reject wrong fingerprint"),
            Ok(Err(_)) => {} // expected: handshake failed
            Err(_) => {}     // timeout is also acceptable
        }

        // Server may fail too (client resets connection)
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn quic_peer_drops_oversized_datagram() {
        let (server_sock, client_sock, server_addr, _client_addr) = quic_socket_pair().await;

        let (cert, key, fingerprint) = generate_self_signed_cert();

        let server_task = tokio::spawn(async move {
            establish_quic_server(server_sock, cert, key).await.unwrap()
        });

        let client_task = tokio::spawn(async move {
            establish_quic_client(client_sock, server_addr, &fingerprint).await.unwrap()
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        let mut server_transport = server_result.unwrap();
        let mut client_transport = client_result.unwrap();

        // Send an oversized datagram (2000 bytes, exceeds QUIC datagram limit)
        let oversized = vec![0u8; 2000];
        let send_result = Pin::new(&mut client_transport).send(oversized).await;
        assert!(send_result.is_ok(), "oversized datagram should be silently dropped, not error");

        // Verify transport is still alive by sending a normal-sized packet
        let normal_pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        Pin::new(&mut client_transport).send(normal_pkt.clone()).await.unwrap();
        let received = tokio::time::timeout(TIMEOUT, server_transport.next())
            .await
            .expect("transport should still work after dropping oversized datagram")
            .unwrap()
            .unwrap();
        assert_eq!(received, normal_pkt);
    }
}
