use std::io;
use std::sync::Arc;
use std::time::Instant;
use log::debug;
use quinn::congestion;

const MSG_SUB: u8 = 0x01;
const MSG_PUB: u8 = 0x02;
const MSG_MATCH: u8 = 0x03;
const RESP_ERROR: u8 = 0xFF;

const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const ALPN: &[u8] = b"spora-relay/1";

#[derive(Debug, Clone)]
struct NoopCc { mtu: u16 }

impl congestion::Controller for NoopCc {
    fn on_congestion_event(&mut self, _now: Instant, _sent: Instant, _is_persistent: bool, _lost_bytes: u64) {}
    fn on_mtu_update(&mut self, new_mtu: u16) { self.mtu = new_mtu; }
    fn window(&self) -> u64 { u64::MAX / 2 }
    fn clone_box(&self) -> Box<dyn congestion::Controller> { Box::new(self.clone()) }
    fn initial_window(&self) -> u64 { u64::MAX / 2 }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> { self }
}

struct NoopCcFactory;

impl congestion::ControllerFactory for NoopCcFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn congestion::Controller> {
        Box::new(NoopCc { mtu: 1200 })
    }
}

/// Embedded CA certificate for verifying relay TLS.
const CA_DER: &[u8] = include_bytes!("../ca.der");

pub struct SubConnection {
    pub connection: quinn::Connection,
    pub endpoint: String,
    match_recv: quinn::RecvStream,
}

impl SubConnection {
    /// Block until the relay notifies us that a peer has matched.
    pub async fn wait_for_match(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 1];
        self.match_recv
            .read_exact(&mut buf)
            .await
            .map_err(|e| io::Error::other(format!("failed to read match notification: {}", e)))?;
        if buf[0] == MSG_MATCH {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "unexpected match byte: 0x{:02x}",
                buf[0]
            )))
        }
    }
}

fn build_client_crypto() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    let ca_cert = rustls::pki_types::CertificateDer::from(CA_DER.to_vec());
    root_store.add(ca_cert).expect("failed to add CA cert");

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto
}

fn build_endpoint(
    protector: &Option<Arc<dyn Fn(i32) + Send + Sync>>,
) -> io::Result<quinn::Endpoint> {
    let crypto = build_client_crypto();
    build_endpoint_with_crypto(crypto, protector)
}

/// Build a QUIC endpoint using a custom client config (for tests with ephemeral certs).
pub fn build_endpoint_with_crypto(
    crypto: rustls::ClientConfig,
    protector: &Option<Arc<dyn Fn(i32) + Send + Sync>>,
) -> io::Result<quinn::Endpoint> {
    let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    #[cfg(unix)]
    if let Some(f) = protector {
        use std::os::unix::io::AsRawFd;
        f(std_socket.as_raw_fd());
    }
    #[cfg(not(unix))]
    let _ = protector;
    std_socket.set_nonblocking(true)?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("failed to build QUIC client config"),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.initial_mtu(1452);
    transport.congestion_controller_factory(Arc::new(NoopCcFactory));
    client_config.transport_config(Arc::new(transport));

    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available"))?;
    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, std_socket, runtime)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Connect to the relay, returning a QUIC Connection. Handles retry logic.
async fn quic_connect(
    endpoint: &quinn::Endpoint,
    relay_addr: std::net::SocketAddr,
    deadline: tokio::time::Instant,
) -> io::Result<quinn::Connection> {
    loop {
        let connecting = match endpoint.connect(relay_addr, "relay.spora.dev") {
            Ok(c) => c,
            Err(e) => {
                debug!("QUIC connect failed: {}", e);
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        match tokio::time::timeout(RETRY_INTERVAL, connecting).await {
            Ok(Ok(conn)) => return Ok(conn),
            Ok(Err(e)) => {
                debug!("QUIC handshake failed: {}", e);
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
                continue;
            }
            Err(_) => {
                debug!("QUIC connect timed out, retrying...");
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
                continue;
            }
        }
    }
}

pub struct PubSubService<'a> {
    host: &'a str,
    port: u16,
}

impl<'a> PubSubService<'a> {
    pub fn new(host: &'a str, port: u16) -> Self {
        PubSubService { host, port }
    }

    /// Subscribe to a key. Returns a SubConnection with the QUIC connection
    /// and the advertised endpoint string.
    pub async fn sub(
        &self,
        key: &str,
        protector: &Option<Arc<dyn Fn(i32) + Send + Sync>>,
    ) -> io::Result<SubConnection> {
        let endpoint = build_endpoint(protector)?;
        self.sub_with_endpoint(key, &endpoint).await
    }

    /// Subscribe using a pre-built endpoint (for tests with custom TLS config).
    pub async fn sub_with_endpoint(
        &self,
        key: &str,
        endpoint: &quinn::Endpoint,
    ) -> io::Result<SubConnection> {
        let relay_addr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| io::Error::other(format!("bad relay addr: {}", e)))?;

        let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;
        let conn = quic_connect(endpoint, relay_addr, deadline).await?;

        // Open bidi stream and send SUB + key
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("failed to open bidi stream: {}", e)))?;

        let mut msg = Vec::with_capacity(1 + key.len());
        msg.push(MSG_SUB);
        msg.extend_from_slice(key.as_bytes());
        send.write_all(&msg)
            .await
            .map_err(|e| io::Error::other(format!("failed to send SUB message: {}", e)))?;
        send.finish().ok();

        // Read the ACK response. The relay sends [MSG_SUB][endpoint] and keeps
        // the stream open for the later MATCH notification.
        let mut buf = vec![0u8; 65535];
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| io::Error::other(format!("failed to read SUB response: {}", e)))?
            .ok_or_else(|| io::Error::other("relay closed stream before ACK"))?;

        match buf[0] {
            MSG_SUB => {
                let endpoint_str = String::from_utf8_lossy(&buf[1..n]).to_string();
                debug!("SUB_ACK received, endpoint={}", endpoint_str);
                Ok(SubConnection {
                    connection: conn,
                    endpoint: endpoint_str,
                    match_recv: recv,
                })
            }
            RESP_ERROR => {
                let err_msg = String::from_utf8_lossy(&buf[1..n]).to_string();
                Err(io::Error::other(err_msg))
            }
            other => Err(io::Error::other(format!(
                "unexpected SUB response: 0x{:02x}",
                other
            ))),
        }
    }

    /// Publish to a key. Returns a QUIC Connection to the relay, ready for
    /// datagram exchange with the matched subscriber.
    pub async fn publish(
        host: &str,
        port: u16,
        key: &str,
        protector: &Option<Arc<dyn Fn(i32) + Send + Sync>>,
    ) -> io::Result<quinn::Connection> {
        let endpoint = build_endpoint(protector)?;
        Self::publish_with_endpoint(host, port, key, &endpoint).await
    }

    /// Publish using a pre-built endpoint (for tests with custom TLS config).
    pub async fn publish_with_endpoint(
        host: &str,
        port: u16,
        key: &str,
        endpoint: &quinn::Endpoint,
    ) -> io::Result<quinn::Connection> {
        let relay_addr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| io::Error::other(format!("bad relay addr: {}", e)))?;

        let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;
        let conn = quic_connect(endpoint, relay_addr, deadline).await?;

        // Open bidi stream and send PUB + key
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("failed to open bidi stream: {}", e)))?;

        let mut msg = Vec::with_capacity(1 + key.len());
        msg.push(MSG_PUB);
        msg.extend_from_slice(key.as_bytes());
        send.write_all(&msg)
            .await
            .map_err(|e| io::Error::other(format!("failed to send PUB message: {}", e)))?;
        send.finish().ok();

        // Read response (relay finishes stream after ACK)
        let resp = recv
            .read_to_end(65535)
            .await
            .map_err(|e| io::Error::other(format!("failed to read PUB response: {}", e)))?;

        if resp.is_empty() {
            return Err(io::Error::other("empty PUB response"));
        }

        match resp[0] {
            MSG_PUB => {
                debug!("PUB_ACK received");
                Ok(conn)
            }
            RESP_ERROR => {
                let err_msg = String::from_utf8_lossy(&resp[1..]).to_string();
                Err(io::Error::other(err_msg))
            }
            other => Err(io::Error::other(format!(
                "unexpected PUB response: 0x{:02x}",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
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
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Relay");
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
        let ca_der = rustls::pki_types::CertificateDer::from(ca_cert.der().to_vec());
        root_store.add(ca_der).unwrap();

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![ALPN.to_vec()];

        (server_config, client_crypto)
    }

    struct FakeSubscriber {
        connection: quinn::Connection,
        send_stream: quinn::SendStream,
    }

    /// Fake relay for testing - mimics the real pubsub relay.
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
                        // Don't finish - keep open for MATCH
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
                            // Forward datagrams
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

    fn start_test_relay() -> (u16, rustls::ClientConfig) {
        let (server_config, client_crypto) = test_certs();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(fake_relay(endpoint));
        (port, client_crypto)
    }

    #[tokio::test]
    async fn sub_receives_endpoint() {
        let (port, client_crypto) = start_test_relay();
        let client_ep = build_endpoint_with_crypto(client_crypto, &None).unwrap();

        let svc = PubSubService::new("127.0.0.1", port);
        let sub_conn = svc.sub_with_endpoint("testkey", &client_ep).await.unwrap();
        assert!(!sub_conn.endpoint.is_empty());
    }

    #[tokio::test]
    async fn publish_receives_ack() {
        let (port, client_crypto) = start_test_relay();

        // First subscribe
        let sub_ep = build_endpoint_with_crypto(client_crypto.clone(), &None).unwrap();
        let svc = PubSubService::new("127.0.0.1", port);
        let _sub_conn = svc.sub_with_endpoint("testkey", &sub_ep).await.unwrap();

        // Then publish
        let pub_ep = build_endpoint_with_crypto(client_crypto, &None).unwrap();
        let pub_conn =
            PubSubService::publish_with_endpoint("127.0.0.1", port, "testkey", &pub_ep)
                .await
                .unwrap();
        assert!(pub_conn.remote_address().port() > 0);
    }

    #[tokio::test]
    async fn sub_wait_for_match_succeeds() {
        let (port, client_crypto) = start_test_relay();

        let sub_ep = build_endpoint_with_crypto(client_crypto.clone(), &None).unwrap();
        let svc = PubSubService::new("127.0.0.1", port);
        let mut sub_conn = svc.sub_with_endpoint("testkey", &sub_ep).await.unwrap();

        // Publish in background
        let pub_ep = build_endpoint_with_crypto(client_crypto, &None).unwrap();
        tokio::spawn(async move {
            PubSubService::publish_with_endpoint("127.0.0.1", port, "testkey", &pub_ep)
                .await
                .unwrap();
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), sub_conn.wait_for_match())
            .await
            .expect("should not timeout")
            .expect("wait_for_match should succeed");
    }

    #[tokio::test]
    async fn datagram_forwarding_works() {
        let (port, client_crypto) = start_test_relay();

        let sub_ep = build_endpoint_with_crypto(client_crypto.clone(), &None).unwrap();
        let svc = PubSubService::new("127.0.0.1", port);
        let mut sub_conn = svc.sub_with_endpoint("testkey", &sub_ep).await.unwrap();

        let pub_ep = build_endpoint_with_crypto(client_crypto, &None).unwrap();
        let pub_conn =
            PubSubService::publish_with_endpoint("127.0.0.1", port, "testkey", &pub_ep)
                .await
                .unwrap();

        sub_conn.wait_for_match().await.unwrap();

        // Publisher → subscriber
        pub_conn
            .send_datagram(bytes::Bytes::from_static(b"hello from pub"))
            .unwrap();

        let data = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sub_conn.connection.read_datagram(),
        )
        .await
        .expect("should not timeout")
        .expect("should receive datagram");
        assert_eq!(&data[..], b"hello from pub");

        // Subscriber → publisher
        sub_conn
            .connection
            .send_datagram(bytes::Bytes::from_static(b"hello from sub"))
            .unwrap();

        let data = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pub_conn.read_datagram(),
        )
        .await
        .expect("should not timeout")
        .expect("should receive datagram");
        assert_eq!(&data[..], b"hello from sub");
    }
}
