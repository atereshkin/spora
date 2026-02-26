use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use clap::Parser;
use log::{debug, info, warn};
use quinn::Connection;
use quinn::congestion;
use tokio::sync::Mutex;

const MSG_SUB: u8 = 0x01;
const MSG_PUB: u8 = 0x02;
const MSG_MATCH: u8 = 0x03;
const RESP_ERROR: u8 = 0xFF;

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

const ALPN: &[u8] = b"spora-relay/1";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Advertised hostname for publisher connections
    #[arg(required = true)]
    host: String,
    /// Port to listen on
    #[arg(short, long, default_value_t = 2334)]
    port: u16,
    /// Path to relay certificate (DER)
    #[arg(long, required = true)]
    cert: String,
    /// Path to relay private key (DER)
    #[arg(long, required = true)]
    key: String,
}

struct Subscriber {
    connection: Connection,
    send_stream: quinn::SendStream,
}

type Subscribers = Arc<Mutex<HashMap<Vec<u8>, Subscriber>>>;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("quinn", log::LevelFilter::Warn)
        .filter_module("quinn_proto", log::LevelFilter::Warn)
        .filter_module("quinn_udp", log::LevelFilter::Warn)
        .filter_module("tracing", log::LevelFilter::Warn)
        .init();
    let args = Args::parse();

    let cert_der = std::fs::read(&args.cert).expect("failed to read cert file");
    let key_der = std::fs::read(&args.key).expect("failed to read key file");

    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("invalid key format");

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("failed to build TLS config");
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .expect("failed to build QUIC server config"),
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(120).try_into().unwrap(),
    ));
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    transport.congestion_controller_factory(Arc::new(NoopCcFactory));
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, ([0, 0, 0, 0], args.port).into())
        .expect("failed to create QUIC endpoint");

    let endpoint_str = format!("{}:{}", args.host, args.port);
    info!(
        "Relay listening on QUIC port {}, advertising {}",
        args.port, endpoint_str
    );

    let subscribers: Subscribers = Arc::new(Mutex::new(HashMap::new()));

    while let Some(incoming) = endpoint.accept().await {
        let subscribers = subscribers.clone();
        let endpoint_str = endpoint_str.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_connection(conn, subscribers, endpoint_str).await {
                        warn!("Connection error: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                }
            }
        });
    }
}

async fn handle_connection(
    conn: Connection,
    subscribers: Subscribers,
    endpoint_str: String,
) -> Result<(), String> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| format!("failed to accept bidi stream: {}", e))?;

    // Read the handshake message: [msg_type] + key
    let handshake = recv
        .read_to_end(65535)
        .await
        .map_err(|e| format!("failed to read handshake: {}", e))?;

    if handshake.is_empty() {
        return Err("empty handshake".into());
    }

    let msg_type = handshake[0];
    let key = handshake[1..].to_vec();

    match msg_type {
        MSG_SUB => {
            info!(
                "SUB from {} key={:?}",
                conn.remote_address(),
                String::from_utf8_lossy(&key)
            );

            // Send ACK with endpoint
            let mut resp = vec![MSG_SUB];
            resp.extend_from_slice(endpoint_str.as_bytes());
            send.write_all(&resp)
                .await
                .map_err(|e| format!("failed to send SUB_ACK: {}", e))?;

            // Keep the send stream open for later MATCH notification.
            // Don't finish() - we need to send MATCH later.
            let sub = Subscriber {
                connection: conn,
                send_stream: send,
            };
            subscribers.lock().await.insert(key, sub);
            Ok(())
        }
        MSG_PUB => {
            info!(
                "PUB from {} key={:?}",
                conn.remote_address(),
                String::from_utf8_lossy(&key)
            );

            let sub = subscribers.lock().await.remove(&key);
            if let Some(mut sub) = sub {
                // Send PUB_ACK to publisher
                send.write_all(&[MSG_PUB])
                    .await
                    .map_err(|e| format!("failed to send PUB_ACK: {}", e))?;
                send.finish().ok();

                // Send MATCH notification to subscriber
                if let Err(e) = sub.send_stream.write_all(&[MSG_MATCH]).await {
                    warn!("Failed to send MATCH to subscriber: {}", e);
                }
                sub.send_stream.finish().ok();

                info!(
                    "Matched {} <-> {}",
                    sub.connection.remote_address(),
                    conn.remote_address()
                );

                // Forward datagrams bidirectionally
                let pub_conn = conn;
                let sub_conn = sub.connection;
                spawn_datagram_forwarding(pub_conn.clone(), sub_conn.clone());

                // After PMTUD converges (~1.5s), notify both peers of the
                // effective tunnel MTU so they can configure TUN devices.
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    let pub_mds = pub_conn.max_datagram_size();
                    let sub_mds = sub_conn.max_datagram_size();
                    if let (Some(p), Some(s)) = (pub_mds, sub_mds) {
                        let mtu = std::cmp::min(p, s) as u16;
                        let msg = [0xFD, (mtu >> 8) as u8, mtu as u8];
                        debug!("Sending MTU notification: {} (pub={}, sub={})", mtu, p, s);
                        let _ = pub_conn.send_datagram(msg.to_vec().into());
                        let _ = sub_conn.send_datagram(msg.to_vec().into());
                    }
                });

                Ok(())
            } else {
                info!(
                    "No subscriber for key {:?}",
                    String::from_utf8_lossy(&key)
                );
                let mut resp = vec![RESP_ERROR];
                resp.extend_from_slice(b"unknown subscriber");
                send.write_all(&resp).await.ok();
                send.finish().ok();
                Err("no subscriber for key".into())
            }
        }
        _ => {
            warn!(
                "Unknown message type 0x{:02x} from {}",
                msg_type,
                conn.remote_address()
            );
            Err(format!("unknown message type 0x{:02x}", msg_type))
        }
    }
}

fn spawn_datagram_forwarding(a: Connection, b: Connection) {
    let a2 = a.clone();
    let b2 = b.clone();

    // a → b
    tokio::spawn(async move {
        loop {
            match a.read_datagram().await {
                Ok(data) => {
                    // send_datagram_wait blocks when the send buffer is full,
                    // which stops us reading from `a`.  This provides natural
                    // back-pressure: when `b` can't keep up, `a`'s newest
                    // datagrams are dropped at the QUIC receive buffer (drop-
                    // newest) instead of evicting the oldest from the send
                    // buffer (FIFO).  Drop-newest is critical for TCP: the
                    // oldest segments are needed for the receiver's contiguous
                    // window to advance.
                    if let Err(e) = b.send_datagram_wait(data).await {
                        warn!("Failed to forward datagram a→b: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    info!("Datagram forwarding a→b ended: {}", e);
                    break;
                }
            }
        }
    });

    // b → a
    tokio::spawn(async move {
        loop {
            match b2.read_datagram().await {
                Ok(data) => {
                    if let Err(e) = a2.send_datagram_wait(data).await {
                        warn!("Failed to forward datagram b→a: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    info!("Datagram forwarding b→a ended: {}", e);
                    break;
                }
            }
        }
    });
}
