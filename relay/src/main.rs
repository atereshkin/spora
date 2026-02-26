use std::collections::HashMap;
use std::sync::Arc;
use clap::Parser;
use log::{debug, error, info, warn};
use quinn::Connection;
use tokio::sync::Mutex;

const MSG_SUB: u8 = 0x01;
const MSG_PUB: u8 = 0x02;
const MSG_MATCH: u8 = 0x03;
const RESP_ERROR: u8 = 0xFF;

const ALPN: &[u8] = b"spora-relay/1";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Advertised hostname for publisher connections
    #[arg(required = true)]
    host: String,
    /// Port to listen on
    #[arg(short, long, default_value_t = 443)]
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
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.black_hole_cooldown(std::time::Duration::from_secs(1));
    transport.mtu_discovery_config(Some(mtud));
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

fn log_conn_stats(label: &str, conn: &Connection) {
    let stats = conn.stats();
    error!(
        "{}: mtu={}, mds={:?}, rtt={:?}, \
         sent_pkts={}, lost_pkts={}, lost_bytes={}, \
         pmtud_sent={}, pmtud_lost={}, black_holes={}, \
         cwnd={}, datagrams_tx={}, datagrams_rx={}",
        label,
        stats.path.current_mtu,
        conn.max_datagram_size(),
        stats.path.rtt,
        stats.path.sent_packets,
        stats.path.lost_packets,
        stats.path.lost_bytes,
        stats.path.sent_plpmtud_probes,
        stats.path.lost_plpmtud_probes,
        stats.path.black_holes_detected,
        stats.path.cwnd,
        stats.frame_tx.datagram,
        stats.frame_rx.datagram,
    );
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
                    match b.send_datagram_wait(data).await {
                        Ok(()) => {}
                        Err(quinn::SendDatagramError::TooLarge) => {
                            // Black hole detection may have temporarily reduced
                            // the MTU.  Skip this datagram; inner TCP will
                            // retransmit.  PMTUD will re-probe shortly.
                            warn!("Forwarding a→b: datagram too large (mds={:?}), skipping", b.max_datagram_size());
                        }
                        Err(e) => {
                            warn!("Failed to forward datagram a→b: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Datagram forwarding a→b ended: {}", e);
                    break;
                }
            }
        }
        log_conn_stats("pub conn stats at forwarding end", &a);
        log_conn_stats("sub conn stats at forwarding end (send side)", &b);
    });

    // b → a
    tokio::spawn(async move {
        loop {
            match b2.read_datagram().await {
                Ok(data) => {
                    match a2.send_datagram_wait(data).await {
                        Ok(()) => {}
                        Err(quinn::SendDatagramError::TooLarge) => {
                            warn!("Forwarding b→a: datagram too large (mds={:?}), skipping", a2.max_datagram_size());
                        }
                        Err(e) => {
                            warn!("Failed to forward datagram b→a: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Datagram forwarding b→a ended: {}", e);
                    break;
                }
            }
        }
        log_conn_stats("sub conn stats at forwarding end", &b2);
        log_conn_stats("pub conn stats at forwarding end (send side)", &a2);
    });
}
