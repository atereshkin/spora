use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use log::{debug, info, warn, error};
use quinn::Connection;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Prefix byte for signaling messages on the relay connection.
/// IPv4 packets start with 0x45–0x4F so there's no ambiguity.
pub const SIGNAL_PREFIX: u8 = 0xFE;

/// Prefix byte for control messages (e.g. MTU notification) from the relay.
/// Doesn't collide with IPv4 (0x4X), IPv6 (0x6X), or signal (0xFE).
pub const CONTROL_PREFIX: u8 = 0xFD;

pub type MtuCallback = Option<Arc<dyn Fn(u16) + Send + Sync>>;

/// Split a relay `quinn::Connection` into a `RelayTransport` (IP traffic) and a
/// `SignalChannel` (signaling messages). A background demux task reads datagrams
/// from the connection and dispatches by first byte.
pub fn relay_connection(
    conn: Connection,
    mtu_callback: MtuCallback,
) -> (RelayTransport, SignalChannel, JoinHandle<()>) {
    let (ip_tx, ip_rx) = mpsc::unbounded_channel();
    let (signal_tx, signal_rx) = mpsc::unbounded_channel();

    let recv_conn = conn.clone();
    let handle = tokio::spawn(async move {
        // Track the running minimum MTU across all 0xFD notifications
        // (relay-reported MTU, peer-reported MDS, own MDS).  Only invoke
        // the callback when a new lower value is discovered so the app
        // never sees the MTU go *up* during the relay phase.
        let mut best_mtu: u16 = u16::MAX;

        loop {
            match recv_conn.read_datagram().await {
                Ok(data) if !data.is_empty() => {
                    if data[0] == SIGNAL_PREFIX {
                        // Strip the prefix byte
                        if signal_tx.send(data[1..].to_vec()).is_err() {
                            debug!("Signal channel closed, demux task exiting");
                            break;
                        }
                    } else if data[0] == CONTROL_PREFIX && data.len() >= 3 {
                        let received_mtu = u16::from_be_bytes([data[1], data[2]]);
                        let own_mds = recv_conn.max_datagram_size()
                            .unwrap_or(received_mtu as usize) as u16;
                        let candidate = std::cmp::min(received_mtu, own_mds);
                        if candidate < best_mtu {
                            best_mtu = candidate;
                            info!(
                                "MTU updated: received={}, own={}, effective={}",
                                received_mtu, own_mds, candidate
                            );
                            if let Some(ref cb) = mtu_callback {
                                cb(candidate);
                            }
                        }
                    } else if ip_tx.send(data.to_vec()).is_err() {
                        debug!("IP channel closed, demux task exiting");
                        break;
                    }
                }
                Ok(_) => {} // empty datagram, ignore
                Err(e) => {
                    let stats = recv_conn.stats();
                    error!(
                        "Relay QUIC connection died: {}. \
                         Stats: mtu={}, mds={:?}, rtt={:?}, \
                         sent_pkts={}, lost_pkts={}, lost_bytes={}, \
                         pmtud_sent={}, pmtud_lost={}, black_holes={}, \
                         datagrams_tx={}, datagrams_rx={}",
                        e,
                        stats.path.current_mtu,
                        recv_conn.max_datagram_size(),
                        stats.path.rtt,
                        stats.path.sent_packets,
                        stats.path.lost_packets,
                        stats.path.lost_bytes,
                        stats.path.sent_plpmtud_probes,
                        stats.path.lost_plpmtud_probes,
                        stats.path.black_holes_detected,
                        stats.frame_tx.datagram,
                        stats.frame_rx.datagram,
                    );
                    break;
                }
            }
        }
    });

    // Report own MDS to the other peer after PMTUD converges.
    // The relay's forwarding tasks will deliver this datagram to the
    // other peer, whose demux will process it as a 0xFD control message.
    let report_conn = conn.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Some(mds) = report_conn.max_datagram_size() {
            let mds = mds as u16;
            let msg: Vec<u8> = vec![CONTROL_PREFIX, (mds >> 8) as u8, mds as u8];
            debug!("Reporting own MDS to peer: {}", mds);
            let _ = report_conn.send_datagram(msg.into());
        }
    });

    // Periodic connection health logging.
    let stats_conn = conn.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let Some(mds) = stats_conn.max_datagram_size() else {
                info!("Relay QUIC stats: connection closed");
                break;
            };
            let stats = stats_conn.stats();
            info!(
                "Relay QUIC stats: mtu={}, mds={}, rtt={:?}, \
                 sent_pkts={}, lost_pkts={}, lost_bytes={}, \
                 pmtud_sent={}, pmtud_lost={}, black_holes={}, \
                 cwnd={}, datagrams_tx={}, datagrams_rx={}",
                stats.path.current_mtu,
                mds,
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
    });

    let send_conn = conn.clone();
    let transport_sink =
        futures_util::sink::unfold(send_conn, move |c, pkt: Vec<u8>| async move {
            // Fire-and-forget: don't use send_datagram_wait here because the
            // UpgradableTransport router couples send and receive in a single
            // select loop.  Blocking here would prevent ACKs from flowing
            // back, stalling the QUIC connection and triggering PMTUD failures.
            // Back-pressure is applied at the relay (pubsub) side instead,
            // where each direction runs in its own task.
            let pkt_len = pkt.len();
            match c.send_datagram(pkt.into()) {
                Ok(()) => {}
                Err(quinn::SendDatagramError::TooLarge) => {
                    warn!(
                        "Relay datagram too large: pkt={} bytes, max_datagram_size={:?}",
                        pkt_len,
                        c.max_datagram_size(),
                    );
                }
                Err(e) => {
                    let stats = c.stats();
                    error!(
                        "Relay send_datagram failed: {}. \
                         Stats: mtu={}, mds={:?}, lost_pkts={}, pmtud_sent={}, pmtud_lost={}",
                        e,
                        stats.path.current_mtu,
                        c.max_datagram_size(),
                        stats.path.lost_packets,
                        stats.path.sent_plpmtud_probes,
                        stats.path.lost_plpmtud_probes,
                    );
                    return Err(io::Error::other(format!("send_datagram failed: {}", e)));
                }
            }
            Ok::<_, io::Error>(c)
        });

    let transport = RelayTransport {
        ip_rx,
        inner_sink: Box::pin(transport_sink),
    };

    let channel = SignalChannel {
        conn,
        signal_rx,
    };

    (transport, channel, handle)
}

/// Transport for IP traffic over the relay QUIC connection.
///
/// - `Stream`: yields IP packets from the demux channel
/// - `Sink`: sends raw bytes as datagrams via the connection
pub struct RelayTransport {
    ip_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    inner_sink: Pin<Box<dyn Sink<Vec<u8>, Error = io::Error> + Send>>,
}

impl Stream for RelayTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.ip_rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for RelayTransport {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_sink.as_mut().poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.inner_sink.as_mut().start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_sink.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner_sink.as_mut().poll_close(cx)
    }
}

/// Channel for signaling messages over the relay QUIC connection.
///
/// Signaling messages are prefixed with `SIGNAL_PREFIX` (0xFE) on the wire.
pub struct SignalChannel {
    conn: Connection,
    signal_rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl SignalChannel {
    /// Send a signaling message (automatically prepends `SIGNAL_PREFIX`).
    pub async fn send_signal(&self, data: &[u8]) -> io::Result<()> {
        let mut msg = Vec::with_capacity(1 + data.len());
        msg.push(SIGNAL_PREFIX);
        msg.extend_from_slice(data);
        self.conn
            .send_datagram(msg.into())
            .map_err(|e| io::Error::other(format!("send_datagram failed: {}", e)))?;
        Ok(())
    }

    /// Receive the next signaling message (prefix already stripped).
    pub async fn recv_signal(&mut self) -> Option<Vec<u8>> {
        self.signal_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Helper: create a QUIC loopback connection pair for testing.
    async fn quic_loopback_pair() -> (Connection, Connection) {
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
            .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
        let relay_cert = relay_params
            .signed_by(&relay_key, &ca_cert, &ca_key)
            .unwrap();

        let cert = rustls::pki_types::CertificateDer::from(relay_cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(relay_key.serialize_der()).unwrap();

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        server_crypto.alpn_protocols = vec![b"test".to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));

        let server_ep =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"test".to_vec()];

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));

        let mut client_ep =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep.set_default_client_config(client_config);

        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            incoming.await.unwrap()
        });

        let client_conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let server_conn = server_task.await.unwrap();

        (client_conn, server_conn)
    }

    #[tokio::test]
    async fn relay_demux_routes_ip_and_signal() {
        let (client_conn, server_conn) = quic_loopback_pair().await;
        let (mut transport, mut signal, _handle) = relay_connection(client_conn, None);

        // Send an IPv4-like packet from peer
        let ip_pkt = vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        server_conn
            .send_datagram(ip_pkt.clone().into())
            .unwrap();

        // Send a signaling packet from peer
        let mut sig_pkt = vec![SIGNAL_PREFIX];
        sig_pkt.extend_from_slice(b"192.168.1.1:5000");
        server_conn.send_datagram(sig_pkt.into()).unwrap();

        // IP packet arrives on transport
        use futures_util::StreamExt;
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.next(),
        )
        .await
        .expect("timeout")
        .unwrap()
        .unwrap();
        assert_eq!(received, vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4]);

        // Signal arrives on signal channel (prefix stripped)
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            signal.recv_signal(),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(received, b"192.168.1.1:5000");
    }

    #[tokio::test]
    async fn relay_transport_sends_raw() {
        let (client_conn, server_conn) = quic_loopback_pair().await;
        let (transport, _signal, _handle) = relay_connection(client_conn, None);

        use futures_util::SinkExt;
        let mut transport = transport;
        let data = vec![0x45, 0x00, 0x00, 0x14, 5, 6, 7, 8];
        Pin::new(&mut transport).send(data.clone()).await.unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server_conn.read_datagram(),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(&received[..], &data);
    }

    #[tokio::test]
    async fn signal_channel_roundtrip() {
        let (client_conn, server_conn) = quic_loopback_pair().await;
        let (_transport, signal, _handle) = relay_connection(client_conn, None);

        // Send signal from our side
        signal.send_signal(b"hello").await.unwrap();

        // Peer receives it with prefix
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server_conn.read_datagram(),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(received[0], SIGNAL_PREFIX);
        assert_eq!(&received[1..], b"hello");
    }

    /// Create a QUIC loopback pair with a custom transport config applied to both sides.
    async fn quic_loopback_pair_with_config(
        transport: quinn::TransportConfig,
    ) -> (Connection, Connection) {
        let transport = Arc::new(transport);

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
            .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
        let relay_cert = relay_params
            .signed_by(&relay_key, &ca_cert, &ca_key)
            .unwrap();

        let cert = rustls::pki_types::CertificateDer::from(relay_cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(relay_key.serialize_der()).unwrap();

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        server_crypto.alpn_protocols = vec![b"test".to_vec()];

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));
        server_config.transport_config(transport.clone());

        let server_ep =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(
                ca_cert.der().to_vec(),
            ))
            .unwrap();

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"test".to_vec()];

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));
        client_config.transport_config(transport);

        let mut client_ep =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep.set_default_client_config(client_config);

        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            incoming.await.unwrap()
        });

        let client_conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let server_conn = server_task.await.unwrap();
        (client_conn, server_conn)
    }

    /// Demonstrates that quinn's send_datagram() silently evicts oldest
    /// datagrams when the send buffer fills, causing packet loss under load.
    #[tokio::test]
    async fn send_datagram_evicts_under_pressure() {
        const NUM_DATAGRAMS: usize = 500;
        const PAYLOAD_SIZE: usize = 1000;

        // Buffer can hold ~50 datagrams.  Larger than a "tiny" buffer so
        // the runtime has a chance to transmit *some*, making the eviction
        // pattern visible (only the newest survive).
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_send_buffer_size(PAYLOAD_SIZE * 50);
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));

        let (client_conn, server_conn) =
            quic_loopback_pair_with_config(transport).await;

        // Let QUIC handshake fully settle so datagrams are accepted.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Blast numbered datagrams.  send_datagram() is synchronous — the
        // QUIC runtime doesn't get to transmit between calls, so the buffer
        // fills and the oldest datagrams get evicted.
        for i in 0..NUM_DATAGRAMS {
            let mut pkt = vec![0u8; PAYLOAD_SIZE];
            pkt[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            let _ = client_conn.send_datagram(pkt.into());
        }

        // Give the runtime time to transmit whatever remains in the buffer.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Collect all datagrams that arrived.
        let mut received = Vec::new();
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                server_conn.read_datagram(),
            )
            .await
            {
                Ok(Ok(data)) => {
                    let seq = u32::from_be_bytes(data[0..4].try_into().unwrap());
                    received.push(seq);
                }
                _ => break,
            }
        }

        eprintln!(
            "send_datagram: sent {NUM_DATAGRAMS}, received {}, lost {}",
            received.len(),
            NUM_DATAGRAMS - received.len(),
        );
        if !received.is_empty() {
            eprintln!(
                "  received seq#s: {:?}",
                &received,
            );
        }

        // The whole point: with burst sends, send_datagram silently drops packets.
        assert!(
            received.len() < NUM_DATAGRAMS,
            "expected packet loss from send_datagram eviction, but all {} arrived",
            NUM_DATAGRAMS,
        );
    }

    /// Shows that send_datagram_wait delivers all datagrams without loss,
    /// because it blocks until buffer space is available.
    #[tokio::test]
    async fn send_datagram_wait_delivers_all() {
        const NUM_DATAGRAMS: usize = 500;
        const PAYLOAD_SIZE: usize = 1000;

        let mut transport = quinn::TransportConfig::default();
        transport.datagram_send_buffer_size(PAYLOAD_SIZE * 50);
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));

        let (client_conn, server_conn) =
            quic_loopback_pair_with_config(transport).await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send with backpressure — send_datagram_wait blocks when full.
        for i in 0..NUM_DATAGRAMS {
            let mut pkt = vec![0u8; PAYLOAD_SIZE];
            pkt[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            client_conn
                .send_datagram_wait(pkt.into())
                .await
                .expect("send_datagram_wait failed");
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let mut received = Vec::new();
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                server_conn.read_datagram(),
            )
            .await
            {
                Ok(Ok(data)) => {
                    let seq = u32::from_be_bytes(data[0..4].try_into().unwrap());
                    received.push(seq);
                }
                _ => break,
            }
        }

        eprintln!(
            "send_datagram_wait: sent {NUM_DATAGRAMS}, received {}",
            received.len(),
        );

        assert_eq!(
            received.len(),
            NUM_DATAGRAMS,
            "send_datagram_wait should deliver all datagrams, but lost {}",
            NUM_DATAGRAMS - received.len(),
        );
    }
}
