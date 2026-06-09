use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{Sink, Stream};
use log::{error, info, warn};
use quinn::Connection;
use quinn::congestion;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// SHA-256 fingerprint of a DER-encoded certificate.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
    let mut fp = [0u8; 32];
    fp.copy_from_slice(digest.as_ref());
    fp
}

/// Generate a self-signed ECDSA P-256 certificate for P2P QUIC.
/// Returns (cert_der, key_der, sha256_fingerprint).
pub fn generate_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>, [u8; 32]) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("spora.peer".try_into().unwrap()));
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    let fingerprint = cert_fingerprint(cert_der.as_ref());

    (cert_der, key_der, fingerprint)
}

/// A `Transport` that carries IP packets as QUIC datagrams over a P2P connection.
pub struct QuicPeerTransport {
    rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    conn: Connection,
    _reader: JoinHandle<()>,
}

impl QuicPeerTransport {
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Returns a clone of the underlying QUIC connection handle.
    /// Useful for reading stats after PMTUD converges.
    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub fn new(conn: Connection) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let read_conn = conn.clone();
        let reader = tokio::spawn(async move {
            loop {
                match read_conn.read_datagram().await {
                    Ok(data) => {
                        if tx.send(Ok(data.to_vec())).is_err() {
                            info!("P2P QUIC reader: channel closed, exiting");
                            break;
                        }
                    }
                    Err(e) => {
                        let stats = read_conn.stats();
                        error!(
                            "P2P QUIC connection died: {}. \
                             Stats: mtu={}, mds={:?}, rtt={:?}, \
                             sent_pkts={}, lost_pkts={}, lost_bytes={}, \
                             pmtud_sent={}, pmtud_lost={}, black_holes={}, \
                             datagrams_tx={}, datagrams_rx={}",
                            e,
                            stats.path.current_mtu,
                            read_conn.max_datagram_size(),
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
                        let _ = tx.send(Err(io::Error::other(format!(
                            "QUIC read_datagram error: {}",
                            e
                        ))));
                        break;
                    }
                }
            }
        });
        Self {
            rx,
            conn,
            _reader: reader,
        }
    }
}

impl Stream for QuicPeerTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for QuicPeerTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let pkt_len = item.len();
        match self.conn.send_datagram(item.into()) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                warn!(
                    "P2P QUIC datagram too large: pkt={} bytes, max_datagram_size={:?}",
                    pkt_len,
                    self.conn.max_datagram_size(),
                );
                Ok(())
            }
            Err(e) => {
                let stats = self.conn.stats();
                error!(
                    "P2P QUIC send_datagram failed: {}. \
                     Stats: mtu={}, mds={:?}, lost_pkts={}, pmtud_sent={}, pmtud_lost={}",
                    e,
                    stats.path.current_mtu,
                    self.conn.max_datagram_size(),
                    stats.path.lost_packets,
                    stats.path.sent_plpmtud_probes,
                    stats.path.lost_plpmtud_probes,
                );
                Err(io::Error::other(format!("QUIC send_datagram error: {}", e)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.conn.close(0u32.into(), b"close");
        Poll::Ready(Ok(()))
    }
}

/// No-op congestion controller — always allows sending.
///
/// We carry IP packets as QUIC datagrams; the inner TCP (smoltcp) already
/// handles its own congestion control, so QUIC-level CC just adds latency
/// and causes send-buffer eviction under load.
#[derive(Debug, Clone)]
struct NoopCc {
    mtu: u16,
}

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

pub fn build_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(QUIC_IDLE_TIMEOUT.try_into().unwrap()));
    transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.black_hole_cooldown(std::time::Duration::from_secs(0));
    transport.mtu_discovery_config(Some(mtud));
    transport.congestion_controller_factory(Arc::new(NoopCcFactory));
    transport
}

