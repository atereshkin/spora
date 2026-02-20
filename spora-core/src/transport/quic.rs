use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Sink, Stream};
use log::debug;
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const P2P_ALPN: &[u8] = b"spora-p2p/1";
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Custom TLS certificate verifier that checks the server cert's SHA-256 fingerprint.
#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual = cert_fingerprint(end_entity.as_ref());
        if actual == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert fingerprint mismatch: expected {:x?}, got {:x?}",
                &self.expected[..4],
                &actual[..4],
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A `Transport` that carries IP packets as QUIC datagrams over a P2P connection.
pub struct QuicPeerTransport {
    rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    conn: Connection,
    _reader: JoinHandle<()>,
}

impl QuicPeerTransport {
    fn new(conn: Connection) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let read_conn = conn.clone();
        let reader = tokio::spawn(async move {
            loop {
                match read_conn.read_datagram().await {
                    Ok(data) => {
                        if tx.send(Ok(data.to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
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
        match self.conn.send_datagram(item.into()) {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                debug!("QUIC datagram too large, dropping");
                Ok(())
            }
            Err(e) => Err(io::Error::other(format!("QUIC send_datagram error: {}", e))),
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

fn build_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(QUIC_IDLE_TIMEOUT.try_into().unwrap()));
    transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport.datagram_send_buffer_size(4 * 1024 * 1024);
    transport
}

/// Accept a QUIC connection on the given UDP socket (server/responder role).
pub async fn establish_quic_server(
    socket: tokio::net::UdpSocket,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<QuicPeerTransport, String> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("server TLS config error: {}", e))?;
    server_crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(|e| format!("QUIC server crypto error: {}", e))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
    server_config.transport_config(Arc::new(build_transport_config()));

    let runtime = quinn::default_runtime()
        .ok_or_else(|| "no async runtime for quinn".to_string())?;
    let socket = socket
        .into_std()
        .map_err(|e| format!("into_std failed: {}", e))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .map_err(|e| format!("endpoint creation failed: {}", e))?;

    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| "endpoint closed before accept".to_string())?;
        incoming
            .await
            .map_err(|e| format!("QUIC handshake failed: {}", e))
    })
    .await
    .map_err(|_| "QUIC server handshake timed out".to_string())??;

    debug!("QUIC P2P server connection established");
    Ok(QuicPeerTransport::new(conn))
}

/// Connect to a QUIC server on the given UDP socket (client/initiator role).
pub async fn establish_quic_client(
    socket: tokio::net::UdpSocket,
    peer_addr: std::net::SocketAddr,
    fingerprint: &[u8; 32],
) -> Result<QuicPeerTransport, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(FingerprintVerifier {
        expected: *fingerprint,
        provider: provider.clone(),
    });

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("client TLS version error: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    let quic_client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(|e| format!("QUIC client crypto error: {}", e))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));
    client_config.transport_config(Arc::new(build_transport_config()));

    let runtime = quinn::default_runtime()
        .ok_or_else(|| "no async runtime for quinn".to_string())?;
    let socket = socket
        .into_std()
        .map_err(|e| format!("into_std failed: {}", e))?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )
    .map_err(|e| format!("endpoint creation failed: {}", e))?;
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        endpoint.connect(peer_addr, "spora.peer")
            .map_err(|e| format!("QUIC connect error: {}", e))?
    )
    .await
    .map_err(|_| "QUIC client handshake timed out".to_string())?
    .map_err(|e| format!("QUIC handshake failed: {}", e))?;

    debug!("QUIC P2P client connection established");
    Ok(QuicPeerTransport::new(conn))
}
