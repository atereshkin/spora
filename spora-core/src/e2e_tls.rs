//! End-to-end TLS between two peers over a byte stream — the stream-native
//! carrier's E2E layer (used by the TCP/TLS relay in `carrier`).
//!
//! This mirrors `e2e.rs` (the QUIC path) but over a plain `AsyncRead + AsyncWrite`
//! stream instead of QUIC datagrams: the SAME cert pinning
//! (`RoutingKeyVerifier`), the SAME identity cert, and the SAME 16-byte secret
//! with an ACK handshake. On success both ends wrap the TLS stream in a framed
//! `StreamPeerTransport` of IP packets.
//!
//! The relay only forwards these encrypted bytes (it holds no keys), so the TLS
//! here is genuinely end-to-end: the peer is pinned to the routing key and
//! proves the secret, exactly as on the QUIC path — the relay is never trusted.

use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::identity::{Identity, ROUTING_KEY_LEN, RoutingKeyVerifier, SECRET_LEN};
use crate::transport::IpTransport;
use crate::transport::stream::StreamPeerTransport;

/// Present as HTTP/3 rather than a product token (matches `e2e.rs`).
const E2E_ALPN: &[u8] = b"h3";
/// rustls verification name; SNI is suppressed and the verifier ignores it.
const SERVER_NAME: &str = "spora.peer";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Byte the server writes once the secret verifies (mirrors `e2e::AUTH_ACK`).
const AUTH_ACK: u8 = 0x01;

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Server (A): TLS-accept `stream` with the identity cert, read and verify the
/// client's secret, ack, and return the IP-packet transport.
pub async fn accept<S>(stream: S, identity: &Identity) -> Result<IpTransport, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls server version: {e}"))?
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert_der()], identity.key_der())
        .map_err(|e| format!("tls server config: {e}"))?;
    server_crypto.alpn_protocols = vec![E2E_ALPN.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_crypto));

    let mut tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| "tls accept timed out".to_string())?
        .map_err(|e| format!("tls accept: {e}"))?;

    // Secret auth, mirroring e2e::authenticate_incoming (constant-time compare).
    let mut got = [0u8; SECRET_LEN];
    tokio::time::timeout(AUTH_TIMEOUT, tls.read_exact(&mut got))
        .await
        .map_err(|_| "secret read timed out".to_string())?
        .map_err(|e| format!("read secret: {e}"))?;
    if !bool::from(got.ct_eq(&identity.secret)) {
        return Err("bad secret".into());
    }
    tls.write_all(&[AUTH_ACK])
        .await
        .map_err(|e| format!("write ack: {e}"))?;
    let _ = tls.flush().await;
    Ok(Box::new(StreamPeerTransport::new(tls)))
}

/// Client (B): TLS-connect over `stream` pinning the server cert to
/// `routing_key`, send the secret, await the ack, and return the transport.
pub async fn connect<S>(
    stream: S,
    routing_key: [u8; ROUTING_KEY_LEN],
    secret: &[u8; SECRET_LEN],
) -> Result<IpTransport, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let provider = ring_provider();
    let verifier = Arc::new(RoutingKeyVerifier::new(routing_key, provider.clone()));
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls client version: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![E2E_ALPN.to_vec()];
    // Pin is by routing key (cert fingerprint); the server name carries no
    // security weight, so suppress SNI (matches the QUIC client).
    client_crypto.enable_sni = false;
    let connector = TlsConnector::from(Arc::new(client_crypto));
    let name = rustls::pki_types::ServerName::try_from(SERVER_NAME)
        .map_err(|e| format!("server name: {e}"))?;

    let mut tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| "tls connect timed out".to_string())?
        .map_err(|e| format!("tls connect (cert pin/handshake): {e}"))?;

    tls.write_all(secret)
        .await
        .map_err(|e| format!("write secret: {e}"))?;
    let _ = tls.flush().await;
    let mut ack = [0u8; 1];
    tokio::time::timeout(AUTH_TIMEOUT, tls.read_exact(&mut ack))
        .await
        .map_err(|_| "auth ack timed out".to_string())?
        .map_err(|e| format!("auth not acked (bad/expired secret?): {e}"))?;
    if ack[0] != AUTH_ACK {
        return Err(format!("unexpected auth ack byte {:#x}", ack[0]));
    }
    Ok(Box::new(StreamPeerTransport::new(tls)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};

    #[tokio::test]
    async fn e2e_tls_handshake_auth_and_ip_round_trip() {
        let _ = env_logger::builder().is_test(true).try_init();
        let identity = Identity::generate();
        let rk = identity.routing_key;
        let secret = identity.secret;
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server_id = identity.clone();
        let server = tokio::spawn(async move { accept(server_io, &server_id).await });
        let mut client = connect(client_io, rk, &secret)
            .await
            .expect("client connects");
        let mut server = server.await.unwrap().expect("server accepts");

        let up = vec![0x45u8, 0, 0, 0x14, 1, 2, 3, 4];
        client.send(up.clone()).await.unwrap();
        assert_eq!(server.next().await.unwrap().unwrap(), up);

        let down = vec![0x45u8, 0, 0, 0x14, 9, 9, 9, 9];
        server.send(down.clone()).await.unwrap();
        assert_eq!(client.next().await.unwrap().unwrap(), down);
    }

    #[tokio::test]
    async fn e2e_tls_rejects_a_bad_secret() {
        let _ = env_logger::builder().is_test(true).try_init();
        let identity = Identity::generate();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_id = identity.clone();
        let server = tokio::spawn(async move { accept(server_io, &server_id).await });

        let mut bad = identity.secret;
        bad[0] ^= 0xFF;
        let r = connect(client_io, identity.routing_key, &bad).await;
        assert!(r.is_err(), "client must not get an ack for a bad secret");
        assert!(
            server.await.unwrap().is_err(),
            "server must reject the bad secret"
        );
    }

    #[tokio::test]
    async fn e2e_tls_client_rejects_a_mismatched_routing_key() {
        let _ = env_logger::builder().is_test(true).try_init();
        // Server presents A's cert; the client pins B's (different) routing key.
        let a = Identity::generate();
        let b = Identity::generate();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move { accept(server_io, &a).await });

        let r = connect(client_io, b.routing_key, &b.secret).await;
        assert!(
            r.is_err(),
            "cert pinning must reject a mismatched routing key"
        );
        let _ = server.await;
    }
}
