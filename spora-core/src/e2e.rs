//! End-to-end QUIC between two peers, optionally via the dumb relay.
//!
//! A acts as a QUIC server bound to a local UDP socket; B acts as a QUIC
//! client. When B dials A through the relay, B's first Initial packet
//! carries `DCID = routing_key` (set via `ClientConfig::initial_dst_cid_provider`)
//! so the dumb forwarder can match B to a registered A.
//!
//! Cert pinning uses [`RoutingKeyVerifier`] on B's side. After the QUIC
//! handshake completes, B opens a bidi stream and sends the 16-byte
//! `secret`; A reads it, verifies, and accepts the session. The same bidi
//! stream is then reused as the [`SignalChannel`] for out-of-band
//! signaling. IP packets travel as QUIC datagrams.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, info};
use quinn::Connection;

use crate::identity::{Identity, RoutingKeyVerifier, ROUTING_KEY_LEN, SECRET_LEN};
use crate::signal::SignalChannel;
use crate::transport::quic::{build_transport_config, QuicPeerTransport};

const E2E_ALPN: &[u8] = b"spora-e2e/1";
const SERVER_NAME: &str = "spora.peer";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// An authenticated, established end-to-end QUIC session.
pub struct E2eSession {
    pub conn: Connection,
    pub transport: QuicPeerTransport,
    pub signal: SignalChannel,
}

// ---------- Server (A) ----------

/// Build a quinn server `Endpoint` for A, bound to `socket`. The identity's
/// cert+key bytes are cloned into the rustls config; `identity` can still be
/// used afterwards (e.g. for direct-upgrade attempts).
pub fn server_endpoint(
    socket: std::net::UdpSocket,
    identity: &Identity,
) -> Result<quinn::Endpoint, String> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert_der()], identity.key_der())
        .map_err(|e| format!("server TLS config: {}", e))?;
    server_crypto.alpn_protocols = vec![E2E_ALPN.to_vec()];

    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(|e| format!("QUIC server crypto: {}", e))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
    server_config.transport_config(Arc::new(build_transport_config()));

    let runtime = quinn::default_runtime().ok_or_else(|| "no async runtime".to_string())?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .map_err(|e| format!("endpoint creation: {}", e))?;
    Ok(endpoint)
}

/// Wait for the next incoming QUIC connection on `endpoint`, complete the
/// handshake, accept the auth bidi stream, verify `expected_secret`, and
/// return an `E2eSession`. Returns `None` if the endpoint shut down. Returns
/// `Err(...)` (and closes the connection) on handshake/auth failure.
pub async fn accept_one(
    endpoint: &quinn::Endpoint,
    expected_secret: &[u8; SECRET_LEN],
) -> Option<Result<E2eSession, String>> {
    let incoming = endpoint.accept().await?;
    let conn_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await;
    let conn = match conn_result {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Some(Err(format!("QUIC handshake failed: {}", e))),
        Err(_) => return Some(Err("QUIC handshake timed out".into())),
    };
    let peer = conn.remote_address();
    debug!("e2e accept: handshake from {} complete", peer);

    let auth_result = tokio::time::timeout(AUTH_TIMEOUT, async {
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| format!("accept_bi: {}", e))?;
        let mut got = [0u8; SECRET_LEN];
        recv.read_exact(&mut got)
            .await
            .map_err(|e| format!("read secret: {}", e))?;
        Ok::<_, String>((send, recv, got))
    })
    .await;

    let (send, recv, presented) = match auth_result {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            conn.close(1u32.into(), b"auth-error");
            return Some(Err(format!("auth from {}: {}", peer, e)));
        }
        Err(_) => {
            conn.close(1u32.into(), b"auth-timeout");
            return Some(Err(format!("auth from {} timed out", peer)));
        }
    };
    if presented != *expected_secret {
        conn.close(1u32.into(), b"bad-secret");
        return Some(Err(format!("auth from {}: bad secret", peer)));
    }
    info!("e2e accept: authenticated peer {}", peer);

    let transport = QuicPeerTransport::new(conn.clone());
    let signal = SignalChannel::new(send, recv);
    Some(Ok(E2eSession {
        conn,
        transport,
        signal,
    }))
}

// ---------- Client (B) ----------

/// Build a quinn client `Endpoint` for B, bound to `socket`. The
/// `ClientConfig` pins certs to `routing_key` and overrides the initial
/// DCID to the same value so the dumb relay can route the first Initial.
pub fn client_endpoint(
    socket: std::net::UdpSocket,
    routing_key: [u8; ROUTING_KEY_LEN],
) -> Result<quinn::Endpoint, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(RoutingKeyVerifier::new(routing_key, provider.clone()));

    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("client TLS version: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![E2E_ALPN.to_vec()];

    let quic_client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(|e| format!("QUIC client crypto: {}", e))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));
    client_config.transport_config(Arc::new(build_transport_config()));
    let rk_bytes = routing_key.to_vec();
    client_config.initial_dst_cid_provider(Arc::new(move || {
        quinn::ConnectionId::new(&rk_bytes)
    }));

    let runtime = quinn::default_runtime().ok_or_else(|| "no async runtime".to_string())?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )
    .map_err(|e| format!("endpoint creation: {}", e))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Open a QUIC connection to `peer_addr` (a relay address for the relay-via
/// path, or the peer's direct address after STUN), open a bidi stream, send
/// the secret, and return an `E2eSession`.
pub async fn client_connect(
    endpoint: &quinn::Endpoint,
    peer_addr: SocketAddr,
    secret: &[u8; SECRET_LEN],
) -> Result<E2eSession, String> {
    let connecting = endpoint
        .connect(peer_addr, SERVER_NAME)
        .map_err(|e| format!("QUIC connect setup: {}", e))?;
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .map_err(|_| "QUIC client handshake timed out".to_string())?
        .map_err(|e| format!("QUIC handshake: {}", e))?;
    debug!(
        "e2e client: handshake via {} complete (remote={})",
        peer_addr,
        conn.remote_address()
    );

    let auth = tokio::time::timeout(AUTH_TIMEOUT, async {
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open_bi: {}", e))?;
        send.write_all(secret)
            .await
            .map_err(|e| format!("write secret: {}", e))?;
        Ok::<_, String>((send, recv))
    })
    .await;
    let (send, recv) = match auth {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            conn.close(1u32.into(), b"auth-error");
            return Err(format!("auth: {}", e));
        }
        Err(_) => {
            conn.close(1u32.into(), b"auth-timeout");
            return Err("auth send timed out".into());
        }
    };

    let transport = QuicPeerTransport::new(conn.clone());
    let signal = SignalChannel::new(send, recv);
    Ok(E2eSession {
        conn,
        transport,
        signal,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::UdpSocket as TokioUdp;

    use super::*;

    /// Start the dumb relay in-process. Returns its addr and a handle that
    /// keeps the serve task alive.
    async fn start_relay() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let h = tokio::spawn(relay::serve(sock, relay::State::default()));
        (addr, h)
    }

    /// Build A's socket, share the fd with a register loop, return
    /// (std_socket_for_quinn, register_task_handle).
    fn split_a_socket(
        std_sock: std::net::UdpSocket,
        relay_addr: SocketAddr,
        routing_key: [u8; ROUTING_KEY_LEN],
    ) -> (std::net::UdpSocket, tokio::task::JoinHandle<()>) {
        let clone = std_sock.try_clone().expect("try_clone");
        clone.set_nonblocking(true).unwrap();
        let tokio_clone = TokioUdp::from_std(clone).unwrap();
        let h = tokio::spawn(relay_client::register_loop(
            Arc::new(tokio_clone),
            relay_addr,
            routing_key,
            Duration::from_millis(50), // tight for tests
        ));
        (std_sock, h)
    }

    #[tokio::test]
    async fn e2e_session_via_dumb_relay() {
        let _ = env_logger::builder().is_test(true).try_init();
        let (relay_addr, _relay_h) = start_relay().await;

        // A's side: identity, socket, register loop, server endpoint.
        let identity = Identity::generate();
        let routing_key = identity.routing_key;
        let secret = identity.secret;

        let a_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        a_std.set_nonblocking(true).unwrap();
        let (a_for_quinn, _reg_h) = split_a_socket(a_std, relay_addr, routing_key);
        let a_endpoint = server_endpoint(a_for_quinn, &identity).unwrap();

        // Give A's first REGISTER a moment to land on the relay.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // B's side.
        let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b_std.set_nonblocking(true).unwrap();
        let b_endpoint = client_endpoint(b_std, routing_key).unwrap();

        // Drive A's accept and B's connect concurrently.
        let accept_task = tokio::spawn(async move {
            accept_one(&a_endpoint, &secret).await.unwrap().unwrap()
        });
        let mut b_session = client_connect(&b_endpoint, relay_addr, &secret).await.unwrap();
        let mut a_session = accept_task.await.unwrap();

        // Verify IP datagrams round-trip via QuicPeerTransport.
        let ip_pkt = vec![0x45, 0x00, 0x00, 0x14, 0xCA, 0xFE, 0xBA, 0xBE];
        b_session.transport.send(ip_pkt.clone()).await.unwrap();
        let recv = tokio::time::timeout(Duration::from_secs(2), a_session.transport.next())
            .await
            .expect("A should receive B's datagram")
            .unwrap()
            .unwrap();
        assert_eq!(recv, ip_pkt);

        // Reverse direction.
        let ip_pkt2 = vec![0x45, 0x00, 0x00, 0x14, 0xDE, 0xAD, 0xBE, 0xEF];
        a_session.transport.send(ip_pkt2.clone()).await.unwrap();
        let recv = tokio::time::timeout(Duration::from_secs(2), b_session.transport.next())
            .await
            .expect("B should receive A's datagram")
            .unwrap()
            .unwrap();
        assert_eq!(recv, ip_pkt2);

        // Verify signaling round-trips via the bidi stream.
        b_session.signal.send_signal(b"hello-A").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), a_session.signal.recv_signal())
            .await
            .expect("A should receive signal")
            .expect("signal not None");
        assert_eq!(got, b"hello-A");

        a_session.signal.send_signal(b"hello-B").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), b_session.signal.recv_signal())
            .await
            .expect("B should receive signal")
            .expect("signal not None");
        assert_eq!(got, b"hello-B");
    }

    #[tokio::test]
    async fn e2e_client_rejects_unregistered_routing_key() {
        let _ = env_logger::builder().is_test(true).try_init();
        let (relay_addr, _relay_h) = start_relay().await;

        // No A registered. B tries to connect with a routing key the relay
        // doesn't know — the relay drops the Initial, so B's handshake
        // times out.
        let identity = Identity::generate();

        let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b_std.set_nonblocking(true).unwrap();
        let b_endpoint = client_endpoint(b_std, identity.routing_key).unwrap();

        let result = client_connect(&b_endpoint, relay_addr, &identity.secret).await;
        assert!(result.is_err(), "should fail when no A is registered");
    }

    #[tokio::test]
    async fn e2e_server_rejects_bad_secret() {
        let _ = env_logger::builder().is_test(true).try_init();
        let (relay_addr, _relay_h) = start_relay().await;

        let identity = Identity::generate();
        let routing_key = identity.routing_key;
        let secret = identity.secret;

        let a_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        a_std.set_nonblocking(true).unwrap();
        let (a_for_quinn, _reg_h) = split_a_socket(a_std, relay_addr, routing_key);
        let a_endpoint = server_endpoint(a_for_quinn, &identity).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Wrong secret.
        let mut bad_secret = secret;
        bad_secret[0] ^= 0xFF;

        let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b_std.set_nonblocking(true).unwrap();
        let b_endpoint = client_endpoint(b_std, routing_key).unwrap();

        let accept_task =
            tokio::spawn(async move { accept_one(&a_endpoint, &secret).await.unwrap() });
        // B's handshake succeeds; sending the bad secret over the stream
        // succeeds too (it's a one-way write). The auth failure happens on
        // A's side. So client_connect may succeed; A's accept returns Err.
        let _b_result = client_connect(&b_endpoint, relay_addr, &bad_secret).await;
        let a_result = tokio::time::timeout(Duration::from_secs(3), accept_task)
            .await
            .expect("accept_one should finish")
            .unwrap();
        let err = match a_result {
            Ok(_) => panic!("A should reject bad secret"),
            Err(e) => e,
        };
        assert!(err.contains("bad secret"), "got: {}", err);
    }
}
