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
use subtle::ConstantTimeEq;

use crate::identity::{Identity, RoutingKeyVerifier, ROUTING_KEY_LEN, SECRET_LEN};
use crate::signal::SignalChannel;
use crate::transport::quic::{build_transport_config, QuicPeerTransport};
use crate::Timings;

// Present as HTTP/3 ("h3") rather than a product-unique token: the ALPN in the
// ClientHello is derivable from a QUIC Initial, so a project-specific value
// positively identifies Spora. Both ends still agree on this exact byte string,
// so negotiation succeeds — no HTTP/3 semantics are involved. Authentication is
// the cert pinning (RoutingKeyVerifier), so ALPN/SNI carry no security weight.
const E2E_ALPN: &[u8] = b"h3";
// rustls verification name for the (fingerprint-pinned) connection. SNI is
// suppressed on the wire (`enable_sni = false`, see `client_endpoint`), so this
// product-specific name never reaches the ClientHello; it survives only as the
// name our custom verifier ignores.
const SERVER_NAME: &str = "spora.peer";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
/// Byte the sharer writes back on the auth stream once it has accepted the
/// client's secret. The client waits for it so a wrong/expired secret surfaces
/// as a connect error instead of an `Ok` that silently reconnect-loops. See
/// `client_connect` / `authenticate_incoming`.
const AUTH_ACK: u8 = 0x01;

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
    timings: &Timings,
) -> Result<quinn::Endpoint, String> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert_der()], identity.key_der())
        .map_err(|e| format!("server TLS config: {}", e))?;
    server_crypto.alpn_protocols = vec![E2E_ALPN.to_vec()];

    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(|e| format!("QUIC server crypto: {}", e))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
    server_config.transport_config(Arc::new(build_transport_config(
        timings.quic_idle_timeout,
        timings.quic_keep_alive,
    )));

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
    send_ack: bool,
) -> Option<Result<E2eSession, String>> {
    let incoming = endpoint.accept().await?;
    Some(authenticate_incoming(incoming, expected_secret, send_ack).await)
}

/// Drive one already-accepted `Incoming` through the QUIC handshake and the
/// secret-auth step. Split out from `accept_one` so the share loop can run this
/// concurrently per connection: a peer that completes the handshake but stalls
/// the secret read (an attacker who knows the routing key but not the secret)
/// only ties up its own task until `AUTH_TIMEOUT`, instead of blocking the
/// serial accept loop and starving legitimate peers.
///
/// `send_ack` writes the [`AUTH_ACK`] byte back once the secret verifies, so the
/// initiator can tell acceptance from a silent close. Used on the relay-via path
/// (where a bad/expired token must surface as a connect error). It is left off
/// for the direct-upgrade path: the secret is already proven good there, the ack
/// would add nothing, and waiting on a post-handshake reverse-direction byte over
/// a freshly-punched NAT only makes the best-effort upgrade fail more often.
pub async fn authenticate_incoming(
    incoming: quinn::Incoming,
    expected_secret: &[u8; SECRET_LEN],
    send_ack: bool,
) -> Result<E2eSession, String> {
    let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(format!("QUIC handshake failed: {}", e)),
        Err(_) => return Err("QUIC handshake timed out".into()),
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

    let (mut send, recv, presented) = match auth_result {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            conn.close(1u32.into(), b"auth-error");
            return Err(format!("auth from {}: {}", peer, e));
        }
        Err(_) => {
            conn.close(1u32.into(), b"auth-timeout");
            return Err(format!("auth from {} timed out", peer));
        }
    };
    // Constant-time compare so the secret can't be recovered by timing the
    // reply (both are fixed 16-byte arrays).
    if !bool::from(presented.ct_eq(expected_secret)) {
        conn.close(1u32.into(), b"bad-secret");
        return Err(format!("auth from {}: bad secret", peer));
    }
    // Acknowledge so the client knows the secret was accepted. A rejected
    // client gets the connection closed above instead of this byte, which is
    // how the client distinguishes a bad token from a healthy session. Only on
    // the relay path (see `send_ack`).
    if send_ack
        && let Err(e) = send.write_all(&[AUTH_ACK]).await
    {
        conn.close(1u32.into(), b"ack-failed");
        return Err(format!("auth ack to {}: {}", peer, e));
    }
    info!("e2e accept: authenticated peer {}", peer);

    let transport = QuicPeerTransport::new(conn.clone());
    let signal = SignalChannel::new(send, recv);
    Ok(E2eSession {
        conn,
        transport,
        signal,
    })
}

// ---------- Client (B) ----------

/// Build a quinn client `Endpoint` for B, bound to `socket`. The
/// `ClientConfig` pins certs to `routing_key` and overrides the initial
/// DCID to the same value so the dumb relay can route the first Initial.
pub fn client_endpoint(
    socket: std::net::UdpSocket,
    routing_key: [u8; ROUTING_KEY_LEN],
    timings: &Timings,
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
    // Don't advertise SNI: pinning is by routing key (cert fingerprint), so the
    // server name has no security value, and a fixed product-specific SNI would
    // be a global on-wire selector. (Absent SNI is itself a weak signal; a
    // realistic per-deployment SNI is a later masquerade option.)
    client_crypto.enable_sni = false;

    let quic_client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(|e| format!("QUIC client crypto: {}", e))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));
    client_config.transport_config(Arc::new(build_transport_config(
        timings.quic_idle_timeout,
        timings.quic_keep_alive,
    )));
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
    expect_ack: bool,
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
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open_bi: {}", e))?;
        send.write_all(secret)
            .await
            .map_err(|e| format!("write secret: {}", e))?;
        // On the relay path, wait for the sharer's accept ack. A wrong/expired
        // secret makes the sharer close the connection instead of acking, so
        // this fails fast and the auth failure propagates to the caller —
        // without it a bad token returns Ok and the tunnel silently
        // reconnect-loops forever. The direct-upgrade path skips this (see
        // `expect_ack` / `authenticate_incoming`).
        if expect_ack {
            let mut ack = [0u8; 1];
            recv.read_exact(&mut ack)
                .await
                .map_err(|e| format!("auth not acked (bad/expired secret?): {}", e))?;
            if ack[0] != AUTH_ACK {
                return Err(format!("unexpected auth ack byte {:#x}", ack[0]));
            }
        }
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
        identity: &Identity,
    ) -> (std::net::UdpSocket, tokio::task::JoinHandle<()>) {
        let clone = std_sock.try_clone().expect("try_clone");
        clone.set_nonblocking(true).unwrap();
        let tokio_clone = TokioUdp::from_std(clone).unwrap();
        let signer = relay_client::protocol::RegisterSigner::new(
            &identity.cert_der_bytes,
            &identity.key_der_bytes,
        )
        .expect("register signer");
        let h = tokio::spawn(relay_client::register_loop(
            Arc::new(tokio_clone),
            vec![relay_addr],
            Duration::from_millis(50), // tight for tests
            signer,
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
        let (a_for_quinn, _reg_h) = split_a_socket(a_std, relay_addr, &identity);
        let a_endpoint = server_endpoint(a_for_quinn, &identity, &Timings::default()).unwrap();

        // Give A's first REGISTER a moment to land on the relay.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // B's side.
        let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b_std.set_nonblocking(true).unwrap();
        let b_endpoint = client_endpoint(b_std, routing_key, &Timings::default()).unwrap();

        // Drive A's accept and B's connect concurrently.
        let accept_task = tokio::spawn(async move {
            accept_one(&a_endpoint, &secret, true).await.unwrap().unwrap()
        });
        let mut b_session = client_connect(&b_endpoint, relay_addr, &secret, true)
            .await
            .unwrap();
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
        let b_endpoint = client_endpoint(b_std, identity.routing_key, &Timings::default()).unwrap();

        let result = client_connect(&b_endpoint, relay_addr, &identity.secret, true).await;
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
        let (a_for_quinn, _reg_h) = split_a_socket(a_std, relay_addr, &identity);
        let a_endpoint = server_endpoint(a_for_quinn, &identity, &Timings::default()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Wrong secret.
        let mut bad_secret = secret;
        bad_secret[0] ^= 0xFF;

        let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b_std.set_nonblocking(true).unwrap();
        let b_endpoint = client_endpoint(b_std, routing_key, &Timings::default()).unwrap();

        let accept_task =
            tokio::spawn(async move { accept_one(&a_endpoint, &secret, true).await.unwrap() });
        // B's handshake succeeds and the bad-secret write goes through, but A
        // rejects it and closes the connection without the accept ack. B waits
        // for that ack, so client_connect now returns Err instead of an Ok that
        // would hand the caller a tunnel which silently reconnect-loops forever.
        let b_result = client_connect(&b_endpoint, relay_addr, &bad_secret, true).await;
        assert!(
            b_result.is_err(),
            "B must surface a bad secret as an error, not Ok"
        );

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

    /// Accept any server cert — only for the raw stalling client below.
    #[derive(Debug)]
    struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _e: &rustls::pki_types::CertificateDer<'_>,
            _i: &[rustls::pki_types::CertificateDer<'_>],
            _s: &rustls::pki_types::ServerName<'_>,
            _o: &[u8],
            _n: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &rustls::pki_types::CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Connect to `addr` and complete the handshake, but never open the auth
    /// stream — a peer that knows enough to handshake but not the secret. Uses a
    /// fresh random DCID (unlike `client_endpoint`'s relay-routing fixed DCID),
    /// so it doesn't collide with the legit client on the direct path.
    async fn connect_and_stall(addr: SocketAddr) -> quinn::Connection {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cc = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth();
        cc.alpn_protocols = vec![E2E_ALPN.to_vec()];
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(cc).unwrap(),
        )));
        let conn = ep
            .connect(addr, SERVER_NAME)
            .unwrap()
            .await
            .expect("stalling client handshake");
        Box::leak(Box::new(ep)); // keep the endpoint (and thus conn) alive
        conn
    }

    // accept_one blocks in endpoint.accept() with no deadline of its own, so a
    // caller that has no other source of progress (the direct-upgrade responder,
    // whose initiator may never dial) must time-box it — otherwise it hangs for
    // the whole session. This guards the premise of that timeout.
    #[tokio::test]
    async fn accept_one_blocks_without_a_peer_and_must_be_timed_out() {
        let identity = Identity::generate();
        let s_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s_std.set_nonblocking(true).unwrap();
        let server_ep = server_endpoint(s_std, &identity, &Timings::default()).unwrap();

        let r = tokio::time::timeout(
            Duration::from_millis(200),
            accept_one(&server_ep, &identity.secret, false),
        )
        .await;
        assert!(
            r.is_err(),
            "accept_one must block (and so needs a caller timeout) when no peer dials"
        );
    }

    // A peer that completes the QUIC handshake but stalls the secret read (an
    // attacker who knows only the public routing key) must not block a
    // legitimate peer from authenticating. Mirrors run_share_loop's structure:
    // accept connections and authenticate each in its own task. Run over the
    // direct path so the relay's flow logic doesn't enter into it.
    #[tokio::test]
    async fn stalled_auth_does_not_block_other_peers() {
        let _ = env_logger::builder().is_test(true).try_init();
        let identity = Identity::generate();
        let secret = identity.secret;
        let rk = identity.routing_key;

        let s_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s_std.set_nonblocking(true).unwrap();
        let s_addr = s_std.local_addr().unwrap();
        let server_ep = server_endpoint(s_std, &identity, &Timings::default()).unwrap();

        // Concurrent accept loop (as in run_share_loop).
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let accept_ep = server_ep.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accept_ep.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(s) = authenticate_incoming(incoming, &secret, false).await {
                        let _ = tx.send(s);
                    }
                });
            }
        });

        // Attacker finishes the handshake first, then deliberately stalls.
        let _attacker = connect_and_stall(s_addr).await;

        // The legit peer must connect AND be delivered to the share side
        // promptly, well within AUTH_TIMEOUT. With a serial accept loop the
        // server can't even drive B's handshake until the attacker's auth times
        // out (AUTH_TIMEOUT), so this whole block would exceed the deadline.
        let legit = tokio::time::timeout(Duration::from_secs(3), async {
            let b_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            b_std.set_nonblocking(true).unwrap();
            let b_ep = client_endpoint(b_std, rk, &Timings::default()).unwrap();
            let _b = client_connect(&b_ep, s_addr, &secret, false)
                .await
                .expect("legit client should authenticate");
            rx.recv().await
        })
        .await;
        assert!(
            matches!(legit, Ok(Some(_))),
            "legit peer must authenticate quickly despite the stalled attacker"
        );
    }
}
