//! TCP/TLS relay carrier server.
//!
//! A dumb byte-splicer, the TCP analogue of the UDP relay: sharers PARK
//! connections at their routing key; a client CONNECTs and the relay splices it
//! 1:1 to a parked sharer connection. The end-to-end TLS runs A<->B *through*
//! the splice, so the relay holds no keys and reads no plaintext (parity with
//! the UDP relay — see `lib.rs`).
//!
//! The sharer keeps a small pool of parked connections; the relay pops one per
//! client and blind-splices. No multiplexing (each client is its own splice),
//! no reverse-tunnel control channel — the sharer simply parks another
//! connection to refill the pool after one is consumed.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use relay_client::authz::{self, ISSUER_PUBKEY_LEN};
use relay_client::protocol::ROUTING_KEY_LEN;
use relay_client::tcp::{self, MAX_TOKEN_LEN, PREAMBLE_HEADER_LEN};

type RoutingKey = [u8; ROUTING_KEY_LEN];

/// How long a parked connection stays eligible. The sharer refreshes its pool
/// well within this; older ones are discarded on pop so a vanished sharer never
/// leaves the relay splicing a client into a dead socket.
pub const PARK_TTL: Duration = Duration::from_secs(90);
/// How long a CONNECT waits for a parked sharer connection to appear (covers the
/// brief window while the sharer refills its pool).
pub const CONNECT_WAIT: Duration = Duration::from_secs(3);
/// Cap on parked connections held per routing key.
pub const MAX_PARKED: usize = 32;
/// Time-box the preamble read so a silent connection can't pin a task.
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);

struct Parked {
    conn: TcpStream,
    at: Instant,
}

/// Shared state: parked sharer connections keyed by routing key, plus the
/// trusted capability-token issuer keys (empty = open mode).
pub struct TcpRelayState {
    parked: Mutex<HashMap<RoutingKey, VecDeque<Parked>>>,
    /// Trusted issuer public keys. **Empty means open mode** (any REGISTER is
    /// parked). When non-empty, a REGISTER must carry a capability token signed
    /// by one of these issuers and bound to its routing key — see [`authz`].
    /// (Key *possession* is proven end-to-end by the pinned TLS cert, not here:
    /// the relay blind-splices and never sees the E2E handshake.)
    issuer_keys: Vec<[u8; ISSUER_PUBKEY_LEN]>,
}

impl TcpRelayState {
    /// Open mode: any REGISTER is parked (no capability token required).
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            parked: Mutex::new(HashMap::new()),
            issuer_keys: Vec::new(),
        })
    }

    /// Require a capability token signed by one of `issuer_keys` and bound to
    /// the registering routing key. An empty set is open mode.
    pub fn with_issuer_keys(issuer_keys: Vec<[u8; ISSUER_PUBKEY_LEN]>) -> Arc<Self> {
        Arc::new(Self {
            parked: Mutex::new(HashMap::new()),
            issuer_keys,
        })
    }

    /// Whether the relay requires capability-token authorization.
    pub fn requires_authorization(&self) -> bool {
        !self.issuer_keys.is_empty()
    }

    fn park(&self, rk: RoutingKey, conn: TcpStream) {
        let mut map = self.parked.lock().unwrap();
        let q = map.entry(rk).or_default();
        while q.len() >= MAX_PARKED {
            q.pop_front(); // drop the oldest rather than grow without bound
        }
        q.push_back(Parked {
            conn,
            at: Instant::now(),
        });
    }

    /// Pop a *fresh* parked connection for `rk`, discarding any that expired.
    fn take_fresh(&self, rk: &RoutingKey) -> Option<TcpStream> {
        let mut map = self.parked.lock().unwrap();
        let q = map.get_mut(rk)?;
        while let Some(p) = q.pop_front() {
            if p.at.elapsed() < PARK_TTL {
                return Some(p.conn);
            }
            // else: stale — discard and keep looking
        }
        None
    }

    /// Number of routing keys with at least one parked connection (for tests).
    pub fn parked_key_count(&self) -> usize {
        self.parked.lock().unwrap().values().filter(|q| !q.is_empty()).count()
    }
}

/// Accept loop. Runs forever.
pub async fn serve_tcp(listener: TcpListener, state: Arc<TcpRelayState>) {
    match listener.local_addr() {
        Ok(a) => info!("tcp-relay listening on {a}"),
        Err(_) => info!("tcp-relay listening"),
    }
    loop {
        match listener.accept().await {
            Ok((conn, _addr)) => {
                let _ = conn.set_nodelay(true);
                tokio::spawn(handle_conn(conn, state.clone()));
            }
            Err(e) => warn!("tcp accept error: {e}"),
        }
    }
}

async fn handle_conn(mut conn: TcpStream, state: Arc<TcpRelayState>) {
    // Read the fixed header, then the (bounded) capability token.
    let mut header = [0u8; PREAMBLE_HEADER_LEN];
    match tokio::time::timeout(PREAMBLE_TIMEOUT, conn.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        _ => {
            debug!("tcp: header read failed/timed out");
            return;
        }
    }
    let Some((role, rk, token_len)) = tcp::parse_header(&header) else {
        debug!("tcp: bad preamble header");
        return;
    };
    if token_len > MAX_TOKEN_LEN {
        debug!("tcp: token_len {token_len} over cap");
        return;
    }
    let mut token = vec![0u8; token_len];
    if token_len > 0
        && !matches!(
            tokio::time::timeout(PREAMBLE_TIMEOUT, conn.read_exact(&mut token)).await,
            Ok(Ok(_))
        )
    {
        debug!("tcp: token read failed/timed out");
        return;
    }

    match role {
        tcp::role::REGISTER => {
            // Authorization: in gated mode the token must be valid and bound to
            // this routing key. Open mode (no issuer keys) parks any REGISTER.
            if !state.issuer_keys.is_empty()
                && let Err(e) = authz::verify_token(&token, &rk, &state.issuer_keys)
            {
                debug!(
                    "tcp: rejecting unauthorized REGISTER rk {:x?}: {:?}",
                    &rk[..4],
                    e
                );
                return;
            }
            debug!("tcp REGISTER rk {:x?}", &rk[..4]);
            // Park the connection; it lives in the queue until a client pops it.
            state.park(rk, conn);
        }
        tcp::role::CONNECT => {
            debug!("tcp CONNECT rk {:x?}", &rk[..4]);
            let deadline = Instant::now() + CONNECT_WAIT;
            let sharer = loop {
                if let Some(s) = state.take_fresh(&rk) {
                    break Some(s);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let Some(mut sharer) = sharer else {
                debug!("tcp: no parked sharer for rk {:x?}; dropping client", &rk[..4]);
                return;
            };
            // Blind 1:1 splice — the E2E TLS runs A<->B through here; the relay
            // sees only ciphertext.
            match tokio::io::copy_bidirectional(&mut conn, &mut sharer).await {
                Ok((c2s, s2c)) => debug!("tcp splice done rk {:x?}: c2s={c2s} s2c={s2c}", &rk[..4]),
                Err(e) => debug!("tcp splice ended rk {:x?}: {e}", &rk[..4]),
            }
        }
        other => warn!("tcp: unknown role {other:#x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn start_with(state: Arc<TcpRelayState>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(listener, state));
        addr
    }

    async fn start() -> (std::net::SocketAddr, Arc<TcpRelayState>) {
        let state = TcpRelayState::new();
        let addr = start_with(state.clone()).await;
        (addr, state)
    }

    /// Park briefly, then poll `parked_key_count` up to ~400 ms.
    async fn wait_parked(state: &Arc<TcpRelayState>, want: usize) -> usize {
        for _ in 0..40 {
            if state.parked_key_count() == want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        state.parked_key_count()
    }

    #[tokio::test]
    async fn splices_client_to_a_parked_sharer_both_directions() {
        let (addr, _state) = start().await;
        let rk = [0x42u8; ROUTING_KEY_LEN];

        // Sharer parks a connection.
        let mut sharer = TcpStream::connect(addr).await.unwrap();
        sharer
            .write_all(&tcp::build_preamble(tcp::role::REGISTER, &rk, &[]))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await; // let the relay park it

        // Client connects and is spliced.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&tcp::build_preamble(tcp::role::CONNECT, &rk, &[]))
            .await
            .unwrap();

        // client -> sharer
        client.write_all(b"hello-sharer").await.unwrap();
        let mut buf = [0u8; 12];
        sharer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-sharer");

        // sharer -> client
        sharer.write_all(b"hello-client").await.unwrap();
        let mut buf2 = [0u8; 12];
        client.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello-client");
    }

    #[tokio::test]
    async fn client_with_no_parked_sharer_is_dropped() {
        let (addr, _state) = start().await;
        let rk = [0x77u8; ROUTING_KEY_LEN];
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&tcp::build_preamble(tcp::role::CONNECT, &rk, &[]))
            .await
            .unwrap();
        // No sharer parked: the relay waits CONNECT_WAIT then closes → EOF.
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(CONNECT_WAIT + Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("relay must close the client, not hang")
            .unwrap();
        assert_eq!(n, 0, "client read must hit EOF (relay closed it)");
    }

    #[tokio::test]
    async fn bad_preamble_is_dropped() {
        let (addr, _state) = start().await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        // A full-length header with wrong magic — parses-and-rejects fast (a
        // short buffer would instead make read_exact wait for PREAMBLE_TIMEOUT).
        let mut bad = vec![0u8; PREAMBLE_HEADER_LEN];
        bad[..4].copy_from_slice(b"XXXX");
        c.write_all(&bad).await.unwrap();
        let mut buf = [0u8; 1];
        let res = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("relay must close on a bad preamble, not hang");
        match res {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("expected the connection closed, but read {n} bytes"),
        }
    }

    // --- Capability-token authorization ---

    #[tokio::test]
    async fn open_mode_parks_a_tokenless_register() {
        let (addr, state) = start().await;
        assert!(!state.requires_authorization());
        let rk = [0x11u8; ROUTING_KEY_LEN];
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&tcp::build_preamble(tcp::role::REGISTER, &rk, &[])).await.unwrap();
        assert_eq!(wait_parked(&state, 1).await, 1, "open mode parks a tokenless register");
    }

    #[tokio::test]
    async fn gated_mode_requires_a_valid_token() {
        let issuer = authz::IssuerKeyPair::generate().unwrap();
        let state = TcpRelayState::with_issuer_keys(vec![issuer.public_key()]);
        assert!(state.requires_authorization());
        let addr = start_with(state.clone()).await;
        let rk = [0x22u8; ROUTING_KEY_LEN];

        // Tokenless => refused, never parks.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&tcp::build_preamble(tcp::role::REGISTER, &rk, &[])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(state.parked_key_count(), 0, "gated relay must refuse a tokenless register");

        // Valid token bound to rk => parks.
        let token = issuer.issue(&rk);
        let mut s2 = TcpStream::connect(addr).await.unwrap();
        s2.write_all(&tcp::build_preamble(tcp::role::REGISTER, &rk, &token)).await.unwrap();
        assert_eq!(wait_parked(&state, 1).await, 1, "a valid token must be accepted");
    }

    #[tokio::test]
    async fn gated_mode_rejects_wrong_issuer_and_wrong_subject() {
        let issuer = authz::IssuerKeyPair::generate().unwrap();
        let rogue = authz::IssuerKeyPair::generate().unwrap();
        let state = TcpRelayState::with_issuer_keys(vec![issuer.public_key()]);
        let addr = start_with(state.clone()).await;
        let rk = [0x33u8; ROUTING_KEY_LEN];

        // Wrong issuer.
        let bad = rogue.issue(&rk);
        TcpStream::connect(addr)
            .await
            .unwrap()
            .write_all(&tcp::build_preamble(tcp::role::REGISTER, &rk, &bad))
            .await
            .unwrap();
        // Wrong subject: a valid token, but bound to a different routing key.
        let wrong_subject = issuer.issue(&[0x44u8; ROUTING_KEY_LEN]);
        TcpStream::connect(addr)
            .await
            .unwrap()
            .write_all(&tcp::build_preamble(tcp::role::REGISTER, &rk, &wrong_subject))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            state.parked_key_count(),
            0,
            "wrong-issuer and wrong-subject tokens must both be refused"
        );
    }
}
