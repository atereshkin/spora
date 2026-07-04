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

use relay_client::protocol::ROUTING_KEY_LEN;
use relay_client::tcp::{self, PREAMBLE_LEN};

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

/// Shared state: parked sharer connections keyed by routing key.
#[derive(Default)]
pub struct TcpRelayState {
    parked: Mutex<HashMap<RoutingKey, VecDeque<Parked>>>,
}

impl TcpRelayState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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
    let mut pre = [0u8; PREAMBLE_LEN];
    match tokio::time::timeout(PREAMBLE_TIMEOUT, conn.read_exact(&mut pre)).await {
        Ok(Ok(_)) => {}
        _ => {
            debug!("tcp: preamble read failed/timed out");
            return;
        }
    }
    let Some((role, rk)) = tcp::parse_preamble(&pre) else {
        debug!("tcp: bad preamble");
        return;
    };

    match role {
        tcp::role::REGISTER => {
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

    async fn start() -> (std::net::SocketAddr, Arc<TcpRelayState>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = TcpRelayState::new();
        tokio::spawn(serve_tcp(listener, state.clone()));
        (addr, state)
    }

    #[tokio::test]
    async fn splices_client_to_a_parked_sharer_both_directions() {
        let (addr, _state) = start().await;
        let rk = [0x42u8; ROUTING_KEY_LEN];

        // Sharer parks a connection.
        let mut sharer = TcpStream::connect(addr).await.unwrap();
        sharer
            .write_all(&tcp::build_preamble(tcp::role::REGISTER, &rk))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await; // let the relay park it

        // Client connects and is spliced.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&tcp::build_preamble(tcp::role::CONNECT, &rk))
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
            .write_all(&tcp::build_preamble(tcp::role::CONNECT, &rk))
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
        c.write_all(b"not-a-valid-preamble-xxxxx").await.unwrap();
        let mut buf = [0u8; 1];
        let res = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("relay must close on a bad preamble, not hang");
        // "Closed" is a clean EOF (Ok(0)) or a reset (Err) — the latter when the
        // relay closes with our extra unconsumed bytes still in its buffer.
        match res {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("expected the connection closed, but read {n} bytes"),
        }
    }
}
