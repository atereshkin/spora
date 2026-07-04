//! In-process wan services, all running on one host thread inside the wan
//! namespace: the real relay (`relay::serve`), a minimal STUN responder,
//! UDP/TCP echo, UDP "whoami" responders (reply with the observed source
//! `ip:port` as ASCII — lets tests verify NAT mapping behavior directly),
//! and bulk TCP source/sink services for one-directional throughput tests.
//!
//! Implementation notes:
//! - `start_wan(&wan_ns, relay_state)` spawns ONE host via `Netns::spawn_host`;
//!   inside it, everything binds on [`crate::WAN_SERVICES_IP`] at the
//!   [`crate::RELAY_PORT`]/[`crate::STUN_PORT`]/[`crate::ECHO_UDP_PORT`]/
//!   [`crate::WHOAMI_UDP_PORT`]/[`WHOAMI2_UDP_PORT`]/[`crate::ECHO_TCP_PORT`]/
//!   [`TCP_SOURCE_PORT`]/[`TCP_SINK_PORT`] constants, each service runs as a
//!   tokio task, and readiness (or a bind error) is reported back through a
//!   std mpsc channel that `start_wan` blocks on — bind errors are returned,
//!   not logged-and-lost.
//! - `relay_state` is a FACTORY (`Fn() -> relay::State`), not a value:
//!   `restart_relay` calls it again for a fresh `State`, so scenarios with
//!   scaled-down relay timeouts keep them across restarts.
//! - Relay restart: `WanHandle::restart_relay()` sends a command into the
//!   host; the relay task is aborted and awaited (dropping its socket), a
//!   fresh socket is bound on the same addr and `relay::serve` restarted with
//!   a fresh `State` (registrations and flows are lost — that's the point).
//!   `stop_relay()` just kills it.
//! - STUN responder: RFC 5389 Binding Request only. Parse: 20-byte header,
//!   type 0x0001, magic cookie 0x2112A442 at offset 4, 12-byte transaction
//!   id. Reply: type 0x0101, one attribute XOR-MAPPED-ADDRESS (0x0020):
//!   family 0x01 (length 8, addr ^ cookie) for v4 sources, family 0x02
//!   (length 20, addr ^ cookie‖txid) for v6 sources. (`stunclient` 0.4
//!   sends standard binding requests on both families.)
//! - Echo UDP: recv → send_to(source). Echo TCP: accept loop, per-conn
//!   `tokio::io::copy` back into the writer (echoes whatever arrives —
//!   used for bulk-throughput assertions). Whoami UDP: recv →
//!   `send_to(format!("{src}"), src)`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use crate::netns::{HostHandle, Netns};
use crate::{
    ECHO_TCP_PORT, ECHO_UDP_PORT, RELAY_PORT, STUN_PORT, WAN_SERVICES_IP, WAN_SERVICES_IP6,
    WHOAMI_UDP_PORT,
};

/// Second whoami responder: NAT mapping comparisons need two distinct wan
/// destination endpoints queried from one client socket.
pub const WHOAMI2_UDP_PORT: u16 = 7003;
/// Bulk TCP source: reads an 8-byte big-endian byte count, sends exactly
/// that many pattern bytes, closes. Download-direction throughput tests use
/// it so bulk data crosses the tunnel in only one direction (unlike the TCP
/// echo, which doubles every byte).
pub const TCP_SOURCE_PORT: u16 = 7004;
/// Bulk TCP sink: counts bytes until EOF, replies with the count as 8 bytes
/// big-endian, closes. Upload-direction counterpart of [`TCP_SOURCE_PORT`].
pub const TCP_SINK_PORT: u16 = 7005;

const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

enum Cmd {
    RestartRelay(std::sync::mpsc::Sender<Result<(), String>>),
    StopRelay(std::sync::mpsc::Sender<Result<(), String>>),
}

pub struct WanHandle {
    cmds: tokio::sync::mpsc::UnboundedSender<Cmd>,
    relay_addr: SocketAddr,
    dual_stack: bool,
    host: HostHandle,
}

impl WanHandle {
    pub fn restart_relay(&self) -> Result<(), String> {
        self.relay_cmd(Cmd::RestartRelay)
    }

    pub fn stop_relay(&self) -> Result<(), String> {
        self.relay_cmd(Cmd::StopRelay)
    }

    fn relay_cmd(
        &self,
        make: fn(std::sync::mpsc::Sender<Result<(), String>>) -> Cmd,
    ) -> Result<(), String> {
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        self.cmds
            .send(make(ack_tx))
            .map_err(|_| "wan services host is gone".to_string())?;
        ack_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|e| format!("relay command was not acknowledged: {e}"))?
    }

    pub fn relay_addr(&self) -> std::net::SocketAddr {
        self.relay_addr
    }

    /// The TCP/TLS relay carrier's endpoint (`WAN_SERVICES_IP:RELAY_PORT`, TCP).
    /// Started alongside the UDP relay by [`start_wan`]; used by the perf suite
    /// to A/B the two carriers.
    pub fn tcp_relay_addr(&self) -> std::net::SocketAddr {
        let ip: Ipv4Addr = WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses");
        SocketAddr::from((ip, RELAY_PORT))
    }

    /// The relay's IPv6 endpoint. Only meaningful under [`start_wan_dual`]
    /// (one dual-stack relay socket serves both families — peers reach it
    /// via either service address).
    pub fn relay_addr6(&self) -> Result<SocketAddr, String> {
        if !self.dual_stack {
            return Err("wan services were started v4-only (use start_wan_dual)".into());
        }
        let ip: Ipv6Addr = WAN_SERVICES_IP6.parse().expect("WAN_SERVICES_IP6 parses");
        Ok(SocketAddr::from((ip, RELAY_PORT)))
    }

    pub fn stun_server(&self) -> String {
        format!("{WAN_SERVICES_IP}:{STUN_PORT}")
    }

    /// The STUN responder's IPv6 endpoint (bracketed, ready for
    /// `Config.stun_server`). Only bound under [`start_wan_dual`].
    pub fn stun_server6(&self) -> Result<String, String> {
        if !self.dual_stack {
            return Err("wan services were started v4-only (use start_wan_dual)".into());
        }
        Ok(format!("[{WAN_SERVICES_IP6}]:{STUN_PORT}"))
    }

    /// CPU time consumed by the wan-services host thread (relay + all
    /// service tasks — they share one current-thread runtime). Perf-suite
    /// report metric. See [`HostHandle::cpu_time`].
    pub fn cpu_time(&self) -> Option<Duration> {
        self.host.cpu_time()
    }
}

/// Start all wan services; blocks until they are bound and ready.
/// `relay_state` builds the relay's `State` — once at startup and once per
/// [`WanHandle::restart_relay`] — letting scenarios pass scaled-down relay
/// timeouts that survive restarts.
pub fn start_wan<F>(wan: &Netns, relay_state: F) -> Result<WanHandle, String>
where
    F: Fn() -> relay::State + Send + 'static,
{
    start_wan_inner(wan, relay_state, false)
}

/// Like [`start_wan`], but for a dual-stack topology (`TopologySpec::ipv6`):
/// every service also binds on [`WAN_SERVICES_IP6`], and the relay runs on
/// ONE dual-stack wildcard socket — the production shape — so a single flow
/// table serves v4, v6, and mixed-family pairings. (The topology pins the
/// wildcard socket's source addresses to the service IPs via per-leg `src`
/// route hints.)
pub fn start_wan_dual<F>(wan: &Netns, relay_state: F) -> Result<WanHandle, String>
where
    F: Fn() -> relay::State + Send + 'static,
{
    start_wan_inner(wan, relay_state, true)
}

fn start_wan_inner<F>(wan: &Netns, relay_state: F, dual_stack: bool) -> Result<WanHandle, String>
where
    F: Fn() -> relay::State + Send + 'static,
{
    let svc_ip: IpAddr = WAN_SERVICES_IP.parse::<Ipv4Addr>().expect("WAN_SERVICES_IP parses").into();
    let relay_addr = SocketAddr::new(svc_ip, RELAY_PORT);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();

    let host = wan.spawn_host("wan-services", move |_cancel| async move {
        let bound = async {
            let mut ips: Vec<IpAddr> = vec![svc_ip];
            if dual_stack {
                ips.push(WAN_SERVICES_IP6.parse::<Ipv6Addr>().expect("WAN_SERVICES_IP6 parses").into());
            }
            for ip in ips {
                tokio::spawn(stun_responder(bind_udp(ip, STUN_PORT).await?));
                tokio::spawn(udp_echo(bind_udp(ip, ECHO_UDP_PORT).await?));
                tokio::spawn(udp_whoami(bind_udp(ip, WHOAMI_UDP_PORT).await?));
                tokio::spawn(udp_whoami(bind_udp(ip, WHOAMI2_UDP_PORT).await?));
                tokio::spawn(tcp_echo(bind_tcp(ip, ECHO_TCP_PORT).await?));
                tokio::spawn(tcp_source(bind_tcp(ip, TCP_SOURCE_PORT).await?));
                tokio::spawn(tcp_sink(bind_tcp(ip, TCP_SINK_PORT).await?));
            }
            // TCP/TLS relay carrier, alongside the UDP relay (same port, TCP).
            tokio::spawn(relay::tcp::serve_tcp(
                bind_tcp(svc_ip, RELAY_PORT).await?,
                relay::tcp::TcpRelayState::new(),
            ));
            bind_relay(svc_ip, dual_stack).await
        }
        .await;
        let relay_sock = match bound {
            Ok(sock) => sock,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        let mut relay_task: Option<JoinHandle<()>> =
            Some(tokio::spawn(relay::serve(relay_sock, relay_state())));
        let _ = ready_tx.send(Ok(()));

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                Cmd::StopRelay(ack) => {
                    stop_task(&mut relay_task).await;
                    let _ = ack.send(Ok(()));
                }
                Cmd::RestartRelay(ack) => {
                    stop_task(&mut relay_task).await;
                    let result = match bind_relay(svc_ip, dual_stack).await {
                        Ok(sock) => {
                            relay_task = Some(tokio::spawn(relay::serve(sock, relay_state())));
                            Ok(())
                        }
                        Err(e) => Err(format!("relay restart: {e}")),
                    };
                    let _ = ack.send(result);
                }
            }
        }
    })?;

    match ready_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => Ok(WanHandle { cmds: cmd_tx, relay_addr, dual_stack, host }),
        Ok(Err(e)) => Err(format!("wan services: {e}")),
        Err(e) => Err(format!("wan services never became ready: {e}")),
    }
}

/// The relay socket: v4-only binds the service IP directly; dual-stack binds
/// the `::` wildcard with IPV6_V6ONLY off (one socket, both families, v4
/// peers appearing v4-mapped — exactly what the deployed relay binary does).
async fn bind_relay(svc_ip: IpAddr, dual_stack: bool) -> Result<UdpSocket, String> {
    if !dual_stack {
        return bind_udp(svc_ip, RELAY_PORT).await;
    }
    let bind = SocketAddr::from((Ipv6Addr::UNSPECIFIED, RELAY_PORT));
    let make = || -> std::io::Result<UdpSocket> {
        let sock = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;
        sock.set_only_v6(false)?;
        sock.set_nonblocking(true)?;
        sock.bind(&bind.into())?;
        UdpSocket::from_std(sock.into())
    };
    make().map_err(|e| format!("bind relay dual-stack {bind}: {e}"))
}

async fn bind_udp(ip: IpAddr, port: u16) -> Result<UdpSocket, String> {
    UdpSocket::bind((ip, port))
        .await
        .map_err(|e| format!("bind udp {ip}:{port}: {e}"))
}

async fn bind_tcp(ip: IpAddr, port: u16) -> Result<TcpListener, String> {
    TcpListener::bind((ip, port))
        .await
        .map_err(|e| format!("bind tcp {ip}:{port}: {e}"))
}

/// Abort the relay task and *await* it, guaranteeing its socket is dropped
/// (and the port free) before any rebind.
async fn stop_task(task: &mut Option<JoinHandle<()>>) {
    if let Some(t) = task.take() {
        t.abort();
        let _ = t.await;
    }
}

async fn udp_echo(sock: UdpSocket) {
    let mut buf = vec![0u8; 65536];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, src)) => {
                let _ = sock.send_to(&buf[..n], src).await;
            }
            Err(e) => log::warn!("udp echo recv: {e}"),
        }
    }
}

async fn udp_whoami(sock: UdpSocket) {
    let mut buf = [0u8; 2048];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((_, src)) => {
                let _ = sock.send_to(format!("{src}").as_bytes(), src).await;
            }
            Err(e) => log::warn!("udp whoami recv: {e}"),
        }
    }
}

async fn tcp_echo(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((mut conn, _)) => {
                tokio::spawn(async move {
                    let (mut rd, mut wr) = conn.split();
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                    let _ = wr.shutdown().await;
                });
            }
            Err(e) => log::warn!("tcp echo accept: {e}"),
        }
    }
}

/// Chunk size for the bulk source/sink: large writes/reads keep the wan-side
/// syscall overhead out of throughput measurements.
const BULK_CHUNK: usize = 256 * 1024;

/// [`TCP_SOURCE_PORT`]: per connection, read an 8-byte big-endian count N,
/// send exactly N pattern bytes ((i % 251) repeating per chunk), close.
async fn tcp_source(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((mut conn, _)) => {
                tokio::spawn(async move {
                    let mut req = [0u8; 8];
                    if conn.read_exact(&mut req).await.is_err() {
                        return;
                    }
                    let mut remaining =
                        usize::try_from(u64::from_be_bytes(req)).unwrap_or(usize::MAX);
                    let chunk: Vec<u8> = (0..BULK_CHUNK).map(|i| (i % 251) as u8).collect();
                    while remaining > 0 {
                        let n = remaining.min(chunk.len());
                        if conn.write_all(&chunk[..n]).await.is_err() {
                            return;
                        }
                        remaining -= n;
                    }
                    let _ = conn.shutdown().await;
                });
            }
            Err(e) => log::warn!("tcp source accept: {e}"),
        }
    }
}

/// [`TCP_SINK_PORT`]: per connection, count bytes until EOF, write the count
/// back as 8 bytes big-endian, close.
async fn tcp_sink(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((mut conn, _)) => {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; BULK_CHUNK];
                    let mut total: u64 = 0;
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => total += n as u64,
                            Err(_) => return,
                        }
                    }
                    let _ = conn.write_all(&total.to_be_bytes()).await;
                    let _ = conn.shutdown().await;
                });
            }
            Err(e) => log::warn!("tcp sink accept: {e}"),
        }
    }
}

async fn stun_responder(sock: UdpSocket) {
    let mut buf = [0u8; 1500];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, src)) => {
                if let Some(reply) = stun_binding_reply(&buf[..n], src) {
                    let _ = sock.send_to(&reply, src).await;
                }
            }
            Err(e) => log::warn!("stun recv: {e}"),
        }
    }
}

/// RFC 5389 Binding Request → Binding Success with one XOR-MAPPED-ADDRESS.
/// Family 0x01 (length-8 attribute, address XORed with the cookie) for v4
/// sources; family 0x02 (length-20, address XORed with cookie‖transaction
/// id per §15.2) for v6 sources.
fn stun_binding_reply(req: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
    if req.len() < 20 || req[0..2] != [0x00, 0x01] || req[4..8] != STUN_COOKIE {
        return None;
    }
    let xport = src.port() ^ u16::from_be_bytes([STUN_COOKIE[0], STUN_COOKIE[1]]);
    let (family, attr_len, msg_len) = match src {
        SocketAddr::V4(_) => (0x01u8, 8u16, 12u16),
        SocketAddr::V6(_) => (0x02u8, 20u16, 24u16),
    };

    let mut out = Vec::with_capacity(20 + 4 + attr_len as usize);
    out.extend_from_slice(&[0x01, 0x01]); // Binding Success Response
    out.extend_from_slice(&msg_len.to_be_bytes());
    out.extend_from_slice(&STUN_COOKIE);
    out.extend_from_slice(&req[8..20]); // transaction id
    out.extend_from_slice(&[0x00, 0x20]); // XOR-MAPPED-ADDRESS
    out.extend_from_slice(&attr_len.to_be_bytes());
    out.push(0x00);
    out.push(family);
    out.extend_from_slice(&xport.to_be_bytes());
    match src {
        SocketAddr::V4(v4) => {
            for (octet, cookie) in v4.ip().octets().iter().zip(STUN_COOKIE) {
                out.push(octet ^ cookie);
            }
        }
        SocketAddr::V6(v6) => {
            // XOR key: magic cookie (4 bytes) followed by the transaction id
            // (12 bytes).
            let key: Vec<u8> = STUN_COOKIE.iter().chain(&req[8..20]).copied().collect();
            for (octet, k) in v6.ip().octets().iter().zip(key) {
                out.push(octet ^ k);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_reply_encodes_xor_mapped_address() {
        let mut req = vec![0x00, 0x01, 0x00, 0x00];
        req.extend_from_slice(&STUN_COOKIE);
        req.extend_from_slice(&[0xAB; 12]);
        let src: SocketAddr = "203.0.113.6:40000".parse().unwrap();
        let reply = stun_binding_reply(&req, src).expect("binding reply");
        assert_eq!(&reply[0..2], &[0x01, 0x01]);
        assert_eq!(&reply[4..8], &STUN_COOKIE);
        assert_eq!(&reply[8..20], &[0xAB; 12]);
        assert_eq!(&reply[20..24], &[0x00, 0x20, 0x00, 0x08]);
        let port = u16::from_be_bytes([reply[26], reply[27]]) ^ 0x2112;
        assert_eq!(port, 40000);
        let ip = Ipv4Addr::new(
            reply[28] ^ STUN_COOKIE[0],
            reply[29] ^ STUN_COOKIE[1],
            reply[30] ^ STUN_COOKIE[2],
            reply[31] ^ STUN_COOKIE[3],
        );
        assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 6));
    }

    #[test]
    fn stun_reply_encodes_v6_xor_mapped_address() {
        let mut req = vec![0x00, 0x01, 0x00, 0x00];
        req.extend_from_slice(&STUN_COOKIE);
        let txid: [u8; 12] = *b"twelve-bytes";
        req.extend_from_slice(&txid);
        let src: SocketAddr = "[2001:db8:0:b::2]:40000".parse().unwrap();
        let reply = stun_binding_reply(&req, src).expect("binding reply");
        assert_eq!(&reply[0..2], &[0x01, 0x01]);
        assert_eq!(u16::from_be_bytes([reply[2], reply[3]]), 24, "message length");
        assert_eq!(&reply[20..24], &[0x00, 0x20, 0x00, 0x14], "attr header, len 20");
        assert_eq!(reply[25], 0x02, "family v6");
        let port = u16::from_be_bytes([reply[26], reply[27]]) ^ 0x2112;
        assert_eq!(port, 40000);
        let key: Vec<u8> = STUN_COOKIE.iter().chain(&txid).copied().collect();
        let octets: Vec<u8> = reply[28..44].iter().zip(key).map(|(b, k)| b ^ k).collect();
        let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(octets.as_slice()).unwrap());
        assert_eq!(ip, "2001:db8:0:b::2".parse::<std::net::Ipv6Addr>().unwrap());
    }

    #[test]
    fn stun_ignores_non_binding_traffic() {
        assert!(stun_binding_reply(b"hello", "1.2.3.4:5".parse().unwrap()).is_none());
        let mut req = vec![0x00, 0x02, 0x00, 0x00]; // wrong type
        req.extend_from_slice(&STUN_COOKIE);
        req.extend_from_slice(&[0u8; 12]);
        assert!(stun_binding_reply(&req, "1.2.3.4:5".parse().unwrap()).is_none());
    }
}
