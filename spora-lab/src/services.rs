//! In-process wan services, all running on one host thread inside the wan
//! namespace: the real relay (`relay::serve`), a minimal STUN responder,
//! UDP/TCP echo, and UDP "whoami" responders (reply with the observed source
//! `ip:port` as ASCII — lets tests verify NAT mapping behavior directly).
//!
//! Implementation notes:
//! - `start_wan(&wan_ns, relay_state)` spawns ONE host via `Netns::spawn_host`;
//!   inside it, everything binds on [`crate::WAN_SERVICES_IP`] at the
//!   [`crate::RELAY_PORT`]/[`crate::STUN_PORT`]/[`crate::ECHO_UDP_PORT`]/
//!   [`crate::WHOAMI_UDP_PORT`]/[`WHOAMI2_UDP_PORT`]/[`crate::ECHO_TCP_PORT`]
//!   constants, each service runs as a tokio task, and readiness (or a bind
//!   error) is reported back through a std mpsc channel that `start_wan`
//!   blocks on — bind errors are returned, not logged-and-lost.
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
//!   id. Reply: type 0x0101, one attribute XOR-MAPPED-ADDRESS (0x0020,
//!   length 8): family 0x01, port ^ 0x2112, IPv4 addr ^ cookie bytes.
//!   (`stunclient` 0.4 sends standard binding requests.)
//! - Echo UDP: recv → send_to(source). Echo TCP: accept loop, per-conn
//!   `tokio::io::copy` back into the writer (echoes whatever arrives —
//!   used for bulk-throughput assertions). Whoami UDP: recv →
//!   `send_to(format!("{src}"), src)`.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use crate::netns::{HostHandle, Netns};
use crate::{ECHO_TCP_PORT, ECHO_UDP_PORT, RELAY_PORT, STUN_PORT, WAN_SERVICES_IP, WHOAMI_UDP_PORT};

/// Second whoami responder: NAT mapping comparisons need two distinct wan
/// destination endpoints queried from one client socket.
pub const WHOAMI2_UDP_PORT: u16 = 7003;

const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

enum Cmd {
    RestartRelay(std::sync::mpsc::Sender<Result<(), String>>),
    StopRelay(std::sync::mpsc::Sender<Result<(), String>>),
}

pub struct WanHandle {
    cmds: tokio::sync::mpsc::UnboundedSender<Cmd>,
    relay_addr: SocketAddr,
    _host: HostHandle,
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

    pub fn stun_server(&self) -> String {
        format!("{WAN_SERVICES_IP}:{STUN_PORT}")
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
    let svc_ip: Ipv4Addr = WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses");
    let relay_addr = SocketAddr::from((svc_ip, RELAY_PORT));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();

    let host = wan.spawn_host("wan-services", move |_cancel| async move {
        let bound = async {
            Ok::<_, String>((
                bind_udp(svc_ip, STUN_PORT).await?,
                bind_udp(svc_ip, ECHO_UDP_PORT).await?,
                bind_udp(svc_ip, WHOAMI_UDP_PORT).await?,
                bind_udp(svc_ip, WHOAMI2_UDP_PORT).await?,
                TcpListener::bind((svc_ip, ECHO_TCP_PORT))
                    .await
                    .map_err(|e| format!("bind tcp {svc_ip}:{ECHO_TCP_PORT}: {e}"))?,
                bind_udp(svc_ip, RELAY_PORT).await?,
            ))
        }
        .await;
        let (stun, echo, who1, who2, tcp, relay_sock) = match bound {
            Ok(socks) => socks,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        tokio::spawn(stun_responder(stun));
        tokio::spawn(udp_echo(echo));
        tokio::spawn(udp_whoami(who1));
        tokio::spawn(udp_whoami(who2));
        tokio::spawn(tcp_echo(tcp));
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
                    let result = match bind_udp(svc_ip, RELAY_PORT).await {
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
        Ok(Ok(())) => Ok(WanHandle { cmds: cmd_tx, relay_addr, _host: host }),
        Ok(Err(e)) => Err(format!("wan services: {e}")),
        Err(e) => Err(format!("wan services never became ready: {e}")),
    }
}

async fn bind_udp(ip: Ipv4Addr, port: u16) -> Result<UdpSocket, String> {
    UdpSocket::bind((ip, port))
        .await
        .map_err(|e| format!("bind udp {ip}:{port}: {e}"))
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
/// Anything that is not an IPv4-sourced binding request is ignored.
fn stun_binding_reply(req: &[u8], src: SocketAddr) -> Option<Vec<u8>> {
    if req.len() < 20 || req[0..2] != [0x00, 0x01] || req[4..8] != STUN_COOKIE {
        return None;
    }
    let SocketAddr::V4(v4) = src else { return None };
    let xport = v4.port() ^ u16::from_be_bytes([STUN_COOKIE[0], STUN_COOKIE[1]]);

    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&[0x01, 0x01]); // Binding Success Response
    out.extend_from_slice(&12u16.to_be_bytes()); // message length
    out.extend_from_slice(&STUN_COOKIE);
    out.extend_from_slice(&req[8..20]); // transaction id
    out.extend_from_slice(&[0x00, 0x20, 0x00, 0x08]); // XOR-MAPPED-ADDRESS, len 8
    out.push(0x00);
    out.push(0x01); // family: IPv4
    out.extend_from_slice(&xport.to_be_bytes());
    for (octet, cookie) in v4.ip().octets().iter().zip(STUN_COOKIE) {
        out.push(octet ^ cookie);
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
    fn stun_ignores_non_binding_traffic() {
        assert!(stun_binding_reply(b"hello", "1.2.3.4:5".parse().unwrap()).is_none());
        let mut req = vec![0x00, 0x02, 0x00, 0x00]; // wrong type
        req.extend_from_slice(&STUN_COOKIE);
        req.extend_from_slice(&[0u8; 12]);
        assert!(stun_binding_reply(&req, "1.2.3.4:5".parse().unwrap()).is_none());
    }
}
