//! Client-side relay protocols ("carriers"): pluggable ways to reach a peer.
//!
//! Each [`RelayClient`] reaches a peer over one relay protocol and returns an
//! authenticated, end-to-end-encrypted [`PeerSession`]. The postcondition is
//! *always* an end-to-end channel — the far end is pinned to the routing key
//! (its self-signed cert's fingerprint) and proves the secret — so the relay is
//! never trusted, in any protocol.
//!
//! Carriers today:
//! - `UdpQuic` — the dumb UDP relay carrying end-to-end QUIC (the default).
//! - `Direct` — relay-less: dial the sharer's own listener (same QUIC dial).
//! - `TcpTls` — a TCP relay carrying end-to-end TLS (stream-native, for
//!   transport diversity). Its E2E is `e2e_tls` over a `StreamPeerTransport`,
//!   NOT QUIC-over-a-stream.
//!
//! QUIC carriers yield a [`QuicSessionExt`] (the connection + signal channel)
//! so the caller can run the hole-punch upgrade and read the dynamic MTU; stream
//! carriers yield `None` there (no upgrade, fixed MTU).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use quinn::Connection;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::e2e::{E2eSession, client_connect, client_endpoint};
use crate::e2e_tls;
use crate::identity::{RelayProtocol, ROUTING_KEY_LEN, SECRET_LEN};
use crate::signal::SignalChannel;
use crate::transport::IpTransport;
use crate::{Timings, SocketProtector, bind_local_udp};

/// Tunnel MTU reported for a stream carrier. A byte stream has no per-packet
/// datagram limit (framing + TCP handle any size), but the inner netstack still
/// needs an MTU; a conservative value keeps the inner TCP MSS sane end to end.
pub(crate) const STREAM_TUNNEL_MTU: u16 = 1400;

/// An established, end-to-end-authenticated peer session — carrier-agnostic.
pub(crate) struct PeerSession {
    pub transport: IpTransport,
    /// Remote address of the bootstrap connection (the relay, or the peer for
    /// `Direct`) — used for events and the connection log.
    pub remote_addr: SocketAddr,
    /// The QUIC connection when the carrier is QUIC — read for the dynamic
    /// PMTUD MTU. `None` for stream/Noise carriers, which use `fixed_mtu`.
    pub quic_conn: Option<Connection>,
    /// The hole-punch signal channel, when the carrier supports a direct upgrade
    /// (QUIC or Noise). `None` for `TcpTls`. Its variant also tells the upgrade
    /// which carrier to rebuild the direct path with.
    pub signal: Option<SignalChannel>,
    /// Fixed tunnel MTU to report when there is no QUIC connection to read a
    /// PMTUD-converged datagram size from (stream and Noise carriers). Ignored
    /// when `quic_conn` is `Some` (PMTUD drives the MTU there).
    pub fixed_mtu: u16,
}

impl PeerSession {
    /// Wrap an established QUIC end-to-end session.
    pub fn from_quic(session: E2eSession) -> Self {
        let E2eSession {
            conn,
            transport,
            signal,
        } = session;
        Self {
            remote_addr: conn.remote_address(),
            transport: Box::new(transport),
            quic_conn: Some(conn),
            signal: Some(signal),
            fixed_mtu: STREAM_TUNNEL_MTU, // unused: PMTUD drives a QUIC session's MTU
        }
    }
}

/// Inputs a client-side dial needs. `target` is the relay's address for relayed
/// protocols, or the peer's own address for `Direct`.
pub(crate) struct DialCtx<'a> {
    pub target: SocketAddr,
    pub routing_key: [u8; ROUTING_KEY_LEN],
    pub secret: [u8; SECRET_LEN],
    pub protector: &'a SocketProtector,
    pub timings: &'a Timings,
    /// Wait for the sharer's accept-ack (relay path: surfaces a bad/expired
    /// secret as a connect error instead of a silent reconnect loop).
    pub expect_ack: bool,
}

pub(crate) type SessionFut<'a> =
    Pin<Box<dyn Future<Output = Result<PeerSession, String>> + Send + 'a>>;

/// A client-side relay protocol: given a target, establish an authenticated
/// end-to-end session with the peer.
pub(crate) trait RelayClient: Send + Sync {
    fn protocol(&self) -> RelayProtocol;
    fn dial<'a>(&'a self, ctx: DialCtx<'a>) -> SessionFut<'a>;
}

/// The dialer for a protocol.
pub(crate) fn relay_client_for(protocol: RelayProtocol) -> Box<dyn RelayClient> {
    match protocol {
        RelayProtocol::UdpQuic => Box::new(UdpQuicRelayClient),
        RelayProtocol::Direct => Box::new(DirectRelayClient),
        RelayProtocol::TcpTls => Box::new(TcpTlsRelayClient),
        RelayProtocol::NoiseUdp => Box::new(NoiseUdpRelayClient),
    }
}

/// Shared QUIC dial (UDP relay + Direct): bind a local UDP socket in the
/// target's family, pin the cert to `routing_key` (DCID = routing_key so a dumb
/// relay routes the first Initial), handshake, authenticate with the secret.
async fn quic_dial(ctx: DialCtx<'_>) -> Result<PeerSession, String> {
    let std_socket = bind_local_udp(ctx.protector, ctx.target)?;
    let endpoint = client_endpoint(std_socket, ctx.routing_key, ctx.timings)?;
    let session = client_connect(&endpoint, ctx.target, &ctx.secret, ctx.expect_ack).await?;
    Ok(PeerSession::from_quic(session))
}

/// TCP/TLS relay dial: connect to the relay, send the CONNECT preamble (routing
/// key), then run the end-to-end TLS handshake + secret over the spliced stream.
async fn tcp_tls_dial(ctx: DialCtx<'_>) -> Result<PeerSession, String> {
    let mut tcp = TcpStream::connect(ctx.target)
        .await
        .map_err(|e| format!("tcp connect {}: {e}", ctx.target))?;
    let _ = tcp.set_nodelay(true);
    protect_tcp(ctx.protector, &tcp);
    tcp.write_all(&relay_client::tcp::build_preamble(
        relay_client::tcp::role::CONNECT,
        &ctx.routing_key,
        &[], // clients aren't relay-authorized — their auth is the E2E secret
    ))
    .await
    .map_err(|e| format!("tcp preamble write: {e}"))?;
    // End-to-end TLS (pinned to routing_key) + secret over the spliced stream.
    // The relay forwards ciphertext only; this is the E2E channel.
    let transport = e2e_tls::connect(tcp, ctx.routing_key, &ctx.secret).await?;
    Ok(PeerSession {
        transport,
        remote_addr: ctx.target,
        quic_conn: None,
        signal: None,
        fixed_mtu: STREAM_TUNNEL_MTU,
    })
}

/// Noise UDP relay dial: bind a local UDP socket in the relay's family, run the
/// NNpsk0 handshake to the sharer through the relay (routed by `routing_key` on
/// the first packet), verify A's cert-auth, and hand back the data-plane
/// transport. Non-QUIC-shaped on the wire; the relay stays dumb and keyless.
async fn noise_dial(ctx: DialCtx<'_>) -> Result<PeerSession, String> {
    let std_socket = bind_local_udp(ctx.protector, ctx.target)?;
    let socket = std::sync::Arc::new(
        tokio::net::UdpSocket::from_std(std_socket).map_err(|e| format!("nz socket: {e}"))?,
    );
    let mut transport = crate::transport::noise::noise_connect(
        socket,
        ctx.target,
        &ctx.routing_key,
        &ctx.secret,
        ctx.timings.relay_dial_timeout,
        ctx.timings.quic_idle_timeout,
    )
    .await?;
    // The in-band signal channel drives the hole-punch direct upgrade.
    let signal = transport.take_signal().map(SignalChannel::noise);
    Ok(PeerSession {
        transport: Box::new(transport),
        remote_addr: ctx.target,
        quic_conn: None,
        signal,
        fixed_mtu: crate::transport::noise::NZ_TUNNEL_MTU,
    })
}

/// Protect a TCP socket's fd (Android VPN bypass); no-op without a protector.
pub(crate) fn protect_tcp(protector: &SocketProtector, _tcp: &TcpStream) {
    #[cfg(unix)]
    if let Some(f) = protector {
        use std::os::unix::io::AsRawFd;
        f(_tcp.as_raw_fd());
    }
}

/// The dumb UDP relay carrying end-to-end QUIC (today's default).
pub(crate) struct UdpQuicRelayClient;
impl RelayClient for UdpQuicRelayClient {
    fn protocol(&self) -> RelayProtocol {
        RelayProtocol::UdpQuic
    }
    fn dial<'a>(&'a self, ctx: DialCtx<'a>) -> SessionFut<'a> {
        Box::pin(quic_dial(ctx))
    }
}

/// Relay-less direct dial: `target` is the sharer's own listener. Same pinned
/// QUIC dial as `UdpQuic`; the sharer serves it without a relay.
pub(crate) struct DirectRelayClient;
impl RelayClient for DirectRelayClient {
    fn protocol(&self) -> RelayProtocol {
        RelayProtocol::Direct
    }
    fn dial<'a>(&'a self, ctx: DialCtx<'a>) -> SessionFut<'a> {
        Box::pin(quic_dial(ctx))
    }
}

/// A TCP relay carrying end-to-end TLS (stream-native; transport diversity).
pub(crate) struct TcpTlsRelayClient;
impl RelayClient for TcpTlsRelayClient {
    fn protocol(&self) -> RelayProtocol {
        RelayProtocol::TcpTls
    }
    fn dial<'a>(&'a self, ctx: DialCtx<'a>) -> SessionFut<'a> {
        Box::pin(tcp_tls_dial(ctx))
    }
}

/// A dumb UDP relay carrying an end-to-end Noise datagram session — the
/// non-QUIC-shaped carrier for censored networks.
pub(crate) struct NoiseUdpRelayClient;
impl RelayClient for NoiseUdpRelayClient {
    fn protocol(&self) -> RelayProtocol {
        RelayProtocol::NoiseUdp
    }
    fn dial<'a>(&'a self, ctx: DialCtx<'a>) -> SessionFut<'a> {
        Box::pin(noise_dial(ctx))
    }
}
