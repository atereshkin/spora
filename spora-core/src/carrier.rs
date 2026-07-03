//! Client-side relay protocols ("carriers"): pluggable ways to reach a peer.
//!
//! Each [`RelayClient`] knows how to reach a peer over one relay protocol and
//! return an authenticated, end-to-end-encrypted [`E2eSession`]. The
//! postcondition is *always* an end-to-end channel — the far end is pinned to
//! the routing key (its self-signed cert's fingerprint) and proves the secret,
//! so the relay is never trusted, in any protocol. A carrier that merely
//! encrypted the leg to the relay would not satisfy this.
//!
//! Selection is by [`RelayProtocol`], carried per-endpoint in the share URL.
//!
//! Today's carriers — `UdpQuic` (the dumb relay) and `Direct` (relay-less) —
//! share one QUIC dial: `Direct` simply targets the sharer's own listener
//! instead of a relay. They differ on the *sharer* side (a `Direct` sharer
//! binds an advertised port and does not register) and in selection. A future
//! TCP/TLS carrier would be a genuinely different `dial` (a stream-native E2E
//! layer), which is exactly what this trait boundary exists to allow.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use crate::e2e::{client_connect, client_endpoint, E2eSession};
use crate::identity::{RelayProtocol, ROUTING_KEY_LEN, SECRET_LEN};
use crate::{bind_local_udp, SocketProtector, Timings};

/// Inputs a client-side dial needs. `target` is the relay's address for relayed
/// protocols, or the peer's own address for `Direct`.
pub(crate) struct DialCtx<'a> {
    pub target: SocketAddr,
    pub routing_key: [u8; ROUTING_KEY_LEN],
    pub secret: [u8; SECRET_LEN],
    pub protector: &'a SocketProtector,
    pub timings: &'a Timings,
    /// Wait for the sharer's accept-ack. On the relay path this surfaces a
    /// bad/expired secret as a connect error instead of a silent reconnect loop.
    pub expect_ack: bool,
}

pub(crate) type SessionFut<'a> =
    Pin<Box<dyn Future<Output = Result<E2eSession, String>> + Send + 'a>>;

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
    }
}

/// Shared QUIC dial: bind a local UDP socket in the target's family, pin the
/// cert to `routing_key` (and set DCID = routing_key so a dumb relay can route
/// the first Initial), complete the handshake, and authenticate with the secret.
async fn quic_dial(ctx: DialCtx<'_>) -> Result<E2eSession, String> {
    let std_socket = bind_local_udp(ctx.protector, ctx.target)?;
    let endpoint = client_endpoint(std_socket, ctx.routing_key, ctx.timings)?;
    client_connect(&endpoint, ctx.target, &ctx.secret, ctx.expect_ack).await
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

/// Relay-less direct dial: `target` is the sharer's own listener. The client
/// dial is the same pinned QUIC handshake as `UdpQuic`; the sharer serves it
/// without a relay (see the share side).
pub(crate) struct DirectRelayClient;

impl RelayClient for DirectRelayClient {
    fn protocol(&self) -> RelayProtocol {
        RelayProtocol::Direct
    }
    fn dial<'a>(&'a self, ctx: DialCtx<'a>) -> SessionFut<'a> {
        Box::pin(quic_dial(ctx))
    }
}
