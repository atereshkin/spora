//! Client side of the dumb UDP relay protocol: shared wire-protocol constants
//! plus a small registration helper that sharers use to announce themselves.

use std::sync::Arc;

use log::warn;

pub mod protocol;

pub use protocol::ROUTING_KEY_LEN;

/// Default interval between REGISTER packets sent by the sharer to the relay.
/// Short enough that the relay's registration entry never expires under
/// normal conditions (relay's default registration timeout is 120s).
pub const DEFAULT_REGISTER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Run a sharer-side registration loop on `socket`, sending a REGISTER packet
/// for `routing_key` to `relay_addr` every `interval`. Cancel by dropping the
/// task or the socket.
///
/// `socket` should be shared (e.g. via `Arc<UdpSocket>`) with quinn's server
/// endpoint so a single NAT mapping is used for both registration and
/// incoming peer connections.
pub async fn register_loop(
    socket: Arc<tokio::net::UdpSocket>,
    relay_addr: std::net::SocketAddr,
    routing_key: [u8; ROUTING_KEY_LEN],
    interval: std::time::Duration,
) {
    let pkt = protocol::build_register(&routing_key);
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = socket.send_to(&pkt, relay_addr).await {
            warn!("register_loop: send_to {} failed: {}", relay_addr, e);
        }
    }
}
