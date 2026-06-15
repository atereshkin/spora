//! Dumb UDP relay binary. See `lib.rs` for the protocol and state machine.

use std::net::SocketAddr;

use clap::Parser;
use log::info;
use tokio::net::UdpSocket;

use relay::{serve, State};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// UDP port to bind (dual-stack wildcard unless --bind is given)
    #[arg(short, long, default_value_t = 443)]
    port: u16,
    /// Explicit bind address (e.g. 0.0.0.0 for v4-only hosts). Default binds
    /// `::` dual-stack so one socket serves v4 (as v4-mapped) and v6 peers.
    #[arg(short, long)]
    bind: Option<std::net::IpAddr>,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let bind = SocketAddr::new(
        args.bind
            .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        args.port,
    );
    let socket = bind_relay_socket(bind).unwrap_or_else(|e| panic!("bind {} failed: {}", bind, e));
    info!("dumb-relay listening on UDP {}", bind);
    serve(socket, State::default()).await;
}

/// Bind the relay socket. A `::` wildcard is made explicitly dual-stack
/// (IPV6_V6ONLY off) rather than trusting the OS default, so v4 peers reach
/// the same socket as v4-mapped addresses and one flow table serves both
/// families — mixed-family flows (v4 sharer, v6 client) included.
fn bind_relay_socket(bind: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind),
        socket2::Type::DGRAM,
        None,
    )?;
    if bind.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&bind.into())?;
    UdpSocket::from_std(socket.into())
}
