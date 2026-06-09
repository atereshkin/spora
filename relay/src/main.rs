//! Dumb UDP relay binary. See `lib.rs` for the protocol and state machine.

use std::net::SocketAddr;

use clap::Parser;
use log::info;
use tokio::net::UdpSocket;

use relay::{serve, State};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// UDP port to bind on 0.0.0.0
    #[arg(short, long, default_value_t = 443)]
    port: u16,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let bind: SocketAddr = ([0, 0, 0, 0], args.port).into();
    let socket = UdpSocket::bind(bind)
        .await
        .unwrap_or_else(|e| panic!("bind {} failed: {}", bind, e));
    info!("dumb-relay listening on UDP {}", bind);
    serve(socket, State::default()).await;
}
