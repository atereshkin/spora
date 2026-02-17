use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use clap::Parser;
use log::{error, info, warn};

const MSG_SUB: u8 = 0x01;
const MSG_PUB: u8 = 0x02;
const RESP_ERROR: u8 = 0xFF;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Advertised hostname for publisher connections
    #[arg(required = true)]
    host: String,
    /// Port to listen on
    #[arg(short, long, default_value_t = 2334)]
    port: u16,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();
    let socket = UdpSocket::bind(("0.0.0.0", args.port))
        .await
        .expect("failed to bind UDP socket");
    let endpoint = format!("{}:{}", args.host, args.port);
    info!("Relay listening on UDP port {}, advertising {}", args.port, endpoint);

    let mut subscribers: HashMap<Vec<u8>, SocketAddr> = HashMap::new();
    let mut routes: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let mut buf = [0u8; 65535];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!("recv_from error: {}", e);
                continue;
            }
        };

        if len == 0 {
            continue;
        }

        // If this peer is already matched, forward raw
        if let Some(&dest) = routes.get(&src) {
            if let Err(e) = socket.send_to(&buf[..len], dest).await {
                warn!("failed to forward data from {} to {}: {}", src, dest, e);
            }
            continue;
        }

        let msg_type = buf[0];
        let payload = &buf[1..len];

        match msg_type {
            MSG_SUB => {
                let key = payload.to_vec();
                info!("SUB from {} key={:?}", src, String::from_utf8_lossy(&key));
                subscribers.insert(key, src);
                let mut resp = vec![MSG_SUB];
                resp.extend_from_slice(endpoint.as_bytes());
                if let Err(e) = socket.send_to(&resp, src).await {
                    warn!("failed to send SUB_ACK to {}: {}", src, e);
                }
            }
            MSG_PUB => {
                let key = payload.to_vec();
                info!("PUB from {} key={:?}", src, String::from_utf8_lossy(&key));
                if let Some(sub_addr) = subscribers.remove(&key) {
                    routes.insert(src, sub_addr);
                    routes.insert(sub_addr, src);
                    if let Err(e) = socket.send_to(&[MSG_PUB], src).await {
                        warn!("failed to send PUB_ACK to {}: {}", src, e);
                    }
                    info!("Matched {} <-> {}", sub_addr, src);
                } else {
                    info!("No subscriber for key {:?}", String::from_utf8_lossy(&key));
                    let mut resp = vec![RESP_ERROR];
                    resp.extend_from_slice(b"unknown subscriber");
                    if let Err(e) = socket.send_to(&resp, src).await {
                        warn!("failed to send ERROR to {}: {}", src, e);
                    }
                }
            }
            0x00 => {
                // NAT keepalive from subscriber — ignore silently
            }
            _ => {
                warn!("Unknown message type 0x{:02x} from unmatched peer {}", msg_type, src);
            }
        }
    }
}
