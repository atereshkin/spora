mod transport;
mod neg;

use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use netstack_smoltcp::{Stack, StackBuilder, TcpListener};
use pubsub_client::PubSubService;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use stunclient::StunClient;
use tokio::io;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use neg::{FramedNegChannel, NegChannel};
use crate::transport::{IpTransport, UdpTransport};
use crate::TunnelError::{PierceError, ProtocolError};

const PUBSUB_SERVER: &str = "188.166.74.116";
const PUBSUB_PORT: u16 = 2334;

async fn connect_socket(local_addr: SocketAddr, remote_addr: &SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local_addr).await?; // TODO: listen on IPv6 as well
    socket.send_to(&[123], remote_addr).await?;
    Ok(socket)
}

async fn run_tunnel(transport: IpTransport, stack: Stack) {
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut peer_sink, mut peer_stream) = transport.split();
    loop {
        tokio::select! {
            res = peer_stream.next() => {
                match res {
                    Some(Ok(v_buf)) => {
                        if let Err(e) = stack_sink.send(v_buf).await {
                            error!("Error writing to stack: {}", e);
                        }
                    }
                    Some(Err(e)) => {
                        error!("Transport read error: {}", e);
                        break;
                    }
                    None => {
                        info!("Transport stream closed (None).");
                        break;
                    }
                }
            }
            res = stack_stream.next() => {
                match res {
                    Some(Ok(pkt)) => {
                        if let Err(e) = peer_sink.send(pkt.to_vec()).await {
                            error!("Transport write error: {}", e);
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("Stack read error: {}", e);
                    }
                    None => {
                        info!("Stack stream closed.");
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_tcp_streams(mut tcp_listener: TcpListener) {
    while let Some((mut stream, local, remote)) = tcp_listener.next().await {
        tokio::spawn(async move {
            info!("new tcp connection: {:?} => {:?}", local, remote);
            match new_tcp_stream(remote).await {
                Ok(mut remote_stream) => {
                    // pipe between two tcp stream
                    match tokio::io::copy_bidirectional(&mut stream, &mut remote_stream).await {
                        Ok(_) => {}
                        Err(e) => warn!(
                            "failed to copy tcp stream {:?}=>{:?}, err: {:?}",
                            local, remote, e
                        ),
                    }
                }
                Err(e) => warn!(
                    "failed to new tcp stream {:?}=>{:?}, err: {:?}",
                    local, remote, e
                ),
            }
        });
    }
}

async fn new_tcp_stream<'a>(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    let stream = TcpSocket::from_std_stream(socket.into())
        .connect(addr)
        .await?;

    Ok(stream)
}

const STUN_SERVER: &str = "stun.l.google.com:19302";
const BASE_PORT: u16 = 54321;

pub async fn share() -> Result<PeerPort, String> {
    let pp = match PeerPort::new().await {
        Ok(pp) => pp,
        Err(e) => {
            return Err(format!("failed to start message subscription: {}", e))
        }
    };
    let clone = pp.clone();
    // TODO: error handling
    tokio::spawn(async move { clone.run().await });
    Ok(pp)
}

pub async fn pierce() -> Result<(SocketAddr, SocketAddr), String> {
    let stun_addr = STUN_SERVER
        .to_socket_addrs()
        .unwrap()
        .filter(|x| x.is_ipv4())
        .next()
        .unwrap();

    let mut local_port = BASE_PORT;
    while local_port < BASE_PORT + 10 {
        let local_addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], local_port));
        let udp = match tokio::net::UdpSocket::bind(&local_addr).await {
            Ok(udp) => udp,
            Err(_) => {
                local_port += 1;
                continue
            },
        };
        debug!("Local addr: {}", udp.local_addr().unwrap());

        let c = StunClient::new(stun_addr);
        let f = c.query_external_address_async(&udp);
        match f.await {
            Ok(addr) => return Ok((local_addr, addr)),
            Err(_) => {
                local_port += 1;
                continue;
            }
        };
    }
    Err("failed to pierce".into())
}

#[derive(Debug)]
enum TunnelError {
    NegChannelClosed,
    ProtocolError(String),
    PierceError(String),
}


#[derive(Clone)]
pub struct PeerPort {
    pub key: String,
    pub endpoint: String,
    control_stream: Arc<Mutex<TcpStream>>,
}

impl PeerPort {
    fn make_key() -> String {
        String::from("abcdef") // TODO
    }

    async fn connect(key: &str) -> io::Result<(TcpStream, String)> {
        let pubsub = PubSubService::new(PUBSUB_SERVER, PUBSUB_PORT);
        pubsub.sub(key).await
    }

    async fn new() -> io::Result<Self> {
        let key = PeerPort::make_key();
        let (stream, endpoint) = Self::connect(&key).await?;
        Ok(PeerPort {
            key,
            control_stream: Arc::new(Mutex::new(stream)),
            endpoint,
        })
    }

    async fn reconnect(&self) -> io::Result<()> {
        let mut guard = self.control_stream.lock().await;
        let (stream, _) = Self::connect(&self.key).await?;
        *guard = stream;
        Ok(())
    }

    async fn negotiate_endpoints(&self) -> Result<(SocketAddr, SocketAddr), TunnelError> {
        // read the other endpoint from the control stream, pierce, write our endpoint to control stream
        let mut cstream = self.control_stream.lock().await;

        let mut neg_channel = FramedNegChannel::from_tcp_stream(&mut *cstream);
        let tun_endpoint = neg_channel.recv_endpoint().await?;

        let (local_addr, external_addr) = pierce().await.map_err(PierceError)?;
        neg_channel.send_endpoint(external_addr).await?;
        Ok((local_addr, tun_endpoint))
    }

    async fn start_tunnel(local_addr:SocketAddr, tun_endpoint: SocketAddr) -> io::Result<()> {
        let builder = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true);

        let (stack, runner, udp_socket, tcp_listener) = builder.build().unwrap();
        // TODO: handle UDP
        // let udp_socket = udp_socket.unwrap(); // udp enabled
        let tcp_listener = tcp_listener.unwrap(); // tcp enabled or icmp enabled

        let sock = Arc::new(connect_socket(local_addr, &tun_endpoint).await?);

        let transport = UdpTransport::new(sock.clone(), tun_endpoint);

        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        let w_tunnel = tokio::spawn(run_tunnel(Box::new(transport), stack));
        let w_tcp = tokio::spawn(handle_tcp_streams(tcp_listener));
        tokio::try_join!(w_tunnel, w_tcp).unwrap();

        Ok(())
    }

    pub async fn run(&self) {
        loop {
            debug!("Waiting for peer to connect...");
            match self.negotiate_endpoints().await {
                Err(TunnelError::NegChannelClosed) =>  {
                    warn!("Negotiation channel closed, reconnecting...");
                    while let Err(e) = self.reconnect().await {
                        warn!("Failed to reconnect: {}. Retrying in 5 seconds...", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
                Err(PierceError(str)) => {
                    panic!("Failed to pierce: {}", str) // TODO: report to caller
                },
                Err(ProtocolError(str)) => {
                    warn!("Protocol error: {}", str);
                },
                Ok((local_addr, tun_endpoint)) => {
                    debug!("Peer connected from {}. Starting tunnel", tun_endpoint);
                    tokio::spawn(Self::start_tunnel(local_addr, tun_endpoint)); // TODO: handle result
                    debug!("Tunnel started")
                },
            }
        }
    }
}
