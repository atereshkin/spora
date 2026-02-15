use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use pubsub_client::PubSubService;
use tokio::sync::Mutex;
use netstack_smoltcp::{Stack, StackBuilder, TcpListener};
use log::{debug, error, info, warn};
use futures_util::{SinkExt, StreamExt};
use crate::neg::{FramedNegChannel, NegChannel};
use crate::transport::{IpTransport, UdpTransport};
use crate::Config;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NATKey(SocketAddr, SocketAddr);

// TODO: the NAT table entries should expire and be cleaned up
async fn handle_inbound_datagram(udp_socket: netstack_smoltcp::UdpSocket) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut read_half, mut write_half) = udp_socket.split();
    tokio::spawn(async move {
        while let Some((data, local, remote)) = rx.recv().await {
            let _ = write_half.send((data, remote, local)).await;
        }
    });

    let mut sockets: HashMap<NATKey, Arc<UdpSocket>> = HashMap::new();

    while let Some((data, local, remote)) = read_half.next().await {
        let key = NATKey(local, remote);
        let sock = if let Some(sock) = sockets.get_mut(&key) {
            sock
        } else {
            &mut match new_udp_packet(remote).await {
                Ok(socket) => {
                    let tx = tx.clone();
                    let socket = Arc::new(socket);
                    sockets.insert(key, socket.clone());
                    let recv_socket = socket.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut buf = vec![0; 1500];
                            match recv_socket.recv_from(&mut buf).await {
                                Ok((len, _)) => {
                                    let _ = tx.send((buf[..len].to_vec(), local, remote));
                                }
                                Err(e) => {
                                    warn!(
                                        "failed to recv udp datagram {:?}<->{:?}: {:?}",
                                        local, remote, e
                                    );
                                    break;
                                }
                            }
                        }
                    });
                    socket
                },
                Err(e) => panic!("failed to create udp socket: {:?}", e)
            }

        };
        let _ = sock.send(&data).await;
    }
}

async fn new_udp_packet(addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;

    let socket = tokio::net::UdpSocket::from_std(socket.into());
    if let Ok(ref socket) = socket {
        socket.connect(addr).await?;
    }
    socket
}

pub const BASE_PORT: u16 = 54321;

#[derive(Debug)]
pub enum TunnelError {
    NegChannelClosed,
    ProtocolError(String),
    PierceError(String),
}

#[derive(Clone)]
pub struct PeerPort {
    pub key: String,
    pub endpoint: String,
    control_stream: Arc<Mutex<TcpStream>>,
    config: Config,
}

impl PeerPort {
    fn make_key() -> String {
        String::from("abcdef") // TODO
    }

    async fn connect_pubsub(key: &str, config: &Config) -> io::Result<(TcpStream, String)> {
        let pubsub = PubSubService::new(&config.pubsub_host, config.pubsub_port);
        pubsub.sub(key).await
    }

    pub async fn new(config: Config) -> io::Result<Self> {
        let key = PeerPort::make_key();
        let (stream, endpoint) = Self::connect_pubsub(&key, &config).await?;
        Ok(PeerPort {
            key,
            control_stream: Arc::new(Mutex::new(stream)),
            endpoint,
            config,
        })
    }

    async fn reconnect(&self) -> io::Result<()> {
        let mut guard = self.control_stream.lock().await;
        let (stream, _) = Self::connect_pubsub(&self.key, &self.config).await?;
        *guard = stream;
        Ok(())
    }

    async fn negotiate_endpoints(&self) -> Result<(SocketAddr, SocketAddr), TunnelError> {
        // read the other endpoint from the control stream, pierce, write our endpoint to control stream
        let mut cstream = self.control_stream.lock().await;

        let mut neg_channel = FramedNegChannel::from_tcp_stream(&mut *cstream);
        let tun_endpoint = neg_channel.recv_endpoint().await?;

        let (local_addr, external_addr) = crate::pierce(&self.config.stun_server).await.map_err(TunnelError::PierceError)?;
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
        let udp_socket = udp_socket.unwrap(); // udp enabled
        let tcp_listener = tcp_listener.unwrap(); // tcp enabled or icmp enabled

        let sock = Arc::new(connect_socket(local_addr, &tun_endpoint).await?);

        let transport = UdpTransport::new(sock.clone(), tun_endpoint);

        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        let w_tunnel = tokio::spawn(run_tunnel(Box::new(transport), stack));
        let w_tcp = tokio::spawn(handle_tcp_streams(tcp_listener));
        let w_udp = tokio::spawn(handle_inbound_datagram(udp_socket));
        tokio::try_join!(w_tunnel, w_tcp, w_udp).unwrap();

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
                Err(TunnelError::PierceError(str)) => {
                    panic!("Failed to pierce: {}", str) // TODO: report to caller
                },
                Err(TunnelError::ProtocolError(str)) => {
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