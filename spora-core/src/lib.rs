mod transport;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use log::{info, warn, error, debug};
use netstack_smoltcp::{AnyIpPktFrame, Stack, StackBuilder, TcpListener};
use pubsub_client::PubSubService;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use stunclient::StunClient;
use tokio::io;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_util::codec::{FramedWrite, LinesCodec, LinesCodecError};
use tokio_util::codec::FramedRead;
use crate::transport::{IpSink, IpStream, UdpTransport};
use crate::TunnelError::{PierceError, ProtocolError};

const PUBSUB_SERVER: &str = "188.166.74.116";
const PUBSUB_PORT: u16 = 2334;

async fn connect_socket(local_addr: SocketAddr, remote_addr: &SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local_addr).await?; // TODO: listen on IPv6 as well
    socket.send_to(&[123], remote_addr).await?;
    Ok(socket)
}


async fn handle_incoming(mut peer_stream: IpStream, mut stack_sink: SplitSink<Stack, AnyIpPktFrame>) {
    while let Some(pkt) = peer_stream.next().await {
        match pkt {
            Ok(v_buf) => {
                if let Err(e) = stack_sink.send(v_buf).await {
                    error!("Error writing incoming packet to stack: {}", e);
                }
            }
            Err(e) => {
                error!("Error receiving from transport: {}", e);
                break;
            }
        }
    }
}

async fn handle_outgoing(mut stack_stream: SplitStream<Stack>, mut peer_sink: IpSink) {
    while let Some(pkt) = stack_stream.next().await {
        if let Ok(pkt) = pkt {
            if let Err(e) = peer_sink.send(pkt.to_vec()).await {
                error!("failed to send packet to transport, err: {:?}", e);
                break;
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
    // Io(std::io::Error),
    // Parse(std::net::AddrParseError),
    ProtocolError(String),
    PierceError(String),
}

trait NegChannel {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError>;
    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError>;
}

struct FramedNegChannel<'a> {
    reader: FramedRead<tokio::net::tcp::ReadHalf<'a>, LinesCodec>,
    writer: FramedWrite<tokio::net::tcp::WriteHalf<'a>, LinesCodec>,
}

impl<'a> FramedNegChannel<'a> {
    fn from_tcp_stream(stream: &'a mut TcpStream) -> Self {
        let (read_half, write_half) = stream.split();
        let decoder = LinesCodec::new();
        let reader = FramedRead::new(read_half, decoder);
        let encoder = LinesCodec::new();
        let writer = FramedWrite::new(write_half, encoder);
        FramedNegChannel { reader, writer }
    }
}

impl<'a> NegChannel for FramedNegChannel<'a> {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError> {
        self.writer.send(addr.to_string()).await.map_err(|error| {
            match error {
                LinesCodecError::MaxLineLengthExceeded => {
                    panic!("max line length exceeded when sending endpoint")
                }
                LinesCodecError::Io(e) => {
                    warn!("failed to send endpoint: {}", e);
                    TunnelError::NegChannelClosed
                }
            }
        })
    }

    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError> {
        let frame = match self.reader.next().await {
            Some(Ok(line)) => line,
            Some(Err(e)) => return Err(match e {
                LinesCodecError::MaxLineLengthExceeded => {
                    error!("max line length exceeded when receiving endpoint, possibly malicious peer");
                    ProtocolError("Line too long".into())
                }
                LinesCodecError::Io(io_err) => {
                    error!("failed to receive endpoint: {}", io_err);
                    return Err(TunnelError::NegChannelClosed);
                }
            }),
            None => return Err(TunnelError::NegChannelClosed),
        };
        Ok(SocketAddr::from_str(&frame).map_err(|parse_err| { ProtocolError(format!("invalid peer address: {}", parse_err))})?)
    }
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

        let (stack_sink, stack_stream) = stack.split();

        if let Some(runner) = runner {
            tokio::spawn(runner);
        }
        let (transport_sink, transport_stream) = transport.split();
        let w_incoming = tokio::spawn(handle_incoming(Box::new(transport_stream), stack_sink));
        let w_outgoing = tokio::spawn(handle_outgoing(stack_stream, Box::new(transport_sink)));
        let w_tcp = tokio::spawn(handle_tcp_streams(tcp_listener));
        // let w_runner = tokio::spawn(runner);
        tokio::try_join!(w_incoming, w_outgoing, w_tcp).unwrap();

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
