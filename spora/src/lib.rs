use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use netstack_smoltcp::{AnyIpPktFrame, Stack, StackBuilder, TcpListener};
use pubsub_client::PubSubService;
use stunclient::StunClient;
use tokio::io;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::sleep;

const PUBSUB_SERVER: &str = "188.166.74.116";
const PUBSUB_PORT: u16 = 2334;

async fn connect_socket(local_addr: SocketAddr, remote_addr: &SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local_addr).await?; // TODO: listen on IPv6 as well
    socket.send_to(&[123], remote_addr).await?;
    Ok(socket)
}

struct Peer {
    socket: Arc<UdpSocket>,
    peer_addr: Mutex<Option<SocketAddr>>,
}

async fn handle_incoming(peer: Arc<Peer>, mut stack_sink: SplitSink<Stack, AnyIpPktFrame>) {
    let mut buffer = vec![0u8; 1500];
    loop {
        match peer.socket.recv_from(&mut buffer).await {
            Ok((n, from_peer)) if n > 0 => {
                let mut lock = peer.peer_addr.lock().await;
                if lock.is_none() {
                    lock.replace(from_peer);
                }
                let v_buf = buffer[..n].to_vec();
                if let Err(e) = stack_sink.send(v_buf).await {
                    // TODO
                    eprintln!("Error writing incoming packet to stack: {}", e)
                }
            }
            Ok(_) => continue,
            Err(e) => {
                eprintln!("Error receiving UDP packet: {}", e);
                break;
            }
        }
    }
}

async fn handle_outgoing(mut stack_stream: SplitStream<Stack>, peer: Arc<Peer>) {
    while let Some(pkt) = stack_stream.next().await {
        if let Ok(pkt) = pkt {
            let lock = peer.peer_addr.lock().await;
            match lock.deref() {
                None => {
                    // Drop all outgoing packets, until we have established the peer
                }
                Some(peer_addr) => {
                    match peer
                        .socket
                        .send_to(pkt.to_vec().as_slice(), peer_addr)
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("failed to send packet to TUN, err: {:?}", e),
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
    let Ok(pp) = PeerPort::new().await else {
        return Err("failed to start message subscription: {}".to_string(), ); // TODO: better error
    };
    let clone = pp.clone();
    // TODO: error handling
    tokio::spawn(async move { clone.start().await });
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
        let udp = tokio::net::UdpSocket::bind(&local_addr).await.unwrap();
        println!("Local addr: {}", udp.local_addr().unwrap());

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
    Err("failed to pinch".parse().unwrap())
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

    async fn new() -> io::Result<Self> {
        let key = PeerPort::make_key();
        let pubsub = PubSubService::new(PUBSUB_SERVER, PUBSUB_PORT);
        let (stream, endpoint) = pubsub.sub(&key).await?;
        Ok(PeerPort {
            key,
            control_stream: Arc::new(Mutex::new(stream)),
            endpoint: endpoint,
        })
    }

    pub async fn start(&self) {
        // TODO: read other endpoint from control stream, pinch, write our endpoint to control stream
        let mut cstream = self.control_stream.lock().await; // TODO we are essentially locking it forever

        let (reader, mut writer) = cstream.split();

        let mut reader = BufReader::new(reader);

        let mut tun_endpoint = String::new();
        reader.read_line(&mut tun_endpoint).await.unwrap(); // TODO: no reason to panic
        tun_endpoint = tun_endpoint.trim().to_string();
        dbg!(&tun_endpoint);
        let tun_endpoint = SocketAddr::from_str(&tun_endpoint).unwrap(); // TODO: do not panic!


        let (local_addr, external_addr) = pierce().await.unwrap();


        writer
            .write_all(external_addr.to_string().as_bytes())
            .await
            .unwrap();
        writer.write_u8('\n' as u8).await.unwrap();
        writer.flush().await.unwrap(); // TODO: do not panic

        let builder = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true);

        let (stack, runner, udp_socket, tcp_listener) = builder.build().unwrap();
        // TODO: handle UDP
        // let udp_socket = udp_socket.unwrap(); // udp enabled
        let tcp_listener = tcp_listener.unwrap(); // tcp enabled or icmp enabled

        let sock = Arc::new(connect_socket(local_addr, &tun_endpoint).await.unwrap());
        let peer = Arc::new(Peer {
            socket: sock.clone(),
            peer_addr: Mutex::new(None),
        });

        let (stack_sink, stack_stream) = stack.split();

        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        let w_incoming = tokio::spawn(handle_incoming(peer.clone(), stack_sink));
        let w_outgoing = tokio::spawn(handle_outgoing(stack_stream, peer));
        let w_tcp = tokio::spawn(handle_tcp_streams(tcp_listener));
        // let w_runner = tokio::spawn(runner);
        tokio::try_join!(w_incoming, w_outgoing, w_tcp).unwrap();
    }
}
