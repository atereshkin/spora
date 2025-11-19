use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::ops::Deref;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use futures_util::stream::{SplitSink, SplitStream};
use log::{info, warn};
use netstack_smoltcp::{AnyIpPktFrame, Stack, StackBuilder, TcpListener};
use stunclient::StunClient;
use tokio::io;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Mutex;

async fn connect_socket(local_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local_addr).await?; // TODO: listen on IPv6 as well
    socket.send_to(&[123], "188.166.74.116:12345").await;
    Ok(socket)
}


struct Peer {
    socket: Arc<UdpSocket>,
    peer_addr: Mutex<Option<SocketAddr>>,
}

async fn handle_incoming(mut peer: Arc<Peer>, mut stack_sink: SplitSink<Stack, AnyIpPktFrame>) {
    let mut buffer = vec![0u8; 1500];
    loop {
        match peer.socket.recv_from(&mut buffer).await {
            Ok((n, from_peer)) if n > 0 => {
                let mut lock = peer.peer_addr.lock().await;
                if lock.is_none() {
                    lock.replace(from_peer);
                }
                let v_buf = buffer[..n].to_vec();
                if let Err(e) = stack_sink.send(v_buf).await { // TODO
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
                    match peer.socket.send_to(pkt.to_vec().as_slice(), peer_addr).await {
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


pub async fn start(local_addr: SocketAddr) {
    let builder = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true);

    let (stack, runner, udp_socket, tcp_listener) = builder.build().unwrap();
    // TODO: handle UDP
    // let udp_socket = udp_socket.unwrap(); // udp enabled
    let tcp_listener = tcp_listener.unwrap(); // tcp enabled or icmp enabled

    // if let Some(runner) = runner {
    //     tokio_spawn!(runner);
    // }
    let sock = Arc::new(connect_socket(local_addr).await.unwrap());
    let mut peer = Arc::new(Peer { socket: sock.clone(), peer_addr: Mutex::new(None) });

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

pub struct Endpoint {
    pub hostname: String,
    pub port: u16,
}


const STUN_SERVER: &str = "stun.l.google.com:19302";
const BASE_PORT: u16 = 54321;

pub async fn share() -> Result<Endpoint, String> {
    let (local_addr, external_addr) = pinch().await.unwrap();
    // TODO: error handling
    tokio::spawn(async move {
        start(local_addr).await;
    });
    Ok(Endpoint { hostname: external_addr.ip().to_string(), port: external_addr.port() })
}

async fn pinch() -> Result<(SocketAddr, SocketAddr), String> {
    let stun_addr = STUN_SERVER.to_socket_addrs().unwrap().filter(|x| x.is_ipv4()).next().unwrap();

    let mut local_port = BASE_PORT;
    while local_port < BASE_PORT + 10 {
        let local_addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], local_port));
        let udp = tokio::net::UdpSocket::bind(&local_addr).await.unwrap();
        println!("Local addr: {}", udp.local_addr().unwrap());

        let c = StunClient::new(stun_addr);
        let f = c.query_external_address_async(&udp);
        match f.await {
            Ok(addr) => return Ok((local_addr, addr)),
            Err(e) => {
                local_port += 1;
                continue;
            }
        };
    }
    Err("failed to share".parse().unwrap())
}