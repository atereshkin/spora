use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::task::AbortHandle;
use pubsub_client::PubSubService;
use tokio_util::sync::CancellationToken;
use netstack_smoltcp::{Stack, StackBuilder, TcpListener};
use log::{debug, error, info, warn};
use futures_util::{SinkExt, StreamExt};
use crate::transport::IpTransport;
use crate::transport::keepalive::{KeepAliveConfig, KeepAliveTransport};
use crate::transport::relay::relay_connection;
use crate::transport::upgradable::upgradable_transport;
use crate::Config;

const EGRESS_CHANNEL_CAPACITY: usize = 512;

/// Guard that aborts a set of tasks when dropped.
struct AbortOnDrop(Vec<AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

pub(crate) async fn run_tunnel(transport: IpTransport, stack: Stack) {
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut peer_sink, mut peer_stream) = transport.split();

    let (egress_tx, mut egress_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(EGRESS_CHANNEL_CAPACITY);

    // Ingress: transport → stack (can .await freely, stack ingress is unbounded)
    let ingress = tokio::spawn(async move {
        while let Some(res) = peer_stream.next().await {
            match res {
                Ok(v_buf) => {
                    if let Err(e) = stack_sink.send(v_buf).await {
                        error!("Error writing to stack: {}", e);
                    }
                }
                Err(e) => {
                    error!("Transport read error: {}", e);
                    break;
                }
            }
        }
        info!("Transport stream closed.");
    });

    // Stack drain: stack → bounded channel (never blocks on transport I/O)
    let drain = tokio::spawn(async move {
        while let Some(res) = stack_stream.next().await {
            match res {
                Ok(pkt) => {
                    if egress_tx.try_send(pkt.to_vec()).is_err() {
                        debug!("Egress channel full, dropping packet");
                    }
                }
                Err(e) => {
                    error!("Stack read error: {}", e);
                }
            }
        }
        info!("Stack stream closed.");
    });

    // Egress: bounded channel → transport (can be slow without affecting drain)
    let egress = tokio::spawn(async move {
        while let Some(pkt) = egress_rx.recv().await {
            if let Err(e) = peer_sink.send(pkt).await {
                error!("Transport write error: {}", e);
                break;
            }
        }
    });

    let _guard = AbortOnDrop(vec![
        ingress.abort_handle(),
        drain.abort_handle(),
        egress.abort_handle(),
    ]);

    // Wait until any task finishes — then the guard aborts the rest.
    tokio::select! {
        _ = ingress => {}
        _ = drain => {}
        _ = egress => {}
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

async fn new_tcp_stream(addr: SocketAddr) -> std::io::Result<TcpStream> {
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

/// Start the virtual IP stack and tunnel with the given transport.
///
/// Blocks until the tunnel ends or `cancel` is triggered.
pub(crate) async fn start_tunnel(transport: IpTransport, cancel: CancellationToken) -> io::Result<()> {
    let builder = StackBuilder::default()
        .stack_buffer_size(4096)
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true);

    let (stack, runner, udp_socket, tcp_listener) = builder.build().unwrap();
    let udp_socket = udp_socket.unwrap();
    let tcp_listener = tcp_listener.unwrap();

    let runner_handle = runner.map(|r| tokio::spawn(r));

    let w_tunnel = tokio::spawn(run_tunnel(transport, stack));
    let w_tcp = tokio::spawn(handle_tcp_streams(tcp_listener));
    let w_udp = tokio::spawn(handle_inbound_datagram(udp_socket));

    let abort_handles = [
        w_tunnel.abort_handle(),
        w_tcp.abort_handle(),
        w_udp.abort_handle(),
    ];
    let runner_abort = runner_handle.as_ref().map(|h| h.abort_handle());

    tokio::select! {
        _ = cancel.cancelled() => {
            info!("Tunnel cancelled, aborting tasks");
            for h in &abort_handles {
                h.abort();
            }
            if let Some(h) = runner_abort {
                h.abort();
            }
        }
        _ = async { tokio::try_join!(w_tunnel, w_tcp, w_udp) } => {}
    }

    Ok(())
}

pub struct PeerPort {
    pub key: String,
    pub endpoint: String,
    /// Socket from the initial subscription — used for the first iteration of run().
    initial_socket: Option<UdpSocket>,
    config: Config,
}

impl PeerPort {
    async fn connect_pubsub(key: &str, config: &Config) -> io::Result<(UdpSocket, String)> {
        let pubsub = PubSubService::new(&config.pubsub_host, config.pubsub_port);
        pubsub.sub(key).await
    }

    pub async fn new(key: String, config: Config) -> io::Result<Self> {
        let (socket, endpoint) = Self::connect_pubsub(&key, &config).await?;
        Ok(PeerPort {
            key,
            endpoint,
            initial_socket: Some(socket),
            config,
        })
    }

    pub async fn run(mut self, cancel: CancellationToken) {
        let mut tunnel_cancel: Option<CancellationToken> = None;

        loop {
            debug!("Waiting for peer to connect...");

            // Use the socket from new() on the first iteration,
            // re-subscribe on subsequent iterations.
            let relay_socket = if let Some(socket) = self.initial_socket.take() {
                socket
            } else {
                let result = tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("Share session cancelled");
                        break;
                    }
                    result = Self::connect_pubsub(&self.key, &self.config) => result,
                };
                match result {
                    Ok((socket, _endpoint)) => socket,
                    Err(e) => {
                        warn!("Failed to subscribe to pubsub: {}. Retrying in 5s...", e);
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                info!("Share session cancelled during retry delay");
                                return;
                            }
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {}
                        }
                        continue;
                    }
                }
            };

            // Wait for a peer to actually connect. peek() reads without consuming,
            // so relay_connection's demux task will see the same first packet.
            let mut peek_buf = [0u8; 1];
            let peek_result = tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Share session cancelled while waiting for peer");
                    break;
                }
                result = relay_socket.peek(&mut peek_buf) => result,
            };
            if peek_result.is_err() {
                warn!("Relay socket error while waiting for peer. Retrying...");
                continue;
            }

            // New peer connected — kick out the previous one.
            if let Some(tc) = tunnel_cancel.take() {
                info!("New peer connected, cancelling previous tunnel");
                tc.cancel();
            }

            debug!("Peer connected. Setting up tunnel...");

            // Demux the relay socket into IP transport and signal channel
            let (relay_transport, signal_channel, demux_handle) =
                relay_connection(relay_socket);

            // Wrap in upgradable transport
            let (upgradable, upgrade_sender, router_handle) =
                upgradable_transport(Box::new(relay_transport));

            // Wrap in keepalive
            let keepalive_cfg = KeepAliveConfig::default();
            let transport: IpTransport =
                Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

            // Spawn background direct upgrade task (server = responder).
            let stun_server = self.config.stun_server.clone();
            let upgrade_task = tokio::spawn(async move {
                crate::try_direct_upgrade(signal_channel, upgrade_sender, &stun_server, false).await;
            });

            // Spawn the tunnel — does NOT block the loop.
            let child_cancel = cancel.child_token();
            tunnel_cancel = Some(child_cancel.clone());

            tokio::spawn(async move {
                let _ = start_tunnel(transport, child_cancel).await;
                // Clean up background tasks
                upgrade_task.abort();
                demux_handle.abort();
                router_handle.abort();
            });

            // Loop immediately to re-subscribe and wait for the next peer.
        }
    }
}
