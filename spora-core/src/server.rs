use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::task::{AbortHandle, JoinHandle};
use pubsub_client::{PubSubService, SubConnection};
use tokio_util::sync::CancellationToken;
use netstack_smoltcp::{Stack, StackBuilder, TcpListener};
use log::{debug, error, info, trace, warn};
use futures_util::{Sink, Stream, SinkExt, StreamExt};
use crate::transport::IpTransport;
use crate::transport::keepalive::{KeepAliveConfig, KeepAliveTransport};
use crate::transport::relay::relay_connection;
use crate::transport::upgradable::upgradable_transport;
use crate::{Config, SocketProtector};

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

pub(crate) async fn run_tunnel(transport: IpTransport, mut stack: Stack) {
    let (mut peer_sink, mut peer_stream) = transport.split();

    let (egress_tx, mut egress_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(EGRESS_CHANNEL_CAPACITY);
    let (ingress_tx, mut ingress_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    // Task 1 — Transport reader: transport → unbounded ingress channel.
    let ingress = tokio::spawn(async move {
        while let Some(res) = peer_stream.next().await {
            match res {
                Ok(pkt) => {
                    if ingress_tx.send(pkt).is_err() {
                        break;
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

    // Task 2 — Stack driver: polls both Stream (egress) and Sink (ingress) on
    // the Stack *without* `split()`.  This avoids the BiLock that couples the
    // two directions and works around a waker bug in the upstream Sink impl
    // (poll_ready / poll_flush return Pending without registering a waker when
    // the internal tcp_tx channel is full, which permanently parks the caller).
    let stack_driver = tokio::spawn(async move {
        use std::pin::Pin;
        use std::task::Poll;

        let mut pending_ingress: Option<Vec<u8>> = None;

        futures_util::future::poll_fn(|cx| {
            // --- Egress: drain stack output → bounded egress channel ---
            loop {
                match Pin::new(&mut stack).poll_next(cx) {
                    Poll::Ready(Some(Ok(pkt))) => {
                        if egress_tx.try_send(pkt.to_vec()).is_err() {
                            debug!("Egress channel full, dropping packet");
                        }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        error!("Stack read error: {}", e);
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break, // waker registered on stack_rx
                }
            }

            // --- Ingress: feed transport data into stack ---
            // First flush any buffered send in the sink.
            match Pin::new(&mut stack).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    // Sink is flushed — push packets while it stays ready.
                    loop {
                        let pkt = pending_ingress
                            .take()
                            .or_else(|| ingress_rx.try_recv().ok());
                        let Some(pkt) = pkt else { break };

                        match Pin::new(&mut stack).poll_ready(cx) {
                            Poll::Ready(Ok(())) => {
                                if let Err(e) = Pin::new(&mut stack).start_send(pkt) {
                                    error!("Stack send error: {}", e);
                                }
                                // Flush after each send so the next poll_ready
                                // reflects the true state.
                                match Pin::new(&mut stack).poll_flush(cx) {
                                    Poll::Ready(Ok(())) => continue,
                                    Poll::Ready(Err(e)) => {
                                        error!("Stack flush error: {}", e);
                                        return Poll::Ready(());
                                    }
                                    Poll::Pending => break, // sink busy
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                error!("Stack sink error: {}", e);
                                return Poll::Ready(());
                            }
                            Poll::Pending => {
                                pending_ingress = Some(pkt);
                                break;
                            }
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    error!("Stack flush error: {}", e);
                    return Poll::Ready(());
                }
                Poll::Pending => {
                    // Sink busy — can't accept data yet.  We'll retry when
                    // woken by poll_next (stack output) or ingress_rx below.
                }
            }

            // Register waker for incoming transport data so we re-enter
            // this poll_fn when new packets arrive.
            if pending_ingress.is_none() {
                match ingress_rx.poll_recv(cx) {
                    Poll::Ready(Some(pkt)) => {
                        pending_ingress = Some(pkt);
                        cx.waker().wake_by_ref();
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => {} // waker registered on ingress_rx
                }
            }

            Poll::Pending
        })
        .await;
        info!("Stack driver ended.");
    });

    // Task 3 — Egress writer: bounded channel → transport.
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
        stack_driver.abort_handle(),
        egress.abort_handle(),
    ]);

    // Wait until any task finishes — then the guard aborts the rest.
    tokio::select! {
        _ = ingress => {}
        _ = stack_driver => {}
        _ = egress => {}
    }
}

async fn handle_tcp_streams(mut tcp_listener: TcpListener, protector: SocketProtector) {
    while let Some((mut stream, local, remote)) = tcp_listener.next().await {
        let protector = protector.clone();
        tokio::spawn(async move {
            info!("new tcp connection: {:?} => {:?}", local, remote);
            match new_tcp_stream(remote, &protector).await {
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

async fn new_tcp_stream(addr: SocketAddr, protector: &SocketProtector) -> std::io::Result<TcpStream> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    socket.set_keepalive(true)?;
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;

    #[cfg(unix)]
    if let Some(ref f) = protector {
        use std::os::unix::io::AsRawFd;
        f(socket.as_raw_fd());
    }
    #[cfg(not(unix))]
    let _ = protector;

    let stream = TcpSocket::from_std_stream(socket.into())
        .connect(addr)
        .await?;

    Ok(stream)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NATKey(SocketAddr, SocketAddr);

const UDP_NAT_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_NAT_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

struct NATEntry {
    socket: Arc<UdpSocket>,
    task: JoinHandle<()>,
    last_activity: Instant,
}

async fn handle_inbound_datagram(udp_socket: netstack_smoltcp::UdpSocket, protector: SocketProtector) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut read_half, mut write_half) = udp_socket.split();
    tokio::spawn(async move {
        while let Some((data, local, remote)) = rx.recv().await {
            let _ = write_half.send((data, remote, local)).await;
        }
    });

    let mut entries: HashMap<NATKey, NATEntry> = HashMap::new();
    let mut sweep_interval = tokio::time::interval(UDP_NAT_SWEEP_INTERVAL);

    loop {
        tokio::select! {
            packet = read_half.next() => {
                let Some((data, local, remote)) = packet else { break };
                let key = NATKey(local, remote);

                if let Some(entry) = entries.get_mut(&key) {
                    entry.last_activity = Instant::now();
                    let _ = entry.socket.send(&data).await;
                } else {
                    match new_udp_packet(remote, &protector).await {
                        Ok(socket) => {
                            let socket = Arc::new(socket);
                            let recv_socket = socket.clone();
                            let tx = tx.clone();
                            let task = tokio::spawn(async move {
                                let mut buf = vec![0; 1500];
                                loop {
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
                            let _ = socket.send(&data).await;
                            entries.insert(key, NATEntry {
                                socket,
                                task,
                                last_activity: Instant::now(),
                            });
                        }
                        Err(e) => {
                            warn!("failed to create udp socket for {:?}<->{:?}: {:?}", local, remote, e);
                        }
                    }
                }
            }
            _ = sweep_interval.tick() => {
                entries.retain(|key, entry| {
                    if entry.last_activity.elapsed() > UDP_NAT_TIMEOUT {
                        trace!("UDP NAT entry expired: {:?} => {:?}", key.0, key.1);
                        entry.task.abort();
                        false
                    } else {
                        true
                    }
                });
            }
        }
    }
}

async fn new_udp_packet(addr: SocketAddr, protector: &SocketProtector) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;

    #[cfg(unix)]
    if let Some(ref f) = protector {
        use std::os::unix::io::AsRawFd;
        f(socket.as_raw_fd());
    }
    #[cfg(not(unix))]
    let _ = protector;

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
pub(crate) async fn start_tunnel(transport: IpTransport, protector: SocketProtector, cancel: CancellationToken) -> io::Result<()> {
    info!("Starting tunnel (virtual IP stack)");
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
    let w_tcp = tokio::spawn(handle_tcp_streams(tcp_listener, protector.clone()));
    let w_udp = tokio::spawn(handle_inbound_datagram(udp_socket, protector));

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
    /// Connection from the initial subscription — used for the first iteration of run().
    initial_conn: Option<SubConnection>,
    config: Config,
}

impl PeerPort {
    async fn connect_pubsub(key: &str, config: &Config) -> io::Result<SubConnection> {
        let crypto = pubsub_client::build_client_crypto();
        let mut transport = pubsub_client::default_transport_config();
        transport.keep_alive_interval(Some(Duration::from_secs(20)));
        let endpoint = pubsub_client::build_endpoint_with_transport_config(
            crypto, transport, &config.protector,
        )?;
        let pubsub = PubSubService::new(&config.pubsub_host, config.pubsub_port);
        pubsub.sub_with_endpoint(key, &endpoint).await
    }

    pub async fn new(key: String, config: Config) -> io::Result<Self> {
        let sub_conn = Self::connect_pubsub(&key, &config).await?;
        let endpoint = sub_conn.endpoint.clone();
        Ok(PeerPort {
            key,
            endpoint,
            initial_conn: Some(sub_conn),
            config,
        })
    }

    pub async fn run(mut self, cancel: CancellationToken) {
        let mut tunnel_cancel: Option<CancellationToken> = None;
        let mut iteration = 0u32;

        loop {
            iteration += 1;
            info!("[share loop #{}] Waiting for peer to connect...", iteration);

            // Use the connection from new() on the first iteration,
            // re-subscribe on subsequent iterations.
            let mut sub_conn = if let Some(conn) = self.initial_conn.take() {
                info!("[share loop #{}] Using initial connection", iteration);
                conn
            } else {
                info!("[share loop #{}] Re-subscribing to pubsub...", iteration);
                let result = tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("Share session cancelled");
                        break;
                    }
                    result = Self::connect_pubsub(&self.key, &self.config) => result,
                };
                match result {
                    Ok(conn) => {
                        info!("[share loop #{}] Re-subscription succeeded", iteration);
                        conn
                    }
                    Err(e) => {
                        warn!("[share loop #{}] Failed to subscribe to pubsub: {}. Retrying in 5s...", iteration, e);
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

            // Wait for a peer to connect. QUIC keepalives replace manual 0x00 packets.
            info!("[share loop #{}] Waiting for peer match...", iteration);
            let match_result = tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Share session cancelled while waiting for peer");
                    break;
                }
                result = sub_conn.wait_for_match() => Some(result),
            };
            let Some(match_result) = match_result else { break };
            if match_result.is_err() {
                warn!("[share loop #{}] Relay connection error while waiting for peer. Retrying...", iteration);
                continue;
            }

            // New peer connected — kick out the previous one.
            if let Some(tc) = tunnel_cancel.take() {
                info!("[share loop #{}] New peer connected, cancelling previous tunnel", iteration);
                tc.cancel();
            }

            info!("[share loop #{}] Peer connected. Setting up tunnel...", iteration);

            // Demux the relay connection into IP transport and signal channel
            let (relay_transport, signal_channel, demux_handle) =
                relay_connection(sub_conn.connection);

            // Wrap in upgradable transport
            let (upgradable, upgrade_sender, router_handle) =
                upgradable_transport(Box::new(relay_transport));

            // Wrap in keepalive
            let keepalive_cfg = KeepAliveConfig::default();
            let transport: IpTransport =
                Box::new(KeepAliveTransport::new(Box::new(upgradable), keepalive_cfg));

            // Spawn the tunnel — does NOT block the loop.
            let child_cancel = cancel.child_token();
            tunnel_cancel = Some(child_cancel.clone());

            // Spawn background direct upgrade task (server = responder).
            let stun_server = self.config.stun_server.clone();
            let upgrade_cancel = child_cancel.clone();
            let protector = self.config.protector.clone();
            let protector2 = self.config.protector.clone();
            let upgrade_task = tokio::spawn(async move {
                crate::try_direct_upgrade(signal_channel, upgrade_sender, &stun_server, false, &protector, upgrade_cancel, None).await;
            });

            tokio::spawn(async move {
                let _ = start_tunnel(transport, protector2, child_cancel).await;
                // Clean up background tasks
                upgrade_task.abort();
                demux_handle.abort();
                router_handle.abort();
            });

            // Loop immediately to re-subscribe and wait for the next peer.
        }
    }
}
