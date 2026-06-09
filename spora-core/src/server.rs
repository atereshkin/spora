use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use netstack_smoltcp::{Stack, StackBuilder, TcpListener};
use log::{error, info, trace, warn};
use futures_util::{Sink, Stream, SinkExt, StreamExt};
use crate::transport::IpTransport;
use crate::SocketProtector;

const EGRESS_CHANNEL_CAPACITY: usize = 4096;

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
        let mut count: u64 = 0;
        while let Some(res) = peer_stream.next().await {
            match res {
                Ok(pkt) => {
                    count += 1;
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
        info!("Transport stream closed. Ingress packets received: {}", count);
    });

    // Task 2 — Stack driver: polls both Stream (egress) and Sink (ingress) on
    // the Stack *without* `split()`.  This avoids the BiLock that couples the
    // two directions and works around a waker bug in the upstream Sink impl
    // (poll_ready / poll_flush return Pending without registering a waker when
    // the internal tcp_tx channel is full, which permanently parks the caller).
    let stack_driver = tokio::spawn(async move {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::Poll;

        let mut pending_ingress: Option<Vec<u8>> = None;

        // --- Diagnostic counters ---
        let mut ingress_delivered: u64 = 0; // packets pushed into stack
        let mut ingress_flush_pending: u64 = 0; // times poll_flush returned Pending
        let mut ingress_ready_pending: u64 = 0; // times poll_ready returned Pending
        let mut egress_produced: u64 = 0; // packets emitted by stack
        let mut egress_dropped: u64 = 0; // egress_tx.try_send failures

        let stats_timer = tokio::time::sleep(std::time::Duration::from_secs(10));
        tokio::pin!(stats_timer);

        futures_util::future::poll_fn(|cx| {
            // --- Periodic stats ---
            if stats_timer.as_mut().poll(cx).is_ready() {
                info!(
                    "Stack driver: ingress_delivered={}, egress_produced={}, egress_dropped={}, \
                     flush_pending={}, ready_pending={}, pending_ingress={}",
                    ingress_delivered, egress_produced, egress_dropped,
                    ingress_flush_pending, ingress_ready_pending, pending_ingress.is_some(),
                );
                stats_timer.as_mut().reset(
                    tokio::time::Instant::now() + std::time::Duration::from_secs(10),
                );
            }

            // --- Egress: drain stack output → bounded egress channel ---
            loop {
                match Pin::new(&mut stack).poll_next(cx) {
                    Poll::Ready(Some(Ok(pkt))) => {
                        egress_produced += 1;
                        if egress_tx.try_send(pkt.to_vec()).is_err() {
                            egress_dropped += 1;
                            warn!("Egress channel full, dropping packet ({} bytes)", pkt.len());
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
                                ingress_delivered += 1;
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
                                    Poll::Pending => {
                                        ingress_flush_pending += 1;
                                        break; // sink busy
                                    }
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                error!("Stack sink error: {}", e);
                                return Poll::Ready(());
                            }
                            Poll::Pending => {
                                ingress_ready_pending += 1;
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
                    ingress_flush_pending += 1;
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
        info!(
            "Stack driver ended. Final stats: ingress_delivered={}, egress_produced={}, \
             egress_dropped={}, flush_pending={}, ready_pending={}",
            ingress_delivered, egress_produced, egress_dropped,
            ingress_flush_pending, ingress_ready_pending,
        );
    });

    // Task 3 — Egress writer: bounded channel → transport.
    let egress = tokio::spawn(async move {
        let mut count: u64 = 0;
        while let Some(pkt) = egress_rx.recv().await {
            count += 1;
            if let Err(e) = peer_sink.send(pkt).await {
                error!("Transport write error after {} packets: {}", count, e);
                break;
            }
        }
        info!("Egress writer ended. Packets sent to transport: {}", count);
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

/// Returns `true` if the address belongs to a private, loopback, link-local,
/// or otherwise non-public IP range that should not be reachable through the tunnel.
fn is_local_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            o[0] == 0                                           // 0.0.0.0/8
                || o[0] == 10                                   // 10.0.0.0/8
                || (o[0] == 100 && (o[1] & 0xC0) == 64)        // 100.64.0.0/10
                || ip == Ipv4Addr::LOCALHOST                    // fast path
                || o[0] == 127                                  // 127.0.0.0/8
                || (o[0] == 169 && o[1] == 254)                 // 169.254.0.0/16
                || (o[0] == 172 && (o[1] & 0xF0) == 16)        // 172.16.0.0/12
                || (o[0] == 192 && o[1] == 168)                 // 192.168.0.0/16
                || (o[0] & 0xF0) == 224                         // 224.0.0.0/4 multicast
                || (o[0] & 0xF0) == 240                         // 240.0.0.0/4 reserved + broadcast
        }
        IpAddr::V6(ip) => {
            ip == Ipv6Addr::LOCALHOST                            // ::1
                || (ip.segments()[0] & 0xFE00) == 0xFC00        // fc00::/7  (ULA)
                || (ip.segments()[0] & 0xFFC0) == 0xFE80        // fe80::/10 (link-local)
        }
    }
}

async fn handle_tcp_streams(mut tcp_listener: TcpListener, protector: SocketProtector, block_local: bool) {
    while let Some((mut stream, local, remote)) = tcp_listener.next().await {
        if block_local && is_local_address(remote.ip()) {
            warn!("blocked TCP connection to local address: {:?} => {:?}", local, remote);
            continue;
        }
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
    if let Some(f) = protector {
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

async fn handle_inbound_datagram(udp_socket: netstack_smoltcp::UdpSocket, protector: SocketProtector, block_local: bool) {
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
                if block_local && is_local_address(remote.ip()) {
                    warn!("blocked UDP datagram to local address: {:?} => {:?}", local, remote);
                    continue;
                }
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
    if let Some(f) = protector {
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
pub(crate) async fn start_tunnel(transport: IpTransport, protector: SocketProtector, cancel: CancellationToken, block_local: bool) -> io::Result<()> {
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
    let w_tcp = tokio::spawn(handle_tcp_streams(tcp_listener, protector.clone(), block_local));
    let w_udp = tokio::spawn(handle_inbound_datagram(udp_socket, protector, block_local));

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

