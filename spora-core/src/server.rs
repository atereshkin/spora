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
    // The peer's tunnel IPv4-fragments any inbound datagram larger than the
    // QUIC max_datagram_size; the netstack can't reassemble, so we do it here
    // before the packets reach the stack (see crate::reassembly).
    let ingress = tokio::spawn(async move {
        let mut count: u64 = 0;
        let mut reassembler = crate::reassembly::IpReassembler::new();
        'outer: while let Some(res) = peer_stream.next().await {
            match res {
                Ok(pkt) => {
                    count += 1;
                    for whole in reassembler.process(pkt, std::time::Instant::now()) {
                        if ingress_tx.send(whole).is_err() {
                            break 'outer;
                        }
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
                        // `pkt` is already an owned Vec<u8>; move it into the
                        // channel instead of cloning (this is the highest-rate
                        // copy on the share side — every download-direction
                        // datagram). On a full channel try_send hands the Vec
                        // back inside the error and we drop it, exactly as before.
                        let len = pkt.len();
                        if egress_tx.try_send(pkt).is_err() {
                            egress_dropped += 1;
                            warn!("Egress channel full, dropping packet ({} bytes)", len);
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
pub fn is_local_address(addr: IpAddr) -> bool {
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

async fn handle_tcp_streams(
    mut tcp_listener: TcpListener,
    protector: SocketProtector,
    block_local: bool,
    cancel: CancellationToken,
) {
    while let Some((mut stream, local, remote)) = tcp_listener.next().await {
        if block_local && is_local_address(remote.ip()) {
            warn!("blocked TCP connection to local address: {:?} => {:?}", local, remote);
            continue;
        }
        let protector = protector.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            info!("new tcp connection: {:?} => {:?}", local, remote);
            // Race the proxy against teardown so the connection (and its OS
            // socket) is dropped when the session ends, rather than leaking.
            tokio::select! {
                _ = cancel.cancelled() => {}
                r = async {
                    match new_tcp_stream(remote, &protector).await {
                        Ok(mut remote_stream) => {
                            // pipe between two tcp stream
                            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut remote_stream).await {
                                warn!("failed to copy tcp stream {:?}=>{:?}, err: {:?}", local, remote, e);
                            }
                        }
                        Err(e) => warn!("failed to new tcp stream {:?}=>{:?}, err: {:?}", local, remote, e),
                    }
                } => { let () = r; }
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
/// Cap on concurrently-tracked UDP NAT flows. Each entry is a real OS socket
/// (an fd) plus a recv task, so an untrusted client spraying distinct
/// destination tuples could otherwise exhaust file descriptors before the 30s
/// idle sweep reclaims anything. At the cap we evict the least-recently-active
/// flow, so a flood sheds idle entries while live flows (which refresh their
/// timestamp) survive.
const MAX_UDP_NAT_ENTRIES: usize = 256;

struct NATEntry {
    socket: Arc<UdpSocket>,
    task: JoinHandle<()>,
    last_activity: Instant,
}

async fn handle_inbound_datagram(
    udp_socket: netstack_smoltcp::UdpSocket,
    protector: SocketProtector,
    block_local: bool,
    cancel: CancellationToken,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut read_half, mut write_half) = udp_socket.split();
    let writer_cancel = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = writer_cancel.cancelled() => {}
            _ = async {
                while let Some((data, local, remote)) = rx.recv().await {
                    let _ = write_half.send((data, remote, local)).await;
                }
            } => {}
        }
    });

    let mut entries: HashMap<NATKey, NATEntry> = HashMap::new();
    let mut sweep_interval = tokio::time::interval(UDP_NAT_SWEEP_INTERVAL);

    loop {
        tokio::select! {
            packet = read_half.next() => {
                // netstack-smoltcp's UDP `ReadHalf` yields `None` for BOTH a
                // genuinely closed channel AND any datagram that fails to
                // parse (`UdpPacket::new_checked` — e.g. a truncated or
                // fragmented UDP packet). Treating that as end-of-stream used
                // to drop this task, which closed the Stack's UDP channel and
                // tore the entire tunnel down on the next UDP packet. Skip the
                // bad datagram and keep going instead; real shutdown is driven
                // by `start_tunnel` aborting this task when the tunnel ends.
                let Some((data, local, remote)) = packet else { continue };
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
                            let recv_cancel = cancel.clone();
                            let task = tokio::spawn(async move {
                                // Stop on teardown so the OS socket + task are
                                // released, not leaked, when the session ends.
                                tokio::select! {
                                    _ = recv_cancel.cancelled() => {}
                                    _ = async {
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
                                    } => {}
                                }
                            });
                            let _ = socket.send(&data).await;
                            insert_bounded(
                                &mut entries,
                                key,
                                NATEntry {
                                    socket,
                                    task,
                                    last_activity: Instant::now(),
                                },
                                MAX_UDP_NAT_ENTRIES,
                            );
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

/// Insert a new UDP NAT entry, evicting the least-recently-active one first if
/// the table is at `cap`. Bounds fds/tasks against a client spraying distinct
/// destination tuples; live flows refresh `last_activity` so a flood sheds idle
/// entries rather than active ones.
fn insert_bounded(entries: &mut HashMap<NATKey, NATEntry>, key: NATKey, entry: NATEntry, cap: usize) {
    if !entries.contains_key(&key)
        && entries.len() >= cap
        && let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, e)| e.last_activity)
            .map(|(k, _)| *k)
        && let Some(evicted) = entries.remove(&oldest)
    {
        evicted.task.abort();
        trace!("UDP NAT table full, evicted {:?} => {:?}", oldest.0, oldest.1);
    }
    entries.insert(key, entry);
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

    // Cancels every per-flow task (TCP copy loops, UDP writer + NAT recv tasks)
    // on teardown. The handlers' own tasks are aborted below, but the per-flow
    // tasks they spawn are detached, so without this they'd leak (sockets + tasks)
    // every time a session ends.
    let flow_cancel = CancellationToken::new();

    let w_tunnel = tokio::spawn(run_tunnel(transport, stack));
    let w_tunnel_abort = w_tunnel.abort_handle();
    let w_tcp = tokio::spawn(handle_tcp_streams(
        tcp_listener,
        protector.clone(),
        block_local,
        flow_cancel.clone(),
    ));
    let w_udp = tokio::spawn(handle_inbound_datagram(
        udp_socket,
        protector,
        block_local,
        flow_cancel.clone(),
    ));

    // `run_tunnel` owns the tunnel's lifecycle. The TCP/UDP NAT handlers and
    // the smoltcp runner are subordinate: when the tunnel driver ends (peer
    // gone, transport closed) or the session is cancelled, abort them all.
    // They no longer self-terminate on channel close (the UDP handler now
    // skips bad datagrams), so teardown has to be driven from here.
    let mut subordinate_aborts = vec![w_tcp.abort_handle(), w_udp.abort_handle()];
    if let Some(h) = runner_handle.as_ref() {
        subordinate_aborts.push(h.abort_handle());
    }

    tokio::select! {
        _ = cancel.cancelled() => {
            info!("Tunnel cancelled, aborting tasks");
            w_tunnel_abort.abort();
        }
        _ = w_tunnel => {
            info!("Tunnel driver ended, tearing down tunnel tasks");
        }
    }
    // Stop the detached per-flow tasks first, then abort the handler loops.
    flow_cancel.cancel();
    for h in &subordinate_aborts {
        h.abort();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::IpTransport;
    use crate::transport::mock::{mock_transport, MockTransportHandle};
    use std::time::Duration;

    #[tokio::test]
    async fn udp_nat_table_evicts_least_recently_active_at_cap() {
        async fn entry(ts: Instant) -> NATEntry {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            NATEntry {
                socket,
                task: tokio::spawn(std::future::pending::<()>()),
                last_activity: ts,
            }
        }
        let key = |port: u16| {
            NATKey(
                "127.0.0.1:1000".parse().unwrap(),
                format!("10.0.0.1:{port}").parse().unwrap(),
            )
        };

        let t0 = Instant::now();
        let mut entries: HashMap<NATKey, NATEntry> = HashMap::new();
        // Fill to the (small) cap; key(10) is the least recently active.
        insert_bounded(&mut entries, key(10), entry(t0).await, 3);
        insert_bounded(&mut entries, key(11), entry(t0 + Duration::from_secs(1)).await, 3);
        insert_bounded(&mut entries, key(12), entry(t0 + Duration::from_secs(2)).await, 3);
        assert_eq!(entries.len(), 3);

        // A distinct new tuple at the cap evicts the oldest, not a live one.
        insert_bounded(&mut entries, key(13), entry(t0 + Duration::from_secs(3)).await, 3);
        assert_eq!(entries.len(), 3, "table stays bounded");
        assert!(!entries.contains_key(&key(10)), "least-recently-active evicted");
        assert!(entries.contains_key(&key(13)), "new flow inserted");
        assert!(entries.contains_key(&key(11)) && entries.contains_key(&key(12)));

        // Refreshing an existing key never evicts.
        insert_bounded(&mut entries, key(11), entry(t0 + Duration::from_secs(4)).await, 3);
        assert_eq!(entries.len(), 3);
    }

    fn icmp_echo_request(id: u16, seq: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .icmpv4_echo_request(id, seq)
            .write(&mut pkt, b"ping")
            .unwrap();
        pkt
    }

    fn is_icmp_echo_reply(pkt: &[u8]) -> bool {
        pkt.len() >= 24 && (pkt[0] >> 4) == 4 && pkt[9] == 1 && pkt[20] == 0
    }

    /// A valid IPv4 UDP packet (to a dst the netstack will just NAT out).
    fn valid_udp(dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .udp(40000, dst_port)
            .write(&mut pkt, b"hi")
            .unwrap();
        pkt
    }

    /// A packet whose IPv4 header is valid (so the Stack routes it to the UDP
    /// channel by protocol) but whose UDP portion is too short to parse —
    /// `UdpPacket::new_checked` rejects it. This is what a truncated or
    /// fragmented UDP datagram looks like when the whole default route is
    /// tunnelled, and it's exactly the packet that crashed the share side.
    fn malformed_udp() -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x18, // IPv4, IHL=5, total length = 24
            0x00, 0x00, 0x00, 0x00, // id, flags/frag
            0x40, 0x11, 0x00, 0x00, // TTL=64, proto=17 (UDP), checksum=0
            10, 0, 0, 2, // src
            10, 0, 0, 1, // dst
            0xDE, 0xAD, 0xBE, 0xEF, // 4 bytes — shorter than the 8-byte UDP header
        ]
    }

    async fn recv_icmp_reply(
        handle: &mut MockTransportHandle,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        tokio::time::timeout(timeout, async {
            loop {
                match handle.recv().await {
                    Some(pkt) if is_icmp_echo_reply(&pkt) => return Some(pkt),
                    Some(_) => continue,
                    None => return None,
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// Regression test: a single unparseable UDP datagram must not tear down
    /// the whole tunnel. Reproduces the share-side crash where one bad UDP
    /// packet ended `handle_inbound_datagram`, closing the Stack's udp channel
    /// so the next UDP packet killed the stack driver.
    #[tokio::test]
    async fn malformed_udp_packet_does_not_kill_tunnel() {
        let _ = env_logger::builder().is_test(true).try_init();
        let (mock, mut handle) = mock_transport();
        let transport: IpTransport = Box::new(mock);
        let cancel = CancellationToken::new();
        let cancel_inner = cancel.clone();
        tokio::spawn(async move {
            let _ = start_tunnel(transport, None, cancel_inner, false).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 1. Tunnel is alive: ICMP echo gets a reply.
        handle.send(icmp_echo_request(0x1111, 1)).unwrap();
        assert!(
            recv_icmp_reply(&mut handle, Duration::from_secs(3)).await.is_some(),
            "tunnel should answer ICMP before the bad packet"
        );

        // 2. A malformed UDP packet arrives.
        handle.send(malformed_udp()).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 3. A subsequent valid UDP packet.
        handle.send(valid_udp(9999)).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 4. The tunnel must STILL answer ICMP. (A dead tunnel drops the
        //    transport, so even the send can fail — treat that as failure.)
        let alive = handle.send(icmp_echo_request(0x2222, 2)).is_ok()
            && recv_icmp_reply(&mut handle, Duration::from_secs(3))
                .await
                .is_some();
        assert!(
            alive,
            "tunnel stopped forwarding after a single malformed UDP packet"
        );

        cancel.cancel();
    }
}

