use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
};

use futures::Stream;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{
        CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
    },
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv6Address, TcpPacket},
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender},
        Notify,
    },
};
use tracing::{error, trace};

use crate::{
    device::VirtualDevice,
    packet::{AnyIpPktFrame, IpPacket},
    Runner,
};

// smoltcp fixes a socket's buffer sizes at creation (no resize API), and the
// receive buffer IS the advertised TCP window — so the size chosen at SYN
// time is that flow's throughput ceiling for its whole life. 320 KiB over a
// 100 ms RTT path supports ~26 Mbit/s per flow, which matches the tunnel's
// measured single-flow rates. (The `0x3FFF * 20` figure is inherited from
// upstream's shadowsocks lineage — "20 AEAD chunks" — but survives on this
// window arithmetic, not on its origin.)
const LARGE_TCP_BUFFER_SIZE: u32 = 0x3FFF * 20;

// Fallback socket-buffer size once LARGE allocations have exhausted
// TCP_BUFFER_BUDGET: enough for handshakes, request/response traffic, and
// slow transfers (~2.6 Mbit/s at 100 ms RTT), so a burst of new flows
// degrades to modest windows instead of unbounded memory or refusal.
const SMALL_TCP_BUFFER_SIZE: u32 = 32 * 1024;

// Ledger budget for smoltcp socket buffers, incremented at admission and
// released when the socket is reaped. New sockets get LARGE buffer pairs
// while the ledger has room — the calm-exit common case, where per-flow
// throughput must not regress — and SMALL pairs beyond it (a storm of new
// flows is exactly when generous windows matter least). ~52 concurrent
// LARGE flows fit; a busy-but-sane exit rarely has more than a handful
// moving data at once.
const TCP_BUFFER_BUDGET: usize = 32 * 1024 * 1024;

// The userland relay rings (`TcpSocketControl`) start here and grow on
// demand (x4 when full, one preserved-content copy per step) toward the
// socket's own buffer size — a ring larger than the window buys nothing.
// Flows that never move bulk data (dial-and-abandon attempts, DNS-ish
// request/response) stay at this size for their whole life.
const INITIAL_RING_BUFFER_SIZE: usize = 16 * 1024;

// A flood of distinct-4-tuple SYNs from the untrusted peer still needs a
// socket-count bound (each socket also costs a slot, a task and an outbound
// dial); at the cap, further SYNs are dropped (smoltcp answers with RST).
// With the buffer ledger above, worst-case TCP buffer memory is
// TCP_BUFFER_BUDGET + MAX_TCP_SOCKETS x (2 x SMALL + rings) ≈ 56 MiB —
// versus ~340 MiB when every socket eagerly took four LARGE buffers.
const MAX_TCP_SOCKETS: usize = 256;

// A freshly-accepted (half-open) socket gets a short idle timeout so a SYN that
// never completes the handshake is reaped quickly and its slot freed; once the
// connection is established the timeout is raised to the generous value below so
// long-lived idle-but-alive connections (kept warm by keep-alive) aren't killed.
const HALF_OPEN_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(30);
const ESTABLISHED_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(7200);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    /// On-demand growth ceiling for `send_buffer` (the socket's send-buffer
    /// size; see `grow_ring`).
    max_send_ring: usize,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    /// On-demand growth ceiling for `recv_buffer`.
    max_recv_ring: usize,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
}

/// Grow `ring` in place (x4, capped at `max`), preserving its queued bytes.
/// Returns false when the ring is already at `max` — the caller then applies
/// backpressure exactly as it would have against a fixed-size ring. The
/// copy is at most `max` bytes, paid once per growth step by the sustained
/// flow that forced it.
fn grow_ring(ring: &mut RingBuffer<'static, u8>, max: usize) -> bool {
    let cap = ring.capacity();
    if cap >= max {
        return false;
    }
    let mut grown = RingBuffer::new(vec![0u8; (cap * 4).min(max)]);
    loop {
        let n = {
            let chunk = ring.dequeue_many(usize::MAX);
            if chunk.is_empty() {
                break;
            }
            grown.enqueue_slice(chunk)
        };
        debug_assert!(n > 0, "grown ring must absorb the old content");
    }
    *ring = grown;
    true
}

/// Warn (rate-limited to one line per 5 s, with a dropped-since count) that
/// the socket cap refused a SYN. Per-drop detail stays at trace.
fn report_syn_drop(src_addr: SocketAddr, dst_addr: SocketAddr) {
    use std::sync::atomic::AtomicU64;
    use std::time::{SystemTime, UNIX_EPOCH};
    static DROPPED: AtomicU64 = AtomicU64::new(0);
    static LAST_WARN_SECS: AtomicU64 = AtomicU64::new(0);

    trace!(
        "TCP socket cap ({}) reached; dropping SYN {} -> {}",
        MAX_TCP_SOCKETS, src_addr, dst_addr
    );
    DROPPED.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_WARN_SECS.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 5
        && LAST_WARN_SECS
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let count = DROPPED.swap(0, Ordering::Relaxed);
        tracing::warn!(
            "TCP socket cap ({}) reached: {} SYN(s) refused (RST) since last report — \
             new TCP connections through the tunnel are failing (latest {} -> {})",
            MAX_TCP_SOCKETS,
            count,
            src_addr,
            dst_addr
        );
    }
}

/// Total smoltcp buffer bytes (both buffers together) for a socket admitted
/// while the ledger sits at `used`: a LARGE pair while the budget has room,
/// a SMALL pair beyond it.
fn admission_buf_bytes(used: usize) -> usize {
    let large = 2 * LARGE_TCP_BUFFER_SIZE as usize;
    if used + large <= TCP_BUFFER_BUDGET {
        large
    } else {
        2 * SMALL_TCP_BUFFER_SIZE as usize
    }
}

struct TcpSocketCreation {
    control: SharedControl,
    socket: TcpSocket<'static>,
    flow: Flow,
    /// smoltcp buffer bytes charged to the ledger for this socket; released
    /// when the socket is reaped.
    buf_bytes: usize,
}

/// A TCP connection 4-tuple: (source addr, dest addr). Used to both cap the
/// number of live sockets and dedup retransmitted SYNs.
type Flow = (SocketAddr, SocketAddr);
/// The set of live connection 4-tuples, shared between the packet task (which
/// admits new SYNs) and the socket task (which releases them on close).
type LiveFlows = Arc<Mutex<HashSet<Flow>>>;

type SharedNotify = Arc<Notify>;
type SharedControl = Arc<SpinMutex<TcpSocketControl>>;

struct TcpListenerRunner;

impl TcpListenerRunner {
    fn create(
        device: VirtualDevice,
        iface: Interface,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        sockets: HashMap<SocketHandle, SharedControl>,
    ) -> Runner {
        Runner::new(async move {
            let notify = Arc::new(Notify::new());
            let (socket_tx, socket_rx) = unbounded_channel::<TcpSocketCreation>();
            // Live connection 4-tuples, shared so the packet task can both cap
            // the number of sockets and skip a duplicate (retransmitted) SYN,
            // and the socket task can release them on close.
            let live_flows: LiveFlows = Arc::new(Mutex::new(HashSet::new()));
            // smoltcp buffer-byte ledger: the packet task charges it at
            // admission (and tiers new sockets by it), the socket task
            // releases it on reap.
            let buffer_bytes = Arc::new(AtomicUsize::new(0));
            let res = tokio::select! {
                v = Self::handle_packet(notify.clone(), iface_ingress_tx, iface_ingress_tx_avail.clone(), tcp_rx, stream_tx, socket_tx, live_flows.clone(), buffer_bytes.clone()) => v,
                v = Self::handle_socket(notify, device, iface, iface_ingress_tx_avail, sockets, socket_rx, live_flows, buffer_bytes) => v,
            };
            res?;
            trace!("VirtDevice::poll thread exited");
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_packet(
        notify: SharedNotify,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        socket_tx: UnboundedSender<TcpSocketCreation>,
        live_flows: LiveFlows,
        buffer_bytes: Arc<AtomicUsize>,
    ) -> std::io::Result<()> {
        while let Some(frame) = tcp_rx.recv().await {
            let packet = match IpPacket::new_checked(frame.as_slice()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP IP packet: {:?}", err,);
                    continue;
                }
            };

            // Specially handle icmp packet by TCP interface.
            if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                iface_ingress_tx
                    .send(frame)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                iface_ingress_tx_avail.store(true, Ordering::Release);
                notify.notify_one();
                continue;
            }

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match TcpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, payload: {payload:?}");
                    continue;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            // TCP first handshake packet, create a new Connection
            if packet.syn() && !packet.ack() {
                let flow: Flow = (src_addr, dst_addr);
                // Admit the SYN only if it's a genuinely new 4-tuple and we're
                // under the socket cap. Two reasons to skip socket creation here:
                //  - Duplicate (retransmitted) SYN: normal whenever a SYN-ACK is
                //    lost on this product's lossy WAN. smoltcp delivers the
                //    retransmit to the existing socket, so creating a second one
                //    leaks ~1.3 MiB + a socket + a duplicate outbound dial.
                //  - Cap: each socket pins ~1.3 MiB, so a flood of distinct SYNs
                //    could exhaust memory.
                // In both cases the frame is still forwarded below (to the
                // existing socket, or so smoltcp answers RST at the cap).
                let admit = {
                    let mut flows = live_flows.lock().unwrap();
                    if flows.contains(&flow) {
                        trace!("duplicate SYN {} -> {}, forwarding to existing socket", src_addr, dst_addr);
                        false
                    } else if flows.len() >= MAX_TCP_SOCKETS {
                        // At the cap every new connection is refused (RST):
                        // an exit-wide outage for new TCP while it lasts.
                        // That must be loud — the September 2026 stall went
                        // undiagnosed for weeks because this was a trace! —
                        // but rate-limited, because the same condition fires
                        // per refused SYN during a storm.
                        report_syn_drop(src_addr, dst_addr);
                        false
                    } else {
                        flows.insert(flow);
                        true
                    }
                };
                if !admit {
                    iface_ingress_tx
                        .send(frame)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                    iface_ingress_tx_avail.store(true, Ordering::Release);
                    notify.notify_one();
                    continue;
                }
                // Tier this socket's buffers by ledger pressure: LARGE while
                // the budget has room (the calm-exit common case — per-flow
                // throughput must not regress), SMALL beyond it (a burst of
                // new flows costs bounded memory instead of ~1.3 MiB each).
                let buf_bytes = admission_buf_bytes(buffer_bytes.load(Ordering::Relaxed));
                let per_buf = buf_bytes / 2;
                if per_buf == SMALL_TCP_BUFFER_SIZE as usize {
                    trace!(
                        "TCP buffer budget exhausted; small buffers for {} -> {}",
                        src_addr,
                        dst_addr
                    );
                }
                buffer_bytes.fetch_add(buf_bytes, Ordering::Relaxed);
                let mut socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0u8; per_buf]),
                    TcpSocketBuffer::new(vec![0u8; per_buf]),
                );
                socket.set_keep_alive(Some(Duration::from_secs(28)));
                // Short timeout until the handshake completes (reaps a SYN that
                // never finishes); raised to ESTABLISHED_TIMEOUT once the
                // connection is established (see handle_socket).
                socket.set_timeout(Some(HALF_OPEN_TIMEOUT));
                // NO ACK delay
                // socket.set_ack_delay(None);
                // Use Cubic instead of smoltcp's default (no congestion
                // control). These sockets terminate the tunneled TCP and
                // re-originate it from the share host; with no controller the
                // sender ran open-loop at a fixed window, leaving shaped/lossy
                // links badly under-utilized.
                socket.set_congestion_control(CongestionControl::Cubic);

                if let Err(err) = socket.listen(dst_addr) {
                    error!("listen error: {:?}", err);
                    // The socket never reaches the socket task, so its
                    // admission must be unwound here: the flow entry (which
                    // was leaked on this path before the ledger existed) and
                    // the buffer bytes just charged.
                    live_flows.lock().unwrap().remove(&flow);
                    buffer_bytes.fetch_sub(buf_bytes, Ordering::Relaxed);
                    continue;
                }

                trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

                let initial_ring = INITIAL_RING_BUFFER_SIZE.min(per_buf);
                let control = Arc::new(SpinMutex::new(TcpSocketControl {
                    send_buffer: RingBuffer::new(vec![0u8; initial_ring]),
                    max_send_ring: per_buf,
                    send_waker: None,
                    recv_buffer: RingBuffer::new(vec![0u8; initial_ring]),
                    max_recv_ring: per_buf,
                    recv_waker: None,
                    recv_state: TcpSocketState::Normal,
                    send_state: TcpSocketState::Normal,
                }));

                stream_tx
                    .send(TcpStream {
                        src_addr,
                        dst_addr,
                        notify: notify.clone(),
                        control: control.clone(),
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                socket_tx
                    .send(TcpSocketCreation {
                        control,
                        socket,
                        flow,
                        buf_bytes,
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            }

            // Pipeline tcp stream packet
            iface_ingress_tx
                .send(frame)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            iface_ingress_tx_avail.store(true, Ordering::Release);
            notify.notify_one();
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_socket(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut sockets: HashMap<SocketHandle, SharedControl>,
        mut socket_rx: UnboundedReceiver<TcpSocketCreation>,
        live_flows: LiveFlows,
        buffer_bytes: Arc<AtomicUsize>,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);
        // Maps each live socket back to its flow (released from `live_flows`,
        // which caps and dedups admissions, when it closes) and its ledger
        // charge (released from `buffer_bytes` at the same moment).
        let mut socket_flows: HashMap<SocketHandle, (Flow, usize)> = HashMap::new();
        loop {
            while let Ok(TcpSocketCreation {
                control,
                socket,
                flow,
                buf_bytes,
            }) = socket_rx.try_recv()
            {
                let handle = socket_set.add(socket);
                sockets.insert(handle, control);
                socket_flows.insert(handle, (flow, buf_bytes));
            }

            let before_poll = Instant::now();
            let updated_sockets = iface.poll(before_poll, &mut device, &mut socket_set);
            if matches!(
                updated_sockets,
                smoltcp::iface::PollResult::SocketStateChanged
            ) {
                trace!("VirtDevice::poll costed {}", Instant::now() - before_poll);
            }

            // Check all the sockets' status
            let mut sockets_to_remove = Vec::new();

            for (socket_handle, control) in sockets.iter() {
                let socket_handle = *socket_handle;
                let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                let mut control = control.lock();

                // Once the handshake completes, grant the generous idle timeout
                // (a half-open SYN keeps the short HALF_OPEN_TIMEOUT it was
                // created with, so a never-completing SYN is reaped quickly).
                if socket.state() == TcpState::Established
                    && socket.timeout() != Some(ESTABLISHED_TIMEOUT)
                {
                    socket.set_timeout(Some(ESTABLISHED_TIMEOUT));
                }

                // Drain readable data FIRST, *before* the closed-socket removal
                // below. A socket can reach Closed with a tail still buffered in
                // smoltcp — a [data, FIN] or [data, RST] burst processed in one
                // iface.poll, or backpressure that filled our recv_buffer. The
                // old order removed the socket before this drain, dropping that
                // tail and reporting a clean EOF (the read-side analogue of the
                // write-side half-close truncation fixed in 84685b8).
                let mut wake_receiver = false;
                while socket.can_recv() {
                    if control.recv_buffer.is_full() {
                        let max = control.max_recv_ring;
                        if !grow_ring(&mut control.recv_buffer, max) {
                            break;
                        }
                    }
                    let result = socket.recv(|buffer| {
                        let n = control.recv_buffer.enqueue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_receiver = true,
                        Err(err) => {
                            error!("socket recv error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.recv_state, TcpSocketState::Normal) {
                                control.recv_state = TcpSocketState::Closed;
                            }
                            wake_receiver = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                // Remove a Closed socket only once it is fully drained (or the
                // reader is gone). If smoltcp still holds data but our
                // recv_buffer filled and the reader is still consuming
                // (recv_state Normal), keep the socket and wake the reader:
                // poll_read notifies us as it frees recv_buffer, so the tail
                // drains over the next polls. recv_state stays Normal until then,
                // so the reader doesn't see a premature EOF (poll_read only
                // reports EOF once recv_buffer is empty and recv_state Closed).
                // The Normal check also bounds this: if the reader dropped, its
                // Drop set recv_state to Close, so we remove instead of leaking.
                if socket.state() == TcpState::Closed {
                    if socket.can_recv() && matches!(control.recv_state, TcpSocketState::Normal) {
                        if let Some(waker) = control.recv_waker.take() {
                            waker.wake();
                        }
                    } else {
                        sockets_to_remove.push(socket_handle);
                        control.send_state = TcpSocketState::Closed;
                        control.recv_state = TcpSocketState::Closed;
                        if let Some(waker) = control.send_waker.take() {
                            waker.wake();
                        }
                        if let Some(waker) = control.recv_waker.take() {
                            waker.wake();
                        }
                        trace!("closed TCP connection");
                    }
                    continue;
                }

                // SHUT_WR is handled AFTER the writable drain below — closing
                // here would move the socket to FIN-WAIT (can_send() == false)
                // before the still-buffered tail is pushed into smoltcp,
                // silently truncating the stream.

                // If socket is not in ESTABLISH, FIN-WAIT-1, FIN-WAIT-2,
                // the local client have closed our receiver.
                let states = [
                    TcpState::Listen,
                    TcpState::SynReceived,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::FinWait2,
                ];
                if matches!(control.recv_state, TcpSocketState::Normal)
                    && !socket.may_recv()
                    && !states.contains(&socket.state())
                {
                    trace!("closed TCP Read Half, {:?}", socket.state());

                    // Let TcpStream::poll_read returns EOF.
                    control.recv_state = TcpSocketState::Closed;
                    wake_receiver = true;
                }

                if wake_receiver && control.recv_waker.is_some() {
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                }

                // Check if writable
                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    let result = socket.send(|buffer| {
                        let n = control.send_buffer.dequeue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_sender = true,
                        Err(err) => {
                            error!("socket send error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.send_state, TcpSocketState::Normal) {
                                control.send_state = TcpSocketState::Closed;
                            }
                            wake_sender = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                // SHUT_WR: everything the writer handed us is now in smoltcp's
                // tx buffer, so it is safe to send the FIN. (Deferred from
                // above so the drain loop isn't skipped — see the note there.)
                if matches!(control.send_state, TcpSocketState::Close)
                    && control.send_buffer.is_empty()
                {
                    trace!("closing TCP Write Half (drained), {:?}", socket.state());
                    socket.close();
                    control.send_state = TcpSocketState::Closing;
                    wake_sender = true;
                }

                if wake_sender && control.send_waker.is_some() {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }
            }

            if !sockets_to_remove.is_empty() {
                let mut flows = live_flows.lock().unwrap();
                for socket_handle in &sockets_to_remove {
                    if let Some((flow, buf_bytes)) = socket_flows.remove(socket_handle) {
                        flows.remove(&flow);
                        buffer_bytes.fetch_sub(buf_bytes, Ordering::Relaxed);
                    }
                }
            }
            for socket_handle in sockets_to_remove {
                sockets.remove(&socket_handle);
                socket_set.remove(socket_handle);
            }

            let next_delay = if iface_ingress_tx_avail.load(Ordering::Acquire) {
                Some(Duration::ZERO)
            } else {
                iface.poll_delay(before_poll, &socket_set)
            };
            match next_delay {
                Some(d) if d == Duration::ZERO => {
                    // poll_delay == 0 (or ingress is waiting) means smoltcp wants
                    // to run again immediately — most importantly when it has data
                    // to send but device.transmit() returned None because the
                    // egress channel is full. Busy-spinning here starves the very
                    // tasks that drain that channel (the egress writer and the
                    // QUIC driver), which deadlocks the share side at 100% CPU,
                    // stops all forwarding, and makes the process ignore SIGINT
                    // (fixed in 63a87f8). Yield cooperatively so egress drains.
                    tokio::task::yield_now().await;
                }
                Some(d) => {
                    // Wait until the next smoltcp timer (retransmit/keepalive/
                    // timeout), or until a notify wakes us earlier.
                    let _ = tokio::time::timeout(
                        tokio::time::Duration::from(d),
                        notify.notified(),
                    )
                    .await;
                }
                None => {
                    // No pending timer at all (idle connected session). Park on
                    // the wake source instead of busy-ticking at ~200 Hz (the old
                    // unwrap_or(5ms)), which woke every 5 ms to re-scan all
                    // sockets under the spin lock — pure idle CPU/battery cost.
                    // notify.notify_one() fires on every rerun-triggering event
                    // (inbound packet, stream read/write, socket create/close),
                    // and tokio Notify is permit-based, so a notify racing this
                    // await is not lost.
                    notify.notified().await;
                }
            }
        }
    }
}

pub struct TcpListener {
    stream_rx: UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub(super) fn new(
        tcp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
    ) -> std::io::Result<(Runner, Self)> {
        let (mut device, iface_ingress_tx, iface_ingress_tx_avail) = VirtualDevice::new(stack_tx);
        let iface = Self::create_interface(&mut device)?;

        let (stream_tx, stream_rx) = unbounded_channel();

        let runner = TcpListenerRunner::create(
            device,
            iface,
            iface_ingress_tx,
            iface_ingress_tx_avail,
            tcp_rx,
            stream_tx,
            HashMap::new(),
        );

        Ok((runner, Self { stream_rx }))
    }

    fn create_interface<D>(device: &mut D) -> std::io::Result<Interface>
    where
        D: Device + ?Sized,
    {
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface.set_any_ip(true);
        Ok(iface)
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx).map(|stream| {
            stream.map(|stream| {
                let local_addr = *stream.local_addr();
                let remote_addr: SocketAddr = *stream.remote_addr();
                (stream, local_addr, remote_addr)
            })
        })
    }
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: SharedNotify,
    control: SharedControl,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut control = self.control.lock();

        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }

        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        self.notify.notify_one();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dst_addr
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        // Read from buffer
        if control.recv_buffer.is_empty() {
            // If socket is already closed / half closed, just return EOF directly.
            if matches!(control.recv_state, TcpSocketState::Closed) {
                return Ok(()).into();
            }

            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf = unsafe {
            std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(buf.unfilled_mut())
        };
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(()).into()
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut control = self.control.lock();

        // If state == Close | Closing | Closed, the TCP stream WR half is closed.
        if !matches!(control.send_state, TcpSocketState::Normal) {
            return Err(std::io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer, growing the ring toward its ceiling before
        // resorting to backpressure.

        if control.send_buffer.is_full() {
            let max = control.max_send_ring;
            if !grow_ring(&mut control.send_buffer, max) {
                if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                    if !old_waker.will_wake(cx.waker()) {
                        old_waker.wake();
                    }
                }

                return Poll::Pending;
            }
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        if matches!(control.send_state, TcpSocketState::Closed) {
            return Ok(()).into();
        }

        // SHUT_WR
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        self.notify.notify_one();

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::MAX_TCP_SOCKETS;
    use crate::StackBuilder;
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;

    // Ring growth must preserve queued bytes across the old ring's wrap
    // point, and stop at the ceiling.
    #[test]
    fn ring_growth_preserves_wrapped_content() {
        use smoltcp::storage::RingBuffer;
        let mut ring = RingBuffer::new(vec![0u8; 8]);
        assert_eq!(ring.enqueue_slice(&[1, 2, 3, 4, 5, 6]), 6);
        let mut head = [0u8; 4];
        assert_eq!(ring.dequeue_slice(&mut head), 4);
        // Wraps: [5, 6] at the tail, [7..11] around the front.
        assert_eq!(ring.enqueue_slice(&[7, 8, 9, 10, 11]), 5);

        assert!(super::grow_ring(&mut ring, 32));
        assert_eq!(ring.capacity(), 32);
        let mut rest = [0u8; 16];
        let n = ring.dequeue_slice(&mut rest);
        assert_eq!(&rest[..n], &[5, 6, 7, 8, 9, 10, 11]);

        assert!(!super::grow_ring(&mut ring, 32), "at the ceiling");
    }

    // The admission tier flips from LARGE to SMALL exactly when one more
    // LARGE pair would overrun the budget.
    #[test]
    fn buffer_tier_flips_at_the_budget() {
        let large = 2 * super::LARGE_TCP_BUFFER_SIZE as usize;
        let small = 2 * super::SMALL_TCP_BUFFER_SIZE as usize;
        assert_eq!(super::admission_buf_bytes(0), large);
        assert_eq!(
            super::admission_buf_bytes(super::TCP_BUFFER_BUDGET - large),
            large
        );
        assert_eq!(
            super::admission_buf_bytes(super::TCP_BUFFER_BUDGET - large + 1),
            small
        );
    }

    /// A bare IPv4 TCP SYN for a distinct 4-tuple.
    fn syn_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
            .tcp(src_port, dst_port, 0, 64240)
            .syn();
        let mut out = Vec::with_capacity(builder.size(0));
        builder.write(&mut out, &[]).unwrap();
        out
    }

    // A flood of distinct-4-tuple SYNs from the untrusted peer must not create
    // an unbounded number of sockets: creation stops at MAX_TCP_SOCKETS, so the
    // host's TCP-buffer memory is bounded. Each accepted SYN emits exactly one
    // TcpStream, so counting them counts the sockets created.
    #[tokio::test]
    async fn syn_flood_is_capped() {
        let (mut stack, runner, _udp, tcp_listener) =
            StackBuilder::default().enable_tcp(true).build().unwrap();
        let mut tcp_listener = tcp_listener.unwrap();
        tokio::spawn(runner.unwrap());

        // Feed well past the cap. The TCP channel (512) holds these without
        // backpressure, and half-open sockets don't close during the test, so
        // the cap is never relieved mid-run.
        let total = MAX_TCP_SOCKETS + 32;
        for i in 0..total {
            let pkt = syn_packet(20000 + i as u16, 30000 + i as u16);
            stack.send(pkt).await.unwrap();
        }

        // Drain every emitted stream; the loop ends when no new stream arrives
        // within the grace window (the surplus SYNs created nothing).
        let mut created = 0usize;
        while tokio::time::timeout(Duration::from_millis(300), tcp_listener.next())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            created += 1;
        }

        assert_eq!(
            created, MAX_TCP_SOCKETS,
            "socket creation must stop at the cap, got {created}"
        );
    }

    // A retransmitted SYN (same 4-tuple, e.g. after a lost SYN-ACK on the lossy
    // WAN) must not create a second socket/stream/outbound dial.
    #[tokio::test]
    async fn retransmitted_syn_creates_one_socket() {
        let (mut stack, runner, _udp, tcp_listener) =
            StackBuilder::default().enable_tcp(true).build().unwrap();
        let mut tcp_listener = tcp_listener.unwrap();
        tokio::spawn(runner.unwrap());

        // Same 4-tuple, sent four times.
        let syn = syn_packet(20000, 30000);
        for _ in 0..4 {
            stack.send(syn.clone()).await.unwrap();
        }

        let mut created = 0usize;
        while tokio::time::timeout(Duration::from_millis(300), tcp_listener.next())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            created += 1;
        }
        assert_eq!(created, 1, "a retransmitted SYN must not create a second socket");
    }
}
