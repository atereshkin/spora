use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
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

// NOTE: Default buffer could contain 20 AEAD packets
const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 0x3FFF * 20;
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 0x3FFF * 20;

// Each accepted SYN allocates four buffers of the sizes above (~1.3 MiB total)
// before any handshake completes, and the inbound packets come from an untrusted
// peer. Cap the number of concurrently-tracked sockets so a flood of
// distinct-4-tuple SYNs can't exhaust host memory; at the cap, further SYNs are
// dropped (smoltcp answers with RST). 256 bounds worst-case TCP buffer memory to
// ~340 MiB while leaving generous headroom for real concurrent flows.
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
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
}

struct TcpSocketCreation {
    control: SharedControl,
    socket: TcpSocket<'static>,
    flow: Flow,
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
            let res = tokio::select! {
                v = Self::handle_packet(notify.clone(), iface_ingress_tx, iface_ingress_tx_avail.clone(), tcp_rx, stream_tx, socket_tx, live_flows.clone()) => v,
                v = Self::handle_socket(notify, device, iface, iface_ingress_tx_avail, sockets, socket_rx, live_flows) => v,
            };
            res?;
            trace!("VirtDevice::poll thread exited");
            Ok(())
        })
    }

    async fn handle_packet(
        notify: SharedNotify,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        socket_tx: UnboundedSender<TcpSocketCreation>,
        live_flows: LiveFlows,
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
                        trace!("TCP socket cap ({}) reached; dropping SYN {} -> {}", MAX_TCP_SOCKETS, src_addr, dst_addr);
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
                let mut socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0u8; DEFAULT_TCP_RECV_BUFFER_SIZE as usize]),
                    TcpSocketBuffer::new(vec![0u8; DEFAULT_TCP_SEND_BUFFER_SIZE as usize]),
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
                    continue;
                }

                trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

                let control = Arc::new(SpinMutex::new(TcpSocketControl {
                    send_buffer: RingBuffer::new(vec![0u8; DEFAULT_TCP_SEND_BUFFER_SIZE as usize]),
                    send_waker: None,
                    recv_buffer: RingBuffer::new(vec![0u8; DEFAULT_TCP_RECV_BUFFER_SIZE as usize]),
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
                    .send(TcpSocketCreation { control, socket, flow })
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

    async fn handle_socket(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut sockets: HashMap<SocketHandle, SharedControl>,
        mut socket_rx: UnboundedReceiver<TcpSocketCreation>,
        live_flows: LiveFlows,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);
        // Maps each live socket back to its flow so we can release it from
        // `live_flows` (which caps and dedups admissions) when it closes.
        let mut socket_flows: HashMap<SocketHandle, Flow> = HashMap::new();
        loop {
            while let Ok(TcpSocketCreation { control, socket, flow }) = socket_rx.try_recv() {
                let handle = socket_set.add(socket);
                sockets.insert(handle, control);
                socket_flows.insert(handle, flow);
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
                while socket.can_recv() && !control.recv_buffer.is_full() {
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
                    if let Some(flow) = socket_flows.remove(socket_handle) {
                        flows.remove(&flow);
                    }
                }
            }
            for socket_handle in sockets_to_remove {
                sockets.remove(&socket_handle);
                socket_set.remove(socket_handle);
            }

            let next_duration = if iface_ingress_tx_avail.load(Ordering::Acquire) {
                Duration::ZERO
            } else {
                iface
                    .poll_delay(before_poll, &socket_set)
                    .unwrap_or(Duration::from_millis(5))
            };
            if next_duration != Duration::ZERO {
                let _ = tokio::time::timeout(
                    tokio::time::Duration::from(next_duration),
                    notify.notified(),
                )
                .await;
            } else {
                // poll_delay == 0 (or ingress is waiting) means smoltcp wants
                // to run again immediately — most importantly when it has data
                // to send but device.transmit() returned None because the
                // egress channel is full. Busy-spinning here starves the very
                // tasks that drain that channel (the egress writer and the
                // QUIC driver), which deadlocks the share side at 100% CPU,
                // stops all forwarding, and makes the process ignore SIGINT.
                // Yield cooperatively so those tasks run and egress drains.
                tokio::task::yield_now().await;
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

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
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
