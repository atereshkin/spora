use crate::IpTransport;
use futures_util::SinkExt;
use futures_util::stream::StreamExt;
use log::{debug, error, info, trace};
use std::io;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How often to emit aggregate tunnel stats at debug level.
const STATS_INTERVAL_SECS: u64 = 30;

/// Summarise an IPv4 packet for trace logging.
fn describe_ip_packet(pkt: &[u8]) -> String {
    if pkt.len() < 20 {
        return format!("too short ({} bytes)", pkt.len());
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return format!("IPv{} ({} bytes)", version, pkt.len());
    }
    let proto = pkt[9];
    let src = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let proto_str = match proto {
        1 => {
            if pkt.len() > ihl {
                let icmp_type = pkt[ihl];
                match icmp_type {
                    0 => "ICMP EchoReply".into(),
                    8 => "ICMP EchoRequest".into(),
                    _ => format!("ICMP type={}", icmp_type),
                }
            } else {
                "ICMP".into()
            }
        }
        6 => {
            if pkt.len() >= ihl + 4 {
                let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                format!("TCP {}→{}", sport, dport)
            } else {
                "TCP".into()
            }
        }
        17 => {
            if pkt.len() >= ihl + 4 {
                let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                format!("UDP {}→{}", sport, dport)
            } else {
                "UDP".into()
            }
        }
        _ => format!("proto={}", proto),
    };
    format!("{} {}→{} ({} bytes)", proto_str, src, dst, pkt.len())
}

/// Counters for periodic aggregate stats.
struct TunnelStats {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    last_report: Instant,
}

impl TunnelStats {
    fn new() -> Self {
        Self {
            rx_packets: 0,
            rx_bytes: 0,
            tx_packets: 0,
            tx_bytes: 0,
            last_report: Instant::now(),
        }
    }

    fn record_rx(&mut self, bytes: usize) {
        self.rx_packets += 1;
        self.rx_bytes += bytes as u64;
    }

    fn record_tx(&mut self, bytes: usize) {
        self.tx_packets += 1;
        self.tx_bytes += bytes as u64;
    }

    fn maybe_report(&mut self) {
        let elapsed = self.last_report.elapsed();
        if elapsed.as_secs() >= STATS_INTERVAL_SECS {
            debug!(
                "Tunnel stats ({}s): rx {} pkts/{} bytes, tx {} pkts/{} bytes",
                elapsed.as_secs(),
                self.rx_packets,
                self.rx_bytes,
                self.tx_packets,
                self.tx_bytes,
            );
            self.rx_packets = 0;
            self.rx_bytes = 0;
            self.tx_packets = 0;
            self.tx_bytes = 0;
            self.last_report = Instant::now();
        }
    }
}

pub async fn start(
    mut transport: IpTransport,
    mut tun: impl AsyncReadExt + AsyncWriteExt + Unpin,
) -> io::Result<()> {
    let mut buffer = vec![0u8; 1500];
    let mut stats = TunnelStats::new();

    loop {
        tokio::select! {
            res = transport.next() => {
                match res {
                    Some(Ok(pkt)) => {
                        trace!("tunnel ← peer: {}", describe_ip_packet(&pkt));
                        stats.record_rx(pkt.len());
                        // Use write() not write_all(): TUN writes are
                        // packet-atomic — one write() = one IP packet.
                        // write_all() retries partial writes, which doesn't
                        // work on packet-oriented devices.
                        if let Err(e) = tun.write(&pkt).await {
                            error!("Error writing packet to tun device: {}", e)
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading from transport: {}", e);
                    }
                    None => {
                        info!("Transport stream closed.");
                        break;
                    }
                }
            }
            res = tun.read(&mut buffer) => {
                match res {
                    Ok(n) if n > 0 => {
                        trace!("tunnel → peer: {}", describe_ip_packet(&buffer[..n]));
                        stats.record_tx(n);
                        if let Err(e) = transport.send(buffer[..n].to_vec()).await {
                            error!("Error sending packet to remote peer: {}", e);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Normal for non-blocking TUN fds (Android); just retry.
                    }
                    Err(e) => {
                        error!("Error reading from tun device: {}", e);
                    }
                    Ok(_) =>  {
                        info!("Tun device closed.");
                        break
                    }
                }
            }
        }
        stats.maybe_report();
    }
    Ok(())
}

/// Like `start`, but takes a raw file descriptor instead of an async I/O object.
///
/// `tokio::fs::File` can't be used for TUN devices because it calls `seek()`
/// internally before every write (to track cursor position across its thread
/// pool), which fails with ESPIPE on non-seekable fds.  Instead, we use
/// `std::fs::File` on dedicated OS threads — plain `read()`/`write()` syscalls
/// with no seeking.
///
/// We share a single fd via `Arc<File>` rather than `try_clone()` (which calls
/// `dup()`), because Android TUN fds don't work correctly after dup.
#[cfg(unix)]
pub async fn start_fd(transport: IpTransport, fd: std::os::fd::OwnedFd) -> io::Result<()> {
    start_fd_inner(transport, fd, false).await
}

/// Like [`start_fd`], but for Apple `utun` descriptors, which frame every
/// packet with a 4-byte protocol-family header (`AF_INET`/`AF_INET6` in
/// network byte order). Reads strip the header; writes prepend it, choosing
/// the family from the IP version nibble. Used by the macOS/iOS
/// NetworkExtension packet tunnel, whose provider hands us a `utun` fd.
#[cfg(unix)]
pub async fn start_fd_utun(transport: IpTransport, fd: std::os::fd::OwnedFd) -> io::Result<()> {
    start_fd_inner(transport, fd, true).await
}

/// utun's per-packet protocol-family header, chosen from the IP version.
/// Darwin expects the family as a 4-byte big-endian value (e.g. `[0,0,0,2]`
/// for `AF_INET`); the header must be written in the same `write()` as the
/// packet body.
#[cfg(unix)]
fn utun_af_header(pkt: &[u8]) -> [u8; 4] {
    let af = match pkt.first().map(|b| b >> 4) {
        Some(6) => libc::AF_INET6 as u32,
        _ => libc::AF_INET as u32,
    };
    af.to_be_bytes()
}

#[cfg(unix)]
async fn start_fd_inner(
    mut transport: IpTransport,
    fd: std::os::fd::OwnedFd,
    utun_prefix: bool,
) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    let file = Arc::new(std::fs::File::from(fd));

    // Channel: TUN reader thread → async transport writer
    let (tun_read_tx, mut tun_read_rx) = mpsc::channel::<Vec<u8>>(64);
    // Channel: async transport reader → TUN writer thread
    let (tun_write_tx, tun_write_rx) = mpsc::channel::<Vec<u8>>(64);

    // TUN reader thread — blocks on read(), sends packets to async world.
    // Uses `impl Read for &File` (shared ref) so no dup() needed.
    let reader_file = file.clone();
    let reader = std::thread::Builder::new()
        .name("tun-read".into())
        .spawn(move || {
            use std::os::fd::AsRawFd;
            let raw_fd = reader_file.as_raw_fd();
            // Room for a 1500-byte MTU plus utun's 4-byte AF header.
            let mut buf = vec![0u8; 2048];
            loop {
                // Wait for the fd to become readable instead of busy-looping
                // on WouldBlock.  The 100ms timeout lets us detect shutdown
                // (channel receiver dropped) without sleeping forever.
                let mut pfd = libc::pollfd {
                    fd: raw_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
                if ret < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    error!("TUN poll error: {}", e);
                    break;
                }
                if ret == 0 {
                    // Timeout — check if the async side dropped the receiver.
                    if tun_read_tx.is_closed() {
                        break;
                    }
                    continue;
                }
                // POLLERR/POLLHUP/POLLNVAL without POLLIN means the fd is gone.
                if pfd.revents & libc::POLLIN == 0 {
                    break;
                }
                match (&*reader_file).read(&mut buf) {
                    Ok(0) => break, // TUN closed
                    Ok(n) => {
                        // utun frames every packet with a 4-byte AF header;
                        // strip it so the transport carries bare IP packets.
                        let payload = if utun_prefix {
                            if n <= 4 {
                                continue;
                            }
                            &buf[4..n]
                        } else {
                            &buf[..n]
                        };
                        if tun_read_tx.blocking_send(payload.to_vec()).is_err() {
                            break; // receiver dropped
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        })
        .map_err(|e| io::Error::other(format!("failed to spawn tun-read thread: {}", e)))?;

    // TUN writer thread — receives packets from async world, blocks on write().
    // Uses `impl Write for &File` (shared ref) so no dup() needed.
    let writer_file = file;
    let writer = std::thread::Builder::new()
        .name("tun-write".into())
        .spawn({
            let mut tun_write_rx = tun_write_rx;
            move || {
                // Reused framing buffer for utun (AF header + packet in one write).
                let mut framed = Vec::with_capacity(2048);
                while let Some(pkt) = tun_write_rx.blocking_recv() {
                    let out: &[u8] = if utun_prefix {
                        framed.clear();
                        framed.extend_from_slice(&utun_af_header(&pkt));
                        framed.extend_from_slice(&pkt);
                        &framed
                    } else {
                        &pkt
                    };
                    if let Err(e) = (&*writer_file).write(out) {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            error!("TUN write error: {}", e);
                        }
                    }
                }
            }
        })
        .map_err(|e| io::Error::other(format!("failed to spawn tun-write thread: {}", e)))?;

    // Bridge between transport and TUN channels.
    let mut stats = TunnelStats::new();
    loop {
        tokio::select! {
            res = transport.next() => {
                match res {
                    Some(Ok(pkt)) => {
                        trace!("tunnel ← peer: {}", describe_ip_packet(&pkt));
                        stats.record_rx(pkt.len());
                        if tun_write_tx.send(pkt).await.is_err() {
                            info!("TUN writer thread exited.");
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading from transport: {}", e);
                    }
                    None => {
                        info!("Transport stream closed.");
                        break;
                    }
                }
            }
            pkt = tun_read_rx.recv() => {
                match pkt {
                    Some(data) => {
                        trace!("tunnel → peer: {}", describe_ip_packet(&data));
                        stats.record_tx(data.len());
                        if let Err(e) = transport.send(data).await {
                            error!("Error sending packet to remote peer: {}", e);
                        }
                    }
                    None => {
                        info!("TUN reader thread exited.");
                        break;
                    }
                }
            }
        }
        stats.maybe_report();
    }

    // Drop channels to signal threads to exit, then wait.
    drop(tun_write_tx);
    drop(tun_read_rx);
    let _ = reader.join();
    let _ = writer.join();

    Ok(())
}
