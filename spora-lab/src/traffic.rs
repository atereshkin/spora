//! Traffic drivers over the client's composed `IpTransport`.
//!
//! The pump OWNS the transport (single consumer): one task select-loops over
//! { commands, transport.next(), outbound queue } and dispatches inbound
//! packets — UDP to the in-flight echo session (match on inner dst port),
//! TCP into the smoltcp ingress queue, ICMP ignored (keepalive replies; the
//! share-side netstack answers pings locally).
//!
//! Drivers:
//! - **UDP echo**: crafts IPv4+UDP (or IPv6+UDP for a v6 server) via
//!   etherparse from [`crate::CLIENT_INNER_IP`] /
//!   [`crate::CLIENT_INNER_IP6`]:&lt;per-session port starting 40000&gt; to the
//!   server; the share netstack verifies lengths but not checksums
//!   client→share; replies arrive src=server, dst=our addr, TTL 20, valid
//!   checksums. Sends with light pacing (a few ms) — the share-side UDP NAT
//!   entry refreshes on outbound only. Echoes are matched by a 12-byte
//!   payload tag (sequence number + nonce) **prefix**, so responders that
//!   pad their replies (used to provoke share→client fragmentation) still
//!   match. Per-packet RTT min/avg/max/p50/p95 and loss are reported in
//!   [`EchoStats`].
//! - **TCP bulk**: a smoltcp `Interface` over a custom in-memory device
//!   (rx = queue fed by the pump, tx = drained straight into the transport
//!   sink after every `iface.poll`). Medium::Ip, device MTU 1100 (stays
//!   under the QUIC datagram floor ≈1162 so client→share packets never need
//!   IP fragmentation, which the share netstack cannot reassemble). Default
//!   `ChecksumCapabilities` (smoltcp computes/verifies — required by the
//!   share-side smoltcp). One socket, 64 KiB buffers, connect → send
//!   `bytes` while reading the echo back until all bytes round-trip →
//!   close. `iface.poll` is driven from the pump loop with
//!   `poll_delay`-based timers.
//! - **TCP download / upload** (perf suites): the same smoltcp machinery
//!   pointed at the wan source/sink services, so bulk data crosses the
//!   tunnel in ONE direction (the echo doubles every byte). Socket buffer
//!   sizes and congestion control (None vs Cubic) come from [`TcpOpts`];
//!   the default matches TcpBulk's historical 64 KiB / no-CC behavior.
//!   [`TrafficCmd::CpuTime`] reports the pump thread's CPU time
//!   (CLOCK_THREAD_CPUTIME_ID) for perf accounting.
//!
//! Both drivers tolerate unrelated inbound packets interleaving (keepalive
//! ICMP, stale echo replies, ...): everything inbound flows through a
//! [`Reassembler`] first — large UDP replies (share→client) arrive as IP
//! FRAGMENTS (IPv4, or the RFC 8200 Fragment header for IPv6) because the
//! tunnel fragments datagrams larger than the QUIC datagram budget and there
//! is no kernel on this side to reassemble them — and is then matched
//! against the in-flight session or dropped.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use smoltcp::time::Instant as SmolInstant;
use spora_core::IpTransport;

use crate::{CLIENT_INNER_IP, CLIENT_INNER_IP6};

/// Default gateway the smoltcp iface routes through — any address on the
/// inner /24 works (Medium::Ip has no neighbor resolution).
const INNER_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);

/// v6 counterpart of [`INNER_GATEWAY`]: any address on the inner /64 works,
/// for the same reason. Like [`crate::CLIENT_INNER_IP6`] it lives in a ULA
/// (fd00::/8) — the inner v6 net mirrors the RFC1918 inner v4 net, so lab
/// traffic can never alias globally routed space.
const INNER_GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0200, 0, 0, 0, 0, 0, 1);

/// First inner source port; one fresh port per traffic command so stale
/// share-side NAT entries from a previous session can never match.
const BASE_PORT: u16 = 40000;

/// Bytes of (sequence ‖ nonce) tag at the start of every echo payload.
const ECHO_TAG_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct EchoStats {
    pub sent: usize,
    pub received: usize,
    pub rtt_min: std::time::Duration,
    pub rtt_avg: std::time::Duration,
    pub rtt_max: std::time::Duration,
    /// Median per-packet RTT (nearest-rank percentile over received echoes).
    pub rtt_p50: std::time::Duration,
    /// 95th-percentile per-packet RTT.
    pub rtt_p95: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct BulkStats {
    pub bytes: usize,
    pub elapsed: std::time::Duration,
}

impl BulkStats {
    pub fn throughput_mbps(&self) -> f64 {
        (self.bytes as f64 * 8.0) / self.elapsed.as_secs_f64() / 1_000_000.0
    }
}

/// Per-command knobs for the smoltcp TCP socket used by [`TrafficCmd::TcpDownload`]
/// / [`TrafficCmd::TcpUpload`]. The defaults match the long-standing
/// [`TrafficCmd::TcpBulk`] behavior (64 KiB buffers, `CongestionControl::None`);
/// perf suites pass 512 KiB / 512 KiB / cubic so the client stack is not the
/// bottleneck being measured.
#[derive(Debug, Clone)]
pub struct TcpOpts {
    pub recv_buf: usize,
    pub send_buf: usize,
    pub cubic: bool,
}

impl Default for TcpOpts {
    fn default() -> Self {
        Self {
            recv_buf: 64 * 1024,
            send_buf: 64 * 1024,
            cubic: false,
        }
    }
}

/// Commands handled by the pump task (constructed in `peers::start_client`).
pub enum TrafficCmd {
    UdpEcho {
        server: std::net::SocketAddr,
        count: usize,
        payload_len: usize,
        respond: tokio::sync::oneshot::Sender<Result<EchoStats, String>>,
    },
    TcpBulk {
        server: std::net::SocketAddr,
        bytes: usize,
        respond: tokio::sync::oneshot::Sender<Result<BulkStats, String>>,
    },
    /// Download `bytes` from the wan TCP source service: connect, send the
    /// 8-byte big-endian request, receive exactly `bytes`. `elapsed` runs
    /// from connection establishment to the last byte.
    TcpDownload {
        server: std::net::SocketAddr,
        bytes: usize,
        opts: TcpOpts,
        respond: tokio::sync::oneshot::Sender<Result<BulkStats, String>>,
    },
    /// Upload `bytes` to the wan TCP sink service: connect, send, half-close
    /// (FIN), await the 8-byte big-endian count ack and verify it. `elapsed`
    /// runs from the first send to the ack.
    TcpUpload {
        server: std::net::SocketAddr,
        bytes: usize,
        opts: TcpOpts,
        respond: tokio::sync::oneshot::Sender<Result<BulkStats, String>>,
    },
    /// CPU time of the PUMP THREAD (`CLOCK_THREAD_CPUTIME_ID`). Handled
    /// inline on the pump task, so on the lab's current-thread host runtimes
    /// this is exactly the client-side tunnel + driver compute.
    CpuTime {
        respond: tokio::sync::oneshot::Sender<Result<Duration, String>>,
    },
    /// Send ONE tagged echo datagram and wait up to `grace` for its reply:
    /// `Ok(Some(rtt))` = echoed, `Ok(None)` = lost. The cheap primitive for
    /// probing "is the tunnel passing traffic right now" on a timeline
    /// (outage-window measurement) without `UdpEcho`'s 3s reply grace.
    UdpProbe {
        server: std::net::SocketAddr,
        grace: Duration,
        respond: tokio::sync::oneshot::Sender<Result<Option<Duration>, String>>,
    },
    /// One deliberately-abandoned inner TCP connection: complete the inner
    /// handshake toward `server` (the share's netstack admits the flow and
    /// starts its outbound dial), then immediately abort (RST) and walk away
    /// — the shape of an app giving up on a slow destination. `Ok(true)` =
    /// the handshake completed before the abort; `Ok(false)` = the netstack
    /// refused the SYN (RST or silence), which is what exhaustion of its
    /// session pool looks like from the client.
    TcpAbortedConnect {
        server: std::net::SocketAddr,
        respond: tokio::sync::oneshot::Sender<Result<bool, String>>,
    },
    /// Drop the composed transport chain while the host runtime is still
    /// alive and end the pump. Unlike host teardown (which drops the whole
    /// runtime mid-poll — abrupt, no clean close on the wire), this lets the
    /// transport's Drop path run and be polled: the upgradable router task
    /// notices, drops the carrier transport, and a clean close (QUIC
    /// CONNECTION_CLOSE(0) / nz CH_CLOSE) actually goes out. The respond
    /// fires after a short settle so the close datagram has left the socket.
    Shutdown {
        respond: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// The pump: owns the transport, serves `TrafficCmd`s. Runs inside the
/// client host runtime.
pub struct TrafficPump {
    transport: IpTransport,
    cmds: tokio::sync::mpsc::UnboundedReceiver<TrafficCmd>,
    next_port: u16,
    /// Set when the transport stream ends. The production client composition
    /// (ReconnectTransport) redials forever and never ends, so this only
    /// trips for bare compositions; commands then fail fast instead of
    /// timing out.
    dead: bool,
}

impl TrafficPump {
    pub fn new(
        transport: spora_core::IpTransport,
        cmds: tokio::sync::mpsc::UnboundedReceiver<TrafficCmd>,
    ) -> Self {
        Self {
            transport,
            cmds,
            next_port: BASE_PORT,
            dead: false,
        }
    }

    /// Run until the command channel closes, the transport dies, or a
    /// [`TrafficCmd::Shutdown`] asks for a clean close.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.cmds.recv() => {
                    let Some(cmd) = cmd else { return };
                    if let TrafficCmd::Shutdown { respond } = cmd {
                        // Swap the transport chain out and drop it on the
                        // live runtime; the sleep yields so the upgradable
                        // router task and the carrier's endpoint driver get
                        // polled and the clean-close datagram is flushed.
                        let transport =
                            std::mem::replace(&mut self.transport, Box::new(ClosedTransport));
                        drop(transport);
                        self.dead = true;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        let _ = respond.send(Ok(()));
                        return;
                    }
                    self.handle_cmd(cmd).await;
                }
                pkt = self.transport.next(), if !self.dead => {
                    match pkt {
                        // Idle inbound (keepalive echo replies, share-side
                        // pings, late echo replies): ignore.
                        Some(Ok(_)) => {}
                        Some(Err(e)) => log::warn!("pump: transport error while idle: {e}"),
                        None => {
                            log::warn!("pump: transport stream ended");
                            self.dead = true;
                        }
                    }
                }
            }
        }
    }

    async fn handle_cmd(&mut self, cmd: TrafficCmd) {
        match cmd {
            TrafficCmd::UdpEcho {
                server,
                count,
                payload_len,
                respond,
            } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.udp_echo(server, count, payload_len).await
                };
                let _ = respond.send(result);
            }
            TrafficCmd::TcpBulk {
                server,
                bytes,
                respond,
            } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.tcp_bulk(server, bytes).await
                };
                let _ = respond.send(result);
            }
            TrafficCmd::TcpDownload {
                server,
                bytes,
                opts,
                respond,
            } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.tcp_download(server, bytes, &opts).await
                };
                let _ = respond.send(result);
            }
            TrafficCmd::TcpUpload {
                server,
                bytes,
                opts,
                respond,
            } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.tcp_upload(server, bytes, &opts).await
                };
                let _ = respond.send(result);
            }
            TrafficCmd::CpuTime { respond } => {
                let _ = respond.send(thread_cpu_time());
            }
            TrafficCmd::UdpProbe {
                server,
                grace,
                respond,
            } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.udp_probe(server, grace).await
                };
                let _ = respond.send(result);
            }
            TrafficCmd::TcpAbortedConnect { server, respond } => {
                let result = if self.dead {
                    Err("transport is closed".to_string())
                } else {
                    self.tcp_aborted_connect(server).await
                };
                let _ = respond.send(result);
            }
            // Handled inline in `run` (it must end the pump loop).
            TrafficCmd::Shutdown { respond } => {
                let _ = respond.send(Err("shutdown must be handled by run()".into()));
            }
        }
    }

    fn alloc_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = self.next_port.wrapping_add(1).max(BASE_PORT);
        port
    }

    /// Send `count` UDP datagrams of `payload_len` bytes (min 12, the tag)
    /// to `server` and collect the echoes. Finishes when every echo is in,
    /// or 3s pass without progress after the last send.
    async fn udp_echo(
        &mut self,
        server: SocketAddr,
        count: usize,
        payload_len: usize,
    ) -> Result<EchoStats, String> {
        const PACING: Duration = Duration::from_millis(5);
        const REPLY_GRACE: Duration = Duration::from_secs(3);

        let local_port = self.alloc_port();
        let nonce = fresh_nonce();
        let mut reasm = Reassembler::default();

        let mut sent_at: Vec<Option<std::time::Instant>> = vec![None; count];
        let mut got = vec![false; count];
        let mut rtts: Vec<Duration> = Vec::with_capacity(count);
        let mut sent = 0usize;
        let mut received = 0usize;

        let mut pace = tokio::time::interval(PACING);
        pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut grace_deadline = tokio::time::Instant::now() + REPLY_GRACE;

        while received < count {
            let mut send_now = false;
            tokio::select! {
                _ = pace.tick(), if sent < count => send_now = true,
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && let Some(seq) = match_echo_reply(&full, server, local_port, nonce)
                        {
                            let seq = seq as usize;
                            if seq < count && !got[seq] {
                                got[seq] = true;
                                received += 1;
                                if let Some(at) = sent_at[seq] {
                                    rtts.push(at.elapsed());
                                }
                                grace_deadline = tokio::time::Instant::now() + REPLY_GRACE;
                            }
                        }
                    }
                    Some(Err(e)) => log::warn!("udp echo: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err(format!(
                            "transport closed mid-echo ({received}/{count} replies in)"
                        ));
                    }
                },
                _ = tokio::time::sleep_until(grace_deadline), if sent >= count => break,
            }
            if send_now {
                let pkt = build_echo_request(local_port, server, sent as u32, nonce, payload_len);
                self.transport
                    .send(pkt)
                    .await
                    .map_err(|e| format!("udp echo send: {e}"))?;
                sent_at[sent] = Some(std::time::Instant::now());
                sent += 1;
                grace_deadline = tokio::time::Instant::now() + REPLY_GRACE;
            }
        }

        rtts.sort_unstable();
        let rtt_min = rtts.first().copied().unwrap_or(Duration::ZERO);
        let rtt_max = rtts.last().copied().unwrap_or(Duration::ZERO);
        let rtt_avg = if rtts.is_empty() {
            Duration::ZERO
        } else {
            rtts.iter().sum::<Duration>() / rtts.len() as u32
        };
        Ok(EchoStats {
            sent,
            received,
            rtt_min,
            rtt_avg,
            rtt_max,
            rtt_p50: percentile(&rtts, 50.0),
            rtt_p95: percentile(&rtts, 95.0),
        })
    }

    /// Send one tagged echo datagram to `server` and wait up to `grace` for
    /// the reply. `Ok(Some(rtt))` on echo, `Ok(None)` on loss. Unrelated
    /// inbound (keepalives, stale replies from earlier probes — each probe
    /// gets a fresh port + nonce) is ignored.
    async fn udp_probe(
        &mut self,
        server: SocketAddr,
        grace: Duration,
    ) -> Result<Option<Duration>, String> {
        let local_port = self.alloc_port();
        let nonce = fresh_nonce();
        let mut reasm = Reassembler::default();

        let pkt = build_echo_request(local_port, server, 0, nonce, 32);
        self.transport
            .send(pkt)
            .await
            .map_err(|e| format!("udp probe send: {e}"))?;
        let sent_at = std::time::Instant::now();

        let deadline = tokio::time::Instant::now() + grace;
        loop {
            tokio::select! {
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && match_echo_reply(&full, server, local_port, nonce) == Some(0)
                        {
                            return Ok(Some(sent_at.elapsed()));
                        }
                    }
                    Some(Err(e)) => log::debug!("udp probe: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err("transport closed mid-probe".into());
                    }
                },
                _ = tokio::time::sleep_until(deadline) => return Ok(None),
            }
        }
    }

    /// Run a real TCP connection (smoltcp) against `server`, write `bytes`
    /// of a deterministic pattern and read the echo back, verifying content.
    async fn tcp_bulk(&mut self, server: SocketAddr, bytes: usize) -> Result<BulkStats, String> {
        use smoltcp::socket::tcp;

        /// Abort if neither direction makes progress for this long.
        const PROGRESS_TIMEOUT: Duration = Duration::from_secs(20);
        /// After all data round-tripped, wait at most this long for the
        /// close handshake before declaring victory anyway.
        const CLOSE_GRACE: Duration = Duration::from_secs(1);
        /// Floor for the poll_delay-based sleep so the progress timeout and
        /// retransmit timers are always re-checked.
        const MAX_IDLE: Duration = Duration::from_millis(20);

        let started = std::time::Instant::now();
        let local_port = self.alloc_port();

        // Default opts == the historical hardcoded behavior: 64 KiB buffers,
        // CongestionControl::None.
        let (mut device, mut iface, mut sockets, handle) =
            tcp_session(server, local_port, &TcpOpts::default())?;

        let data: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
        let mut scratch = vec![0u8; 16 * 1024];
        let mut written = 0usize;
        let mut echoed = 0usize;
        let mut fin_sent = false;
        let mut close_deadline: Option<tokio::time::Instant> = None;
        let mut reasm = Reassembler::default();
        let mut last_progress = std::time::Instant::now();

        loop {
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);

            // tx: push everything smoltcp produced straight into the tunnel.
            while let Some(frame) = device.tx.pop_front() {
                self.transport
                    .send(frame)
                    .await
                    .map_err(|e| format!("tcp bulk: transport send: {e}"))?;
            }

            {
                let sock = sockets.get_mut::<tcp::Socket>(handle);

                while sock.can_recv() && echoed < bytes {
                    let n = sock
                        .recv_slice(&mut scratch)
                        .map_err(|e| format!("tcp recv: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    let end = echoed + n;
                    if end > bytes || scratch[..n] != data[echoed..end] {
                        return Err(format!("tcp echo mismatch at offset {echoed}"));
                    }
                    echoed = end;
                    last_progress = std::time::Instant::now();
                }

                while sock.can_send() && written < bytes {
                    let n = sock
                        .send_slice(&data[written..])
                        .map_err(|e| format!("tcp send: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    written += n;
                    last_progress = std::time::Instant::now();
                }

                if echoed >= bytes && !fin_sent {
                    sock.close();
                    fin_sent = true;
                    close_deadline = Some(tokio::time::Instant::now() + CLOSE_GRACE);
                }

                let state = sock.state();
                if fin_sent && matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
                    break;
                }
                if !fin_sent && state == tcp::State::Closed {
                    return Err(format!(
                        "tcp connection closed early (wrote {written}, echoed {echoed} of {bytes})"
                    ));
                }
            }

            if let Some(d) = close_deadline
                && tokio::time::Instant::now() >= d
            {
                break; // all data verified; don't sweat the FIN handshake
            }
            if last_progress.elapsed() > PROGRESS_TIMEOUT {
                return Err(format!(
                    "tcp bulk stalled (wrote {written}, echoed {echoed} of {bytes})"
                ));
            }

            // Anything smoltcp scheduled (retransmits, delayed ACKs) bounds
            // the sleep; MAX_IDLE bounds it from above so the progress and
            // close deadlines are re-checked.
            let delay = iface
                .poll_delay(SmolInstant::now(), &sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(MAX_IDLE)
                .min(MAX_IDLE);
            if delay.is_zero() {
                continue; // smoltcp wants an immediate re-poll
            }

            tokio::select! {
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && is_session_tcp(&full, server, local_port)
                        {
                            device.rx.push_back(full);
                        }
                    }
                    Some(Err(e)) => log::warn!("tcp bulk: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err(format!(
                            "transport closed mid-bulk (echoed {echoed}/{bytes})"
                        ));
                    }
                },
                _ = tokio::time::sleep(delay) => {}
            }
        }

        Ok(BulkStats {
            bytes: echoed,
            elapsed: started.elapsed(),
        })
    }

    /// Download `bytes` from the wan TCP source service: send the 8-byte
    /// big-endian request, receive exactly `bytes` (content not verified —
    /// TCP checksums already cover integrity and the wan pattern is opaque
    /// here). `elapsed` runs from connection establishment to the last byte.
    async fn tcp_download(
        &mut self,
        server: SocketAddr,
        bytes: usize,
        opts: &TcpOpts,
    ) -> Result<BulkStats, String> {
        use smoltcp::socket::tcp;

        const PROGRESS_TIMEOUT: Duration = Duration::from_secs(20);
        const MAX_IDLE: Duration = Duration::from_millis(20);

        let local_port = self.alloc_port();
        let (mut device, mut iface, mut sockets, handle) = tcp_session(server, local_port, opts)?;

        let mut scratch = vec![0u8; 64 * 1024];
        let mut request_sent = false;
        let mut received = 0usize;
        let mut started: Option<std::time::Instant> = None; // set when established
        let mut elapsed: Option<Duration> = None;
        let mut reasm = Reassembler::default();
        let mut last_progress = std::time::Instant::now();

        loop {
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            while let Some(frame) = device.tx.pop_front() {
                self.transport
                    .send(frame)
                    .await
                    .map_err(|e| format!("tcp download: transport send: {e}"))?;
            }

            {
                let sock = sockets.get_mut::<tcp::Socket>(handle);

                if !request_sent && sock.can_send() {
                    // Connection just became established: the clock starts
                    // here, and the length request goes out first.
                    started = Some(std::time::Instant::now());
                    let n = sock
                        .send_slice(&(bytes as u64).to_be_bytes())
                        .map_err(|e| format!("tcp download: request send: {e}"))?;
                    if n != 8 {
                        return Err("tcp download: could not queue the 8-byte request".into());
                    }
                    request_sent = true;
                    last_progress = std::time::Instant::now();
                }

                while sock.can_recv() && received < bytes {
                    let want = scratch.len().min(bytes - received);
                    let n = sock
                        .recv_slice(&mut scratch[..want])
                        .map_err(|e| format!("tcp download recv: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    received += n;
                    last_progress = std::time::Instant::now();
                }

                if received >= bytes {
                    elapsed = Some(
                        started
                            .expect("bytes were received, so the connection was established")
                            .elapsed(),
                    );
                    sock.close();
                } else if sock.state() == tcp::State::Closed {
                    return Err(format!(
                        "tcp download: connection closed early ({received}/{bytes})"
                    ));
                }
            }

            if let Some(elapsed) = elapsed {
                // Best-effort: push the FIN/ACK we just queued, then finish —
                // the measurement is done, no need to sit out the handshake.
                iface.poll(SmolInstant::now(), &mut device, &mut sockets);
                while let Some(frame) = device.tx.pop_front() {
                    let _ = self.transport.send(frame).await;
                }
                return Ok(BulkStats {
                    bytes: received,
                    elapsed,
                });
            }
            if last_progress.elapsed() > PROGRESS_TIMEOUT {
                return Err(format!("tcp download stalled ({received}/{bytes})"));
            }

            let delay = iface
                .poll_delay(SmolInstant::now(), &sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(MAX_IDLE)
                .min(MAX_IDLE);
            if delay.is_zero() {
                continue;
            }

            tokio::select! {
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && is_session_tcp(&full, server, local_port)
                        {
                            device.rx.push_back(full);
                        }
                    }
                    Some(Err(e)) => log::warn!("tcp download: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err(format!(
                            "transport closed mid-download ({received}/{bytes})"
                        ));
                    }
                },
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// One abandoned inner TCP connection (see
    /// [`TrafficCmd::TcpAbortedConnect`]): SYN toward `server`, and the
    /// moment the handshake completes, close — FIN, the shape of an app
    /// calling `close()` and moving on — then drop the session without ever
    /// reading. The share-side netstack has by then admitted the flow and
    /// started its outbound dial; its socket sits in CLOSE_WAIT until the
    /// exit side closes its half, so whether the session-pool slot outlives
    /// the abandonment is exactly what the exit suite probes. (An RST abort
    /// would drive the netstack socket straight to Closed and free the slot
    /// immediately — a different, already-working path.) `Ok(false)` = the
    /// handshake never completed (RST back, or nothing within the deadline).
    async fn tcp_aborted_connect(&mut self, server: SocketAddr) -> Result<bool, String> {
        use smoltcp::socket::tcp;

        const DEADLINE: Duration = Duration::from_secs(3);
        const MAX_IDLE: Duration = Duration::from_millis(20);

        let local_port = self.alloc_port();
        let opts = TcpOpts::default();
        let (mut device, mut iface, mut sockets, handle) = tcp_session(server, local_port, &opts)?;
        let mut reasm = Reassembler::default();
        let start = std::time::Instant::now();
        let mut established = false;

        loop {
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            while let Some(frame) = device.tx.pop_front() {
                self.transport
                    .send(frame)
                    .await
                    .map_err(|e| format!("aborted connect: transport send: {e}"))?;
            }

            {
                let sock = sockets.get_mut::<tcp::Socket>(handle);
                if !established && sock.may_send() {
                    // Established. Orderly close (queues FIN) — then keep
                    // the session polling until the close handshake
                    // resolves, like a real client's KERNEL does after the
                    // app calls close(): the peer's FIN must be ACKed, or
                    // the share-side socket parks in LAST_ACK and the
                    // scenario measures a vanished host instead of an
                    // abandoning app.
                    established = true;
                    sock.close();
                }
                match sock.state() {
                    // Never established: the SYN was answered with RST —
                    // refused. Established: the teardown fully resolved.
                    tcp::State::Closed => return Ok(established),
                    // Both FINs exchanged and ACKed from the peer's point
                    // of view; flush our final ACK and finish.
                    tcp::State::TimeWait => {
                        iface.poll(SmolInstant::now(), &mut device, &mut sockets);
                        while let Some(frame) = device.tx.pop_front() {
                            let _ = self.transport.send(frame).await;
                        }
                        return Ok(true);
                    }
                    _ => {}
                }
            }

            if start.elapsed() > DEADLINE {
                return Ok(established);
            }

            let delay = iface
                .poll_delay(SmolInstant::now(), &sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(MAX_IDLE)
                .min(MAX_IDLE);
            if delay.is_zero() {
                continue;
            }

            tokio::select! {
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && is_session_tcp(&full, server, local_port)
                        {
                            device.rx.push_back(full);
                        }
                    }
                    Some(Err(e)) => log::warn!("aborted connect: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err("transport closed mid-connect".into());
                    }
                },
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// Upload `bytes` to the wan TCP sink service: send a deterministic
    /// pattern, half-close (FIN), await the sink's 8-byte big-endian byte
    /// count and verify it equals `bytes`. `elapsed` runs from the first
    /// send to the complete ack.
    async fn tcp_upload(
        &mut self,
        server: SocketAddr,
        bytes: usize,
        opts: &TcpOpts,
    ) -> Result<BulkStats, String> {
        use smoltcp::socket::tcp;

        const PROGRESS_TIMEOUT: Duration = Duration::from_secs(20);
        const MAX_IDLE: Duration = Duration::from_millis(20);

        let local_port = self.alloc_port();
        let (mut device, mut iface, mut sockets, handle) = tcp_session(server, local_port, opts)?;

        let data: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
        let mut written = 0usize;
        let mut fin_sent = false;
        let mut started: Option<std::time::Instant> = None; // first send
        let mut ack = [0u8; 8];
        let mut ack_len = 0usize;
        let mut elapsed: Option<Duration> = None;
        let mut reasm = Reassembler::default();
        let mut last_progress = std::time::Instant::now();

        loop {
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            while let Some(frame) = device.tx.pop_front() {
                self.transport
                    .send(frame)
                    .await
                    .map_err(|e| format!("tcp upload: transport send: {e}"))?;
            }

            {
                let sock = sockets.get_mut::<tcp::Socket>(handle);

                while sock.can_send() && written < bytes {
                    if started.is_none() {
                        started = Some(std::time::Instant::now());
                    }
                    let n = sock
                        .send_slice(&data[written..])
                        .map_err(|e| format!("tcp upload send: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    written += n;
                    last_progress = std::time::Instant::now();
                }

                if written >= bytes && !fin_sent && sock.may_send() {
                    if started.is_none() {
                        started = Some(std::time::Instant::now()); // bytes == 0 edge
                    }
                    sock.close(); // FIN goes out after the queued data drains
                    fin_sent = true;
                    last_progress = std::time::Instant::now();
                }

                // The sink's count ack stays readable even after the close
                // handshake races ahead: smoltcp keeps a non-empty rx buffer
                // receivable in any state.
                while sock.can_recv() && ack_len < 8 {
                    let n = sock
                        .recv_slice(&mut ack[ack_len..])
                        .map_err(|e| format!("tcp upload: ack recv: {e}"))?;
                    if n == 0 {
                        break;
                    }
                    ack_len += n;
                    last_progress = std::time::Instant::now();
                }

                if ack_len == 8 {
                    elapsed = Some(started.expect("the ack implies data was sent").elapsed());
                    let counted = u64::from_be_bytes(ack);
                    if counted != bytes as u64 {
                        return Err(format!(
                            "tcp upload: sink counted {counted} bytes, expected {bytes}"
                        ));
                    }
                } else if matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    // Remote FIN processed and rx drained: the rest of the
                    // ack can never arrive.
                    return Err(format!(
                        "tcp upload: connection closed before the count ack \
                         (wrote {written}/{bytes}, ack {ack_len}/8)"
                    ));
                }
            }

            if let Some(elapsed) = elapsed {
                // Best-effort final flush (ACK of the sink's FIN), then done.
                iface.poll(SmolInstant::now(), &mut device, &mut sockets);
                while let Some(frame) = device.tx.pop_front() {
                    let _ = self.transport.send(frame).await;
                }
                return Ok(BulkStats { bytes, elapsed });
            }
            if last_progress.elapsed() > PROGRESS_TIMEOUT {
                return Err(format!(
                    "tcp upload stalled (wrote {written}/{bytes}, ack {ack_len}/8)"
                ));
            }

            let delay = iface
                .poll_delay(SmolInstant::now(), &sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(MAX_IDLE)
                .min(MAX_IDLE);
            if delay.is_zero() {
                continue;
            }

            tokio::select! {
                pkt = self.transport.next() => match pkt {
                    Some(Ok(p)) => {
                        if let Some(full) = reasm.push(p)
                            && is_session_tcp(&full, server, local_port)
                        {
                            device.rx.push_back(full);
                        }
                    }
                    Some(Err(e)) => log::warn!("tcp upload: transport error: {e}"),
                    None => {
                        self.dead = true;
                        return Err(format!(
                            "transport closed mid-upload (wrote {written}/{bytes})"
                        ));
                    }
                },
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }
}

/// Build the smoltcp interface plus one TCP socket (already `connect`ed to
/// `server` from `local_port`) over a fresh [`SmolDevice`], applying `opts`'
/// buffer sizes and congestion control. Shared by TcpBulk / TcpDownload /
/// TcpUpload. The interface is dual-stack regardless of `server`'s family;
/// smoltcp picks the inner source ([`CLIENT_INNER_IP`] or
/// [`CLIENT_INNER_IP6`]) by route lookup.
#[allow(clippy::type_complexity)]
fn tcp_session(
    server: SocketAddr,
    local_port: u16,
    opts: &TcpOpts,
) -> Result<
    (
        SmolDevice,
        smoltcp::iface::Interface,
        smoltcp::iface::SocketSet<'static>,
        smoltcp::iface::SocketHandle,
    ),
    String,
> {
    use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
    use smoltcp::socket::tcp;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

    let mut device = SmolDevice::default();
    let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
    iface_cfg.random_seed = fresh_nonce();
    let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::now());
    // Mirror a host that owns both inner addresses: the v4 address on a /24,
    // the v6 ULA on a /64, a default route per family (Medium::Ip has no
    // neighbor resolution, so any on-link gateway works — same trick for
    // both), and any-ip (parity with the share-side stack).
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(CLIENT_INNER_IP), 24))
            .expect("first interface address always fits");
        addrs
            .push(IpCidr::new(IpAddress::Ipv6(CLIENT_INNER_IP6), 64))
            .expect("IFACE_MAX_ADDR_COUNT is 2: the v6 address fits");
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(INNER_GATEWAY)
        .map_err(|e| format!("default v4 route: {e}"))?;
    iface
        .routes_mut()
        .add_default_ipv6_route(INNER_GATEWAY6)
        .map_err(|e| format!("default v6 route: {e}"))?;

    let mut sockets = SocketSet::new(vec![]);
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; opts.recv_buf]),
        tcp::SocketBuffer::new(vec![0; opts.send_buf]),
    );
    if opts.cubic {
        sock.set_congestion_control(tcp::CongestionControl::Cubic);
    }
    let handle = sockets.add(sock);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::from(server.ip()), server.port()),
            local_port,
        )
        .map_err(|e| format!("tcp connect: {e}"))?;
    Ok((device, iface, sockets, handle))
}

/// CPU time consumed by the CALLING thread
/// (`clock_gettime(CLOCK_THREAD_CPUTIME_ID)`).
pub fn thread_cpu_time() -> Result<Duration, String> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } != 0 {
        return Err(format!(
            "clock_gettime(CLOCK_THREAD_CPUTIME_ID): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// Nearest-rank percentile over an ascending-sorted slice; ZERO when empty.
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// A random-enough u64 without a rand dependency: `RandomState` is seeded
/// from the OS per instance.
fn fresh_nonce() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// IP+UDP echo request from our inner address (the family follows `server`:
/// CLIENT_INNER_IP for v4, CLIENT_INNER_IP6 for v6) at `local_port`,
/// payload = [seq:4][nonce:8][0xA5 padding] (min 12 bytes).
fn build_echo_request(
    local_port: u16,
    server: SocketAddr,
    seq: u32,
    nonce: u64,
    payload_len: usize,
) -> Vec<u8> {
    let payload_len = payload_len.max(ECHO_TAG_LEN);
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.resize(payload_len, 0xA5);

    let mut pkt = Vec::with_capacity(48 + payload.len());
    match server {
        SocketAddr::V4(s) => {
            etherparse::PacketBuilder::ipv4(CLIENT_INNER_IP.octets(), s.ip().octets(), 64)
                .udp(local_port, s.port())
                .write(&mut pkt, &payload)
                .expect("writing a UDP packet into a Vec cannot fail");
        }
        SocketAddr::V6(s) => {
            etherparse::PacketBuilder::ipv6(CLIENT_INNER_IP6.octets(), s.ip().octets(), 64)
                .udp(local_port, s.port())
                .write(&mut pkt, &payload)
                .expect("writing a UDP packet into a Vec cannot fail");
        }
    }
    pkt
}

/// If `pkt` is a whole IP packet of `proto` (17 = UDP, 6 = TCP) from
/// `server`'s address to our inner address of the matching family, return
/// the offset of the transport header.
///
/// The v6 branch requires `next_header == proto` right in the fixed header —
/// the lab's own traffic carries no extension headers, and reassembled
/// fragments come out of the [`Reassembler`] with `next_header` restored to
/// the transport proto.
fn session_transport_offset(pkt: &[u8], server: SocketAddr, proto: u8) -> Option<usize> {
    match server {
        SocketAddr::V4(s) => {
            if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != proto {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return None;
            }
            (pkt[12..16] == s.ip().octets() && pkt[16..20] == CLIENT_INNER_IP.octets())
                .then_some(ihl)
        }
        SocketAddr::V6(s) => {
            if pkt.len() < 40 || pkt[0] >> 4 != 6 || pkt[6] != proto {
                return None;
            }
            (pkt[8..24] == s.ip().octets() && pkt[24..40] == CLIENT_INNER_IP6.octets())
                .then_some(40)
        }
    }
}

/// If `pkt` is a (whole) IP/UDP reply from `server` to our echo session,
/// return the sequence number from its payload tag. Matching is on the
/// 12-byte tag prefix so padded replies still count.
fn match_echo_reply(pkt: &[u8], server: SocketAddr, local_port: u16, nonce: u64) -> Option<u32> {
    let off = session_transport_offset(pkt, server, 17)?;
    if pkt.len() < off + 8 + ECHO_TAG_LEN {
        return None;
    }
    if u16::from_be_bytes([pkt[off], pkt[off + 1]]) != server.port()
        || u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) != local_port
    {
        return None;
    }
    let payload = &pkt[off + 8..];
    if payload[4..12] != nonce.to_be_bytes() {
        return None;
    }
    Some(u32::from_be_bytes(payload[0..4].try_into().unwrap()))
}

/// True if `pkt` is an IP/TCP segment belonging to the in-flight bulk
/// session (src = server, dst = our inner address:local_port).
fn is_session_tcp(pkt: &[u8], server: SocketAddr, local_port: u16) -> bool {
    let Some(off) = session_transport_offset(pkt, server, 6) else {
        return false;
    };
    pkt.len() >= off + 4
        && u16::from_be_bytes([pkt[off], pkt[off + 1]]) == server.port()
        && u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) == local_port
}

// ---------------------------------------------------------------------------
// IP fragment reassembly

/// Reassembles IP fragments (IPv4, and the IPv6 Fragment-header form the
/// tunnel emits) back into whole packets.
///
/// The tunnel fragments any inner IP packet larger than the QUIC datagram
/// budget (spora-core's QuicPeerTransport: RFC 791 fragments for v4, RFC
/// 8200 Fragment extension headers for v6), and there is no kernel on this
/// side of the transport to reassemble — so large UDP replies
/// (share→client) arrive as fragments. v4 fragments are grouped by the RFC
/// 791 key (src, dst, protocol, identification), v6 by (src, dst,
/// identification); chunks are ordered by fragment offset and completed
/// once the no-MF tail is present and every byte up to it is covered.
/// Non-fragments pass straight through.
#[derive(Default)]
pub struct Reassembler {
    partial: HashMap<FragKey, Partial>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum FragKey {
    /// RFC 791 reassembly key.
    V4 {
        src: [u8; 4],
        dst: [u8; 4],
        proto: u8,
        id: u16,
    },
    /// RFC 8200 reassembly key (the transport proto is not part of it —
    /// it travels in the Fragment header's `next_header` instead).
    V6 {
        src: [u8; 16],
        dst: [u8; 16],
        id: u32,
    },
}

/// One parsed fragment, family-independent: everything [`Reassembler::push`]
/// needs to file it into a [`Partial`].
struct Fragment {
    key: FragKey,
    /// Byte offset of this fragment's payload within the original payload.
    offset: usize,
    more_fragments: bool,
    /// The reassembled packet's IP header as carved from this fragment
    /// (v4: the IHL bytes verbatim; v6: the 40-byte fixed header with
    /// `next_header` already restored from the Fragment header). Only the
    /// offset-0 fragment's copy is kept.
    header: Vec<u8>,
    data: Vec<u8>,
}

struct Partial {
    /// payload chunks keyed by byte offset
    chunks: BTreeMap<usize, Vec<u8>>,
    /// total payload length, known once the no-MF tail arrives
    total: Option<usize>,
    /// IP header from the offset-0 fragment (see [`Fragment::header`])
    header: Option<Vec<u8>>,
    created: std::time::Instant,
}

/// Partial reassemblies older than this are evicted.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

impl Reassembler {
    /// Feed one inbound IP packet. Returns a complete packet — the input
    /// itself when it isn't a fragment, or the reassembled datagram when
    /// `pkt` completes one — or `None` while fragments are still pending.
    pub fn push(&mut self, pkt: Vec<u8>) -> Option<Vec<u8>> {
        let frag = match pkt.first().map(|b| b >> 4) {
            Some(4) => parse_fragment_v4(&pkt),
            Some(6) => parse_fragment_v6(&pkt),
            _ => None,
        };
        let Some(frag) = frag else {
            // Not a fragment (or malformed): pass through, callers ignore it.
            return Some(pkt);
        };

        self.partial
            .retain(|_, p| p.created.elapsed() < REASSEMBLY_TIMEOUT);

        let partial = self
            .partial
            .entry(frag.key.clone())
            .or_insert_with(|| Partial {
                chunks: BTreeMap::new(),
                total: None,
                header: None,
                created: std::time::Instant::now(),
            });
        if frag.offset == 0 {
            partial.header = Some(frag.header);
        }
        if !frag.more_fragments {
            partial.total = Some(frag.offset + frag.data.len());
        }
        partial.chunks.insert(frag.offset, frag.data);

        let assembled = partial.try_assemble();
        if assembled.is_some() {
            self.partial.remove(&frag.key);
        }
        assembled
    }
}

/// Parse `pkt` as an IPv4 FRAGMENT (MF set or a nonzero offset); `None` for
/// whole packets and anything malformed.
fn parse_fragment_v4(pkt: &[u8]) -> Option<Fragment> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let more_fragments = flags_frag & 0x2000 != 0;
    let offset = ((flags_frag & 0x1fff) as usize) * 8;
    if !more_fragments && offset == 0 {
        return None; // not fragmented
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None; // malformed
    }
    let total_field = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let end = total_field.clamp(ihl, pkt.len());
    Some(Fragment {
        key: FragKey::V4 {
            src: pkt[12..16].try_into().unwrap(),
            dst: pkt[16..20].try_into().unwrap(),
            proto: pkt[9],
            id: u16::from_be_bytes([pkt[4], pkt[5]]),
        },
        offset,
        more_fragments,
        header: pkt[..ihl].to_vec(),
        data: pkt[ihl..end].to_vec(),
    })
}

/// Parse `pkt` as an IPv6 packet carrying a Fragment extension header the
/// way the tunnel emits them (RFC 8200: the 40-byte fixed header with
/// `next_header` = 44, then the 8-byte Fragment header, then the payload
/// slice); `None` for non-fragments and anything malformed. The fixed
/// header copied out for reassembly gets `next_header` restored to the
/// transport proto from the Fragment header.
fn parse_fragment_v6(pkt: &[u8]) -> Option<Fragment> {
    if pkt.len() < 48 || pkt[0] >> 4 != 6 || pkt[6] != 44 {
        return None;
    }
    // Fragment header: next_header, reserved, offset/flags u16 BE (top 13
    // bits = offset in 8-byte units, bit 0 = M), identification u32 BE.
    let frag_field = u16::from_be_bytes([pkt[42], pkt[43]]);
    let offset = ((frag_field >> 3) as usize) * 8;
    let more_fragments = frag_field & 0x0001 != 0;
    let mut header = pkt[..40].to_vec();
    header[6] = pkt[40]; // restore the transport proto
    // payload_length covers the Fragment header (8 bytes) + the slice.
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let end = (40 + payload_len).clamp(48, pkt.len());
    Some(Fragment {
        key: FragKey::V6 {
            src: pkt[8..24].try_into().unwrap(),
            dst: pkt[24..40].try_into().unwrap(),
            id: u32::from_be_bytes(pkt[44..48].try_into().unwrap()),
        },
        offset,
        more_fragments,
        header,
        data: pkt[48..end].to_vec(),
    })
}

impl Partial {
    /// Build the whole packet if the tail has arrived and coverage from 0 to
    /// the tail is contiguous. The header comes from the offset-0 fragment:
    /// v4 gets total length fixed up, MF/offset cleared, and a recomputed
    /// checksum; v6 (whose `next_header` was already restored at parse time)
    /// only needs `payload_length` fixed up — IPv6 has no header checksum.
    fn try_assemble(&self) -> Option<Vec<u8>> {
        let total = self.total?;
        let header = self.header.as_ref()?;

        let mut covered = 0usize;
        for (&off, data) in &self.chunks {
            if off > covered {
                return None; // hole
            }
            covered = covered.max(off + data.len());
        }
        if covered < total {
            return None;
        }

        let mut payload = vec![0u8; total];
        for (&off, data) in &self.chunks {
            let end = (off + data.len()).min(total);
            if off < end {
                payload[off..end].copy_from_slice(&data[..end - off]);
            }
        }

        let hlen = header.len();
        let mut pkt = Vec::with_capacity(hlen + total);
        pkt.extend_from_slice(header);
        pkt.extend_from_slice(&payload);
        if header[0] >> 4 == 6 {
            pkt[4..6].copy_from_slice(&(total as u16).to_be_bytes());
        } else {
            let total_len = (hlen + total) as u16;
            pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
            pkt[6] &= 0x40; // keep only DF; clear MF + offset high bits
            pkt[7] = 0;
            pkt[10] = 0;
            pkt[11] = 0;
            let cks = ipv4_header_checksum(&pkt[..hlen]);
            pkt[10..12].copy_from_slice(&cks.to_be_bytes());
        }
        Some(pkt)
    }
}

/// RFC 1071 ones'-complement header checksum (checksum field must be zero).
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// smoltcp device

/// In-memory smoltcp device: rx is fed by the pump from the transport, tx is
/// drained into the transport sink right after every `iface.poll`.
///
/// MTU 1100 keeps every client→share TCP segment under the tunnel's QUIC
/// datagram floor (≈1162 at the 1200-byte initial MTU), so client→share
/// packets are never IP-fragmented — the share-side netstack cannot
/// reassemble fragments. It also bounds the share→client segments: the SYN
/// advertises MSS = 1100 - 40 = 1060, which the share-side smoltcp clamps to.
const SMOL_DEVICE_MTU: usize = 1100;

#[derive(Default)]
struct SmolDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct SmolRxToken(Vec<u8>);

impl smoltcp::phy::RxToken for SmolRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct SmolTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl smoltcp::phy::TxToken for SmolTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

impl smoltcp::phy::Device for SmolDevice {
    type RxToken<'a> = SmolRxToken;
    type TxToken<'a> = SmolTxToken<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(SmolRxToken, SmolTxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((SmolRxToken(pkt), SmolTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<SmolTxToken<'_>> {
        Some(SmolTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = SMOL_DEVICE_MTU;
        // checksum: ChecksumCapabilities::default() — smoltcp computes AND
        // verifies all checksums, as the share-side smoltcp requires.
        caps
    }
}

// ---------------------------------------------------------------------------

/// What the pump's transport slot holds after [`TrafficCmd::Shutdown`]
/// dropped the real chain: stream ended, sink refuses. Never polled in
/// practice (`dead` is set and the pump returns), but the slot must hold a
/// valid `IpTransport`.
struct ClosedTransport;

impl futures_util::Stream for ClosedTransport {
    type Item = std::io::Result<Vec<u8>>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(None)
    }
}

impl futures_util::Sink<Vec<u8>> for ClosedTransport {
    type Error = std::io::Error;
    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn start_send(self: std::pin::Pin<&mut Self>, _item: Vec<u8>) -> Result<(), Self::Error> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddrV4, SocketAddrV6};

    use super::*;

    /// The wan-side v6 server address used across the v6 tests (any global
    /// unicast works; the inner v6 net is the ULA).
    const SERVER_IP6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100);

    /// A full IPv4/UDP packet as the share-side netstack would build it
    /// (fresh header, TTL 20, valid checksums).
    fn udp_packet(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 253) as u8).collect();
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4([203, 0, 113, 100], [10, 200, 0, 2], 20)
            .udp(7, 40000)
            .write(&mut pkt, &payload)
            .unwrap();
        pkt
    }

    /// The IPv6 counterpart of [`udp_packet`]: a whole IPv6/UDP reply
    /// addressed to our inner v6 address.
    fn udp_packet_v6(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 253) as u8).collect();
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv6(SERVER_IP6.octets(), CLIENT_INNER_IP6.octets(), 20)
            .udp(7, 40000)
            .write(&mut pkt, &payload)
            .unwrap();
        pkt
    }

    /// Split `pkt` into IPv4 fragments carrying `chunk` payload bytes each
    /// (must be a multiple of 8), mimicking spora-core's `fragment_ipv4`:
    /// each fragment copies the IP header with MF set (except the tail),
    /// adjusted total length / fragment offset, and a valid checksum.
    fn split_fragments(pkt: &[u8], chunk: usize, id: u16) -> Vec<Vec<u8>> {
        assert_eq!(chunk % 8, 0);
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        let payload = &pkt[ihl..];
        let mut frags = Vec::new();
        let mut off = 0usize;
        while off < payload.len() {
            let end = (off + chunk).min(payload.len());
            let mf = end < payload.len();
            let mut frag = Vec::with_capacity(ihl + end - off);
            frag.extend_from_slice(&pkt[..ihl]);
            frag.extend_from_slice(&payload[off..end]);
            frag[2..4].copy_from_slice(&((ihl + end - off) as u16).to_be_bytes());
            frag[4..6].copy_from_slice(&id.to_be_bytes());
            let flags_frag = (if mf { 0x2000u16 } else { 0 }) | (off / 8) as u16;
            frag[6..8].copy_from_slice(&flags_frag.to_be_bytes());
            frag[10] = 0;
            frag[11] = 0;
            let cks = ipv4_header_checksum(&frag[..ihl]);
            frag[10..12].copy_from_slice(&cks.to_be_bytes());
            frags.push(frag);
            off = end;
        }
        frags
    }

    /// Split a whole IPv6 packet into RFC 8200 fragments carrying `chunk`
    /// payload bytes each (must be a multiple of 8), mimicking spora-core's
    /// v6 fragmenter: each fragment copies the 40-byte fixed header with
    /// `next_header` = 44 and an adjusted `payload_length`, then the 8-byte
    /// Fragment header, then the payload slice.
    fn split_fragments_v6(pkt: &[u8], chunk: usize, id: u32) -> Vec<Vec<u8>> {
        assert_eq!(chunk % 8, 0);
        let next_header = pkt[6];
        let payload = &pkt[40..];
        let mut frags = Vec::new();
        let mut off = 0usize;
        while off < payload.len() {
            let end = (off + chunk).min(payload.len());
            let more = end < payload.len();
            let mut frag = Vec::with_capacity(48 + end - off);
            frag.extend_from_slice(&pkt[..40]);
            frag[4..6].copy_from_slice(&((8 + end - off) as u16).to_be_bytes());
            frag[6] = 44; // Fragment extension header
            frag.push(next_header);
            frag.push(0); // reserved
            let frag_field = (((off / 8) as u16) << 3) | u16::from(more);
            frag.extend_from_slice(&frag_field.to_be_bytes());
            frag.extend_from_slice(&id.to_be_bytes());
            frag.extend_from_slice(&payload[off..end]);
            frags.push(frag);
            off = end;
        }
        frags
    }

    #[test]
    fn percentile_nearest_rank() {
        let ms = |n: u64| Duration::from_millis(n);
        assert_eq!(percentile(&[], 50.0), Duration::ZERO);
        assert_eq!(percentile(&[ms(7)], 50.0), ms(7));
        assert_eq!(percentile(&[ms(7)], 95.0), ms(7));
        let sorted: Vec<Duration> = (1..=100).map(ms).collect();
        assert_eq!(percentile(&sorted, 50.0), ms(50));
        assert_eq!(percentile(&sorted, 95.0), ms(95));
        assert_eq!(percentile(&sorted, 100.0), ms(100));
        // 4 samples: p50 = ceil(2) = 2nd, p95 = ceil(3.8) = 4th.
        let four = [ms(1), ms(2), ms(3), ms(4)];
        assert_eq!(percentile(&four, 50.0), ms(2));
        assert_eq!(percentile(&four, 95.0), ms(4));
    }

    #[test]
    fn unfragmented_packet_passes_through() {
        let mut r = Reassembler::default();
        let pkt = udp_packet(64);
        assert_eq!(r.push(pkt.clone()), Some(pkt));
    }

    #[test]
    fn non_ipv4_passes_through() {
        let mut r = Reassembler::default();
        let junk = vec![0x60u8; 48]; // IPv6 version nibble
        assert_eq!(r.push(junk.clone()), Some(junk));
    }

    #[test]
    fn reassembles_out_of_order_fragments() {
        let mut r = Reassembler::default();
        let pkt = udp_packet(1400); // 1428-byte IP packet
        let frags = split_fragments(&pkt, 512, 0xBEEF);
        assert_eq!(frags.len(), 3);

        // Feed tail first, then head, then the middle completes it.
        assert_eq!(r.push(frags[2].clone()), None);
        assert_eq!(r.push(frags[0].clone()), None);
        let full = r.push(frags[1].clone()).expect("complete on last piece");

        // Payload and addressing survive; header checksum is valid.
        let ihl = ((full[0] & 0x0f) as usize) * 4;
        assert_eq!(&full[ihl..], &pkt[20..], "reassembled IP payload");
        assert_eq!(&full[12..20], &pkt[12..20], "addresses");
        assert_eq!(full[9], 17, "protocol");
        assert_eq!(
            u16::from_be_bytes([full[2], full[3]]) as usize,
            full.len(),
            "total length"
        );
        let flags_frag = u16::from_be_bytes([full[6], full[7]]);
        assert_eq!(flags_frag & 0x3fff, 0, "MF and offset cleared");
        let mut hdr = full[..ihl].to_vec();
        hdr[10] = 0;
        hdr[11] = 0;
        assert_eq!(
            ipv4_header_checksum(&hdr),
            u16::from_be_bytes([full[10], full[11]]),
            "recomputed header checksum"
        );

        // The reassembled packet matches the echo session it belongs to.
        let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 100), 7);
        assert!(is_complete_udp_for(&full, server, 40000));
    }

    /// Sanity helper for the test above: dst/ports parse out of the
    /// reassembled packet like any other whole UDP packet.
    fn is_complete_udp_for(pkt: &[u8], server: SocketAddrV4, local_port: u16) -> bool {
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        pkt[9] == 17
            && pkt[12..16] == server.ip().octets()
            && u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) == server.port()
            && u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]) == local_port
    }

    #[test]
    fn interleaved_fragment_trains_reassemble_independently() {
        let mut r = Reassembler::default();
        let a = udp_packet(900);
        let b = udp_packet(1200);
        let fa = split_fragments(&a, 488, 0x0001);
        let fb = split_fragments(&b, 488, 0x0002);
        assert_eq!(fa.len(), 2);
        assert_eq!(fb.len(), 3);

        assert_eq!(r.push(fa[0].clone()), None);
        assert_eq!(r.push(fb[1].clone()), None);
        assert_eq!(r.push(fb[0].clone()), None);
        let full_a = r.push(fa[1].clone()).expect("train A completes");
        let full_b = r.push(fb[2].clone()).expect("train B completes");
        assert_eq!(&full_a[20..], &a[20..]);
        assert_eq!(&full_b[20..], &b[20..]);
    }

    #[test]
    fn incomplete_train_stays_pending() {
        let mut r = Reassembler::default();
        let pkt = udp_packet(1400);
        let frags = split_fragments(&pkt, 512, 0x7777);
        // Head and tail but no middle: never completes.
        assert_eq!(r.push(frags[0].clone()), None);
        assert_eq!(r.push(frags[2].clone()), None);
    }

    #[test]
    fn echo_request_and_reply_match() {
        let server: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 100), 7).into();
        let req = build_echo_request(40000, server, 3, 0xDEAD_BEEF_CAFE_F00D, 200);
        assert_eq!(req.len(), 20 + 8 + 200);

        // Reflect it the way the echo path does: same payload, swapped
        // addressing.
        let payload = &req[28..];
        let mut reply = Vec::new();
        etherparse::PacketBuilder::ipv4([203, 0, 113, 100], [10, 200, 0, 2], 20)
            .udp(7, 40000)
            .write(&mut reply, payload)
            .unwrap();
        assert_eq!(
            match_echo_reply(&reply, server, 40000, 0xDEAD_BEEF_CAFE_F00D),
            Some(3)
        );
        // Wrong nonce, wrong port: no match.
        assert_eq!(match_echo_reply(&reply, server, 40000, 1), None);
        assert_eq!(
            match_echo_reply(&reply, server, 40001, 0xDEAD_BEEF_CAFE_F00D),
            None
        );
        // A padded reply still matches on the tag prefix.
        let mut padded = Vec::new();
        let mut big = payload.to_vec();
        big.resize(1400, 0x5A);
        etherparse::PacketBuilder::ipv4([203, 0, 113, 100], [10, 200, 0, 2], 20)
            .udp(7, 40000)
            .write(&mut padded, &big)
            .unwrap();
        assert_eq!(
            match_echo_reply(&padded, server, 40000, 0xDEAD_BEEF_CAFE_F00D),
            Some(3)
        );
    }

    #[test]
    fn echo_request_and_reply_match_v6() {
        let server: SocketAddr = SocketAddrV6::new(SERVER_IP6, 7, 0, 0).into();
        let req = build_echo_request(40000, server, 3, 0xDEAD_BEEF_CAFE_F00D, 200);
        assert_eq!(req.len(), 40 + 8 + 200);
        assert_eq!(req[0] >> 4, 6, "version");
        assert_eq!(req[6], 17, "next_header is UDP");
        assert_eq!(&req[8..24], &CLIENT_INNER_IP6.octets(), "inner v6 source");

        // Reflect it the way the echo path does: same payload, swapped
        // addressing.
        let payload = &req[48..];
        let mut reply = Vec::new();
        etherparse::PacketBuilder::ipv6(SERVER_IP6.octets(), CLIENT_INNER_IP6.octets(), 20)
            .udp(7, 40000)
            .write(&mut reply, payload)
            .unwrap();
        assert_eq!(
            match_echo_reply(&reply, server, 40000, 0xDEAD_BEEF_CAFE_F00D),
            Some(3)
        );
        // Wrong nonce, wrong port: no match.
        assert_eq!(match_echo_reply(&reply, server, 40000, 1), None);
        assert_eq!(
            match_echo_reply(&reply, server, 40001, 0xDEAD_BEEF_CAFE_F00D),
            None
        );
        // A v4 session never claims a v6 reply.
        let v4: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 100), 7).into();
        assert_eq!(
            match_echo_reply(&reply, v4, 40000, 0xDEAD_BEEF_CAFE_F00D),
            None
        );
    }

    #[test]
    fn reassembles_out_of_order_fragments_v6() {
        let mut r = Reassembler::default();
        let pkt = udp_packet_v6(1400); // 1448-byte IP packet
        let frags = split_fragments_v6(&pkt, 512, 0xDEAD_0001);
        assert_eq!(frags.len(), 3);
        // While pending, the matcher must not see the fragments as session
        // traffic (next_header is 44, not UDP).
        let server: SocketAddr = SocketAddrV6::new(SERVER_IP6, 7, 0, 0).into();
        assert_eq!(match_echo_reply(&frags[0], server, 40000, 0), None);

        // Feed tail first, then head, then the middle completes it.
        assert_eq!(r.push(frags[2].clone()), None);
        assert_eq!(r.push(frags[0].clone()), None);
        let full = r.push(frags[1].clone()).expect("complete on last piece");

        // The Fragment headers are stripped and the fixed header restored:
        // byte-identical to the original packet.
        assert_eq!(full, pkt);
        assert_eq!(&full[8..40], &pkt[8..40], "addresses");
        assert_eq!(full[6], 17, "next_header restored to UDP");
        assert_eq!(
            u16::from_be_bytes([full[4], full[5]]) as usize,
            full.len() - 40,
            "payload length"
        );
    }

    #[test]
    fn interleaved_v4_and_v6_trains_reassemble_independently() {
        let mut r = Reassembler::default();
        let a = udp_packet(1200);
        let b = udp_packet_v6(1200);
        let fa = split_fragments(&a, 488, 0x0001);
        // Same low identification bits as the v4 train: the family tag in
        // the key must keep them apart.
        let fb = split_fragments_v6(&b, 488, 0x0000_0001);
        assert_eq!(fa.len(), 3);
        assert_eq!(fb.len(), 3);

        assert_eq!(r.push(fa[0].clone()), None);
        assert_eq!(r.push(fb[2].clone()), None);
        assert_eq!(r.push(fb[0].clone()), None);
        assert_eq!(r.push(fa[2].clone()), None);
        let full_b = r.push(fb[1].clone()).expect("v6 train completes");
        let full_a = r.push(fa[1].clone()).expect("v4 train completes");
        assert_eq!(&full_a[20..], &a[20..]);
        assert_eq!(full_b, b);
    }

    #[test]
    fn session_tcp_matching_v6() {
        let server: SocketAddr = SocketAddrV6::new(SERVER_IP6, 5201, 0, 0).into();
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv6(SERVER_IP6.octets(), CLIENT_INNER_IP6.octets(), 20)
            .tcp(5201, 40000, 1, 1024)
            .write(&mut pkt, &[])
            .unwrap();
        assert!(is_session_tcp(&pkt, server, 40000));
        // Wrong local port, wrong server address, v4 session: no match.
        assert!(!is_session_tcp(&pkt, server, 40001));
        let other: SocketAddr = SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x200),
            5201,
            0,
            0,
        )
        .into();
        assert!(!is_session_tcp(&pkt, other, 40000));
        let v4: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 100), 5201).into();
        assert!(!is_session_tcp(&pkt, v4, 40000));
    }
}
