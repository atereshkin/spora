//! Production peers as lab hosts: the sharer (`spora_core::share`, netstack
//! exit by default) and the client (`spora_core::connect`), each on its own
//! pinned host thread, with `TunnelEvent`s and traffic commands bridged over
//! channels so scenarios (on the main thread) drive everything synchronously.
//!
//! Threading: peers MUST run via [`Netns::spawn_host`] (current-thread
//! runtime on a thread `setns`'d into the namespace) — every socket the peer
//! ever creates, including direct-upgrade punch sockets and netstack egress
//! sockets, then lands in the right namespace. All handle methods are
//! blocking with explicit timeouts; they are meant to be called from
//! scenario code on the suite main thread (never from inside a host
//! runtime).
//!
//! Events: `Config::event_hook` pushes every [`TunnelEvent`] into an
//! unbounded std channel. [`EventStream::wait_event`] drains that channel
//! into a buffer and scans buffered events first, so events that fired
//! before the call still match; a matched event is consumed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use spora_core::identity::Identity;
use spora_core::{Config, ConnectResult, TunnelEvent};
use url::Url;

use crate::harness;
use crate::netns::{HostHandle, Netns};
use crate::traffic::{BulkStats, EchoStats, TcpOpts, TrafficCmd, TrafficPump};

/// How long `start_sharer` waits for `share()` to come up (it only binds a
/// socket and builds an endpoint — fast).
const SHARE_START_TIMEOUT: Duration = Duration::from_secs(15);
/// How long `start_client` waits for `connect()` to either establish the
/// relay-via session or fail. `connect()` has its own internal handshake
/// (10s) and auth (5s) timeouts, so a real failure surfaces well within
/// this; the margin covers slow-path scenarios (netem latency).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(40);

/// Options for a lab peer, mapped onto `spora_core::Config`.
pub struct LabPeerOpts {
    pub timings: spora_core::Timings,
    pub enable_direct_upgrade: bool,
    /// Relays in preference order (the sharer registers with all; the client
    /// tries them IPv6-first then by this order). [`LabPeerOpts::new`] sets a
    /// single relay; multi-relay scenarios push more.
    pub relays: Vec<spora_core::identity::RelayEndpoint>,
    pub stun_server: String,
    /// Share side only: enable the sharer's connection log
    /// (`Config::conn_log`). The connlog suite points this at a per-scenario
    /// temp dir and asserts on the resulting database.
    pub conn_log: Option<spora_core::connlog::ConnLogConfig>,
    /// Keep a diagnostic record of how each connection went
    /// (`Config::record`). The record suite points this at a per-scenario
    /// temp dir and asserts on what the peers wrote there.
    pub record: Option<spora_core::record::RecordConfig>,
    /// Share side only: identity to share as. `None` (default) generates a
    /// fresh one per `start_sharer` call; recovery scenarios that restart the
    /// sharer pass the SAME identity so the share URL — and the routing key
    /// the relay and the surviving client hold — stays stable.
    pub identity: Option<Identity>,
    /// Share side only: what the sharer's DNS forwarder does
    /// (`Config::dns_forwarder`, see spora-core's `dns`).
    pub dns: DnsExit,
}

/// The sharer's DNS forwarder in a scenario.
#[derive(Clone, Default)]
pub enum DnsExit {
    /// The core default: this host's system resolvers. Meaningless inside a
    /// namespace (nothing there answers them), harmless unless a scenario
    /// sends DNS.
    #[default]
    Default,
    /// No forwarder: the synthetic resolver address is a dropped private
    /// destination like any other.
    Off,
    /// A forwarder the scenario built itself (upstreams, timeouts) and keeps
    /// a handle on, to assert on its health decisions.
    Forwarder(Arc<spora_core::dns::DnsForwarder>),
}

impl LabPeerOpts {
    /// Default-timing options against the given relay + STUN endpoints
    /// (typically `wan.relay_addr()` / `wan.stun_server()`).
    pub fn new(relay: SocketAddr, stun_server: impl Into<String>) -> Self {
        Self {
            timings: spora_core::Timings::default(),
            enable_direct_upgrade: true,
            relays: vec![relay_endpoint(relay)],
            stun_server: stun_server.into(),
            conn_log: None,
            record: None,
            identity: None,
            dns: DnsExit::Default,
        }
    }

    /// Replace the relay list (preference order). Convenience for
    /// multi-relay/failover scenarios.
    pub fn with_relays(mut self, relays: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.relays = relays.into_iter().map(relay_endpoint).collect();
        self
    }

    /// Build a `spora_core::Config` from these options, with the event hook
    /// wired to a fresh [`EventStream`]. Everything not covered by the
    /// options is `Config::default()` (notably `exit_mode: Netstack`).
    pub fn config(&self) -> (Config, EventStream) {
        let (hook, events) = event_channel();
        let mut config = Config {
            // Lab scenarios name their isolated in-namespace STUN service
            // explicitly and must never fall back to the public internet.
            stun_servers: vec![self.stun_server.clone()],
            relays: self.relays.clone(),
            timings: self.timings.clone(),
            enable_direct_upgrade: self.enable_direct_upgrade,
            event_hook: Some(hook),
            conn_log: self.conn_log.clone(),
            record: self.record.clone(),
            ..Config::default()
        };
        match &self.dns {
            DnsExit::Default => {}
            DnsExit::Off => config.dns_forwarder = None,
            DnsExit::Forwarder(fwd) => config.dns_forwarder = Some(fwd.clone()),
        }
        (config, events)
    }
}

/// A lab relay address as a `RelayEndpoint`: IP literal host (bracketing of
/// v6 is the URL layer's job) + port.
fn relay_endpoint(addr: SocketAddr) -> spora_core::identity::RelayEndpoint {
    spora_core::identity::RelayEndpoint::new(addr.ip().to_string(), addr.port())
}

/// A non-blocking `event_hook` (pushes into an unbounded std channel) plus
/// the [`EventStream`] that consumes it. Public so suites that build their
/// own `Config` (the loopback suite) get the same `wait_event` semantics.
pub fn event_channel() -> (Arc<dyn Fn(TunnelEvent) + Send + Sync>, EventStream) {
    let (tx, rx) = mpsc::channel::<TunnelEvent>();
    let hook = Arc::new(move |ev: TunnelEvent| {
        let _ = tx.send(ev);
    });
    (
        hook,
        EventStream {
            rx,
            buffer: Vec::new(),
        },
    )
}

/// Blocking consumer of a peer's `TunnelEvent`s with replay semantics:
/// events are drained into an internal buffer, the buffer is scanned first,
/// and a matched event is removed (so waiting twice for the same predicate
/// requires two emissions).
pub struct EventStream {
    rx: mpsc::Receiver<TunnelEvent>,
    buffer: Vec<TunnelEvent>,
}

impl EventStream {
    /// Drop everything emitted so far (buffered and pending). Call right
    /// after injecting a fault so subsequent `wait_event`s can only be
    /// satisfied by events the fault actually caused — without this, a
    /// spurious pre-fault reconnect cycle could satisfy a post-fault wait
    /// with stale events.
    pub fn discard_pending(&mut self) {
        while self.rx.try_recv().is_ok() {}
        self.buffer.clear();
    }

    /// Block until an event matching `pred` is available (buffered or newly
    /// arriving) or `timeout` elapses.
    pub fn wait_event<P: Fn(&TunnelEvent) -> bool>(
        &mut self,
        pred: P,
        timeout: Duration,
    ) -> Result<TunnelEvent, String> {
        // Drain whatever already arrived, then scan the buffer.
        while let Ok(ev) = self.rx.try_recv() {
            self.buffer.push(ev);
        }
        if let Some(i) = self.buffer.iter().position(&pred) {
            return Ok(self.buffer.remove(i));
        }

        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "no matching event within {timeout:?} (buffered: {:?})",
                    self.buffer
                ));
            }
            match self.rx.recv_timeout(deadline - now) {
                Ok(ev) => {
                    if pred(&ev) {
                        return Ok(ev);
                    }
                    self.buffer.push(ev);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "no matching event within {timeout:?} (buffered: {:?})",
                        self.buffer
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "event channel closed — peer host is gone (buffered: {:?})",
                        self.buffer
                    ));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sharer

pub struct SharerHandle {
    url: Url,
    events: EventStream,
    host: Option<HostHandle>,
}

impl SharerHandle {
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Block until a `TunnelEvent` matching `pred` was emitted (see
    /// [`EventStream::wait_event`]).
    pub fn wait_event<P: Fn(&TunnelEvent) -> bool>(
        &mut self,
        pred: P,
        timeout: Duration,
    ) -> Result<TunnelEvent, String> {
        self.events.wait_event(pred, timeout)
    }

    /// See [`EventStream::discard_pending`] — call after injecting a fault.
    pub fn discard_events(&mut self) {
        self.events.discard_pending();
    }

    /// CPU time consumed by the sharer's host thread so far (the whole share
    /// side: QUIC, netstack, egress sockets — everything runs on this one
    /// pinned thread). See [`HostHandle::cpu_time`].
    pub fn cpu_time(&self) -> Option<Duration> {
        self.host.as_ref()?.cpu_time()
    }

    /// Cancel the share session and join the host thread.
    pub fn stop(mut self) {
        if let Some(host) = self.host.take() {
            host.stop();
        }
    }
}

/// Run the production sharer inside `ns` with a fresh identity. Blocks until
/// `share()` reports its URL (or its error).
pub fn start_sharer(ns: &Netns, opts: &LabPeerOpts) -> Result<SharerHandle, String> {
    let (config, events) = opts.config();
    let identity = opts.identity.clone().unwrap_or_else(Identity::generate);
    let (url_tx, url_rx) = mpsc::channel::<Result<Url, String>>();

    let host = ns.spawn_host("sharer", move |cancel| async move {
        match spora_core::share(identity, config).await {
            Ok(session) => {
                let _ = url_tx.send(Ok(session.url.clone()));
                // Keep the host alive until cancelled. NOTE: spawn_host
                // selects on this same token, so the future is usually
                // dropped right at the await below — `session.stop()` is
                // best-effort and in practice teardown happens by dropping
                // the host runtime (abrupt, no clean QUIC close). The
                // resilience suite's flow-expiry budgets DEPEND on that
                // abruptness; if spawn_host ever lets futures finish after
                // cancellation, revisit those budgets.
                cancel.cancelled().await;
                session.stop().await;
            }
            Err(e) => {
                let _ = url_tx.send(Err(e));
            }
        }
    })?;

    match url_rx.recv_timeout(SHARE_START_TIMEOUT) {
        Ok(Ok(url)) => Ok(SharerHandle {
            url,
            events,
            host: Some(host),
        }),
        Ok(Err(e)) => {
            host.stop();
            Err(format!("share() failed: {e}"))
        }
        Err(e) => {
            host.stop();
            Err(format!("sharer never reported its URL: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Client

pub struct ClientHandle {
    events: EventStream,
    cmds: tokio::sync::mpsc::UnboundedSender<TrafficCmd>,
    host: Option<HostHandle>,
    /// The client's adaptive-keepalive knob + waker (see
    /// `ConnectResult::keepalive_knob`): 0 = dormant ("screen off"), N>0 =
    /// probe every N seconds. Starts at 0.
    keepalive_knob: Arc<std::sync::atomic::AtomicU64>,
    keepalive_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
}

impl ClientHandle {
    /// Block until a `TunnelEvent` matching `pred` was emitted (see
    /// [`EventStream::wait_event`]).
    pub fn wait_event<P: Fn(&TunnelEvent) -> bool>(
        &mut self,
        pred: P,
        timeout: Duration,
    ) -> Result<TunnelEvent, String> {
        self.events.wait_event(pred, timeout)
    }

    /// See [`EventStream::discard_pending`] — call after injecting a fault.
    pub fn discard_events(&mut self) {
        self.events.discard_pending();
    }

    /// UDP-echo `count` datagrams of `payload_len` bytes against `server`
    /// (v4 or v6 — the inner family follows the server address) through the
    /// tunnel; blocks up to `timeout` for the stats. On timeout the pump
    /// keeps running the command to completion in the background.
    pub fn udp_echo(
        &self,
        server: impl Into<SocketAddr>,
        count: usize,
        payload_len: usize,
        timeout: Duration,
    ) -> Result<EchoStats, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::UdpEcho {
                server,
                count,
                payload_len,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, timeout, "udp echo")
    }

    /// Round-trip `bytes` of data over a real TCP connection to `server`
    /// (the wan TCP echo, v4 or v6) through the tunnel; blocks up to
    /// `timeout`.
    pub fn tcp_bulk(
        &self,
        server: impl Into<SocketAddr>,
        bytes: usize,
        timeout: Duration,
    ) -> Result<BulkStats, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::TcpBulk {
                server,
                bytes,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, timeout, "tcp bulk")
    }

    /// Download `bytes` over TCP from `server` (the wan SOURCE service, v4
    /// or v6) through the tunnel; blocks up to `timeout`.
    /// `BulkStats::elapsed` runs from connection establishment to the last
    /// byte.
    pub fn tcp_download(
        &self,
        server: impl Into<SocketAddr>,
        bytes: usize,
        opts: TcpOpts,
        timeout: Duration,
    ) -> Result<BulkStats, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::TcpDownload {
                server,
                bytes,
                opts,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, timeout, "tcp download")
    }

    /// Upload `bytes` over TCP to `server` (the wan SINK service, v4 or v6)
    /// through the tunnel; blocks up to `timeout`. `BulkStats::elapsed` runs
    /// from the first send to the sink's verified byte-count ack.
    pub fn tcp_upload(
        &self,
        server: impl Into<SocketAddr>,
        bytes: usize,
        opts: TcpOpts,
        timeout: Duration,
    ) -> Result<BulkStats, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::TcpUpload {
                server,
                bytes,
                opts,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, timeout, "tcp upload")
    }

    /// One aborted inner TCP connection through the tunnel: complete the
    /// inner handshake toward `server`, then immediately RST and walk away
    /// (an app giving up on a slow destination). `Ok(true)` = handshake
    /// completed before the abort; `Ok(false)` = the share's netstack
    /// refused the SYN — what session-pool exhaustion looks like from here.
    pub fn tcp_aborted_connect(
        &self,
        server: impl Into<SocketAddr>,
        timeout: Duration,
    ) -> Result<bool, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::TcpAbortedConnect {
                server,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, timeout, "tcp aborted connect")
    }

    /// Send one tagged echo probe through the tunnel and wait up to `grace`
    /// for the reply: `Ok(Some(rtt))` = tunnel is passing traffic,
    /// `Ok(None)` = probe lost. Cheap enough to call in a loop for
    /// outage-window timelines (unlike `udp_echo`, no 3s reply grace).
    pub fn udp_probe(
        &self,
        server: impl Into<SocketAddr>,
        grace: Duration,
    ) -> Result<Option<Duration>, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::UdpProbe {
                server,
                grace,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        // The pump answers within `grace` + scheduling slack.
        recv_result(rx, grace + Duration::from_secs(5), "udp probe")
    }

    /// Send one raw UDP `payload` to `server` through the tunnel and wait
    /// up to `grace` for the first datagram back from it: `Ok(Some(reply))`,
    /// or `Ok(None)` if nothing came. The DNS suite's primitive.
    pub fn udp_query(
        &self,
        server: impl Into<SocketAddr>,
        payload: Vec<u8>,
        grace: Duration,
    ) -> Result<Option<Vec<u8>>, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::UdpQuery {
                server,
                payload,
                grace,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, grace + Duration::from_secs(5), "udp query")
    }

    /// One TCP request/response exchange through the tunnel: connect to
    /// `server`, send `request`, read until it closes its side. `grace`
    /// bounds each wait for progress.
    pub fn tcp_request(
        &self,
        server: impl Into<SocketAddr>,
        request: Vec<u8>,
        grace: Duration,
    ) -> Result<Vec<u8>, String> {
        let server = server.into();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::TcpRequest {
                server,
                request,
                grace,
                respond: tx,
            })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, grace * 3 + Duration::from_secs(5), "tcp request")
    }

    /// Close the session CLEANLY: the pump drops the composed transport
    /// chain while the host runtime is still alive, so the carrier's clean
    /// close (QUIC CONNECTION_CLOSE(0) / nz CH_CLOSE) actually reaches the
    /// wire — unlike [`ClientHandle::stop`], whose runtime teardown is
    /// deliberately abrupt. Call `stop()` afterwards to join the host.
    pub fn shutdown_clean(&self, timeout: Duration) -> Result<(), String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::Shutdown { respond: tx })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, timeout, "clean shutdown")
    }

    /// Drive the adaptive-keepalive knob at runtime, exactly as the apps do:
    /// store the new value, then wake the possibly-parked keepalive task.
    /// 0 = dormant (screen off), N>0 = probe every N seconds.
    pub fn set_keepalive(&self, secs: u64) {
        self.keepalive_knob
            .store(secs, std::sync::atomic::Ordering::Relaxed);
        if let Some(w) = self.keepalive_waker.lock().unwrap().take() {
            w.wake();
        }
    }

    /// CPU time of the pump THREAD (`CLOCK_THREAD_CPUTIME_ID`, measured on
    /// the pump task). On a lab host this equals [`host_cpu_time`]
    /// (current-thread runtime), but it also works for pumps driven outside
    /// a `Netns` host (the loopback suite).
    ///
    /// [`host_cpu_time`]: ClientHandle::host_cpu_time
    pub fn pump_cpu_time(&self, timeout: Duration) -> Result<Duration, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmds
            .send(TrafficCmd::CpuTime { respond: tx })
            .map_err(|_| "client traffic pump is gone".to_string())?;
        recv_result(rx, timeout, "cpu time")
    }

    /// CPU time consumed by the client's host thread so far (client tunnel
    /// stack + traffic pump). See [`HostHandle::cpu_time`].
    pub fn host_cpu_time(&self) -> Option<Duration> {
        self.host.as_ref()?.cpu_time()
    }

    /// Tear down the client session and join the host thread.
    pub fn stop(mut self) {
        if let Some(host) = self.host.take() {
            host.stop();
        }
    }
}

fn recv_result<T>(
    rx: tokio::sync::oneshot::Receiver<Result<T, String>>,
    timeout: Duration,
    what: &str,
) -> Result<T, String> {
    harness::block_on(async move {
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(format!("{what}: pump dropped the command")),
            Err(_) => Err(format!("{what}: no result within {timeout:?}")),
        }
    })
}

/// Run the production client inside `ns` against `url`. Blocks until
/// `connect()` establishes the relay-via session — a failed connect is
/// returned as `Err`, it is never logged-and-hung (resilience scenarios
/// assert on failed connects).
pub fn start_client(ns: &Netns, url: Url, opts: &LabPeerOpts) -> Result<ClientHandle, String> {
    type KnobPair = (
        Arc<std::sync::atomic::AtomicU64>,
        Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    );
    let (config, events) = opts.config();
    let (result_tx, result_rx) = mpsc::channel::<Result<KnobPair, String>>();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<TrafficCmd>();

    let host = ns.spawn_host("client", move |_cancel| async move {
        match spora_core::connect(url, &config).await {
            Ok(connected) => {
                let _ = result_tx.send(Ok((
                    connected.keepalive_knob.clone(),
                    connected.keepalive_waker.clone(),
                )));
                drive_client(connected, cmd_rx).await;
            }
            Err(e) => {
                let _ = result_tx.send(Err(e));
            }
        }
    })?;

    match result_rx.recv_timeout(CONNECT_TIMEOUT) {
        Ok(Ok((keepalive_knob, keepalive_waker))) => Ok(ClientHandle {
            events,
            cmds: cmd_tx,
            host: Some(host),
            keepalive_knob,
            keepalive_waker,
        }),
        Ok(Err(e)) => {
            host.stop();
            Err(format!("connect() failed: {e}"))
        }
        Err(e) => {
            host.stop();
            Err(format!("client never reported its connect result: {e}"))
        }
    }
}

/// Hand a fresh `ConnectResult`'s transport to a [`TrafficPump`] and serve
/// traffic commands until the command channel closes (or the host runtime is
/// torn down). Public so the loopback suite can drive the real pump over the
/// real client composition without a `Netns`.
pub async fn drive_client(
    connected: ConnectResult,
    cmds: tokio::sync::mpsc::UnboundedReceiver<TrafficCmd>,
) {
    let pump = TrafficPump::new(connected.transport, cmds);
    pump.run().await;
    // Pump done (command channel closed): cancel the session's background
    // tasks (signal holder, upgrade task) too.
    connected.cancel.cancel();
}
