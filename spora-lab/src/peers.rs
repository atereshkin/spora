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
use crate::traffic::{BulkStats, EchoStats, TrafficCmd, TrafficPump};

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
    pub relay_host: String,
    pub relay_port: u16,
    pub stun_server: String,
}

impl LabPeerOpts {
    /// Default-timing options against the given relay + STUN endpoints
    /// (typically `wan.relay_addr()` / `wan.stun_server()`).
    pub fn new(relay: SocketAddr, stun_server: impl Into<String>) -> Self {
        Self {
            timings: spora_core::Timings::default(),
            enable_direct_upgrade: true,
            relay_host: relay.ip().to_string(),
            relay_port: relay.port(),
            stun_server: stun_server.into(),
        }
    }

    /// Build a `spora_core::Config` from these options, with the event hook
    /// wired to a fresh [`EventStream`]. Everything not covered by the
    /// options is `Config::default()` (notably `exit_mode: Netstack`).
    pub fn config(&self) -> (Config, EventStream) {
        let (hook, events) = event_channel();
        let config = Config {
            stun_server: self.stun_server.clone(),
            relay_host: self.relay_host.clone(),
            relay_port: self.relay_port,
            timings: self.timings.clone(),
            enable_direct_upgrade: self.enable_direct_upgrade,
            event_hook: Some(hook),
            ..Config::default()
        };
        (config, events)
    }
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
    let (url_tx, url_rx) = mpsc::channel::<Result<Url, String>>();

    let host = ns.spawn_host("sharer", move |cancel| async move {
        match spora_core::share(Identity::generate(), config).await {
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
    /// through the tunnel; blocks up to `timeout` for the stats. On timeout
    /// the pump keeps running the command to completion in the background.
    pub fn udp_echo(
        &self,
        server: std::net::SocketAddrV4,
        count: usize,
        payload_len: usize,
        timeout: Duration,
    ) -> Result<EchoStats, String> {
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
    /// (the wan TCP echo) through the tunnel; blocks up to `timeout`.
    pub fn tcp_bulk(
        &self,
        server: std::net::SocketAddrV4,
        bytes: usize,
        timeout: Duration,
    ) -> Result<BulkStats, String> {
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
    let (config, events) = opts.config();
    let (result_tx, result_rx) = mpsc::channel::<Result<(), String>>();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<TrafficCmd>();

    let host = ns.spawn_host("client", move |_cancel| async move {
        match spora_core::connect(url, &config).await {
            Ok(connected) => {
                let _ = result_tx.send(Ok(()));
                drive_client(connected, cmd_rx).await;
            }
            Err(e) => {
                let _ = result_tx.send(Err(e));
            }
        }
    })?;

    match result_rx.recv_timeout(CONNECT_TIMEOUT) {
        Ok(Ok(())) => Ok(ClientHandle {
            events,
            cmds: cmd_tx,
            host: Some(host),
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
