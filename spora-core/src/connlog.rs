//! Sharer-side connection log.
//!
//! The sharer's IP fronts the client's traffic, so the sharer keeps a local,
//! auto-expiring record able to answer "which client connected to destination
//! IP X during [T1,T2]" — NetFlow-style per-flow records (no payload, no
//! packets), tied to the share identity and to what is known about the
//! client's outer address. See docs/connection-logging.md for the full design
//! and the honest-limitations list.
//!
//! Storage is a single SQLite database per identity (WAL mode). SQLite was
//! chosen over a bespoke binary format deliberately: flow volume is bounded
//! (kilobytes-to-megabytes per day), and the log only has value if whoever
//! reads it later — the user, a lawyer, a forensic lab — can open it without
//! trusting a Spora binary.
//!
//! Architecture: the async side never touches the database. Hooks hold cheap
//! handles ([`SessionLog`], [`FlowGuard`]) that `try_send` events into a
//! bounded channel; a dedicated writer thread batches them into transactions.
//! A full channel drops the event and counts it — the writer folds the count
//! into a `log_gap` mark, so a gap in the log is always *visible* (an absence
//! of records that cannot be distinguished from absence of traffic would
//! quietly destroy the log's exculpatory value). The same thinking drives the
//! `share_start`/`share_stop` and `clock_jump` marks.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use rusqlite::Connection;

use crate::identity::Identity;

/// Bump when the schema changes; stored in `meta` so any database file is
/// self-identifying.
pub const FORMAT_VERSION: i64 = 1;

/// Events queued toward the writer thread. Capacity is generous relative to
/// the flow-record rate limit; hitting the cap means the writer is stalled
/// (disk trouble), and dropping-with-a-counter is the designed behavior.
const CHANNEL_CAPACITY: usize = 16 * 1024;

/// Wall-vs-monotonic divergence that gets recorded as a `clock_jump` mark
/// (suspend/resume, NTP step, manual clock change).
const CLOCK_JUMP_THRESHOLD_MS: i64 = 2_000;

/// How often the retention sweep runs (also runs once at startup).
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Resolves the egress (post-NAT) source address for a flow the core cannot
/// observe directly — e.g. the CLI's `--os-routing` mode looks the flow up in
/// the kernel's conntrack table. Called on the writer thread (may block
/// briefly), once per flow: `(proto, inner_src, dst) -> egress`.
pub type EgressLookup = Arc<dyn Fn(u8, SocketAddr, SocketAddr) -> Option<SocketAddr> + Send + Sync>;

#[derive(Clone)]
pub struct ConnLogConfig {
    /// Directory holding `connlog.sqlite` (created 0700 on unix).
    pub dir: PathBuf,
    /// Records older than this are deleted by the periodic sweep, unless
    /// pinned by a hold (see [`add_hold`]). Default 90 days.
    pub retention: Duration,
    /// `false` = sessions-only mode: record who was connected and when, but
    /// no per-flow destination records. For sharers who want the
    /// privacy-leaning posture without keeping nothing.
    pub log_destinations: bool,
    /// Record flows that were refused by policy (`block_local`) — they never
    /// egressed, but the attempt is an abuse signal. Default true.
    pub log_blocked: bool,
    /// Writer batch window: events are committed at least this often.
    pub flush_interval: Duration,
    /// Meter-path flow delimitation (the netstack path uses its own NAT
    /// timeout): a UDP flow with no packets for this long is closed.
    pub udp_idle: Duration,
    /// Meter-path fallback close for TCP flows whose FIN/RST was never seen.
    pub tcp_idle: Duration,
    /// Token-bucket rate limit on flow-record creation, per session. A
    /// hostile client can spray unique tuples; suppressed records are counted
    /// and surfaced as `flow_throttle` marks instead of bloating the log.
    pub max_flow_records_per_sec: u32,
    pub flow_record_burst: u32,
    /// See [`EgressLookup`].
    pub egress_lookup: Option<EgressLookup>,
}

impl ConnLogConfig {
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            retention: Duration::from_secs(90 * 24 * 60 * 60),
            log_destinations: true,
            log_blocked: true,
            flush_interval: Duration::from_secs(1),
            udp_idle: Duration::from_secs(30),
            tcp_idle: Duration::from_secs(600),
            max_flow_records_per_sec: 25,
            flow_record_burst: 250,
            egress_lookup: None,
        }
    }
}

/// Provenance of a recorded client/sharer address. The distinction matters
/// evidentially: `Reported` is client-asserted and must never be read as an
/// observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrKind {
    /// The peer's self-reported STUN endpoint from the upgrade negotiation.
    /// Carried over the authenticated channel but chosen by the client.
    Reported,
    /// Learned from the source of the peer's actual punch/verify packets —
    /// address-validated, exists even when the direct QUIC build then fails.
    PunchVerified,
    /// The remote address of the established direct QUIC connection
    /// (punch + cert pinning + secret auth). Strongest.
    Verified,
    /// The sharer's *own* STUN-discovered public address, recorded to
    /// corroborate "your IP X" in a request. IP-level corroboration only:
    /// the punch socket's port mapping differs from the relay path's.
    SharerPublic,
}

impl AddrKind {
    fn as_str(self) -> &'static str {
        match self {
            AddrKind::Reported => "reported",
            AddrKind::PunchVerified => "punch_verified",
            AddrKind::Verified => "verified",
            AddrKind::SharerPublic => "sharer_public",
        }
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn random_id() -> i64 {
    loop {
        let id = (rand::random::<u64>() >> 1) as i64;
        if id != 0 {
            return id;
        }
    }
}

enum Ev {
    SessionStart {
        id: i64,
        ts_ms: i64,
        relay: SocketAddr,
    },
    SessionAddr {
        session: i64,
        ts_ms: i64,
        kind: &'static str,
        addr: SocketAddr,
    },
    SessionEnd {
        session: i64,
        ts_ms: i64,
        reason: &'static str,
    },
    FlowOpen {
        id: i64,
        session: i64,
        ts_ms: i64,
        proto: u8,
        src: SocketAddr,
        dst: SocketAddr,
        /// `true` when the exit mode confirms the traffic actually egressed
        /// (netstack re-origination); `false` for the passive meter, which
        /// sees traffic *offered* to the tunnel.
        confirmed: bool,
    },
    /// A flow refused by policy: one self-contained row, no close needed.
    FlowBlocked {
        id: i64,
        session: i64,
        ts_ms: i64,
        proto: u8,
        src: SocketAddr,
        dst: SocketAddr,
    },
    FlowEstablished {
        id: i64,
        egress: Option<SocketAddr>,
    },
    FlowClose {
        id: i64,
        last_ms: i64,
        up: u64,
        down: u64,
        established: bool,
        reason: &'static str,
    },
    Mark {
        ts_ms: i64,
        kind: &'static str,
        detail: String,
    },
}

/// Shared sender side: try_send that counts drops instead of blocking (the
/// EventHook discipline — never stall a tunnel task on the log).
#[derive(Clone)]
struct EvSender {
    tx: SyncSender<Ev>,
    dropped: Arc<AtomicU64>,
}

impl EvSender {
    fn send(&self, ev: Ev) {
        match self.tx.try_send(ev) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Open handle to the share's connection log. Created once per `share()`;
/// hands out per-session [`SessionLog`]s. Dropping every handle (sessions and
/// flows included) lets the writer thread flush, write a `share_stop` mark,
/// and exit.
pub struct ConnLog {
    sender: EvSender,
    cfg: ConnLogConfig,
}

impl ConnLog {
    /// Open (or create) the database and start the writer thread. Errors are
    /// returned synchronously so a default-on log that cannot be written
    /// fails `share()` loudly instead of degrading silently from the start.
    /// `hook` receives [`TunnelEvent::ConnLogDegraded`](crate::TunnelEvent)
    /// when writing breaks at runtime.
    pub fn open(
        cfg: ConnLogConfig,
        identity: &Identity,
        hook: crate::EventHook,
    ) -> Result<ConnLog, String> {
        std::fs::create_dir_all(&cfg.dir)
            .map_err(|e| format!("connlog: create dir {}: {}", cfg.dir.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&cfg.dir, std::fs::Permissions::from_mode(0o700));
        }
        let path = cfg.dir.join("connlog.sqlite");
        let db = open_db(&path, identity)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // The -wal/-shm side files inherit the database file's mode.
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        let (tx, rx) = std::sync::mpsc::sync_channel::<Ev>(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_cfg = cfg.clone();
        let writer_dropped = dropped.clone();
        std::thread::Builder::new()
            .name("spora-connlog".into())
            .spawn(move || writer_loop(db, rx, writer_cfg, writer_dropped, hook))
            .map_err(|e| format!("connlog: spawn writer: {}", e))?;

        info!("connlog: logging to {}", path.display());
        Ok(ConnLog {
            sender: EvSender { tx, dropped },
            cfg,
        })
    }

    /// Record a new accepted session. `relay` is the QUIC connection's remote
    /// address at accept time — the *relay's* address, since accepted
    /// sessions always bootstrap relay-via; it is recorded as such.
    pub(crate) fn session(&self, relay: SocketAddr) -> Arc<SessionLog> {
        let id = random_id();
        self.sender.send(Ev::SessionStart {
            id,
            ts_ms: now_ms(),
            relay,
        });
        Arc::new(SessionLog {
            id,
            sender: self.sender.clone(),
            log_destinations: self.cfg.log_destinations,
            log_blocked: self.cfg.log_blocked,
            udp_idle: self.cfg.udp_idle,
            tcp_idle: self.cfg.tcp_idle,
            throttle: std::sync::Mutex::new(Throttle::new(
                self.cfg.max_flow_records_per_sec,
                self.cfg.flow_record_burst,
            )),
            seen_addrs: std::sync::Mutex::new(std::collections::HashSet::new()),
            ended: AtomicBool::new(false),
        })
    }
}

/// Per-session log handle. Flow hooks and the upgrade task hold this via
/// `Arc`; ending is idempotent and `Drop` is the fallback so a session can
/// never silently vanish from the log.
pub struct SessionLog {
    id: i64,
    sender: EvSender,
    log_destinations: bool,
    log_blocked: bool,
    pub(crate) udp_idle: Duration,
    pub(crate) tcp_idle: Duration,
    throttle: std::sync::Mutex<Throttle>,
    seen_addrs: std::sync::Mutex<std::collections::HashSet<(u8, SocketAddr)>>,
    ended: AtomicBool,
}

/// Cap on distinct (kind, addr) records per session. The `Reported` value is
/// client-chosen, so without a cap a client cycling fake endpoints every
/// upgrade round would grow both this set and the log without bound.
const MAX_SESSION_ADDRS: usize = 64;

impl SessionLog {
    /// Record what is known about an outer address for this session. The
    /// upgrade loop re-learns the same endpoints every retry round (~15s
    /// cadence), so each (kind, addr) pair is recorded once per session — a
    /// *changed* address still gets its own row and timestamp.
    pub(crate) fn addr(&self, kind: AddrKind, addr: SocketAddr) {
        {
            let mut seen = self.seen_addrs.lock().unwrap();
            if seen.len() >= MAX_SESSION_ADDRS || !seen.insert((kind as u8, addr)) {
                return;
            }
        }
        self.sender.send(Ev::SessionAddr {
            session: self.id,
            ts_ms: now_ms(),
            kind: kind.as_str(),
            addr,
        });
    }

    /// Open a flow record. Returns `None` when flow logging is off for this
    /// session or the rate limiter suppressed the record (counted and
    /// surfaced as a `flow_throttle` mark) — callers proxy regardless.
    pub(crate) fn flow_open(
        &self,
        proto: u8,
        src: SocketAddr,
        dst: SocketAddr,
        confirmed: bool,
    ) -> Option<FlowGuard> {
        if !self.log_destinations || !self.allow_flow_record() {
            return None;
        }
        let id = random_id();
        let ts_ms = now_ms();
        self.sender.send(Ev::FlowOpen {
            id,
            session: self.id,
            ts_ms,
            proto,
            src,
            dst,
            confirmed,
        });
        Some(FlowGuard {
            id,
            sender: self.sender.clone(),
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            established: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }

    /// Record a policy-refused flow (one self-contained row).
    pub(crate) fn flow_blocked(&self, proto: u8, src: SocketAddr, dst: SocketAddr) {
        if !self.log_destinations || !self.log_blocked || !self.allow_flow_record() {
            return;
        }
        self.sender.send(Ev::FlowBlocked {
            id: random_id(),
            session: self.id,
            ts_ms: now_ms(),
            proto,
            src,
            dst,
        });
    }

    fn allow_flow_record(&self) -> bool {
        let now = now_ms();
        let mut t = self.throttle.lock().unwrap();
        let (allowed, summary) = t.allow(now);
        if let Some((from, to, count)) = summary {
            self.sender.send(Ev::Mark {
                ts_ms: now,
                kind: "flow_throttle",
                detail: format!(
                    "{{\"session\":{},\"suppressed\":{},\"from_ms\":{},\"to_ms\":{}}}",
                    self.id, count, from, to
                ),
            });
        }
        allowed
    }

    /// Idempotent session end; `Drop` falls back to reason `"dropped"`.
    pub(crate) fn end(&self, reason: &'static str) {
        if !self.ended.swap(true, Ordering::SeqCst) {
            let now = now_ms();
            let summary = self.throttle.lock().unwrap().take_summary();
            if let Some((from, to, count)) = summary {
                self.sender.send(Ev::Mark {
                    ts_ms: now,
                    kind: "flow_throttle",
                    detail: format!(
                        "{{\"session\":{},\"suppressed\":{},\"from_ms\":{},\"to_ms\":{}}}",
                        self.id, count, from, to
                    ),
                });
            }
            self.sender.send(Ev::SessionEnd {
                session: self.id,
                ts_ms: now,
                reason,
            });
        }
    }
}

impl Drop for SessionLog {
    fn drop(&mut self) {
        self.end("dropped");
    }
}

/// Drop-guard for one flow. The open record is written when the guard is
/// created; the close record is emitted exactly once — explicitly via
/// [`close`](FlowGuard::close), or from `Drop` with reason `"session_end"`.
/// Drop fires on clean completion, error paths, and abort-driven teardown
/// alike, which is what makes "flush flows at session end" automatic.
pub struct FlowGuard {
    id: i64,
    sender: EvSender,
    /// Client→world bytes. Shared with whatever counts (a counting IO
    /// wrapper, the UDP send path, the meter).
    pub(crate) up: Arc<AtomicU64>,
    /// World→client bytes.
    pub(crate) down: Arc<AtomicU64>,
    established: AtomicBool,
    closed: AtomicBool,
}

impl FlowGuard {
    /// Mark the flow established and record the egress (post-NAT-ish) source
    /// address when known — for netstack TCP/UDP this is `getsockname()` of
    /// the re-origination socket, i.e. the source the destination actually
    /// saw from this host.
    pub(crate) fn established(&self, egress: Option<SocketAddr>) {
        if !self.established.swap(true, Ordering::SeqCst) {
            self.sender.send(Ev::FlowEstablished {
                id: self.id,
                egress,
            });
        }
    }

    pub(crate) fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }

    /// Close with an explicit reason. `idle_for` backdates the last-activity
    /// timestamp for idle-evicted flows (the sweep notices up to a sweep
    /// interval late).
    pub(crate) fn close(&self, reason: &'static str, idle_for: Duration) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.sender.send(Ev::FlowClose {
                id: self.id,
                last_ms: now_ms() - idle_for.as_millis() as i64,
                up: self.up.load(Ordering::Relaxed),
                down: self.down.load(Ordering::Relaxed),
                established: self.established.load(Ordering::SeqCst),
                reason,
            });
        }
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.close("session_end", Duration::ZERO);
    }
}

/// Token bucket with suppressed-record accounting.
struct Throttle {
    rate_per_sec: f64,
    burst: f64,
    tokens: f64,
    last_ms: i64,
    suppressed: u64,
    suppressed_from_ms: i64,
    suppressed_to_ms: i64,
}

impl Throttle {
    fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            rate_per_sec: rate_per_sec.max(1) as f64,
            burst: burst.max(1) as f64,
            tokens: burst.max(1) as f64,
            last_ms: 0,
            suppressed: 0,
            suppressed_from_ms: 0,
            suppressed_to_ms: 0,
        }
    }

    /// Returns (allowed, optional summary of a *finished* suppression window).
    fn allow(&mut self, now_ms: i64) -> (bool, Option<(i64, i64, u64)>) {
        if self.last_ms == 0 {
            self.last_ms = now_ms;
        }
        let elapsed = (now_ms - self.last_ms).max(0) as f64 / 1000.0;
        self.last_ms = now_ms;
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            let summary = self.take_summary();
            (true, summary)
        } else {
            if self.suppressed == 0 {
                self.suppressed_from_ms = now_ms;
            }
            self.suppressed += 1;
            self.suppressed_to_ms = now_ms;
            (false, None)
        }
    }

    fn take_summary(&mut self) -> Option<(i64, i64, u64)> {
        if self.suppressed == 0 {
            return None;
        }
        let s = (
            self.suppressed_from_ms,
            self.suppressed_to_ms,
            self.suppressed,
        );
        self.suppressed = 0;
        Some(s)
    }
}

// ---------- Writer thread ----------

fn open_db(path: &Path, identity: &Identity) -> Result<Connection, String> {
    let db = Connection::open(path).map_err(|e| format!("connlog: open {}: {}", path.display(), e))?;
    // auto_vacuum must be set before the first table is created to take
    // effect; on an existing database the pragma is a no-op (kept FULL/INCR
    // from creation time).
    db.pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .map_err(|e| format!("connlog: auto_vacuum: {}", e))?;
    db.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("connlog: WAL: {}", e))?;
    db.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| format!("connlog: synchronous: {}", e))?;
    db.execute_batch(SCHEMA)
        .map_err(|e| format!("connlog: schema: {}", e))?;

    let rk_hex: String = identity
        .routing_key
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let stored_rk: Option<String> = db
        .query_row(
            "SELECT value FROM meta WHERE key='routing_key'",
            [],
            |r| r.get(0),
        )
        .ok();
    if let Some(stored) = stored_rk
        && stored != rk_hex
    {
        return Err(format!(
            "connlog: {} belongs to identity {}, not {} — use a per-identity directory",
            path.display(),
            &stored[..8.min(stored.len())],
            &rk_hex[..8]
        ));
    }
    let version = env!("CARGO_PKG_VERSION");
    db.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES
            ('format_version', ?1), ('routing_key', ?2), ('created_ms', ?3)",
        rusqlite::params![FORMAT_VERSION.to_string(), rk_hex, now_ms().to_string()],
    )
    .map_err(|e| format!("connlog: meta: {}", e))?;
    db.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('software_version', ?1)",
        rusqlite::params![version],
    )
    .map_err(|e| format!("connlog: meta: {}", e))?;
    db.execute(
        "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, 'share_start', ?2)",
        rusqlite::params![now_ms(), format!("{{\"software\":\"{}\"}}", version)],
    )
    .map_err(|e| format!("connlog: share_start mark: {}", e))?;
    Ok(db)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY,
    start_ms   INTEGER NOT NULL,
    end_ms     INTEGER,
    end_reason TEXT,
    relay_addr TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session_addrs (
    session_id INTEGER NOT NULL,
    ts_ms      INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    addr       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS session_addrs_session ON session_addrs(session_id);
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY,
    session_id  INTEGER NOT NULL,
    proto       INTEGER NOT NULL,
    src_ip      TEXT NOT NULL,
    src_port    INTEGER NOT NULL,
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER NOT NULL,
    first_ms    INTEGER NOT NULL,
    last_ms     INTEGER,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    egress_addr TEXT,
    established INTEGER NOT NULL DEFAULT 0,
    confirmed   INTEGER NOT NULL DEFAULT 1,
    end_reason  TEXT
);
CREATE INDEX IF NOT EXISTS flows_dst  ON flows(dst_ip, first_ms);
CREATE INDEX IF NOT EXISTS flows_time ON flows(first_ms);
CREATE TABLE IF NOT EXISTS marks (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms  INTEGER NOT NULL,
    kind   TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS holds (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    from_ms    INTEGER NOT NULL,
    to_ms      INTEGER NOT NULL,
    note       TEXT,
    created_ms INTEGER NOT NULL
);
";

struct WriterState {
    anchor_instant: Instant,
    anchor_wall_ms: i64,
    dropped_seen: u64,
    last_sweep: Option<Instant>,
    /// Set after a write failure; cleared (with a log_gap mark) on recovery.
    degraded_since_ms: Option<i64>,
}

fn writer_loop(
    mut db: Connection,
    rx: Receiver<Ev>,
    cfg: ConnLogConfig,
    dropped: Arc<AtomicU64>,
    hook: crate::EventHook,
) {
    let mut state = WriterState {
        anchor_instant: Instant::now(),
        anchor_wall_ms: now_ms(),
        dropped_seen: 0,
        last_sweep: None,
        degraded_since_ms: None,
    };
    let mut batch: Vec<Ev> = Vec::new();

    loop {
        let disconnected = match rx.recv_timeout(cfg.flush_interval) {
            Ok(ev) => {
                // Drain whatever is immediately available (bounded by the
                // channel capacity) into one transaction.
                batch.push(ev);
                while batch.len() < CHANNEL_CAPACITY {
                    match rx.try_recv() {
                        Ok(ev) => batch.push(ev),
                        Err(_) => break,
                    }
                }
                false
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
        };

        housekeeping(&mut db, &cfg, &mut state, &dropped, &mut batch);

        if !batch.is_empty() {
            match flush_batch(&mut db, &cfg, &batch) {
                Ok(()) => {
                    if let Some(since) = state.degraded_since_ms.take() {
                        let _ = db.execute(
                            "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, 'log_gap', ?2)",
                            rusqlite::params![
                                now_ms(),
                                format!("{{\"reason\":\"write_error\",\"from_ms\":{}}}", since)
                            ],
                        );
                        info!("connlog: writer recovered");
                    }
                    batch.clear();
                }
                Err(e) => {
                    // Keep the batch and retry next round; the tunnel is never
                    // affected. The gap becomes visible via the log_gap mark
                    // written on recovery (and the drop counter if the channel
                    // backs up meanwhile).
                    if state.degraded_since_ms.is_none() {
                        state.degraded_since_ms = Some(now_ms());
                        error!("connlog: write failed (will retry, tunnel unaffected): {}", e);
                        if let Some(h) = &hook {
                            h(crate::TunnelEvent::ConnLogDegraded {
                                detail: e.to_string(),
                            });
                        }
                    }
                    if batch.len() >= CHANNEL_CAPACITY {
                        let dropped_now = batch.len() as u64;
                        dropped.fetch_add(dropped_now, Ordering::Relaxed);
                        warn!("connlog: dropping {} buffered records while degraded", dropped_now);
                        batch.clear();
                    }
                }
            }
        }

        if disconnected {
            let _ = db.execute(
                "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, 'share_stop', NULL)",
                rusqlite::params![now_ms()],
            );
            let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            info!("connlog: writer stopped");
            return;
        }
    }
}

fn housekeeping(
    db: &mut Connection,
    cfg: &ConnLogConfig,
    state: &mut WriterState,
    dropped: &AtomicU64,
    batch: &mut Vec<Ev>,
) {
    // Clock-jump detection: wall time diverging from the monotonic clock
    // (suspend, NTP step, manual change) is recorded so a reader can
    // reconstruct the true timeline instead of silently mis-ordering.
    let expected = state.anchor_wall_ms + state.anchor_instant.elapsed().as_millis() as i64;
    let actual = now_ms();
    let drift = actual - expected;
    if drift.abs() > CLOCK_JUMP_THRESHOLD_MS {
        batch.push(Ev::Mark {
            ts_ms: actual,
            kind: "clock_jump",
            detail: format!("{{\"drift_ms\":{}}}", drift),
        });
        state.anchor_instant = Instant::now();
        state.anchor_wall_ms = actual;
    }

    // Fold channel-overflow drops into a visible gap record.
    let cur = dropped.load(Ordering::Relaxed);
    if cur > state.dropped_seen {
        batch.push(Ev::Mark {
            ts_ms: actual,
            kind: "log_gap",
            detail: format!(
                "{{\"reason\":\"channel_full\",\"dropped\":{}}}",
                cur - state.dropped_seen
            ),
        });
        state.dropped_seen = cur;
    }

    let due = state
        .last_sweep
        .is_none_or(|t| t.elapsed() >= RETENTION_SWEEP_INTERVAL);
    if due {
        state.last_sweep = Some(Instant::now());
        if let Err(e) = retention_sweep(db, cfg.retention) {
            warn!("connlog: retention sweep failed: {}", e);
        }
        let _ = db.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
    }
}

fn flush_batch(db: &mut Connection, cfg: &ConnLogConfig, batch: &[Ev]) -> Result<(), rusqlite::Error> {
    let tx = db.transaction()?;
    for ev in batch {
        match ev {
            Ev::SessionStart { id, ts_ms, relay } => {
                tx.execute(
                    "INSERT OR IGNORE INTO sessions(id, start_ms, relay_addr) VALUES (?1, ?2, ?3)",
                    rusqlite::params![id, ts_ms, relay.to_string()],
                )?;
            }
            Ev::SessionAddr {
                session,
                ts_ms,
                kind,
                addr,
            } => {
                tx.execute(
                    "INSERT INTO session_addrs(session_id, ts_ms, kind, addr) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![session, ts_ms, kind, addr.to_string()],
                )?;
            }
            Ev::SessionEnd {
                session,
                ts_ms,
                reason,
            } => {
                tx.execute(
                    "UPDATE sessions SET end_ms=?2, end_reason=?3 WHERE id=?1 AND end_ms IS NULL",
                    rusqlite::params![session, ts_ms, reason],
                )?;
            }
            Ev::FlowOpen {
                id,
                session,
                ts_ms,
                proto,
                src,
                dst,
                confirmed,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO flows(id, session_id, proto, src_ip, src_port, dst_ip, dst_port, first_ms, confirmed)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        id,
                        session,
                        proto,
                        src.ip().to_string(),
                        src.port(),
                        dst.ip().to_string(),
                        dst.port(),
                        ts_ms,
                        confirmed
                    ],
                )?;
                // Unconfirmed flows (meter path) get one shot at conntrack
                // enrichment: the kernel's entry is freshest right after the
                // first packet, and we're already off the hot path here.
                if !confirmed
                    && let Some(lookup) = &cfg.egress_lookup
                    && let Some(egress) = lookup(*proto, *src, *dst)
                {
                    tx.execute(
                        "UPDATE flows SET egress_addr=?2 WHERE id=?1",
                        rusqlite::params![id, egress.to_string()],
                    )?;
                }
            }
            Ev::FlowBlocked {
                id,
                session,
                ts_ms,
                proto,
                src,
                dst,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO flows(id, session_id, proto, src_ip, src_port, dst_ip, dst_port, first_ms, last_ms, end_reason, confirmed)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'blocked', 1)",
                    rusqlite::params![
                        id,
                        session,
                        proto,
                        src.ip().to_string(),
                        src.port(),
                        dst.ip().to_string(),
                        dst.port(),
                        ts_ms
                    ],
                )?;
            }
            Ev::FlowEstablished { id, egress } => {
                tx.execute(
                    "UPDATE flows SET established=1, egress_addr=COALESCE(?2, egress_addr) WHERE id=?1",
                    rusqlite::params![id, egress.map(|a| a.to_string())],
                )?;
            }
            Ev::FlowClose {
                id,
                last_ms,
                up,
                down,
                established,
                reason,
            } => {
                // MAX(.., first_ms): idle backdating computes last_ms from a
                // monotonic elapsed value, so a wall-clock step between open
                // and close could otherwise place last_ms before first_ms.
                tx.execute(
                    "UPDATE flows SET last_ms=MAX(?2, first_ms), bytes_up=?3, bytes_down=?4,
                        established=MAX(established, ?5), end_reason=?6
                     WHERE id=?1 AND end_reason IS NULL",
                    rusqlite::params![id, last_ms, up, down, *established, reason],
                )?;
            }
            Ev::Mark { ts_ms, kind, detail } => {
                tx.execute(
                    "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, ?2, ?3)",
                    rusqlite::params![ts_ms, kind, detail],
                )?;
            }
        }
    }
    tx.commit()
}

/// Delete expired records, skipping anything overlapping a hold range.
fn retention_sweep(db: &mut Connection, retention: Duration) -> Result<(), rusqlite::Error> {
    let cutoff = now_ms() - retention.as_millis() as i64;
    let tx = db.transaction()?;
    // A flow with last_ms NULL is still open (or was lost to a crash): its
    // age is judged by first_ms, but it is never deleted while its session
    // is younger than the cutoff.
    tx.execute(
        "DELETE FROM flows WHERE COALESCE(last_ms, first_ms) < ?1
           AND NOT EXISTS (SELECT 1 FROM holds h
                           WHERE flows.first_ms <= h.to_ms
                             AND COALESCE(flows.last_ms, flows.first_ms) >= h.from_ms)",
        rusqlite::params![cutoff],
    )?;
    tx.execute(
        "DELETE FROM sessions WHERE COALESCE(end_ms, start_ms) < ?1
           AND NOT EXISTS (SELECT 1 FROM flows f WHERE f.session_id = sessions.id)
           AND NOT EXISTS (SELECT 1 FROM holds h
                           WHERE sessions.start_ms <= h.to_ms
                             AND COALESCE(sessions.end_ms, sessions.start_ms) >= h.from_ms)",
        rusqlite::params![cutoff],
    )?;
    tx.execute(
        "DELETE FROM session_addrs
         WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = session_addrs.session_id)",
        [],
    )?;
    tx.execute(
        "DELETE FROM marks WHERE ts_ms < ?1
           AND NOT EXISTS (SELECT 1 FROM holds h WHERE marks.ts_ms BETWEEN h.from_ms AND h.to_ms)",
        rusqlite::params![cutoff],
    )?;
    tx.commit()?;
    let _ = db.execute_batch("PRAGMA incremental_vacuum;");
    Ok(())
}

// ---------- Read side (used by the CLI's `spora log` and by tests) ----------

/// Open a connlog database read-only.
pub fn open_readonly(dir: &Path) -> Result<Connection, String> {
    let path = dir.join("connlog.sqlite");
    Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| format!("open {}: {}", path.display(), e))
}

/// Open a connlog database read-write (hold management).
pub fn open_readwrite(dir: &Path) -> Result<Connection, String> {
    let path = dir.join("connlog.sqlite");
    Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .map_err(|e| format!("open {}: {}", path.display(), e))
}

#[derive(Debug, Clone)]
pub struct FlowRow {
    pub id: i64,
    pub session_id: i64,
    pub proto: u8,
    pub src: String,
    pub src_port: u16,
    pub dst: String,
    pub dst_port: u16,
    pub first_ms: i64,
    pub last_ms: Option<i64>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub egress_addr: Option<String>,
    pub established: bool,
    pub confirmed: bool,
    pub end_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FlowQuery {
    /// Destination IP to match (canonicalized).
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub session: Option<i64>,
    /// Match flows whose [first,last] interval overlaps [from,to].
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
}

pub fn query_flows(db: &Connection, q: &FlowQuery) -> Result<Vec<FlowRow>, String> {
    let mut sql = String::from(
        "SELECT id, session_id, proto, src_ip, src_port, dst_ip, dst_port, first_ms, last_ms,
                bytes_up, bytes_down, egress_addr, established, confirmed, end_reason
         FROM flows WHERE 1=1",
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(ip) = q.ip {
        params.push(Box::new(ip.to_string()));
        sql.push_str(&format!(" AND dst_ip = ?{}", params.len()));
    }
    if let Some(port) = q.port {
        params.push(Box::new(port));
        sql.push_str(&format!(" AND dst_port = ?{}", params.len()));
    }
    if let Some(session) = q.session {
        params.push(Box::new(session));
        sql.push_str(&format!(" AND session_id = ?{}", params.len()));
    }
    if let Some(to) = q.to_ms {
        params.push(Box::new(to));
        sql.push_str(&format!(" AND first_ms <= ?{}", params.len()));
    }
    if let Some(from) = q.from_ms {
        params.push(Box::new(from));
        sql.push_str(&format!(
            " AND (last_ms IS NULL OR last_ms >= ?{})",
            params.len()
        ));
    }
    sql.push_str(" ORDER BY first_ms");
    let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())), |r| {
            Ok(FlowRow {
                id: r.get(0)?,
                session_id: r.get(1)?,
                proto: r.get(2)?,
                src: r.get(3)?,
                src_port: r.get(4)?,
                dst: r.get(5)?,
                dst_port: r.get(6)?,
                first_ms: r.get(7)?,
                last_ms: r.get(8)?,
                bytes_up: r.get::<_, i64>(9)? as u64,
                bytes_down: r.get::<_, i64>(10)? as u64,
                egress_addr: r.get(11)?,
                established: r.get(12)?,
                confirmed: r.get(13)?,
                end_reason: r.get(14)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows)
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: i64,
    pub start_ms: i64,
    pub end_ms: Option<i64>,
    pub end_reason: Option<String>,
    pub relay_addr: String,
    /// (ts_ms, kind, addr) records, oldest first.
    pub addrs: Vec<(i64, String, String)>,
}

pub fn query_sessions(db: &Connection, ids: Option<&[i64]>) -> Result<Vec<SessionRow>, String> {
    let sql = match ids {
        Some(ids) => format!(
            "SELECT id, start_ms, end_ms, end_reason, relay_addr FROM sessions WHERE id IN ({}) ORDER BY start_ms",
            ids.iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        None => "SELECT id, start_ms, end_ms, end_reason, relay_addr FROM sessions ORDER BY start_ms"
            .to_string(),
    };
    let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
    let mut sessions = stmt
        .query_map([], |r| {
            Ok(SessionRow {
                id: r.get(0)?,
                start_ms: r.get(1)?,
                end_ms: r.get(2)?,
                end_reason: r.get(3)?,
                relay_addr: r.get(4)?,
                addrs: Vec::new(),
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut addr_stmt = db
        .prepare("SELECT ts_ms, kind, addr FROM session_addrs WHERE session_id=?1 ORDER BY ts_ms")
        .map_err(|e| e.to_string())?;
    for s in &mut sessions {
        s.addrs = addr_stmt
            .query_map([s.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
    }
    Ok(sessions)
}

#[derive(Debug, Clone)]
pub struct MarkRow {
    pub ts_ms: i64,
    pub kind: String,
    pub detail: Option<String>,
}

/// Marks overlapping a window — `spora log query` surfaces these so a gap or
/// clock jump inside the queried interval is never silently omitted.
pub fn query_marks(db: &Connection, from_ms: Option<i64>, to_ms: Option<i64>) -> Result<Vec<MarkRow>, String> {
    let mut stmt = db
        .prepare("SELECT ts_ms, kind, detail FROM marks WHERE ts_ms >= ?1 AND ts_ms <= ?2 ORDER BY seq")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(
            rusqlite::params![from_ms.unwrap_or(0), to_ms.unwrap_or(i64::MAX)],
            |r| {
                Ok(MarkRow {
                    ts_ms: r.get(0)?,
                    kind: r.get(1)?,
                    detail: r.get(2)?,
                })
            },
        )
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows)
}

/// Pin a time range against the retention sweep (legal hold / preservation
/// request). Returns the hold id.
pub fn add_hold(db: &Connection, from_ms: i64, to_ms: i64, note: Option<&str>) -> Result<i64, String> {
    db.execute(
        "INSERT INTO holds(from_ms, to_ms, note, created_ms) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![from_ms, to_ms, note, now_ms()],
    )
    .map_err(|e| e.to_string())?;
    Ok(db.last_insert_rowid())
}

/// `(id, from_ms, to_ms, note)`.
pub type HoldRow = (i64, i64, i64, Option<String>);

pub fn list_holds(db: &Connection) -> Result<Vec<HoldRow>, String> {
    let mut stmt = db
        .prepare("SELECT id, from_ms, to_ms, note FROM holds ORDER BY id")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows)
}

pub fn remove_hold(db: &Connection, id: i64) -> Result<bool, String> {
    let n = db
        .execute("DELETE FROM holds WHERE id=?1", rusqlite::params![id])
        .map_err(|e| e.to_string())?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
    }

    fn test_cfg(dir: &Path) -> ConnLogConfig {
        let mut cfg = ConnLogConfig::in_dir(dir);
        cfg.flush_interval = Duration::from_millis(20);
        cfg
    }

    /// Poll the database until `pred` passes (the writer thread is async to
    /// the test) or the deadline expires.
    fn wait_for<F: Fn(&Connection) -> bool>(dir: &Path, pred: F) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(db) = open_readonly(dir)
                && pred(&db)
            {
                return;
            }
            assert!(Instant::now() < deadline, "condition not met within 5s");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn flow_count(db: &Connection) -> i64 {
        db.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))
            .unwrap_or(0)
    }

    #[test]
    fn session_and_flow_lifecycle_lands_in_db() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let log = ConnLog::open(test_cfg(dir.path()), &identity, None).unwrap();

        let session = log.session(addr([203, 0, 113, 1], 443));
        session.addr(AddrKind::Reported, addr([198, 51, 100, 7], 6000));
        session.addr(AddrKind::PunchVerified, addr([198, 51, 100, 7], 6001));

        let flow = session
            .flow_open(6, addr([10, 0, 85, 2], 50000), addr([93, 184, 216, 34], 443), true)
            .unwrap();
        flow.established(Some(addr([192, 0, 2, 10], 41000)));
        flow.add_up(1200);
        flow.add_down(48_000);
        flow.close("closed", Duration::ZERO);
        drop(flow);

        session.flow_blocked(6, addr([10, 0, 85, 2], 50001), addr([192, 168, 1, 1], 80));
        session.end("ended");
        drop(session);
        drop(log);

        wait_for(dir.path(), |db| {
            flow_count(db) == 2
                && db
                    .query_row(
                        "SELECT COUNT(*) FROM marks WHERE kind='share_stop'",
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap_or(0)
                    == 1
        });

        let db = open_readonly(dir.path()).unwrap();
        let flows = query_flows(
            &db,
            &FlowQuery {
                ip: Some("93.184.216.34".parse().unwrap()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(flows.len(), 1);
        let f = &flows[0];
        assert_eq!(f.dst_port, 443);
        assert_eq!(f.bytes_up, 1200);
        assert_eq!(f.bytes_down, 48_000);
        assert!(f.established);
        assert_eq!(f.egress_addr.as_deref(), Some("192.0.2.10:41000"));
        assert_eq!(f.end_reason.as_deref(), Some("closed"));

        let blocked = query_flows(
            &db,
            &FlowQuery {
                ip: Some("192.168.1.1".parse().unwrap()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].end_reason.as_deref(), Some("blocked"));

        let sessions = query_sessions(&db, None).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].end_reason.as_deref(), Some("ended"));
        assert_eq!(sessions[0].addrs.len(), 2);
        assert_eq!(sessions[0].relay_addr, "203.0.113.1:443");
    }

    #[test]
    fn dropped_flow_guard_closes_with_session_end() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let log = ConnLog::open(test_cfg(dir.path()), &identity, None).unwrap();
        let session = log.session(addr([203, 0, 113, 1], 443));
        let flow = session
            .flow_open(17, addr([10, 0, 85, 2], 5353), addr([8, 8, 8, 8], 53), true)
            .unwrap();
        flow.add_up(64);
        // Simulate abort-driven teardown: the guard is dropped, never closed.
        drop(flow);
        drop(session);
        drop(log);

        wait_for(dir.path(), |db| {
            db.query_row(
                "SELECT COUNT(*) FROM flows WHERE end_reason='session_end' AND bytes_up=64",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
                == 1
        });
    }

    #[test]
    fn throttle_suppresses_and_summarizes() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let mut cfg = test_cfg(dir.path());
        cfg.max_flow_records_per_sec = 1;
        cfg.flow_record_burst = 5;
        let log = ConnLog::open(cfg, &identity, None).unwrap();
        let session = log.session(addr([203, 0, 113, 1], 443));

        let mut opened = 0;
        for i in 0..50u16 {
            if let Some(f) = session.flow_open(
                17,
                addr([10, 0, 85, 2], 40000 + i),
                addr([8, 8, 8, 8], 53),
                true,
            ) {
                opened += 1;
                f.close("closed", Duration::ZERO);
            }
        }
        assert!(opened <= 6, "burst cap should limit records, got {}", opened);
        session.end("ended");
        drop(session);
        drop(log);

        wait_for(dir.path(), |db| {
            db.query_row(
                "SELECT COUNT(*) FROM marks WHERE kind='flow_throttle'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
                >= 1
        });
        let db = open_readonly(dir.path()).unwrap();
        let marks = query_marks(&db, None, None).unwrap();
        let throttle = marks.iter().find(|m| m.kind == "flow_throttle").unwrap();
        assert!(throttle.detail.as_deref().unwrap().contains("\"suppressed\":"));
    }

    #[test]
    fn sessions_only_mode_logs_no_flows() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let mut cfg = test_cfg(dir.path());
        cfg.log_destinations = false;
        let log = ConnLog::open(cfg, &identity, None).unwrap();
        let session = log.session(addr([203, 0, 113, 1], 443));
        assert!(session
            .flow_open(6, addr([10, 0, 85, 2], 50000), addr([93, 184, 216, 34], 443), true)
            .is_none());
        session.flow_blocked(6, addr([10, 0, 85, 2], 50001), addr([192, 168, 1, 1], 80));
        session.end("ended");
        drop(session);
        drop(log);

        wait_for(dir.path(), |db| {
            db.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
                == 1
        });
        let db = open_readonly(dir.path()).unwrap();
        assert_eq!(flow_count(&db), 0);
    }

    #[test]
    fn retention_sweep_respects_holds() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let log = ConnLog::open(test_cfg(dir.path()), &identity, None).unwrap();
        drop(log); // schema exists; writer exits
        wait_for(dir.path(), |db| {
            db.query_row(
                "SELECT COUNT(*) FROM marks WHERE kind='share_stop'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
                == 1
        });

        let db = open_readwrite(dir.path()).unwrap();
        let now = now_ms();
        let old = now - 200 * 24 * 3600 * 1000; // 200 days ago
        // Session 2 (and its flow) sit outside the hold window below.
        db.execute(
            "INSERT INTO sessions(id, start_ms, end_ms, relay_addr) VALUES (1, ?1, ?1, 'r'), (2, ?2, ?2, 'r')",
            rusqlite::params![old, old - 1000],
        )
        .unwrap();
        db.execute(
            "INSERT INTO flows(id, session_id, proto, src_ip, src_port, dst_ip, dst_port, first_ms, last_ms)
             VALUES (10, 1, 6, 's', 1, 'held.example', 443, ?1, ?1),
                    (11, 2, 6, 's', 1, 'expired.example', 443, ?2, ?2)",
            rusqlite::params![old, old - 1000],
        )
        .unwrap();
        // Hold covering flow 10's interval only.
        add_hold(&db, old - 10, old + 10, Some("preservation request")).unwrap();
        drop(db);

        let mut db = open_readwrite(dir.path()).unwrap();
        retention_sweep(&mut db, Duration::from_secs(90 * 24 * 3600)).unwrap();

        let remaining: Vec<String> = {
            let mut stmt = db.prepare("SELECT dst_ip FROM flows ORDER BY id").unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(remaining, vec!["held.example".to_string()]);
        // Session 1 still has a flow → survives; session 2 lost its flow → gone.
        let session_ids: Vec<i64> = {
            let mut stmt = db.prepare("SELECT id FROM sessions ORDER BY id").unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(session_ids, vec![1]);
    }

    #[test]
    fn rejects_db_of_a_different_identity() {
        let dir = tempfile::tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let log = ConnLog::open(test_cfg(dir.path()), &id_a, None).unwrap();
        drop(log);
        wait_for(dir.path(), |db| {
            db.query_row(
                "SELECT COUNT(*) FROM marks WHERE kind='share_stop'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
                >= 1
        });
        let err = match ConnLog::open(test_cfg(dir.path()), &id_b, None) {
            Ok(_) => panic!("opening another identity's log must fail"),
            Err(e) => e,
        };
        assert!(err.contains("belongs to identity"), "{}", err);
    }

    #[test]
    fn flow_query_overlap_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let log = ConnLog::open(test_cfg(dir.path()), &identity, None).unwrap();
        drop(log);
        wait_for(dir.path(), |db| {
            db.query_row("SELECT COUNT(*) FROM marks", [], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
                >= 1
        });

        let db = open_readwrite(dir.path()).unwrap();
        db.execute(
            "INSERT INTO flows(id, session_id, proto, src_ip, src_port, dst_ip, dst_port, first_ms, last_ms)
             VALUES (1, 1, 6, 's', 1, '1.2.3.4', 443, 1000, 2000),
                    (2, 1, 6, 's', 1, '1.2.3.4', 443, 5000, NULL),
                    (3, 1, 6, 's', 1, '1.2.3.4', 443, 9000, 9500)",
            [],
        )
        .unwrap();

        // Window [1500, 6000]: flow 1 overlaps, flow 2 (still open) counts,
        // flow 3 starts after the window.
        let rows = query_flows(
            &db,
            &FlowQuery {
                ip: Some("1.2.3.4".parse().unwrap()),
                from_ms: Some(1500),
                to_ms: Some(6000),
                ..Default::default()
            },
        )
        .unwrap();
        let ids: Vec<i64> = rows.iter().map(|f| f.id).collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn throttle_token_bucket_refills() {
        let mut t = Throttle::new(10, 10);
        let t0 = 1_000_000i64;
        for i in 0..10 {
            assert!(t.allow(t0 + i).0, "burst allows first 10");
        }
        assert!(!t.allow(t0 + 11).0, "bucket empty");
        assert!(!t.allow(t0 + 12).0);
        // 500ms later: 5 tokens refilled, and the first allow carries the
        // suppression summary.
        let (ok, summary) = t.allow(t0 + 512);
        assert!(ok);
        let (from, to, count) = summary.expect("summary of the finished window");
        assert_eq!(count, 2);
        assert!(from <= to);
    }
}
