//! Persistent relay session log.
//!
//! The dumb relay forwards by 5-tuple and holds no keys, but the relay
//! *operator* fronts every byte that crosses it, so — like the sharer's
//! connection log (see `docs/connection-logging.md`) — it keeps a local,
//! auto-expiring record of which client address reached which sharer (by
//! routing key) and when. This answers the operator's analog of the abuse/LE
//! query: "which client used routing key Z through this relay during
//! [T1,T2]". No payload, no QUIC inspection beyond the DCID the forwarder
//! already reads.
//!
//! It stays off the forwarding hot path: `serve`/`handle_packet` only bump
//! in-memory atomic counters and `try_send` open/close events into a bounded
//! channel; a dedicated writer thread batches them into SQLite transactions.
//! A full channel drops the event and counts it (folded into a `log_gap`
//! mark), so forwarding never blocks on disk — and a gap is always visible
//! rather than masquerading as "no sessions".

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use rusqlite::Connection;

pub const FORMAT_VERSION: i64 = 1;

const CHANNEL_CAPACITY: usize = 16 * 1024;
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Clone)]
pub struct SessionLogConfig {
    /// SQLite file (its parent directory is created 0700 on unix).
    pub path: PathBuf,
    /// Sessions older than this are deleted by the periodic sweep. Default 90d.
    pub retention: Duration,
    /// Writer batch window: events are committed at least this often.
    pub flush_interval: Duration,
}

impl SessionLogConfig {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            retention: Duration::from_secs(90 * 24 * 60 * 60),
            flush_interval: Duration::from_secs(1),
        }
    }
}

fn now_ms() -> i64 {
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

/// Live accounting for one matched flow (client <-> sharer). Shared by both
/// directions' forwarding-table entries via `Arc`, so either direction's
/// packets accumulate into the same totals with no cross-lookup, and the
/// close is emitted exactly once (idempotent `closed` flag).
pub struct SessionState {
    id: i64,
    routing_key_hex: String,
    start_ms: i64,
    pkts_c2s: AtomicU64,
    bytes_c2s: AtomicU64,
    pkts_s2c: AtomicU64,
    bytes_s2c: AtomicU64,
    closed: AtomicBool,
}

impl SessionState {
    fn new(routing_key: &[u8]) -> SessionState {
        let routing_key_hex = routing_key.iter().map(|b| format!("{:02x}", b)).collect();
        SessionState {
            id: random_id(),
            routing_key_hex,
            start_ms: now_ms(),
            pkts_c2s: AtomicU64::new(0),
            bytes_c2s: AtomicU64::new(0),
            pkts_s2c: AtomicU64::new(0),
            bytes_s2c: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    /// Account a client→sharer packet of `bytes` (hot path: one atomic add).
    pub fn add_c2s(&self, bytes: u64) {
        self.pkts_c2s.fetch_add(1, Ordering::Relaxed);
        self.bytes_c2s.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Account a sharer→client packet of `bytes`.
    pub fn add_s2c(&self, bytes: u64) {
        self.pkts_s2c.fetch_add(1, Ordering::Relaxed);
        self.bytes_s2c.fetch_add(bytes, Ordering::Relaxed);
    }
}

enum Ev {
    Open {
        id: i64,
        routing_key_hex: String,
        client: String,
        sharer: String,
        start_ms: i64,
    },
    Close {
        id: i64,
        end_ms: i64,
        reason: &'static str,
        pkts_c2s: u64,
        bytes_c2s: u64,
        pkts_s2c: u64,
        bytes_s2c: u64,
    },
    Mark {
        ts_ms: i64,
        kind: &'static str,
        detail: Option<String>,
    },
}

/// Cheap, clonable handle held by the relay's `State`. Sending never blocks
/// the forwarding loop: a full channel drops the event and bumps `dropped`.
#[derive(Clone)]
pub struct SessionLog {
    tx: SyncSender<Ev>,
    dropped: Arc<AtomicU64>,
}

impl SessionLog {
    /// Open (or create) the database and start the writer thread. Errors are
    /// returned synchronously so the operator learns at startup that the log
    /// they asked for cannot be written, rather than discovering a silent gap
    /// later.
    pub fn open(cfg: SessionLogConfig) -> Result<SessionLog, String> {
        if let Some(parent) = cfg.path.parent()
            && !parent.as_os_str().is_empty()
        {
            // Only tighten a directory we actually create here — never an
            // existing one. `--session-log /var/lib/foo.sqlite` (as root) or
            // `./foo.sqlite` must not silently chmod a shared dir or the cwd.
            let existed = parent.exists();
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("session log: create dir {}: {}", parent.display(), e))?;
            #[cfg(unix)]
            if !existed {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let db = open_db(&cfg.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&cfg.path, std::fs::Permissions::from_mode(0o600));
        }

        let (tx, rx) = std::sync::mpsc::sync_channel::<Ev>(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_dropped = dropped.clone();
        std::thread::Builder::new()
            .name("relay-sessionlog".into())
            .spawn(move || writer_loop(db, rx, cfg, writer_dropped))
            .map_err(|e| format!("session log: spawn writer: {}", e))?;

        Ok(SessionLog { tx, dropped })
    }

    /// Begin accounting for a matched flow; returns the shared state to stash
    /// on both forwarding-table entries.
    pub fn open_session(
        &self,
        routing_key: &[u8],
        client: SocketAddr,
        sharer: SocketAddr,
    ) -> Arc<SessionState> {
        let st = Arc::new(SessionState::new(routing_key));
        self.send(Ev::Open {
            id: st.id,
            routing_key_hex: st.routing_key_hex.clone(),
            client: client.to_string(),
            sharer: sharer.to_string(),
            start_ms: st.start_ms,
        });
        st
    }

    /// Close a session exactly once (idempotent). `reason` is `idle`,
    /// `displaced`, or `shutdown`.
    pub fn close_session(&self, st: &SessionState, reason: &'static str) {
        if st.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.send(Ev::Close {
            id: st.id,
            end_ms: now_ms(),
            reason,
            pkts_c2s: st.pkts_c2s.load(Ordering::Relaxed),
            bytes_c2s: st.bytes_c2s.load(Ordering::Relaxed),
            pkts_s2c: st.pkts_s2c.load(Ordering::Relaxed),
            bytes_s2c: st.bytes_s2c.load(Ordering::Relaxed),
        });
    }

    fn send(&self, ev: Ev) {
        match self.tx.try_send(ev) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ---------- Writer thread ----------

fn open_db(path: &Path) -> Result<Connection, String> {
    // Pre-create the database file 0600 *before* opening it, so SQLite copies
    // that mode onto the -wal/-shm sidecars it creates when WAL is enabled
    // (chmod-ing afterwards would leave the sidecars at the umask default,
    // and the default path may sit in a world-readable cwd).
    #[cfg(unix)]
    if !path.exists() {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path);
    }
    let db = Connection::open(path)
        .map_err(|e| format!("session log: open {}: {}", path.display(), e))?;
    db.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("session log: WAL: {}", e))?;
    db.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| format!("session log: synchronous: {}", e))?;
    db.execute_batch(SCHEMA)
        .map_err(|e| format!("session log: schema: {}", e))?;
    let version = env!("CARGO_PKG_VERSION");
    db.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES ('format_version', ?1), ('created_ms', ?2)",
        rusqlite::params![FORMAT_VERSION.to_string(), now_ms().to_string()],
    )
    .map_err(|e| format!("session log: meta: {}", e))?;
    db.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('software_version', ?1)",
        rusqlite::params![version],
    )
    .map_err(|e| format!("session log: meta: {}", e))?;
    db.execute(
        "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, 'relay_start', ?2)",
        rusqlite::params![now_ms(), format!("{{\"software\":\"{}\"}}", version)],
    )
    .map_err(|e| format!("session log: relay_start mark: {}", e))?;
    Ok(db)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY,
    routing_key TEXT NOT NULL,
    client_addr TEXT NOT NULL,
    sharer_addr TEXT NOT NULL,
    start_ms    INTEGER NOT NULL,
    end_ms      INTEGER,
    end_reason  TEXT,
    pkts_c2s    INTEGER NOT NULL DEFAULT 0,
    bytes_c2s   INTEGER NOT NULL DEFAULT 0,
    pkts_s2c    INTEGER NOT NULL DEFAULT 0,
    bytes_s2c   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_rk     ON sessions(routing_key, start_ms);
CREATE INDEX IF NOT EXISTS sessions_client ON sessions(client_addr, start_ms);
CREATE INDEX IF NOT EXISTS sessions_time   ON sessions(start_ms);
CREATE TABLE IF NOT EXISTS marks (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms  INTEGER NOT NULL,
    kind   TEXT NOT NULL,
    detail TEXT
);
";

fn writer_loop(
    mut db: Connection,
    rx: Receiver<Ev>,
    cfg: SessionLogConfig,
    dropped: Arc<AtomicU64>,
) {
    let mut batch: Vec<Ev> = Vec::new();
    let mut dropped_seen: u64 = 0;
    let mut last_sweep: Option<Instant> = None;
    let mut degraded_since_ms: Option<i64> = None;

    loop {
        let disconnected = match rx.recv_timeout(cfg.flush_interval) {
            Ok(ev) => {
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

        // Fold channel-overflow drops into a visible gap record.
        let cur = dropped.load(Ordering::Relaxed);
        if cur > dropped_seen {
            batch.push(Ev::Mark {
                ts_ms: now_ms(),
                kind: "log_gap",
                detail: Some(format!(
                    "{{\"reason\":\"channel_full\",\"dropped\":{}}}",
                    cur - dropped_seen
                )),
            });
            dropped_seen = cur;
        }

        if last_sweep.is_none_or(|t| t.elapsed() >= RETENTION_SWEEP_INTERVAL) {
            last_sweep = Some(Instant::now());
            if let Err(e) = retention_sweep(&db, cfg.retention) {
                warn!("session log: retention sweep failed: {}", e);
            }
            let _ = db.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
        }

        if !batch.is_empty() {
            match flush_batch(&mut db, &batch) {
                Ok(()) => {
                    if let Some(since) = degraded_since_ms.take() {
                        let _ = db.execute(
                            "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, 'log_gap', ?2)",
                            rusqlite::params![
                                now_ms(),
                                format!("{{\"reason\":\"write_error\",\"from_ms\":{}}}", since)
                            ],
                        );
                        info!("session log: writer recovered");
                    }
                    batch.clear();
                }
                Err(e) => {
                    if degraded_since_ms.is_none() {
                        degraded_since_ms = Some(now_ms());
                        error!(
                            "session log: write failed (will retry, forwarding unaffected): {}",
                            e
                        );
                    }
                    if batch.len() >= CHANNEL_CAPACITY {
                        dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
                        batch.clear();
                    }
                }
            }
        }

        if disconnected {
            let _ = db.execute(
                "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, 'relay_stop', NULL)",
                rusqlite::params![now_ms()],
            );
            let _ = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            info!("session log: writer stopped");
            return;
        }
    }
}

fn flush_batch(db: &mut Connection, batch: &[Ev]) -> Result<(), rusqlite::Error> {
    let tx = db.transaction()?;
    for ev in batch {
        match ev {
            Ev::Open {
                id,
                routing_key_hex,
                client,
                sharer,
                start_ms,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO sessions(id, routing_key, client_addr, sharer_addr, start_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![id, routing_key_hex, client, sharer, start_ms],
                )?;
            }
            Ev::Close {
                id,
                end_ms,
                reason,
                pkts_c2s,
                bytes_c2s,
                pkts_s2c,
                bytes_s2c,
            } => {
                // MAX(?2, start_ms): a backward wall-clock step between open
                // and close must not record an end earlier than the start.
                tx.execute(
                    "UPDATE sessions SET end_ms=MAX(?2, start_ms), end_reason=?3,
                        pkts_c2s=?4, bytes_c2s=?5, pkts_s2c=?6, bytes_s2c=?7
                     WHERE id=?1 AND end_ms IS NULL",
                    rusqlite::params![id, end_ms, reason, pkts_c2s, bytes_c2s, pkts_s2c, bytes_s2c],
                )?;
            }
            Ev::Mark {
                ts_ms,
                kind,
                detail,
            } => {
                tx.execute(
                    "INSERT INTO marks(ts_ms, kind, detail) VALUES (?1, ?2, ?3)",
                    rusqlite::params![ts_ms, kind, detail],
                )?;
            }
        }
    }
    tx.commit()
}

fn retention_sweep(db: &Connection, retention: Duration) -> Result<(), rusqlite::Error> {
    let cutoff = now_ms() - retention.as_millis() as i64;
    db.execute(
        "DELETE FROM sessions WHERE COALESCE(end_ms, start_ms) < ?1",
        rusqlite::params![cutoff],
    )?;
    db.execute(
        "DELETE FROM marks WHERE ts_ms < ?1",
        rusqlite::params![cutoff],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn wait_for<F: Fn(&Connection) -> bool>(path: &Path, pred: F) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(db) =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                && pred(&db)
            {
                return;
            }
            assert!(Instant::now() < deadline, "condition not met within 5s");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn cfg(path: &Path) -> SessionLogConfig {
        let mut c = SessionLogConfig::at(path);
        c.flush_interval = Duration::from_millis(20);
        c
    }

    #[test]
    fn open_count_close_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.sqlite");
        let log = SessionLog::open(cfg(&path)).unwrap();

        let rk = [0xABu8; 20];
        let st = log.open_session(&rk, addr("203.0.113.9:51000"), addr("198.51.100.4:443"));
        st.add_c2s(1200);
        st.add_c2s(800);
        st.add_s2c(64_000);
        log.close_session(&st, "idle");
        // Double close is a no-op.
        log.close_session(&st, "displaced");
        drop(log);

        wait_for(&path, |db| {
            db.query_row(
                "SELECT COUNT(*) FROM sessions WHERE end_reason='idle'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
                == 1
        });

        let db = Connection::open(&path).unwrap();
        let (rk_hex, client, sharer, c2s_b, c2s_p, s2c_b, reason): (
            String,
            String,
            String,
            i64,
            i64,
            i64,
            String,
        ) = db
            .query_row(
                "SELECT routing_key, client_addr, sharer_addr, bytes_c2s, pkts_c2s, bytes_s2c, end_reason FROM sessions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        assert_eq!(rk_hex, "ab".repeat(20));
        assert_eq!(client, "203.0.113.9:51000");
        assert_eq!(sharer, "198.51.100.4:443");
        assert_eq!(c2s_b, 2000);
        assert_eq!(c2s_p, 2);
        assert_eq!(s2c_b, 64_000);
        assert_eq!(reason, "idle");

        // relay_start mark present; relay_stop written on clean drop.
        let marks: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM marks WHERE kind IN ('relay_start','relay_stop')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(marks, 2);
    }

    #[test]
    fn retention_deletes_old_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.sqlite");
        let log = SessionLog::open(cfg(&path)).unwrap();
        drop(log);
        wait_for(&path, |db| {
            db.query_row(
                "SELECT COUNT(*) FROM marks WHERE kind='relay_stop'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
                == 1
        });

        let db = Connection::open(&path).unwrap();
        let old = now_ms() - 200 * 24 * 3600 * 1000;
        let recent = now_ms() - 1000;
        db.execute(
            "INSERT INTO sessions(id, routing_key, client_addr, sharer_addr, start_ms, end_ms)
             VALUES (1,'a','c','s',?1,?1), (2,'a','c','s',?2,?2)",
            rusqlite::params![old, recent],
        )
        .unwrap();
        retention_sweep(&db, Duration::from_secs(90 * 24 * 3600)).unwrap();
        let ids: Vec<i64> = {
            let mut stmt = db.prepare("SELECT id FROM sessions ORDER BY id").unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(ids, vec![2]);
    }
}
