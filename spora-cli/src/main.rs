#[cfg(not(windows))]
use spora_core::{connect, identity::Identity, share, tun_util, Config, ExitMode};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio_tun::Tun;
use url::Url;

#[cfg(not(windows))]
mod os_route;

/// Active keepalive/liveness probe interval (seconds) for the always-on CLI
/// client. Non-zero opts out of spora-core's dormant ("screen off") mode.
const KEEPALIVE_PROBE_SECS: u64 = 10;

/// Use jemalloc on non-Windows. The default glibc allocator holds onto pages
/// under heavy alloc/free churn (every IP packet on the share side allocates
/// a `Vec<u8>`); jemalloc returns memory to the OS far more aggressively.
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(name = "spora")]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug, Clone)]
enum Mode {
    /// Share over a tunnel. Loads (or creates on first run) a persistent
    /// identity at $XDG_CONFIG_HOME/spora/identity.bin so the share URL stays
    /// the same across invocations.
    Share {
        /// Override the identity file path.
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// Generate a fresh identity for this run and overwrite the
        /// persisted one.
        #[arg(long)]
        fresh: bool,
        /// Bypass the userland netstack: write client packets to a TUN device
        /// and let the kernel route/NAT them. Requires root (or
        /// CAP_NET_ADMIN). Linux only.
        #[arg(long)]
        os_routing: bool,
        /// TUN interface address in CIDR form (with --os-routing).
        #[arg(long, default_value = "10.213.0.1/24", requires = "os_routing")]
        tun_addr: String,
        /// TUN MTU (with --os-routing).
        #[arg(long, default_value_t = 1280, requires = "os_routing")]
        tun_mtu: u16,
        /// With --os-routing: don't touch ip_forward or iptables. You are
        /// responsible for forwarding + NAT; per-client return routes on the
        /// TUN are still installed.
        #[arg(long, requires = "os_routing")]
        no_nat: bool,
        /// Override the relay address (host:port) used for registration and
        /// baked into the share URL.
        #[arg(long)]
        relay: Option<String>,
        /// Override the STUN server (host:port) used for direct-upgrade
        /// endpoint discovery.
        #[arg(long)]
        stun: Option<String>,
    },
    Use {
        url: String,
        /// Override the STUN server (host:port) used for direct-upgrade
        /// endpoint discovery.
        #[arg(long)]
        stun: Option<String>,
    },
}

/// Split `host:port` on the LAST ':' (so bracketed IPv6 like `[::1]:443`
/// works) and validate the port.
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let Some(idx) = s.rfind(':') else {
        return Err(format!("'{}' is not a host:port pair (no ':' found)", s));
    };
    let (host, port_str) = (&s[..idx], &s[idx + 1..]);
    if host.is_empty() {
        return Err(format!("'{}' has an empty host part", s));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("'{}' is not a valid port in '{}'", port_str, s))?;
    Ok((host.to_string(), port))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("quinn", log::LevelFilter::Warn)
        .filter_module("quinn_proto", log::LevelFilter::Warn)
        .filter_module("quinn_udp", log::LevelFilter::Warn)
        .filter_module("tracing", log::LevelFilter::Warn)
        .filter_module("smoltcp", log::LevelFilter::Warn)
        .init();
    let args = Args::parse();
    match args.mode {
        Mode::Share {
            identity_file,
            fresh,
            os_routing,
            tun_addr,
            tun_mtu,
            no_nat,
            relay,
            stun,
        } => {
            let path = identity_file.unwrap_or_else(default_identity_path);
            let identity = load_or_create_identity(&path, fresh)?;
            let mut config = Config::default();
            if let Some(relay) = relay {
                let (host, port) = parse_host_port(&relay)
                    .map_err(|e| format!("--relay: {}", e))?;
                config.relay_host = host;
                config.relay_port = port;
            }
            if let Some(stun) = stun {
                parse_host_port(&stun).map_err(|e| format!("--stun: {}", e))?;
                config.stun_server = stun;
            }
            let mut routing = None;
            if os_routing {
                let opts = os_route::Options::parse(&tun_addr, tun_mtu, !no_nat)?;
                let guard = os_route::OsRoute::setup(&opts)?;
                config.exit_mode = ExitMode::Custom(guard.session_handler());
                routing = Some(guard);
            }
            let session = share(identity, config).await?;
            println!("Share this URL with the peer that wants to connect:");
            println!("{}", session.url);
            println!("(Identity persisted at {})", path.display());
            if let Some(g) = &routing {
                println!(
                    "OS routing enabled: client traffic is forwarded by the kernel via {}.",
                    g.tun_name()
                );
            }
            println!("Press Ctrl+C to stop sharing.");
            wait_for_shutdown().await?;
            println!("Stopping share session...");
            session.stop().await;
            // `routing` (if any) drops here, after the session has stopped,
            // running OsRoute's cleanup. Dropping at scope end — rather than an
            // explicit call — means cleanup also runs if `share()` errored above
            // or the task panicked.
            drop(routing);
        }
        Mode::Use { url, stun } => {
            #[cfg(windows)]
            {
                let _ = (url, stun); // silence unused warning
                return Err("The 'use' mode is not supported on Windows yet (requires a TUN device).".into());
            }

            #[cfg(not(windows))]
            {
                let url = Url::parse(&url)?;
                if url.scheme() != "https" {
                    panic!("Unsupported scheme {}. Expected an https:// URL", url.scheme());
                }
                let mut config = Config::default();
                if let Some(stun) = stun {
                    parse_host_port(&stun).map_err(|e| format!("--stun: {}", e))?;
                    config.stun_server = stun;
                }
                let result = connect(url, &config).await.unwrap();
                // The CLI is always-on and has no screen state, so opt out of the
                // Android dormant/battery semantics. A keepalive knob of 0 means
                // "screen off" to spora-core, which disables the liveness probe
                // (a dead tunnel is never detected) and parks the direct upgrade
                // after a few transient failures. Set an active probe interval so
                // neither happens; only the Android FFI drives the knob to 0.
                result
                    .keepalive_knob
                    .store(KEEPALIVE_PROBE_SECS, std::sync::atomic::Ordering::Relaxed);
                if let Some(w) = result.keepalive_waker.lock().unwrap().take() {
                    w.wake();
                }
                let tun = Tun::builder().name("").up().try_build().unwrap();
                tun_util::start(result.transport, tun).await?;
            }
        }
    }
    Ok(())
}

/// Wait for an interactive (Ctrl+C / SIGINT) or service (SIGTERM) shutdown
/// signal. Handling SIGTERM matters for `--os-routing`: `systemctl stop` and
/// `kill` send SIGTERM, and we want OsRoute's cleanup to run before we exit.
async fn wait_for_shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(not(windows))]
fn default_identity_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("spora").join("identity.bin")
}

#[cfg(windows)]
fn default_identity_path() -> PathBuf {
    // The Use mode is the only one usable on Windows; Share won't be hit, but
    // be defensive about the binary still compiling.
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("spora")
        .join("identity.bin")
}

#[cfg(not(windows))]
fn load_or_create_identity(
    path: &std::path::Path,
    fresh: bool,
) -> Result<Identity, Box<dyn std::error::Error>> {
    if !fresh
        && let Ok(bytes) = std::fs::read(path)
    {
        return Ok(Identity::from_bytes(&bytes)?);
    }
    let identity = Identity::generate();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_identity_atomically(path, &identity.to_bytes())?;
    Ok(identity)
}

/// Persist the identity (private key + secret) durably and privately.
///
/// `std::fs::write` truncates-then-writes in place: a crash or power loss
/// mid-write leaves a torn file, and `Identity::from_bytes` then fails on every
/// later launch — bricking `spora share` and the user's stable URL. It also
/// creates the file with the umask (typically world-/group-readable) and only
/// chmods afterward, leaving a window where the private key is exposed.
///
/// Instead, write to a sibling temp file created `0600` from the start, fsync
/// it, then atomically rename over the target: a reader (and a crash) sees
/// either the old file or the complete new one, never a truncated mix, and the
/// key bytes are never group/world-readable.
#[cfg(unix)]
fn write_identity_atomically(
    path: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("identity.bin");
    // Per-process temp name so a concurrent writer can't clobber our partial
    // file before the rename.
    let tmp = dir.join(format!(".{}.{}.tmp", stem, std::process::id()));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    let res = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(windows)]
fn load_or_create_identity(
    _path: &std::path::Path,
    _fresh: bool,
) -> Result<Identity, Box<dyn std::error::Error>> {
    unreachable!("Share mode is not supported on Windows in the CLI")
}

#[cfg(all(test, unix))]
mod identity_persistence_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A unique scratch dir under the temp dir (no tempfile dependency).
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "spora-cli-test-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn created_identity_is_private_and_round_trips() {
        let dir = scratch("create");
        let path = dir.join("identity.bin");

        let id = load_or_create_identity(&path, false).unwrap();

        // The private key must never be group/world readable, even briefly.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "identity file must be 0600");

        // Loading again (fresh=false) returns the SAME identity, not a new one.
        let again = load_or_create_identity(&path, false).unwrap();
        assert_eq!(
            id.to_bytes(),
            again.to_bytes(),
            "persisted identity must be stable across launches"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_write_replaces_without_leaving_a_temp() {
        let dir = scratch("atomic");
        let path = dir.join("identity.bin");

        write_identity_atomically(&path, b"first-version").unwrap();
        write_identity_atomically(&path, b"second-version-which-is-longer").unwrap();

        // The final file holds the complete new content (never a torn mix)...
        assert_eq!(std::fs::read(&path).unwrap(), b"second-version-which-is-longer");
        // ...and the rename consumed the temp — no `.identity.bin.<pid>.tmp` litter.
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "temp file leaked: {:?}", leftover);

        std::fs::remove_dir_all(&dir).ok();
    }
}
