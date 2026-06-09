#[cfg(not(windows))]
use spora_core::{connect, identity::Identity, share, tun_util, Config};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio_tun::Tun;
use url::Url;

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
    },
    Use {
        url: String,
    },
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
        } => {
            let path = identity_file.unwrap_or_else(default_identity_path);
            let identity = load_or_create_identity(&path, fresh)?;
            let session = share(identity, Config::default()).await?;
            println!("Share this URL with the peer that wants to connect:");
            println!("{}", session.url);
            println!("(Identity persisted at {})", path.display());
            println!("Press Ctrl+C to stop sharing.");
            tokio::signal::ctrl_c().await?;
            println!("Stopping share session...");
            session.stop().await;
        }
        Mode::Use { url } => {
            #[cfg(windows)]
            {
                let _ = url; // silence unused warning
                return Err("The 'use' mode is not supported on Windows yet (requires a TUN device).".into());
            }

            #[cfg(not(windows))]
            {
                let url = Url::parse(&url)?;
                if url.scheme() != "https" {
                    panic!("Unsupported scheme {}. Expected an https:// URL", url.scheme());
                }
                let result = connect(url, &Config::default()).await.unwrap();
                let tun = Tun::builder().name("").up().try_build().unwrap();
                tun_util::start(result.transport, tun).await?;
            }
        }
    }
    Ok(())
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
    std::fs::write(path, identity.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(identity)
}

#[cfg(windows)]
fn load_or_create_identity(
    _path: &std::path::Path,
    _fresh: bool,
) -> Result<Identity, Box<dyn std::error::Error>> {
    unreachable!("Share mode is not supported on Windows in the CLI")
}
