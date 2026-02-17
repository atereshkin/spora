#[cfg(not(windows))]

use spora_core::{connect, make_secret_key, share, tun_util, Config};
use clap::{Parser, Subcommand};
use tokio_tun::Tun;
use url::{Url};

#[derive(Parser, Debug)]
#[command(name = "spora")]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    mode: Mode
}

#[derive(Subcommand, Debug, Clone)]
enum Mode {
    Share {
        /// Use a specific key instead of generating one
        key: Option<String>,
    },

    Use {
        url: String,
    },
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    match args.mode{
        Mode::Share{ key } => {
            let key = key.unwrap_or_else(make_secret_key);
            let session = share(key, Config::default()).await?;
            println!("Expecting peer negotiation at spora://{}/{}", session.endpoint, session.key);
            println!("Press Ctrl+C to stop sharing.");
            tokio::signal::ctrl_c().await?;
            println!("Stopping share session...");
            session.stop().await;
        }
        Mode::Use{url} => {
            #[cfg(windows)]
            {
                let _ = url; // silence unused warning
                return Err("The 'use' mode is not supported on Windows yet (requires a TUN device).".into());
            }

            #[cfg(not(windows))]
            {
                let url = Url::parse(&url)?;
                if url.scheme() != "spora" {
                    panic!("Unsupported scheme {}. Expected a spora:// URL", url.scheme());
                }
                let result = connect(url, &Config::default()).await.unwrap();
                let tun = Tun::builder().name("").up().try_build().unwrap();
                tun_util::start(result.transport, tun).await?;
            }
        }
    }
    Ok(())
}