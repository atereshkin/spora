#[cfg(not(windows))]

use std::time::Duration;
use tokio::time::sleep;
use spora_core::{connect, share, tun_util};
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
        Mode::Share{..} => {
            let pp = share().await?;
            println!("Expecting peer negotiation at spora://{}/{}", pp.endpoint, pp.key);
            sleep(Duration::from_secs(1000)).await; //TODO: join instead or something
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
                let transport = connect(url).await.unwrap();
                let tun = Tun::builder().name("").up().try_build().unwrap();
                tun_util::start(transport, tun).await?;
            }
        }
    }
    Ok(())
}