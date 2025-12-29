mod tun;

use tokio::io::{AsyncBufReadExt, BufReader, BufWriter};
use std::time::Duration;
use tokio::time::sleep;
use spora_core::{connect, pierce, share};
use clap::{Parser, Subcommand};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use url::{Url};
use pubsub_client::PubSubService;

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
            let url = Url::parse(&url)?;
            if url.scheme() != "spora" {
                panic!("Unsupported scheme {}. Expected a spora:// URL", url.scheme());
            }
            let transport = connect(url).await.unwrap();

            tun::Tunnel::new(transport).start().await?;
        }
    }
    Ok(())
}