use std::fs::write;
use tokio::io::{AsyncBufReadExt, BufReader, BufWriter};
use std::time::Duration;
use tokio::time::sleep;
use spora::{pierce, share};
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
            let (local_addr, extrenal_addr) = pierce().await?;

            let mut stream = PubSubService::publish(url.host_str().unwrap(), url.port().unwrap(), url.path().strip_prefix("/").unwrap()).await?;
            let (reader, mut writer) = stream.split();
            let mut writer = BufWriter::new(writer);
            writer.write_all(extrenal_addr.to_string().as_bytes()).await?;
            writer.write_u8('\n' as u8).await?;
            writer.flush().await?;
            dbg!("Sent external addr {} to sharer", extrenal_addr);
            let mut reader = BufReader::new(reader);
            let mut other_end = String::new();
            reader.read_line(&mut other_end).await?;
            dbg!("Other end {}", &other_end);
            let other_end =  other_end.trim();
            let sock = UdpSocket::bind(local_addr).await?;
            sock.connect(other_end).await?;
            sock.send(&[123]).await?;
            nanovpn::Tunnel::new(sock).start().await.unwrap();
        }
    }
    Ok(())
}