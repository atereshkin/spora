use futures_util::SinkExt;
use futures_util::stream::StreamExt;
use log::{error, info};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::IpTransport;

pub async fn start(mut transport: IpTransport, mut tun: impl AsyncReadExt+AsyncWriteExt+Unpin) -> io::Result<()> {
    let mut buffer = vec![0u8; 1500];

    loop {
        tokio::select! {
            res = transport.next() => {
                match res {
                    Some(Ok(pkt)) => {
                        if let Err(e) = tun.write_all(&pkt).await {
                            error!("Error writing packet to tun device: {}", e)
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading from transport: {}", e);
                    }
                    None => {
                        info!("Transport stream closed.");
                        break;
                    }
                }
            }
            res = tun.read(&mut buffer) => {
                match res {
                    Ok(n) if n > 0 => {
                        if let Err(e) = transport.send(buffer[..n].to_vec()).await {
                            error!("Error sending packet to remote peer: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Error reading from tun device: {}", e);
                    }
                    Ok(_) =>  {
                        info!("Tun device closed.");
                        break
                    }
                }
            }
        }
    }
    Ok(())
}
