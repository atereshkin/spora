use futures_util::stream::StreamExt;
use std::io;
use futures_util::SinkExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tun::Tun;
use log::{error, info};
use spora_core::IpTransport;


pub struct Tunnel {
    transport: IpTransport,
}

impl Tunnel {
    pub fn new(transport: IpTransport) -> Self {
        Self { transport }
    }

    pub async fn start(&mut self) -> io::Result<()> {
        let mut tun = Self::init_tun();
        let mut buffer = vec![0u8; 1500];

        loop {

            tokio::select! {
                res = self.transport.next() => {
                    match res {
                        Some(Ok(pkt)) => {
                            if let Err(e) = tun.write_all(&pkt).await {
                                error!("Error writing packet to tun device: {}", e)
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error reading from transport: {}", e);
                            break;
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
                            if let Err(e) = self.transport.send(buffer[..n].to_vec()).await {
                                error!("Error sending packet to remote peer: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Error reading from tun device: {}", e);
                            break;
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

    fn init_tun() -> Tun {
        Tun::builder().name("").up().try_build().unwrap()
    }

}
