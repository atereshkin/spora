use std::io as std_io;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub struct PubSubService<'a> {
    host: &'a str,
    port: u16,
}

pub trait HasStream {
    type Stream: AsyncReadExt + AsyncWriteExt;
    fn stream(&self) -> &mut Self::Stream;
}


impl<'a> PubSubService<'a> {
    pub fn new(host: &'a str, port: u16) -> Self {
        PubSubService{host, port}
    }

    pub async fn sub(&self, key: &str) -> std_io::Result<(TcpStream, String)> {
        let mut stream = TcpStream::connect((self.host, self.port)).await?;
        stream.write_all(key.as_bytes()).await?;
        stream.write_u8('\n' as u8).await?;
        stream.flush().await?;
        let mut br = BufReader::new(stream);
        let mut addr = String::new();
        br.read_line(&mut addr).await?;
        //TODO: validate the addr!
        Ok((br.into_inner(), addr.trim().to_string()))
    }

    pub async fn publish(host: &str, port: u16, key: &str) -> std_io::Result<TcpStream> {
        let mut stream = TcpStream::connect((host, port)).await?;
        stream.write_all(key.as_bytes()).await?;
        stream.write_u8('\n' as u8).await?;
        stream.flush().await?;
        let mut br = BufReader::new(stream);
        let mut ack = String::new();
        br.read_line(&mut ack).await?;
        if ack == "OK\n" {
            Ok(br.into_inner())
        } else {
            Err(std_io::Error::new(std_io::ErrorKind::Other, ack)) // TODO: custom error type
        }
    }
}

