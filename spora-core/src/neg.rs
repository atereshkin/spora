use std::net::SocketAddr;
use std::str::FromStr;
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec, LinesCodecError};
use log::{error, warn};
use tokio::net::TcpStream;
use futures_util::{SinkExt, StreamExt};
use crate::TunnelError;
use crate::TunnelError::ProtocolError;

pub trait NegChannel {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError>;
    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError>;
}

pub struct FramedNegChannel<'a> {
    reader: FramedRead<tokio::net::tcp::ReadHalf<'a>, LinesCodec>,
    writer: FramedWrite<tokio::net::tcp::WriteHalf<'a>, LinesCodec>,
}

impl<'a> FramedNegChannel<'a> {
    pub fn from_tcp_stream(stream: &'a mut TcpStream) -> Self {
        let (read_half, write_half) = stream.split();
        let decoder = LinesCodec::new();
        let reader = FramedRead::new(read_half, decoder);
        let encoder = LinesCodec::new();
        let writer = FramedWrite::new(write_half, encoder);
        FramedNegChannel { reader, writer }
    }
}

impl<'a> NegChannel for FramedNegChannel<'a> {
    async fn send_endpoint(&mut self, addr: SocketAddr) -> Result<(), TunnelError> {
        self.writer.send(addr.to_string()).await.map_err(|error| {
            match error {
                LinesCodecError::MaxLineLengthExceeded => {
                    panic!("max line length exceeded when sending endpoint")
                }
                LinesCodecError::Io(e) => {
                    warn!("failed to send endpoint: {}", e);
                    TunnelError::NegChannelClosed
                }
            }
        })
    }

    async fn recv_endpoint(&mut self) -> Result<SocketAddr, TunnelError> {
        let frame = match self.reader.next().await {
            Some(Ok(line)) => line,
            Some(Err(e)) => return Err(match e {
                LinesCodecError::MaxLineLengthExceeded => {
                    error!("max line length exceeded when receiving endpoint, possibly malicious peer");
                    ProtocolError("Line too long".into())
                }
                LinesCodecError::Io(io_err) => {
                    error!("failed to receive endpoint: {}", io_err);
                    return Err(TunnelError::NegChannelClosed);
                }
            }),
            None => return Err(TunnelError::NegChannelClosed),
        };
        Ok(SocketAddr::from_str(&frame).map_err(|parse_err| { ProtocolError(format!("invalid peer address: {}", parse_err))})?)
    }
}