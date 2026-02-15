use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use log::debug;

const MSG_SUB: u8 = 0x01;
const MSG_PUB: u8 = 0x02;
const RESP_ERROR: u8 = 0xFF;

const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct PubSubService<'a> {
    host: &'a str,
    port: u16,
}

impl<'a> PubSubService<'a> {
    pub fn new(host: &'a str, port: u16) -> Self {
        PubSubService { host, port }
    }

    /// Subscribe to a key. Returns a UDP socket connected to the relay and the
    /// advertised endpoint string (host:port) for publishers.
    pub async fn sub(&self, key: &str) -> io::Result<(UdpSocket, String)> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let relay_addr: SocketAddr = format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| io::Error::other(format!("bad relay addr: {}", e)))?;

        let mut msg = Vec::with_capacity(1 + key.len());
        msg.push(MSG_SUB);
        msg.extend_from_slice(key.as_bytes());

        let mut buf = [0u8; 65535];
        let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;

        loop {
            socket.send_to(&msg, relay_addr).await?;
            debug!("SUB sent to {}, waiting for ACK", relay_addr);

            let timeout = std::cmp::min(RETRY_INTERVAL, deadline.duration_since(tokio::time::Instant::now()));
            match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, src))) if src == relay_addr && len > 0 => {
                    match buf[0] {
                        MSG_SUB => {
                            let endpoint = String::from_utf8_lossy(&buf[1..len]).to_string();
                            debug!("SUB_ACK received, endpoint={}", endpoint);
                            socket.connect(relay_addr).await?;
                            return Ok((socket, endpoint));
                        }
                        RESP_ERROR => {
                            let err_msg = String::from_utf8_lossy(&buf[1..len]).to_string();
                            return Err(io::Error::other(err_msg));
                        }
                        _ => {}
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "SUB timed out"));
            }
        }
    }

    /// Publish to a key. Returns a UDP socket connected to the relay, ready for
    /// raw data exchange with the matched subscriber.
    pub async fn publish(host: &str, port: u16, key: &str) -> io::Result<UdpSocket> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let relay_addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| io::Error::other(format!("bad relay addr: {}", e)))?;

        let mut msg = Vec::with_capacity(1 + key.len());
        msg.push(MSG_PUB);
        msg.extend_from_slice(key.as_bytes());

        let mut buf = [0u8; 65535];
        let deadline = tokio::time::Instant::now() + TOTAL_TIMEOUT;

        loop {
            socket.send_to(&msg, relay_addr).await?;
            debug!("PUB sent to {}, waiting for ACK", relay_addr);

            let timeout = std::cmp::min(RETRY_INTERVAL, deadline.duration_since(tokio::time::Instant::now()));
            match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, src))) if src == relay_addr && len > 0 => {
                    match buf[0] {
                        MSG_PUB => {
                            debug!("PUB_ACK received");
                            socket.connect(relay_addr).await?;
                            return Ok(socket);
                        }
                        RESP_ERROR => {
                            let err_msg = String::from_utf8_lossy(&buf[1..len]).to_string();
                            return Err(io::Error::other(err_msg));
                        }
                        _ => {}
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "PUB timed out"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sub_receives_endpoint() {
        // Fake relay
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();

        let svc = PubSubService::new("127.0.0.1", relay_addr.port());
        let handle = tokio::spawn(async move { svc.sub("testkey").await });

        // Relay receives SUB, sends back SUB_ACK with endpoint
        let mut buf = [0u8; 256];
        let (len, client_addr) = relay.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[0], MSG_SUB);
        assert_eq!(&buf[1..len], b"testkey");

        let mut resp = vec![MSG_SUB];
        resp.extend_from_slice(b"relay.example.com:2334");
        relay.send_to(&resp, client_addr).await.unwrap();

        let (socket, endpoint) = handle.await.unwrap().unwrap();
        assert_eq!(endpoint, "relay.example.com:2334");
        // Socket is connected — can send/recv without specifying addr
        socket.send(b"hello").await.unwrap();
        let (len, src) = relay.recv_from(&mut buf).await.unwrap();
        assert_eq!(src, client_addr);
        assert_eq!(&buf[..len], b"hello");
    }

    #[tokio::test]
    async fn publish_receives_ack() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            PubSubService::publish("127.0.0.1", relay_addr.port(), "testkey").await
        });

        let mut buf = [0u8; 256];
        let (len, client_addr) = relay.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[0], MSG_PUB);
        assert_eq!(&buf[1..len], b"testkey");

        relay.send_to(&[MSG_PUB], client_addr).await.unwrap();

        let socket = handle.await.unwrap().unwrap();
        socket.send(b"world").await.unwrap();
        let (len, src) = relay.recv_from(&mut buf).await.unwrap();
        assert_eq!(src, client_addr);
        assert_eq!(&buf[..len], b"world");
    }
}
