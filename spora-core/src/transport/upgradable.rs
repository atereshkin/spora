use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use log::{debug, error};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::IpTransport;

/// Sender used to push an upgraded transport into the router task.
pub type UpgradeSender = mpsc::UnboundedSender<IpTransport>;

/// Create an upgradable transport backed by channel indirection.
///
/// Returns:
/// - `UpgradableTransport` — implements `Stream + Sink`, hand this to `run_tunnel`
/// - `UpgradeSender` — send a new `IpTransport` here to hot-swap the inner transport
/// - `JoinHandle` — the background router task; abort it when the tunnel ends
pub fn upgradable_transport(
    initial: IpTransport,
) -> (UpgradableTransport, UpgradeSender, JoinHandle<()>) {
    let (in_tx, in_rx) = mpsc::unbounded_channel::<io::Result<Vec<u8>>>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (upgrade_tx, upgrade_rx) = mpsc::unbounded_channel::<IpTransport>();

    let handle = tokio::spawn(transport_router(initial, upgrade_rx, in_tx, out_rx));

    let transport = UpgradableTransport { in_rx, out_tx };

    (transport, upgrade_tx, handle)
}

/// Background task that bridges between the real transport and the channels.
///
/// When an upgrade arrives, the old transport's split halves are dropped and
/// the new transport takes over. The tunnel (reading from `UpgradableTransport`)
/// is unaware of the swap.
async fn transport_router(
    initial: IpTransport,
    mut upgrade_rx: mpsc::UnboundedReceiver<IpTransport>,
    in_tx: mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut current = initial;
    loop {
        match route_one(current, &mut upgrade_rx, &in_tx, &mut out_rx).await {
            RouteResult::Upgraded(new_transport) => {
                debug!("Transport upgraded");
                current = new_transport;
                // continue loop — will re-split the new transport
            }
            RouteResult::Done => return,
        }
    }
}

enum RouteResult {
    /// Got an upgrade — caller should loop with the new transport.
    Upgraded(IpTransport),
    /// Stream ended or channels closed — router should exit.
    Done,
}

/// Run the select loop for one transport. Consumes it via `split()`.
///
/// Returns `Upgraded(new)` if an upgrade arrived, or `Done` if the
/// tunnel should end (stream closed, channels closed, etc).
async fn route_one(
    transport: IpTransport,
    upgrade_rx: &mut mpsc::UnboundedReceiver<IpTransport>,
    in_tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    out_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> RouteResult {
    let (mut sink, mut stream) = transport.split();

    loop {
        tokio::select! {
            upgrade = upgrade_rx.recv() => {
                match upgrade {
                    Some(new_transport) => {
                        return RouteResult::Upgraded(new_transport);
                    }
                    None => {
                        // UpgradeSender dropped — no more upgrades.
                        // Keep draining with current transport.
                        debug!("Upgrade channel closed, continuing with current transport");
                        drain_loop(&mut sink, &mut stream, in_tx, out_rx).await;
                        return RouteResult::Done;
                    }
                }
            }
            pkt = stream.next() => {
                match pkt {
                    Some(result) => {
                        if in_tx.send(result).is_err() {
                            debug!("Tunnel consumer dropped, router exiting");
                            return RouteResult::Done;
                        }
                    }
                    None => {
                        debug!("Inner transport stream ended, router exiting");
                        return RouteResult::Done;
                    }
                }
            }
            pkt = out_rx.recv() => {
                match pkt {
                    Some(data) => {
                        if let Err(e) = sink.send(data).await {
                            error!("Router sink send error: {}", e);
                            return RouteResult::Done;
                        }
                    }
                    None => {
                        debug!("Tunnel producer dropped, router exiting");
                        return RouteResult::Done;
                    }
                }
            }
        }
    }
}

/// Continue forwarding without checking for upgrades.
async fn drain_loop(
    sink: &mut futures_util::stream::SplitSink<IpTransport, Vec<u8>>,
    stream: &mut futures_util::stream::SplitStream<IpTransport>,
    in_tx: &mpsc::UnboundedSender<io::Result<Vec<u8>>>,
    out_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) {
    loop {
        tokio::select! {
            pkt = stream.next() => {
                match pkt {
                    Some(result) => {
                        if in_tx.send(result).is_err() {
                            return;
                        }
                    }
                    None => return,
                }
            }
            pkt = out_rx.recv() => {
                match pkt {
                    Some(data) => {
                        if let Err(e) = sink.send(data).await {
                            error!("Router sink send error (drain): {}", e);
                            return;
                        }
                    }
                    None => return,
                }
            }
        }
    }
}

/// A `Transport` that delegates to a background router task via channels.
///
/// The router can hot-swap the actual inner transport without this type
/// knowing about it.
pub struct UpgradableTransport {
    in_rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl Stream for UpgradableTransport {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.in_rx.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for UpgradableTransport {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.out_tx.is_closed() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "router task gone",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.out_tx
            .send(item)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "router task gone"))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::mock_transport;
    use futures_util::{SinkExt, StreamExt};

    #[tokio::test]
    async fn upgradable_passes_through() {
        let (local, mut handle) = mock_transport();
        let (mut transport, _upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local));

        // Inbound: handle → transport
        handle.send(vec![1, 2, 3]).unwrap();
        let pkt = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.next(),
        )
        .await
        .expect("timeout")
        .unwrap()
        .unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Outbound: transport → handle
        Pin::new(&mut transport).send(vec![4, 5, 6]).await.unwrap();
        let pkt = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            handle.recv(),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(pkt, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn upgradable_switches_on_upgrade() {
        let (local1, handle1) = mock_transport();
        let (mut transport, upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local1));

        // Initial transport works
        handle1.send(vec![1, 2, 3]).unwrap();
        let pkt = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.next(),
        )
        .await
        .expect("timeout")
        .unwrap()
        .unwrap();
        assert_eq!(pkt, vec![1, 2, 3]);

        // Upgrade to new transport
        let (local2, mut handle2) = mock_transport();
        upgrade_tx.send(Box::new(local2)).unwrap();

        // Give router time to process the upgrade
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Data on new handle should arrive
        handle2.send(vec![7, 8, 9]).unwrap();
        let pkt = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.next(),
        )
        .await
        .expect("timeout")
        .unwrap()
        .unwrap();
        assert_eq!(pkt, vec![7, 8, 9]);

        // Outbound goes to new handle
        Pin::new(&mut transport).send(vec![10, 11]).await.unwrap();
        let pkt = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            handle2.recv(),
        )
        .await
        .expect("timeout")
        .unwrap();
        assert_eq!(pkt, vec![10, 11]);
    }

    #[tokio::test]
    async fn upgradable_ends_on_stream_close() {
        let (local, handle) = mock_transport();
        let (mut transport, _upgrade_tx, _router_handle) =
            upgradable_transport(Box::new(local));

        // Close the inner transport
        handle.close();

        // The UpgradableTransport stream should end
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.next(),
        )
        .await
        .expect("timeout");
        assert!(result.is_none(), "expected stream to end after inner close");
    }
}
