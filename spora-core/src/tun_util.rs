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
                        // Use write() not write_all(): TUN writes are
                        // packet-atomic — one write() = one IP packet.
                        // write_all() retries partial writes, which doesn't
                        // work on packet-oriented devices.
                        if let Err(e) = tun.write(&pkt).await {
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
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Normal for non-blocking TUN fds (Android); just retry.
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

/// Like `start`, but takes a raw file descriptor instead of an async I/O object.
///
/// `tokio::fs::File` can't be used for TUN devices because it calls `seek()`
/// internally before every write (to track cursor position across its thread
/// pool), which fails with ESPIPE on non-seekable fds.  Instead, we use
/// `std::fs::File` on dedicated OS threads — plain `read()`/`write()` syscalls
/// with no seeking.
///
/// We share a single fd via `Arc<File>` rather than `try_clone()` (which calls
/// `dup()`), because Android TUN fds don't work correctly after dup.
#[cfg(unix)]
pub async fn start_fd(mut transport: IpTransport, fd: std::os::fd::OwnedFd) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    let file = Arc::new(std::fs::File::from(fd));

    // Channel: TUN reader thread → async transport writer
    let (tun_read_tx, mut tun_read_rx) = mpsc::channel::<Vec<u8>>(64);
    // Channel: async transport reader → TUN writer thread
    let (tun_write_tx, tun_write_rx) = mpsc::channel::<Vec<u8>>(64);

    // TUN reader thread — blocks on read(), sends packets to async world.
    // Uses `impl Read for &File` (shared ref) so no dup() needed.
    let reader_file = file.clone();
    let reader = std::thread::Builder::new()
        .name("tun-read".into())
        .spawn(move || {
            let mut buf = vec![0u8; 1500];
            loop {
                match (&*reader_file).read(&mut buf) {
                    Ok(0) => break, // TUN closed
                    Ok(n) => {
                        if tun_read_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break; // receiver dropped
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock
                           || e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        })
        .map_err(|e| io::Error::other(format!("failed to spawn tun-read thread: {}", e)))?;

    // TUN writer thread — receives packets from async world, blocks on write().
    // Uses `impl Write for &File` (shared ref) so no dup() needed.
    let writer_file = file;
    let writer = std::thread::Builder::new()
        .name("tun-write".into())
        .spawn({
            let mut tun_write_rx = tun_write_rx;
            move || {
                while let Some(pkt) = tun_write_rx.blocking_recv() {
                    if let Err(e) = (&*writer_file).write(&pkt) {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            error!("TUN write error: {}", e);
                        }
                    }
                }
            }
        })
        .map_err(|e| io::Error::other(format!("failed to spawn tun-write thread: {}", e)))?;

    // Bridge between transport and TUN channels.
    loop {
        tokio::select! {
            res = transport.next() => {
                match res {
                    Some(Ok(pkt)) => {
                        if tun_write_tx.send(pkt).await.is_err() {
                            info!("TUN writer thread exited.");
                            break;
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
            pkt = tun_read_rx.recv() => {
                match pkt {
                    Some(data) => {
                        if let Err(e) = transport.send(data).await {
                            error!("Error sending packet to remote peer: {}", e);
                        }
                    }
                    None => {
                        info!("TUN reader thread exited.");
                        break;
                    }
                }
            }
        }
    }

    // Drop channels to signal threads to exit, then wait.
    drop(tun_write_tx);
    drop(tun_read_rx);
    let _ = reader.join();
    let _ = writer.join();

    Ok(())
}
