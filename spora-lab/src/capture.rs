//! tcpdump packet capture inside a lab namespace — the tap feeding the Tier-1
//! QUIC fingerprint inspector ([`crate::quic_inspect`]). Spawns
//! `tcpdump -i <dev> -U -w <file> udp` as a child pinned in `ns`'s **network**
//! namespace; the child stays in the lab's mount namespace, so the pcap path
//! is shared with the suite. Returns the pcap bytes on `stop()`.
//!
//! tcpdump must be present — gate the suite with
//! `lab_main_with_tools(.., &["tcpdump"])`. Within the lab's owned netns the
//! (userns-root) process has the CAP_NET_RAW needed for AF_PACKET, same as it
//! already has CAP_NET_ADMIN for iptables.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::netns::Netns;

static CAP_ID: AtomicUsize = AtomicUsize::new(0);

/// A running tcpdump capture. Dropping it (without `stop()`) still tears down
/// the child and removes the temp pcap, so an early scenario return can't leak.
pub struct Capture {
    child: Child,
    path: PathBuf,
}

impl Capture {
    /// Start capturing UDP on `dev` inside `ns`, blocking until tcpdump's
    /// capture socket is attached — it prints "listening on <dev>" on stderr
    /// once `pcap_activate` succeeds, so waiting for that line is the only
    /// race-free readiness signal (a fixed sleep loses the client's single,
    /// un-retransmitted Initial on fast veths).
    pub fn start(ns: &Netns, dev: &str) -> Result<Capture, String> {
        let id = CAP_ID.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("spora-lab-cap-{}-{id}.pcap", ns.name()));
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_str().ok_or("non-utf8 temp path")?.to_string();

        let mut cmd = ns.command("tcpdump");
        // `-Z root`: don't drop privileges — the setuid to user `tcpdump`
        // fails in the lab's single-uid userns and leaves the capture empty.
        // `--immediate-mode`: deliver packets to userspace as they arrive
        // instead of after the ~1s pcap buffer timeout; without it a sub-second
        // session's packets sit in the kernel buffer and are lost on stop
        // ("received by filter" but "0 captured"). `-U`: flush each packet to
        // the savefile as written.
        cmd.args([
            "-i",
            dev,
            "--immediate-mode",
            "-U",
            "-Z",
            "root",
            "-w",
            &path_str,
            "udp",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("spawn tcpdump: {e}"))?;

        // Drain tcpdump's stderr on a thread, signaling once it is listening
        // (the only race-free readiness signal); draining also keeps the pipe
        // from filling.
        let stderr = child.stderr.take().ok_or("tcpdump stderr unavailable")?;
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut signaled = false;
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if !signaled && line.contains("listening on") {
                    let _ = ready_tx.send(());
                    signaled = true;
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| format!("tcpdump never reported listening on {dev}"))?;
        std::thread::sleep(Duration::from_millis(200)); // socket-attach settle
        Ok(Capture { child, path })
    }

    /// SIGTERM tcpdump (so it flushes), wait, and return the pcap bytes.
    pub fn stop(mut self) -> Result<Vec<u8>, String> {
        self.terminate();
        let bytes = std::fs::read(&self.path).map_err(|e| format!("read pcap: {e}"))?;
        let _ = std::fs::remove_file(&self.path);
        Ok(bytes)
    }

    fn terminate(&mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let _ = self.child.wait();
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.terminate();
        let _ = std::fs::remove_file(&self.path);
    }
}
