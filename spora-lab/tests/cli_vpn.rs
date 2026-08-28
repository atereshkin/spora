//! The CLI as a VPN client: `spora-cli use` (without `--tun-name`) must bring
//! the interface up, route the host through it, swap the resolver, follow the
//! path's MTU, keep its own outer sockets out of the tunnel (the relay socket
//! AND the hole-punched one), and put everything back when it exits — and
//! `--tun-name` must keep touching nothing, because the field lab relies on
//! that contract.
//!
//! Unlike the other suites this one runs the real `spora-cli` binary (as the
//! sharer and as the client) inside the lab namespaces and reads its `--json`
//! event stream, so it needs `target/debug/spora-cli` to exist: run
//! `cargo build -p spora-cli` first (CI builds the workspace before testing).
//!
//! The resolver assertions bind-mount a private copy over `/etc/resolv.conf`
//! inside the lab's mount namespace (the real file is never touched).

use std::collections::VecDeque;
use std::io::BufRead as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};

use spora_lab::netns::Netns;
use spora_lab::services;
use spora_lab::topology::{Topology, TopologySpec};
use spora_lab::{ECHO_TCP_PORT, NatKind, RELAY_PORT, STUN_PORT, WAN_SERVICES_IP, WHOAMI_UDP_PORT};

fn main() {
    let ok = spora_lab::harness::lab_main(
        "cli_vpn",
        spora_lab::scenarios![
            full_tunnel_relay,
            full_tunnel_direct_upgrade,
            split_tunnel,
            attach_mode_touches_nothing,
        ],
    );
    std::process::exit(if ok { 0 } else { 1 });
}

// ---------------------------------------------------------------------------
// helpers

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RECV_TIMEOUT: Duration = Duration::from_secs(3);
/// A second service address on the wan, outside any split-tunnel prefix the
/// scenarios route, so "goes direct" is observable next to "goes via tunnel".
const WAN_SERVICES_IP_ALT: &str = "203.0.113.101";
/// The Linux backend's policy-rule preferences and table (vpn/linux.rs).
const RULE_PREF_MAIN: &str = "21327";
const RULE_PREF_TABLE: &str = "21328";
const TABLE: &str = "21328";

fn svc_ip() -> Ipv4Addr {
    WAN_SERVICES_IP.parse().expect("WAN_SERVICES_IP parses")
}

/// `target/debug/spora-cli`, next to this test executable's `deps/` dir.
fn cli_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let debug_dir = exe
        .parent()
        .and_then(Path::parent)
        .ok_or("test executable has no target dir")?;
    let bin = debug_dir.join("spora-cli");
    if !bin.is_file() {
        return Err(format!(
            "{} not found: build it first (`cargo build -p spora-cli`)",
            bin.display()
        ));
    }
    Ok(bin)
}

fn scratch_dir(tag: &str) -> Result<PathBuf, String> {
    let d = std::env::temp_dir().join(format!("spora-lab-cli-vpn-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
    Ok(d)
}

/// A `spora-cli` process inside a namespace, with its `--json` stdout parsed
/// into events. stderr (the log) is relayed to ours, prefixed.
struct Cli {
    label: String,
    child: Child,
    events: mpsc::Receiver<Value>,
    pending: VecDeque<Value>,
    stopped: bool,
}

impl Cli {
    fn spawn(ns: &Netns, label: &str, args: &[String]) -> Result<Cli, String> {
        use std::os::unix::process::CommandExt as _;
        let bin = cli_binary()?;
        let mut cmd = ns.command(bin.to_str().ok_or("binary path is not utf8")?);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("{label}: spawn {}: {e}", bin.display()))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (tx, rx) = mpsc::channel();
        let out_label = label.to_string();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                match serde_json::from_str::<Value>(&line) {
                    Ok(v) if v.get("event").is_some() => {
                        eprintln!("    [{out_label} event] {line}");
                        if tx.send(v).is_err() {
                            break;
                        }
                    }
                    _ => eprintln!("    [{out_label} out] {line}"),
                }
            }
        });
        let err_label = label.to_string();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                eprintln!("    [{err_label}] {line}");
            }
        });
        Ok(Cli {
            label: label.to_string(),
            child,
            events: rx,
            pending: VecDeque::new(),
            stopped: false,
        })
    }

    /// The first event (in arrival order) satisfying `pred`, within
    /// `timeout`; events that do not match are kept for later calls.
    fn wait_event<P: Fn(&Value) -> bool>(
        &mut self,
        timeout: Duration,
        pred: P,
    ) -> Result<Value, String> {
        if let Some(i) = self.pending.iter().position(&pred) {
            return Ok(self.pending.remove(i).expect("index in range"));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!("{}: timed out waiting for an event", self.label));
            }
            match self.events.recv_timeout(left) {
                Ok(v) if pred(&v) => return Ok(v),
                Ok(v) => self.pending.push_back(v),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(format!("{}: timed out waiting for an event", self.label));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(format!("{}: process ended (stdout closed)", self.label));
                }
            }
        }
    }

    fn wait_named(&mut self, name: &str, timeout: Duration) -> Result<Value, String> {
        self.wait_event(timeout, |v| v["event"] == name)
            .map_err(|e| format!("{e} (wanted {name:?})"))
    }

    /// SIGTERM the process group and wait for a clean exit (the cleanup path
    /// runs on SIGTERM); SIGKILL after 10s as a last resort.
    fn stop(&mut self) -> Result<std::process::ExitStatus, String> {
        self.stopped = true;
        let pid = self.child.id() as libc::pid_t;
        unsafe { libc::kill(-pid, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Ok(None) => {
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    let _ = self.child.wait();
                    return Err(format!(
                        "{}: did not exit on SIGTERM within 10s",
                        self.label
                    ));
                }
                Err(e) => return Err(format!("{}: wait: {e}", self.label)),
            }
        }
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        if !self.stopped {
            let pid = self.child.id() as libc::pid_t;
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = self.child.wait();
        }
    }
}

/// A private `/etc/resolv.conf` for the lab's mount namespace, so the CLI's
/// resolver changes are observable without touching the real file. Handles
/// the two shapes a host has: a regular file (bind-mount a copy over it) or
/// a symlink into `/run` (systemd-resolved; `/run` is a private tmpfs in the
/// lab, so the target is simply created).
struct IsolatedResolvConf {
    original: String,
}

impl IsolatedResolvConf {
    fn setup() -> Result<IsolatedResolvConf, String> {
        let path = Path::new("/etc/resolv.conf");
        let original = "nameserver 192.0.2.53\nsearch lab.example\n".to_string();
        match std::fs::canonicalize(path) {
            Ok(real) => {
                let copy = Path::new("/run/spora-lab-resolv.conf");
                std::fs::write(copy, &original)
                    .map_err(|e| format!("write {}: {e}", copy.display()))?;
                bind_mount(copy, &real)?;
            }
            Err(_) => {
                // A dangling symlink into the lab's private /run tmpfs (the
                // systemd-resolved shape). Debian/Ubuntu create it RELATIVE
                // ('../run/systemd/resolve/stub-resolv.conf'), so resolve it
                // against /etc lexically before the policy check and writes.
                let raw =
                    std::fs::read_link(path).map_err(|e| format!("{}: {e}", path.display()))?;
                let target = lexical_resolve(Path::new("/etc"), &raw);
                if !target.starts_with("/run") {
                    return Err(format!(
                        "/etc/resolv.conf -> {} is a dangling symlink outside /run; cannot isolate it",
                        raw.display()
                    ));
                }
                if let Some(dir) = target.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
                }
                std::fs::write(&target, &original)
                    .map_err(|e| format!("write {}: {e}", target.display()))?;
            }
        }
        let seen =
            std::fs::read_to_string(path).map_err(|e| format!("read back resolv.conf: {e}"))?;
        if seen != original {
            return Err("resolv.conf isolation did not take effect".into());
        }
        Ok(IsolatedResolvConf { original })
    }

    fn current(&self) -> Result<String, String> {
        std::fs::read_to_string("/etc/resolv.conf").map_err(|e| format!("read resolv.conf: {e}"))
    }
}

/// Resolve `link` against `base` lexically (no filesystem access — the
/// target is dangling): absolute stays as is; `..`/`.` components collapse.
fn lexical_resolve(base: &Path, link: &Path) -> PathBuf {
    let joined = if link.is_absolute() {
        link.to_path_buf()
    } else {
        base.join(link)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn bind_mount(src: &Path, dst: &Path) -> Result<(), String> {
    let s = std::ffi::CString::new(src.to_str().ok_or("path not utf8")?).unwrap();
    let d = std::ffi::CString::new(dst.to_str().ok_or("path not utf8")?).unwrap();
    let r = unsafe {
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if r != 0 {
        return Err(format!(
            "bind mount {} over {}: {}",
            src.display(),
            dst.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Run an async closure on a host thread pinned inside `ns` (see smoke.rs).
fn in_ns<T, F, Fut>(ns: &Netns, label: &str, timeout: Duration, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let (tx, rx) = mpsc::channel();
    let host = ns.spawn_host(label, move |_cancel| async move {
        let _ = tx.send(f().await);
    })?;
    let out = rx
        .recv_timeout(timeout)
        .map_err(|e| format!("{label}: host did not report back: {e}"));
    host.stop();
    out?
}

/// Ask a whoami service which source address it saw for a plain (unmarked)
/// UDP socket bound inside `ns`: the sharer's external address when the
/// packet went through the tunnel, the client's own when it went direct.
fn whoami_from(ns: &Netns, dst: SocketAddrV4) -> Result<SocketAddrV4, String> {
    in_ns(ns, "whoami", Duration::from_secs(15), move || async move {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind: {e}"))?;
        let mut last_err = String::new();
        for _ in 0..3 {
            sock.send_to(b"whoami", dst)
                .await
                .map_err(|e| format!("send to {dst}: {e}"))?;
            let mut buf = [0u8; 256];
            match tokio::time::timeout(RECV_TIMEOUT, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    let text =
                        std::str::from_utf8(&buf[..n]).map_err(|e| format!("whoami utf8: {e}"))?;
                    return match text.parse::<SocketAddr>() {
                        Ok(SocketAddr::V4(v4)) => Ok(v4),
                        other => Err(format!("whoami reply unparseable {text:?}: {other:?}")),
                    };
                }
                Ok(Err(e)) => last_err = format!("recv: {e}"),
                Err(_) => last_err = "timed out".into(),
            }
        }
        Err(format!("whoami {dst}: {last_err}"))
    })
}

/// Round-trip `len` bytes through the TCP echo service from inside `ns`.
fn tcp_echo_from(ns: &Netns, dst: SocketAddrV4, len: usize) -> Result<(), String> {
    in_ns(
        ns,
        "tcp-echo",
        Duration::from_secs(30),
        move || async move {
            let mut s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(dst))
                .await
                .map_err(|_| format!("connect {dst}: timed out"))?
                .map_err(|e| format!("connect {dst}: {e}"))?;
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            s.write_all(&payload)
                .await
                .map_err(|e| format!("write: {e}"))?;
            let mut back = vec![0u8; len];
            tokio::time::timeout(Duration::from_secs(15), s.read_exact(&mut back))
                .await
                .map_err(|_| "echo read timed out".to_string())?
                .map_err(|e| format!("read: {e}"))?;
            if back != payload {
                return Err("echoed bytes differ".into());
            }
            Ok(())
        },
    )
}

/// A whoami responder on the alternative service address, started in the wan.
fn start_alt_whoami(topo: &Topology) -> Result<spora_lab::netns::HostHandle, String> {
    topo.wan
        .run(&format!("ip addr add {WAN_SERVICES_IP_ALT}/32 dev svc0"))?;
    let addr: SocketAddr = format!("{WAN_SERVICES_IP_ALT}:{WHOAMI_UDP_PORT}")
        .parse()
        .unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let host = topo
        .wan
        .spawn_host("alt-whoami", move |_cancel| async move {
            let sock = match UdpSocket::bind(addr).await {
                Ok(s) => {
                    let _ = ready_tx.send(Ok(()));
                    s
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("bind {addr}: {e}")));
                    return;
                }
            };
            let mut buf = [0u8; 256];
            while let Ok((_, from)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(from.to_string().as_bytes(), from).await;
            }
        })?;
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|e| format!("alt whoami did not start: {e}"))??;
    Ok(host)
}

fn relay_arg() -> String {
    format!("{WAN_SERVICES_IP}:{RELAY_PORT}")
}

fn stun_arg() -> String {
    format!("{WAN_SERVICES_IP}:{STUN_PORT}")
}

fn strs(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Start `spora-cli share` in the sharer namespace and return it with its URL.
fn start_sharer(
    topo: &Topology,
    dir: &Path,
    direct_upgrade: bool,
) -> Result<(Cli, String), String> {
    let mut args = strs(&[
        "share",
        "--relay",
        &relay_arg(),
        "--stun",
        &stun_arg(),
        "--no-conn-log",
        "--identity-file",
        dir.join("identity.bin").to_str().unwrap(),
        "--record-dir",
        dir.join("records-share").to_str().unwrap(),
        "--json",
    ]);
    if !direct_upgrade {
        args.push("--no-direct-upgrade".into());
    }
    let mut sharer = Cli::spawn(&topo.sharer, "sharer", &args)?;
    let ready = sharer.wait_named("share_ready", Duration::from_secs(20))?;
    let url = ready["url"]
        .as_str()
        .ok_or("share_ready without a url")?
        .to_string();
    Ok((sharer, url))
}

fn use_args(url: &str, dir: &Path, extra: &[&str]) -> Vec<String> {
    let mut args = strs(&[
        "use",
        url,
        "--stun",
        &stun_arg(),
        "--record-dir",
        dir.join("records-use").to_str().unwrap(),
        "--json",
    ]);
    args.extend(strs(extra));
    args
}

fn json_strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn expect(cond: bool, msg: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg.into()) }
}

/// What the client namespace's routing looks like, for the assertions.
struct ClientRouting {
    rules4: String,
    rules6: String,
    table4: String,
    table6: String,
    main4: String,
}

fn client_routing(ns: &Netns) -> Result<ClientRouting, String> {
    // A table nobody has populated "does not exist" to `ip`; that is the
    // same as empty for our purposes.
    let table = |family: &str| -> Result<String, String> {
        match ns.run(&format!("ip {family} route show table {TABLE}")) {
            Ok(out) => Ok(out),
            Err(e) if e.contains("FIB table does not exist") => Ok(String::new()),
            Err(e) => Err(e),
        }
    };
    Ok(ClientRouting {
        rules4: ns.run("ip -4 rule show")?,
        rules6: ns.run("ip -6 rule show")?,
        table4: table("-4")?,
        table6: table("-6")?,
        main4: ns.run("ip -4 route show")?,
    })
}

/// `main` route-table text without the lines that belong to `dev` — the
/// kernel's connected route for the tunnel's own subnet is expected there
/// while the interface exists.
fn without_dev(table: &str, dev: &str) -> Vec<String> {
    norm_lines(table)
        .into_iter()
        .filter(|l| !l.contains(&format!("dev {dev}")))
        .collect()
}

/// Route-table text as trimmed, non-empty lines (the tool pads with trailing
/// spaces).
fn norm_lines(table: &str) -> Vec<String> {
    table
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Attaching a process to a TUN clears its `linkdown` flag; that is carrier
/// state, not routing policy.
fn strip_linkdown(table: &str) -> String {
    table.replace(" linkdown", "")
}

fn has_policy_rules(rules: &str) -> bool {
    rules.contains(&format!("{RULE_PREF_MAIN}:")) && rules.contains(&format!("{RULE_PREF_TABLE}:"))
}

fn link_mtu(ns: &Netns, dev: &str) -> Result<u64, String> {
    let out = ns.run(&format!("ip -o link show dev {dev}"))?;
    let mut it = out.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "mtu" {
            return it
                .next()
                .and_then(|m| m.parse().ok())
                .ok_or_else(|| format!("no mtu value in {out:?}"));
        }
    }
    Err(format!("no mtu in {out:?}"))
}

// ---------------------------------------------------------------------------
// 1. full tunnel over the relay path

fn full_tunnel_relay() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let _wan = services::start_wan(&topo.wan, relay::State::default)?;
    let dir = scratch_dir("relay")?;
    let resolv = IsolatedResolvConf::setup()?;
    let before = client_routing(&topo.client)?;
    expect(
        !has_policy_rules(&before.rules4),
        "fresh namespace must have no spora rules",
    )?;

    let (mut sharer, url) = start_sharer(&topo, &dir, false)?;
    let mut client = Cli::spawn(
        &topo.client,
        "client",
        &use_args(&url, &dir, &["--no-direct-upgrade"]),
    )?;

    let ready = client.wait_named("tunnel_ready", CONNECT_TIMEOUT)?;
    expect(
        ready["mode"] == "vpn",
        format!("tunnel_ready.mode: {ready}"),
    )?;
    let tun = ready["tun_name"]
        .as_str()
        .ok_or("tunnel_ready without tun_name")?
        .to_string();
    expect(
        tun.starts_with("spora"),
        format!("interface named {tun}, expected spora<N>"),
    )?;
    expect(
        ready["tun_addr"] == "10.11.0.2/24",
        format!("tun_addr: {ready}"),
    )?;
    expect(
        ready["tun_addr6"] == "fd00:5350::2/64",
        format!("tun_addr6: {ready}"),
    )?;
    expect(ready["mtu"] == 1280, format!("initial mtu: {ready}"))?;
    expect(
        json_strings(&ready["routes"]) == ["0.0.0.0/0", "::/0"],
        format!("routes: {ready}"),
    )?;
    expect(
        json_strings(&ready["dns"]) == ["8.8.8.8", "1.1.1.1"],
        format!("dns: {ready}"),
    )?;
    let dns_method = ready["dns_method"].as_str().unwrap_or("").to_string();
    expect(
        ["resolv.conf", "resolvconf", "resolvectl"].contains(&dns_method.as_str()),
        format!("dns_method: {ready}"),
    )?;
    let activated = client.wait_named("path_activated", CONNECT_TIMEOUT)?;
    expect(
        activated["carrier"] == "quic" && activated["path"] == "relay",
        format!("first path: {activated}"),
    )?;

    // The host is pointed at the tunnel: own table with both defaults, the
    // two policy rules, the main table's default untouched.
    let now = client_routing(&topo.client)?;
    expect(
        has_policy_rules(&now.rules4),
        format!("v4 rules missing:\n{}", now.rules4),
    )?;
    expect(
        has_policy_rules(&now.rules6),
        format!("v6 rules missing:\n{}", now.rules6),
    )?;
    expect(
        now.rules4.contains("suppress_prefixlength 0") && now.rules4.contains("fwmark 0x5350"),
        format!("v4 rules wrong:\n{}", now.rules4),
    )?;
    expect(
        now.table4.contains(&format!("default dev {tun}")),
        format!("v4 tunnel table:\n{}", now.table4),
    )?;
    expect(
        now.table6.contains(&format!("default dev {tun}")),
        format!("v6 tunnel table:\n{}", now.table6),
    )?;
    expect(
        without_dev(&now.main4, &tun) == norm_lines(&before.main4),
        format!(
            "main table changed beyond {tun}'s own routes:\n{}\n--\n{}",
            before.main4, now.main4
        ),
    )?;
    let addrs = topo.client.run(&format!("ip addr show dev {tun}"))?;
    expect(
        addrs.contains("10.11.0.2/24") && addrs.contains("fd00:5350::2/64"),
        format!("addresses on {tun}:\n{addrs}"),
    )?;

    // Resolver swapped (and, for the file tier, the original kept safe for
    // the way back). Whichever tier the host offered, the file must now name
    // our resolvers — a tier that "succeeds" without effect is a bug.
    if dns_method != "resolvectl" {
        let text = resolv.current()?;
        expect(
            text.contains("nameserver 8.8.8.8\n") && text.contains("nameserver 1.1.1.1\n"),
            format!("resolv.conf while up ({dns_method}):\n{text}"),
        )?;
    }
    if dns_method == "resolv.conf" {
        let text = resolv.current()?;
        expect(
            text.starts_with("# Generated by spora use") && text.contains("search lab.example"),
            format!("resolv.conf while up:\n{text}"),
        )?;
        let backed_up = [
            "/etc/resolv.conf.spora-backup",
            "/run/spora/resolv.conf.spora-backup",
        ]
        .iter()
        .any(|p| std::fs::read_to_string(p).ok().as_deref() == Some(resolv.original.as_str()));
        expect(
            backed_up,
            "backup of the original resolv.conf missing or wrong",
        )?;
    }

    // The TUN follows the path's MTU report (the carrier's datagram budget
    // after PMTUD; 1414 on the lab's 1500-byte links), within the v6 floor.
    let reported = client.wait_named("path_mtu", Duration::from_secs(15))?;
    let set = client.wait_named("tun_mtu", Duration::from_secs(10))?;
    let reported_mtu = reported["mtu"].as_u64().ok_or("path_mtu without mtu")?;
    let set_mtu = set["mtu"].as_u64().ok_or("tun_mtu without mtu")?;
    expect(
        reported_mtu >= 1280,
        format!("unexpectedly small path mtu {reported_mtu}"),
    )?;
    expect(
        set_mtu == reported_mtu,
        format!("tun_mtu {set_mtu} != path_mtu {reported_mtu}"),
    )?;
    let mut seen = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        seen = link_mtu(&topo.client, &tun)?;
        if seen == set_mtu {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    expect(
        seen == set_mtu,
        format!("interface mtu {seen}, expected {set_mtu}"),
    )?;

    // Traffic from an ordinary socket goes through the tunnel: the whoami
    // service sees the SHARER's external address. This also proves the
    // relay socket stayed out of the tunnel (SO_MARK): if it had looped, the
    // session would be dead by now.
    let seen = whoami_from(&topo.client, SocketAddrV4::new(svc_ip(), WHOAMI_UDP_PORT))?;
    expect(
        *seen.ip() == topo.ext_ip_a,
        format!(
            "whoami saw {} — expected the sharer's {} (client's own is {})",
            seen.ip(),
            topo.ext_ip_a,
            topo.ext_ip_b
        ),
    )?;
    // A TCP flow larger than any MTU, end to end.
    tcp_echo_from(
        &topo.client,
        SocketAddrV4::new(svc_ip(), ECHO_TCP_PORT),
        64 * 1024,
    )?;

    // Clean exit on SIGTERM puts everything back.
    let status = client.stop()?;
    expect(status.success(), format!("client exit status {status}"))?;
    let after = client_routing(&topo.client)?;
    expect(
        !has_policy_rules(&after.rules4),
        format!("v4 rules left behind:\n{}", after.rules4),
    )?;
    expect(
        !has_policy_rules(&after.rules6),
        format!("v6 rules left behind:\n{}", after.rules6),
    )?;
    expect(
        after.table4.trim().is_empty(),
        format!("v4 tunnel table left behind:\n{}", after.table4),
    )?;
    expect(after.main4 == before.main4, "main table differs after exit")?;
    expect(
        topo.client.run(&format!("ip link show dev {tun}")).is_err(),
        format!("{tun} still exists after exit"),
    )?;
    expect(
        resolv.current()? == resolv.original,
        format!("resolv.conf not restored:\n{}", resolv.current()?),
    )?;
    let backup_left = [
        "/etc/resolv.conf.spora-backup",
        "/run/spora/resolv.conf.spora-backup",
    ]
    .iter()
    .any(|p| Path::new(p).exists());
    expect(!backup_left, "resolv.conf backup left behind")?;

    sharer.stop()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. full tunnel that upgrades to a punched direct path

fn full_tunnel_direct_upgrade() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(NatKind::FullCone, NatKind::FullCone))?;
    let _wan = services::start_wan(&topo.wan, relay::State::default)?;
    let dir = scratch_dir("direct")?;
    let _resolv = IsolatedResolvConf::setup()?;

    let (mut sharer, url) = start_sharer(&topo, &dir, true)?;
    let mut client = Cli::spawn(&topo.client, "client", &use_args(&url, &dir, &[]))?;
    let ready = client.wait_named("tunnel_ready", CONNECT_TIMEOUT)?;
    expect(
        ready["upgrade_enabled"] == true,
        format!("upgrade_enabled: {ready}"),
    )?;
    client.wait_event(CONNECT_TIMEOUT, |v| {
        v["event"] == "path_activated" && v["path"] == "relay"
    })?;

    // The punch happens AFTER the routes are installed: the STUN/punch
    // socket must be marked too, or its packets loop into the tunnel and the
    // upgrade never completes.
    let direct = client.wait_event(Duration::from_secs(40), |v| {
        v["event"] == "path_activated" && v["path"] == "direct_punched"
    })?;
    expect(
        direct["carrier"] == "quic",
        format!("direct path carrier: {direct}"),
    )?;

    // Traffic still egresses at the sharer over the direct path.
    let seen = whoami_from(&topo.client, SocketAddrV4::new(svc_ip(), WHOAMI_UDP_PORT))?;
    expect(
        *seen.ip() == topo.ext_ip_a,
        format!(
            "whoami saw {} over the direct path — expected {}",
            seen.ip(),
            topo.ext_ip_a
        ),
    )?;
    tcp_echo_from(
        &topo.client,
        SocketAddrV4::new(svc_ip(), ECHO_TCP_PORT),
        64 * 1024,
    )?;

    let status = client.stop()?;
    expect(status.success(), format!("client exit status {status}"))?;
    sharer.stop()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. split tunnel: one prefix via the tunnel, everything else direct,
//    no v6, resolver untouched

fn split_tunnel() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let _wan = services::start_wan(&topo.wan, relay::State::default)?;
    let _alt = start_alt_whoami(&topo)?;
    let dir = scratch_dir("split")?;
    let resolv = IsolatedResolvConf::setup()?;

    let (mut sharer, url) = start_sharer(&topo, &dir, false)?;
    let routed = format!("{WAN_SERVICES_IP}/32");
    let mut client = Cli::spawn(
        &topo.client,
        "client",
        &use_args(
            &url,
            &dir,
            &[
                "--no-direct-upgrade",
                "--route",
                &routed,
                "--no-ipv6",
                "--no-dns",
            ],
        ),
    )?;
    let ready = client.wait_named("tunnel_ready", CONNECT_TIMEOUT)?;
    let tun = ready["tun_name"]
        .as_str()
        .ok_or("tunnel_ready without tun_name")?
        .to_string();
    expect(
        json_strings(&ready["routes"]) == [routed.as_str()],
        format!("routes: {ready}"),
    )?;
    expect(
        json_strings(&ready["dns"]).is_empty() && ready["dns_method"].is_null(),
        format!("dns: {ready}"),
    )?;
    expect(
        ready["tun_addr6"].is_null(),
        format!("tun_addr6 with --no-ipv6: {ready}"),
    )?;
    client.wait_named("path_activated", CONNECT_TIMEOUT)?;

    let now = client_routing(&topo.client)?;
    expect(
        has_policy_rules(&now.rules4),
        format!("v4 rules missing:\n{}", now.rules4),
    )?;
    expect(
        !has_policy_rules(&now.rules6),
        format!("v6 rules installed despite --no-ipv6:\n{}", now.rules6),
    )?;
    expect(
        now.table4.contains(&format!("{WAN_SERVICES_IP} dev {tun}"))
            && !now.table4.contains("default"),
        format!("split table:\n{}", now.table4),
    )?;
    expect(
        now.table6.trim().is_empty(),
        format!("v6 table not empty:\n{}", now.table6),
    )?;
    let addrs = topo.client.run(&format!("ip addr show dev {tun}"))?;
    expect(
        !addrs.contains("fd00:"),
        format!("ULA present despite --no-ipv6:\n{addrs}"),
    )?;
    expect(
        resolv.current()? == resolv.original,
        "resolv.conf changed despite --no-dns",
    )?;

    // The routed address goes via the sharer; the other one stays direct.
    let via = whoami_from(&topo.client, SocketAddrV4::new(svc_ip(), WHOAMI_UDP_PORT))?;
    expect(
        *via.ip() == topo.ext_ip_a,
        format!(
            "routed destination saw {} — expected {}",
            via.ip(),
            topo.ext_ip_a
        ),
    )?;
    let alt: Ipv4Addr = WAN_SERVICES_IP_ALT.parse().unwrap();
    let direct = whoami_from(&topo.client, SocketAddrV4::new(alt, WHOAMI_UDP_PORT))?;
    expect(
        *direct.ip() == topo.ext_ip_b,
        format!(
            "unrouted destination saw {} — expected the client's own {}",
            direct.ip(),
            topo.ext_ip_b
        ),
    )?;

    let status = client.stop()?;
    expect(status.success(), format!("client exit status {status}"))?;
    let after = client_routing(&topo.client)?;
    expect(
        !has_policy_rules(&after.rules4) && after.table4.trim().is_empty(),
        "split-tunnel state left behind",
    )?;
    sharer.stop()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. --tun-name: the field lab's contract — the caller's interface is used
//    as is and nothing else on the host moves, not even the MTU

fn attach_mode_touches_nothing() -> Result<(), String> {
    let topo = Topology::build(&TopologySpec::new(
        NatKind::PortRestricted,
        NatKind::PortRestricted,
    ))?;
    let _wan = services::start_wan(&topo.wan, relay::State::default)?;
    let dir = scratch_dir("attach")?;
    let resolv = IsolatedResolvConf::setup()?;
    let _alt = start_alt_whoami(&topo)?;
    let tun = "splab-cafe0001";
    topo.client
        .run(&format!("ip tuntap add dev {tun} mode tun"))?;
    topo.client
        .run(&format!("ip addr replace 10.231.0.2/24 dev {tun}"))?;
    topo.client
        .run(&format!("ip link set dev {tun} mtu 1280 up"))?;
    // Route a service into the TUN — but never the relay's own address:
    // attach mode has no socket protector (the caller owns routing policy),
    // so the relay dial must stay off the TUN, exactly as the field lab
    // routes only its probe hosts.
    topo.client.run(&format!(
        "ip route replace {WAN_SERVICES_IP_ALT}/32 dev {tun}"
    ))?;
    let before = client_routing(&topo.client)?;

    let (mut sharer, url) = start_sharer(&topo, &dir, false)?;
    let mut client = Cli::spawn(
        &topo.client,
        "client",
        &use_args(&url, &dir, &["--no-direct-upgrade", "--tun-name", tun]),
    )?;
    let ready = client.wait_named("tunnel_ready", CONNECT_TIMEOUT)?;
    expect(
        ready["mode"] == "attached",
        format!("tunnel_ready.mode: {ready}"),
    )?;
    expect(
        ready["tun_name"] == tun,
        format!("tunnel_ready.tun_name: {ready}"),
    )?;
    expect(
        ready["upgrade_enabled"] == false,
        format!("upgrade_enabled: {ready}"),
    )?;
    expect(
        ready.get("routes").is_none(),
        "attached mode must not report routes",
    )?;
    client.wait_named("path_activated", CONNECT_TIMEOUT)?;
    // The MTU report is informational here: the interface keeps ours.
    client.wait_named("path_mtu", Duration::from_secs(15))?;
    std::thread::sleep(Duration::from_millis(500));
    expect(
        link_mtu(&topo.client, tun)? == 1280,
        "attached interface MTU changed",
    )?;

    let now = client_routing(&topo.client)?;
    expect(
        now.rules4 == before.rules4 && now.rules6 == before.rules6,
        "attach mode added policy rules",
    )?;
    expect(
        strip_linkdown(&now.main4) == strip_linkdown(&before.main4),
        format!(
            "attach mode changed the main table:\n{}\n--\n{}",
            before.main4, now.main4
        ),
    )?;
    expect(
        now.table4.trim().is_empty(),
        "attach mode populated the tunnel table",
    )?;
    expect(
        resolv.current()? == resolv.original,
        "attach mode touched resolv.conf",
    )?;
    let addrs = topo.client.run(&format!("ip addr show dev {tun}"))?;
    expect(
        addrs.contains("10.231.0.2/24") && !addrs.contains("10.11.0.2"),
        format!("attach mode changed addresses:\n{addrs}"),
    )?;

    // And it works: the routed service is reached through the tunnel.
    let alt: Ipv4Addr = WAN_SERVICES_IP_ALT.parse().unwrap();
    let seen = whoami_from(&topo.client, SocketAddrV4::new(alt, WHOAMI_UDP_PORT))?;
    expect(
        *seen.ip() == topo.ext_ip_a,
        format!("whoami saw {} — expected {}", seen.ip(), topo.ext_ip_a),
    )?;

    let status = client.stop()?;
    expect(status.success(), format!("client exit status {status}"))?;
    // The caller owns the interface: it must still be there.
    expect(
        topo.client.run(&format!("ip link show dev {tun}")).is_ok(),
        "attach mode deleted the caller's interface",
    )?;
    sharer.stop()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
