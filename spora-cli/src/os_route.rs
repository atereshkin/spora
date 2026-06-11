//! Privileged exit-mode bypass: instead of terminating flows in the userland
//! netstack, write the client's IP packets to a TUN device and let the kernel
//! route (and NAT) them.
//!
//! What this module does per `spora share --os-routing` run:
//!  - creates a TUN device with the given address/MTU;
//!  - (unless `--no-nat`) enables `ip_forward` and installs iptables rules:
//!    FORWARD accepts for the TUN and TCP MSS clamping to the TUN MTU;
//!  - learns each client's inner source address from the packets it sends and
//!    installs a `/32` return route plus a MASQUERADE rule for it — the
//!    client's TUN address is chosen by the client platform, so it can't be
//!    assumed to sit inside our TUN's subnet;
//!  - answers ICMP echo requests aimed at blocked (private) destinations.
//!    This is load-bearing: the client's keepalive layer pings a synthetic
//!    private address (10.0.0.2 by default) and declares the tunnel dead if
//!    nothing ever comes back. In netstack mode smoltcp answers those pings;
//!    here we must do it ourselves because the kernel has no route to them.
//!
//! Packets to private/local destinations are dropped (parity with the
//! netstack's `block_local`), so a client can't reach the sharer's LAN.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures_util::{SinkExt, StreamExt};
use log::{debug, info, trace, warn};
use spora_core::{is_local_address, CancellationToken, IpTransport, SessionFuture, SessionHandler};
use tokio_tun::Tun;

/// Upper bound on learned client addresses. Sessions are sequential, but a
/// client could spray source addresses; don't let it grow our route table and
/// NAT rule set without bound.
const MAX_PEERS: usize = 64;

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

pub struct Options {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub configure_nat: bool,
}

impl Options {
    /// Parse `--tun-addr` ("a.b.c.d/len") plus the other flags.
    pub fn parse(tun_addr: &str, mtu: u16, configure_nat: bool) -> Result<Self, String> {
        let (addr, prefix) = tun_addr
            .split_once('/')
            .ok_or_else(|| format!("--tun-addr must be CIDR (e.g. 10.213.0.1/24), got {}", tun_addr))?;
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|e| format!("bad --tun-addr address: {}", e))?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|e| format!("bad --tun-addr prefix length: {}", e))?;
        if !(8..=30).contains(&prefix_len) {
            return Err(format!("--tun-addr prefix length must be 8..=30, got {}", prefix_len));
        }
        if !(576..=9000).contains(&mtu) {
            return Err(format!("--tun-mtu must be 576..=9000, got {}", mtu));
        }
        Ok(Self {
            addr,
            prefix_len,
            mtu,
            configure_nat,
        })
    }

    fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::MAX << (32 - self.prefix_len))
    }
}

enum Undo {
    Cmd(&'static str, Vec<String>),
    ProcWrite(&'static str, String),
}

struct Shared {
    tun_name: String,
    configure_nat: bool,
    /// Learned client source addresses with their last-seen time, so the table
    /// can evict the least-recently-active peer instead of bricking once full.
    peers: Mutex<HashMap<Ipv4Addr, Instant>>,
    undo: Mutex<Vec<Undo>>,
    /// Set by `cleanup()` so an in-flight session pump doesn't install a fresh
    /// MASQUERADE rule after we've already drained the undo list.
    shutting_down: AtomicBool,
}

/// Guard owning the TUN device and the system configuration we applied.
/// Call [`OsRoute::cleanup`] on shutdown to undo iptables/sysctl changes;
/// the TUN device itself (and the routes bound to it) die with the process.
pub struct OsRoute {
    tun: Arc<Tun>,
    mtu: u16,
    shared: Arc<Shared>,
}

impl OsRoute {
    pub fn setup(opts: &Options) -> Result<Self, String> {
        let tun = Tun::builder()
            .name("")
            .address(opts.addr)
            .netmask(opts.netmask())
            .mtu(i32::from(opts.mtu))
            .up()
            .try_build()
            .map_err(|e| {
                format!(
                    "failed to create TUN device (--os-routing requires root or CAP_NET_ADMIN): {}",
                    e
                )
            })?;
        info!(
            "os-routing: TUN {} up, {}/{}, mtu {}",
            tun.name(),
            opts.addr,
            opts.prefix_len,
            opts.mtu
        );

        let shared = Arc::new(Shared {
            tun_name: tun.name().to_string(),
            configure_nat: opts.configure_nat,
            peers: Mutex::new(HashMap::new()),
            undo: Mutex::new(Vec::new()),
            shutting_down: AtomicBool::new(false),
        });
        let route = Self {
            tun: Arc::new(tun),
            mtu: opts.mtu,
            shared,
        };
        if opts.configure_nat {
            route.configure_forwarding(opts);
        } else {
            info!(
                "os-routing: --no-nat set; you are responsible for ip_forward and a MASQUERADE \
                 rule covering the client's source address"
            );
        }
        Ok(route)
    }

    pub fn tun_name(&self) -> &str {
        &self.shared.tun_name
    }

    /// Enable IPv4 forwarding and install the interface-scoped iptables rules.
    /// Failures are downgraded to warnings: the pump still works and the user
    /// may have equivalent rules of their own (e.g. native nftables).
    fn configure_forwarding(&self, opts: &Options) {
        match std::fs::read_to_string(IP_FORWARD) {
            Ok(v) if v.trim() == "1" => debug!("os-routing: ip_forward already enabled"),
            Ok(v) => match std::fs::write(IP_FORWARD, "1") {
                Ok(()) => {
                    info!("os-routing: enabled net.ipv4.ip_forward");
                    self.shared
                        .undo
                        .lock()
                        .unwrap()
                        .push(Undo::ProcWrite(IP_FORWARD, v.trim().to_string()));
                }
                Err(e) => warn!("os-routing: could not enable ip_forward: {}", e),
            },
            Err(e) => warn!("os-routing: could not read {}: {}", IP_FORWARD, e),
        }

        let tun = self.shared.tun_name.clone();
        // Clamp TCP MSS in both directions to fit the TUN MTU. The flows are
        // end-to-end here (unlike the netstack, which terminates TCP), so
        // without this a client behind a 1500-MTU TUN negotiates an MSS that
        // overflows our QUIC datagram budget and relies on IP fragmentation.
        let mss = opts.mtu.saturating_sub(40).max(536).to_string();
        let rules: Vec<(Vec<String>, Vec<String>)> = vec![
            (
                svec(&["-w", "-I", "FORWARD", "1", "-i", &tun, "-j", "ACCEPT"]),
                svec(&["-w", "-D", "FORWARD", "-i", &tun, "-j", "ACCEPT"]),
            ),
            (
                svec(&["-w", "-I", "FORWARD", "1", "-o", &tun, "-j", "ACCEPT"]),
                svec(&["-w", "-D", "FORWARD", "-o", &tun, "-j", "ACCEPT"]),
            ),
            (
                svec(&[
                    "-w", "-t", "mangle", "-A", "FORWARD", "-i", &tun, "-p", "tcp", "--tcp-flags",
                    "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                ]),
                svec(&[
                    "-w", "-t", "mangle", "-D", "FORWARD", "-i", &tun, "-p", "tcp", "--tcp-flags",
                    "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                ]),
            ),
            (
                svec(&[
                    "-w", "-t", "mangle", "-A", "FORWARD", "-o", &tun, "-p", "tcp", "--tcp-flags",
                    "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                ]),
                svec(&[
                    "-w", "-t", "mangle", "-D", "FORWARD", "-o", &tun, "-p", "tcp", "--tcp-flags",
                    "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                ]),
            ),
        ];
        for (add, del) in rules {
            if run_cmd("iptables", &add) {
                self.shared.undo.lock().unwrap().push(Undo::Cmd("iptables", del));
            }
        }
    }

    /// Build the per-session handler to plug into `Config::exit_mode`.
    pub fn session_handler(&self) -> SessionHandler {
        let dev = self.tun.clone();
        let shared = self.shared.clone();
        // TUN reads are bounded by the MTU we set, but leave headroom in case
        // the user raises it at runtime with `ip link`.
        let recv_buf_len = usize::from(self.mtu).max(1500) + 64;
        Arc::new(move |transport, cancel| {
            let dev = dev.clone();
            let learn = peer_learner(shared.clone());
            Box::pin(pump(transport, dev, cancel, learn, recv_buf_len))
        })
    }

    /// Undo iptables/sysctl changes (reverse order). The TUN device and its
    /// routes are not persistent and disappear when the process exits.
    ///
    /// Idempotent: the undo list is drained, so a later `Drop` is a no-op. Runs
    /// from `Drop`, so it must use only synchronous calls and never panic.
    fn cleanup(&self) {
        // Stop pumps from racing a fresh MASQUERADE add past our drain.
        self.shared.shutting_down.store(true, Ordering::Relaxed);
        let items: Vec<Undo> = match self.shared.undo.lock() {
            Ok(mut undo) => undo.drain(..).collect(),
            Err(_) => return, // poisoned during unwind — don't double-panic
        };
        for item in items.into_iter().rev() {
            match item {
                Undo::Cmd(program, args) => {
                    let _ = run_cmd(program, &args);
                }
                Undo::ProcWrite(path, value) => {
                    info!("os-routing: restoring {} = {}", path, value);
                    if let Err(e) = std::fs::write(path, &value) {
                        warn!("os-routing: could not restore {}: {}", path, e);
                    }
                }
            }
        }
    }
}

impl Drop for OsRoute {
    fn drop(&mut self) {
        self.cleanup();
    }
}

type PeerLearner = Arc<dyn Fn(Ipv4Addr) -> SessionFuture + Send + Sync>;

fn peer_learner(shared: Arc<Shared>) -> PeerLearner {
    Arc::new(move |ip| {
        let shared = shared.clone();
        Box::pin(async move { shared.learn_peer(ip).await })
    })
}

impl Shared {
    /// Install the return route (and MASQUERADE rule) for a client source
    /// address the first time we see it. Awaited inline from the pump so the
    /// route exists before the first reply can arrive (rp_filter would
    /// otherwise drop the client's packets until the route lands).
    async fn learn_peer(&self, ip: Ipv4Addr) {
        if self.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        // Already learned? Refresh its activity so it isn't the eviction victim,
        // and we're done — no slot is consumed by a repeat, and the table only
        // holds peers whose routes we actually installed.
        {
            let mut peers = self.peers.lock().unwrap();
            if let Some(ts) = peers.get_mut(&ip) {
                *ts = Instant::now();
                return;
            }
        }
        // Even within private space, refuse to shadow an address the host can
        // already reach over a real route — whether directly-connected (the
        // sharer's own LAN) or via a gateway (a downstream router, nested VPN, or
        // corporate subnet behind the default route). A /32 on the TUN would
        // override that route and divert the sharer's own egress to it into the
        // tunnel. Fail open: if we can't read the table, install.
        if host_has_conflicting_route(ip, &self.tun_name).await {
            warn!(
                "os-routing: client source {} collides with an existing host route; \
                 refusing to install a return route",
                ip
            );
            return;
        }
        info!("os-routing: learned client address {}, installing return route", ip);
        let dst = format!("{}/32", ip);
        // No undo needed: the route is bound to the TUN device and dies with it.
        run_cmd_async("ip", svec(&["route", "replace", &dst, "dev", &self.tun_name])).await;
        if self.configure_nat {
            let add = svec(&[
                "-w", "-t", "nat", "-I", "POSTROUTING", "1", "-s", &dst, "!", "-o",
                &self.tun_name, "-j", "MASQUERADE",
            ]);
            let del = svec(&[
                "-w", "-t", "nat", "-D", "POSTROUTING", "-s", &dst, "!", "-o", &self.tun_name,
                "-j", "MASQUERADE",
            ]);
            if run_cmd_async("iptables", add).await {
                // Race with cleanup(): it sets `shutting_down` *before* draining
                // the undo stack under the same lock (see cleanup()), and the
                // check below happens under that lock after the rule is added.
                // So if cleanup already ran (shutting_down set, stack drained) we
                // remove the rule ourselves; otherwise we record it for cleanup.
                // Without this, a rule added after the drain would leak — the
                // undo pushed onto an already-emptied stack is never run.
                let delete_now = match self.undo.lock() {
                    Ok(mut undo) => record_undo_or_signal_delete(
                        self.shutting_down.load(Ordering::Relaxed),
                        &mut undo,
                        Undo::Cmd("iptables", del.clone()),
                    ),
                    Err(_) => true, // poisoned: remove defensively
                };
                if delete_now {
                    warn!("os-routing: shutting down, removing just-added MASQUERADE for {}", ip);
                    run_cmd_async("iptables", del).await;
                }
            }
        }

        // Reserve the slot now that the route is actually installed (so refused
        // peers never consumed one), evicting the least-recently-active peer if
        // the table is full — otherwise one client spraying 64 distinct sources
        // would permanently brick return routing for every later client.
        let evicted = {
            let mut peers = self.peers.lock().unwrap();
            reserve_peer_slot(&mut peers, ip, Instant::now(), MAX_PEERS)
        };
        if let Some(victim) = evicted {
            info!("os-routing: peer table full, evicting least-recently-active {}", victim);
            let vdst = format!("{}/32", victim);
            run_cmd_async("ip", svec(&["route", "del", &vdst, "dev", &self.tun_name])).await;
            if self.configure_nat {
                run_cmd_async(
                    "iptables",
                    svec(&[
                        "-w", "-t", "nat", "-D", "POSTROUTING", "-s", &vdst, "!", "-o",
                        &self.tun_name, "-j", "MASQUERADE",
                    ]),
                )
                .await;
            }
        }
    }
}

/// (Re)insert `ip` into the peer table with timestamp `now`, evicting the
/// least-recently-active peer if the table is at `cap`. Returns the evicted
/// address (whose `/32` route and MASQUERADE the caller must remove), or None.
fn reserve_peer_slot(
    peers: &mut HashMap<Ipv4Addr, Instant>,
    ip: Ipv4Addr,
    now: Instant,
    cap: usize,
) -> Option<Ipv4Addr> {
    let evicted = if !peers.contains_key(&ip) && peers.len() >= cap {
        let victim = peers.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k);
        if let Some(v) = victim {
            peers.remove(&v);
        }
        victim
    } else {
        None
    };
    peers.insert(ip, now);
    evicted
}

/// True if the host already has a real path to `ip` that a `/32` on the TUN
/// would shadow. We must consult the whole route table, not just `ip route get`:
/// a client-chosen private source can collide not only with a directly-connected
/// subnet but with one the host reaches via a *gateway* (a downstream router, a
/// nested VPN, a corporate subnet). `ip route get` can't distinguish such a
/// specific gateway route from the default route, so we parse the table and look
/// for any non-default route covering `ip` on an interface other than our TUN.
async fn host_has_conflicting_route(ip: Ipv4Addr, tun: &str) -> bool {
    let tun = tun.to_string();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("ip")
            .args(["-4", "route", "show"])
            .output()
    })
    .await;
    match out {
        Ok(Ok(o)) if o.status.success() => {
            route_table_conflicts(&String::from_utf8_lossy(&o.stdout), ip, &tun)
        }
        _ => false, // fail open: don't block routing if we can't tell
    }
}

/// Does `routes` (the output of `ip -4 route show`) contain a non-default route
/// covering `ip` via an interface other than `tun`? The default route is
/// ignored: a private destination "reached via default" has no real path back
/// (the default gateway won't route private space), so a `/32` for it is safe.
fn route_table_conflicts(routes: &str, ip: Ipv4Addr, tun: &str) -> bool {
    for line in routes.lines() {
        let mut toks = line.split_whitespace();
        let Some(prefix) = toks.next() else { continue };
        if prefix == "default" {
            continue;
        }
        let Some((net, plen)) = parse_ipv4_prefix(prefix) else { continue };
        if plen == 0 || !ipv4_in_prefix(ip, net, plen) {
            continue;
        }
        // A route on our own TUN (the client subnet) isn't a conflict.
        let mut dev = None;
        while let Some(t) = toks.next() {
            if t == "dev" {
                dev = toks.next();
                break;
            }
        }
        if dev != Some(tun) {
            return true;
        }
    }
    false
}

/// Decide what to do with a just-added rule's undo. If we're shutting down,
/// `cleanup()` has already drained the undo stack (it sets `shutting_down`
/// before draining, under the same lock held by the caller here), so pushing
/// would leak the rule — signal the caller to remove it now (`true`). Otherwise
/// record the undo for `cleanup()` to run later (`false`).
fn record_undo_or_signal_delete(shutting_down: bool, undo: &mut Vec<Undo>, undo_cmd: Undo) -> bool {
    if shutting_down {
        true
    } else {
        undo.push(undo_cmd);
        false
    }
}

/// Parse an IPv4 route prefix like `192.168.1.0/24`, or a bare host `10.0.0.5`
/// (treated as `/32`).
fn parse_ipv4_prefix(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, plen) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (s, 32),
    };
    if plen > 32 {
        return None;
    }
    Some((addr.parse::<Ipv4Addr>().ok()?, plen))
}

fn ipv4_in_prefix(ip: Ipv4Addr, net: Ipv4Addr, plen: u8) -> bool {
    if plen == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - plen as u32);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// Minimal async device interface so the pump can be tested without a real
/// TUN (creating one requires CAP_NET_ADMIN).
trait ExitDevice: Send + Sync + 'static {
    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

impl ExitDevice for Tun {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        Tun::send(self, buf).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        Tun::recv(self, buf).await
    }
}

/// What to do with a packet arriving from the client.
enum Verdict {
    /// Hand to the kernel; learn the source address for the return route.
    Forward(Ipv4Addr),
    /// Locally-generated ICMP echo reply (keepalive ping to a private dst).
    ReplyEcho(Vec<u8>),
    Drop(&'static str),
}

fn classify(pkt: &[u8]) -> Verdict {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        // The netstack path is IPv4-only too; v6 noise from the client's TUN.
        return Verdict::Drop("not IPv4");
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if is_local_address(IpAddr::V4(dst)) {
        if let Some(reply) = icmp_echo_reply_for(pkt) {
            return Verdict::ReplyEcho(reply);
        }
        return Verdict::Drop("local destination");
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    if !is_private_client_source(src) {
        // The client picks its own inner TUN address, but it MUST be a private
        // one. The source field is fully client-controlled, and we install a
        // `/32` return route per learned source; a client-chosen *public*
        // source (e.g. 8.8.8.8) would install `8.8.8.8/32 dev tun`, shadowing
        // the host's real route and letting the client black-hole or intercept
        // the sharer's OWN egress to that address. Refuse anything outside
        // RFC1918 / CGNAT space (this also covers multicast/loopback/etc.).
        return Verdict::Drop("non-private source");
    }
    Verdict::Forward(src)
}

/// True for source addresses a client is allowed to use for its inner TUN:
/// RFC1918 private space plus RFC6598 CGNAT (100.64.0.0/10). Everything else —
/// public unicast, loopback, link-local, multicast, broadcast — is refused so a
/// client cannot install a return route that shadows one of the sharer's real
/// routes. Known client platforms already use private addresses (the CLI/FFI
/// keepalive sources from 10.0.0.1, wincore's TUN is 10.0.85.1).
fn is_private_client_source(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10
        || (o[0] == 172 && (o[1] & 0xF0) == 16)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
}

/// Per-session packet pump: transport <-> TUN.
async fn pump<D: ExitDevice>(
    mut transport: IpTransport,
    dev: Arc<D>,
    cancel: CancellationToken,
    learn: PeerLearner,
    recv_buf_len: usize,
) {
    info!("os-routing: session pump started");
    let mut buf = vec![0u8; recv_buf_len];
    // Session-local fast path; cross-session dedup lives behind `learn`.
    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    let mut rx: u64 = 0;
    let mut tx: u64 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("os-routing: session cancelled");
                break;
            }
            res = transport.next() => match res {
                Some(Ok(pkt)) => match classify(&pkt) {
                    Verdict::Forward(src) => {
                        if seen.insert(src) {
                            learn(src).await;
                        }
                        rx += 1;
                        if let Err(e) = dev.send(&pkt).await {
                            warn!("os-routing: TUN write error: {}", e);
                        }
                    }
                    Verdict::ReplyEcho(reply) => {
                        trace!("os-routing: answering keepalive/local ping");
                        if let Err(e) = transport.send(reply).await {
                            warn!("os-routing: failed to send echo reply: {}", e);
                        }
                    }
                    Verdict::Drop(reason) => trace!("os-routing: dropping packet: {}", reason),
                },
                Some(Err(e)) => warn!("os-routing: transport read error: {}", e),
                None => {
                    info!("os-routing: transport stream closed");
                    break;
                }
            },
            res = dev.recv(&mut buf) => match res {
                Ok(n) => {
                    if n == 0 || buf[0] >> 4 != 4 {
                        // The kernel auto-assigns an IPv6 link-local to the TUN
                        // and emits Router Solicitation / MLD / DAD chatter. The
                        // client->host direction is IPv4-only (see classify), so
                        // keep this direction symmetric and drop non-IPv4 frames
                        // instead of leaking them (and the link-local) to the peer.
                        trace!("os-routing: dropping non-IPv4 frame from TUN ({} bytes)", n);
                        continue;
                    }
                    tx += 1;
                    if let Err(e) = transport.send(buf[..n].to_vec()).await {
                        warn!("os-routing: transport write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("os-routing: TUN read error: {}", e);
                    break;
                }
            },
        }
    }
    info!("os-routing: session pump ended (client->kernel {} pkts, kernel->client {} pkts)", rx, tx);
}

/// Craft an ICMP echo reply for an echo request, or `None` if `pkt` isn't an
/// unfragmented ICMP echo request.
fn icmp_echo_reply_for(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    if pkt[9] != 1 {
        return None; // not ICMP
    }
    let more_fragments = pkt[6] & 0x20 != 0;
    let frag_offset = u16::from_be_bytes([pkt[6] & 0x1F, pkt[7]]);
    if more_fragments || frag_offset != 0 {
        return None; // can't answer a fragment
    }
    if pkt[ihl] != 8 || pkt[ihl + 1] != 0 {
        return None; // not an echo request
    }
    let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if total_len < ihl + 8 || total_len > pkt.len() {
        return None;
    }

    let mut r = pkt[..total_len].to_vec();
    for i in 0..4 {
        r.swap(12 + i, 16 + i); // swap src/dst
    }
    r[8] = 64; // fresh TTL
    r[10] = 0;
    r[11] = 0;
    let ip_csum = inet_checksum(&r[..ihl]);
    r[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    r[ihl] = 0; // type: echo reply (id/seq/payload preserved)
    r[ihl + 2] = 0;
    r[ihl + 3] = 0;
    let icmp_csum = inet_checksum(&r[ihl..]);
    r[ihl + 2..ihl + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    Some(r)
}

/// RFC 1071 internet checksum.
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [b] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*b, 0]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn svec(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn run_cmd(program: &str, args: &[String]) -> bool {
    info!("os-routing: # {} {}", program, args.join(" "));
    match std::process::Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            warn!(
                "os-routing: {} failed ({}): {}",
                program,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            warn!("os-routing: could not run {}: {}", program, e);
            false
        }
    }
}

async fn run_cmd_async(program: &'static str, args: Vec<String>) -> bool {
    tokio::task::spawn_blocking(move || run_cmd(program, &args))
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{Sink, Stream};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::sync::mpsc;

    fn ipv4_udp(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4(src, dst, 64)
            .udp(40000, 53)
            .write(&mut pkt, payload)
            .unwrap();
        pkt
    }

    fn icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv4(src, dst, 64)
            .icmpv4_echo_request(id, seq)
            .write(&mut pkt, b"spka")
            .unwrap();
        pkt
    }

    #[test]
    fn checksum_known_vector() {
        // Example from RFC 1071 / common references.
        let data = [0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
                    0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7];
        assert_eq!(inet_checksum(&data), 0xb861);
    }

    #[test]
    fn echo_reply_is_valid_and_mirrored() {
        let req = icmp_echo_request([10, 0, 0, 1], [10, 0, 0, 2], 0x5350, 7);
        let reply = icmp_echo_reply_for(&req).expect("should answer echo request");

        // Addresses swapped.
        assert_eq!(&reply[12..16], &[10, 0, 0, 2]);
        assert_eq!(&reply[16..20], &[10, 0, 0, 1]);
        // Type 0 (echo reply), id/seq/payload preserved.
        let ihl = ((reply[0] & 0x0F) as usize) * 4;
        assert_eq!(reply[ihl], 0);
        assert_eq!(&reply[ihl + 4..ihl + 8], &req[ihl + 4..ihl + 8]);
        assert_eq!(&reply[ihl + 8..], &req[ihl + 8..]);
        // Both checksums verify (sum over region including checksum == 0).
        assert_eq!(inet_checksum(&reply[..ihl]), 0);
        assert_eq!(inet_checksum(&reply[ihl..]), 0);
    }

    #[test]
    fn echo_reply_ignores_non_echo() {
        // UDP to a private address is not answered.
        assert!(icmp_echo_reply_for(&ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], b"x")).is_none());
        // Truncated packet.
        assert!(icmp_echo_reply_for(&[0x45, 0x00]).is_none());
    }

    #[test]
    fn classify_verdicts() {
        // Public destination → forwarded, source learned.
        match classify(&ipv4_udp([10, 0, 85, 1], [8, 8, 8, 8], b"x")) {
            Verdict::Forward(src) => assert_eq!(src, Ipv4Addr::new(10, 0, 85, 1)),
            _ => panic!("expected Forward"),
        }
        // Private destination → blocked.
        assert!(matches!(
            classify(&ipv4_udp([10, 0, 85, 1], [192, 168, 1, 10], b"x")),
            Verdict::Drop(_)
        ));
        // Keepalive ping to a private destination → answered.
        assert!(matches!(
            classify(&icmp_echo_request([10, 0, 0, 1], [10, 0, 0, 2], 0x5350, 1)),
            Verdict::ReplyEcho(_)
        ));
        // Ping to a public destination → forwarded like normal traffic.
        assert!(matches!(
            classify(&icmp_echo_request([10, 0, 85, 1], [1, 1, 1, 1], 1, 1)),
            Verdict::Forward(_)
        ));
        // IPv6 → dropped.
        assert!(matches!(classify(&[0x60, 0, 0, 0]), Verdict::Drop(_)));
        // Martian source → dropped.
        assert!(matches!(
            classify(&ipv4_udp([224, 0, 0, 1], [8, 8, 8, 8], b"x")),
            Verdict::Drop(_)
        ));
        // Public SOURCE to a public dst → dropped (would otherwise install a
        // /32 hijack route for the sharer's own egress to that address).
        assert!(matches!(
            classify(&ipv4_udp([8, 8, 8, 8], [1, 1, 1, 1], b"x")),
            Verdict::Drop(_)
        ));
        // CGNAT source (100.64/10) is accepted.
        assert!(matches!(
            classify(&ipv4_udp([100, 64, 0, 5], [8, 8, 8, 8], b"x")),
            Verdict::Forward(_)
        ));
    }

    #[test]
    fn private_client_source_ranges() {
        for ip in [[10, 0, 0, 1], [10, 0, 85, 1], [172, 16, 0, 1], [172, 31, 255, 9],
                   [192, 168, 1, 1], [100, 64, 0, 1], [100, 127, 255, 1]] {
            assert!(is_private_client_source(Ipv4Addr::from(ip)), "{:?} should be allowed", ip);
        }
        for ip in [[8, 8, 8, 8], [1, 1, 1, 1], [172, 15, 0, 1], [172, 32, 0, 1],
                   [100, 63, 0, 1], [100, 128, 0, 1], [169, 254, 0, 1], [127, 0, 0, 1],
                   [192, 167, 0, 1], [11, 0, 0, 1]] {
            assert!(!is_private_client_source(Ipv4Addr::from(ip)), "{:?} should be refused", ip);
        }
    }

    #[test]
    fn masquerade_undo_recorded_or_deleted_on_shutdown() {
        let cmd = || Undo::Cmd("iptables", svec(&["-w", "-t", "nat", "-D", "POSTROUTING"]));
        // Normal: record the undo for cleanup, don't delete now.
        let mut undo = Vec::new();
        assert!(!record_undo_or_signal_delete(false, &mut undo, cmd()));
        assert_eq!(undo.len(), 1, "undo recorded for cleanup");
        // Shutting down (stack already drained): signal delete, push nothing —
        // otherwise the rule would leak past shutdown.
        let mut undo = Vec::new();
        assert!(record_undo_or_signal_delete(true, &mut undo, cmd()));
        assert!(undo.is_empty(), "must not push onto an already-drained stack");
    }

    #[test]
    fn peer_table_evicts_least_recently_active() {
        use std::time::Duration;
        let mut peers: HashMap<Ipv4Addr, Instant> = HashMap::new();
        let t0 = Instant::now();
        let ip = |a: u8| Ipv4Addr::new(10, 0, 0, a);

        // Fill to cap=3 with increasing timestamps; ip(1) is least recent.
        assert_eq!(reserve_peer_slot(&mut peers, ip(1), t0, 3), None);
        assert_eq!(reserve_peer_slot(&mut peers, ip(2), t0 + Duration::from_secs(1), 3), None);
        assert_eq!(reserve_peer_slot(&mut peers, ip(3), t0 + Duration::from_secs(2), 3), None);
        assert_eq!(peers.len(), 3);

        // A new peer at the cap evicts the least-recently-active (ip(1)).
        assert_eq!(
            reserve_peer_slot(&mut peers, ip(4), t0 + Duration::from_secs(3), 3),
            Some(ip(1))
        );
        assert_eq!(peers.len(), 3, "table stays bounded");
        assert!(!peers.contains_key(&ip(1)));
        assert!(peers.contains_key(&ip(4)));

        // Refreshing an existing peer never evicts.
        assert_eq!(
            reserve_peer_slot(&mut peers, ip(2), t0 + Duration::from_secs(4), 3),
            None
        );
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn route_table_conflict_detection() {
        let tun = "tun0";
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let table = "\
            192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10\n\
            10.5.0.0/16 via 192.168.1.1 dev eth0\n\
            10.0.0.0/8 dev wg0 scope link\n\
            10.213.0.0/24 dev tun0 scope link\n\
            default via 192.168.1.1 dev eth0\n";

        // Directly-connected LAN on another device → conflict.
        assert!(route_table_conflicts(table, ip("192.168.1.50"), tun));
        // Private subnet reached via a gateway (the #5 fix; the old
        // directly-connected check treated this as safe).
        assert!(route_table_conflicts(table, ip("10.5.0.7"), tun));
        // Covered only by our own TUN route (10.213.0.0/24 dev tun0) — but note
        // 10.0.0.0/8 dev wg0 also covers it and is checked first in this table.
        assert!(route_table_conflicts(table, ip("10.0.0.1"), tun));
        // A private source covered by NO non-default, non-tun route → allowed.
        assert!(!route_table_conflicts(
            "192.168.1.0/24 dev eth0\ndefault via 192.168.1.1 dev eth0",
            ip("172.31.5.9"),
            tun
        ));
        // Covered only by our own TUN route → not a conflict.
        assert!(!route_table_conflicts(
            "10.213.0.0/24 dev tun0\ndefault via 192.168.1.1 dev eth0",
            ip("10.213.0.5"),
            tun
        ));
        // Empty table → fail open (no conflict).
        assert!(!route_table_conflicts("", ip("10.0.0.1"), tun));
    }

    // ---- pump tests with a mock transport + mock device ----

    /// Channel-backed `Transport` for tests.
    struct ChanTransport {
        rx: mpsc::UnboundedReceiver<Vec<u8>>,
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl Stream for ChanTransport {
        type Item = io::Result<Vec<u8>>;
        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.rx.poll_recv(cx).map(|opt| opt.map(Ok))
        }
    }

    impl Sink<Vec<u8>> for ChanTransport {
        type Error = io::Error;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), io::Error> {
            self.tx
                .send(item)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct MockDev {
        to_pump: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        from_pump: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl ExitDevice for MockDev {
        async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.from_pump
                .send(buf.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))?;
            Ok(buf.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let pkt = self
                .to_pump
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "closed"))?;
            let n = pkt.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt[..n]);
            Ok(n)
        }
    }

    struct Harness {
        to_transport: mpsc::UnboundedSender<Vec<u8>>,
        from_transport: mpsc::UnboundedReceiver<Vec<u8>>,
        to_dev: mpsc::UnboundedSender<Vec<u8>>,
        from_dev: mpsc::UnboundedReceiver<Vec<u8>>,
        learned: Arc<Mutex<Vec<Ipv4Addr>>>,
        cancel: CancellationToken,
        pump_task: tokio::task::JoinHandle<()>,
    }

    fn start_pump() -> Harness {
        let (to_transport, transport_rx) = mpsc::unbounded_channel();
        let (transport_tx, from_transport) = mpsc::unbounded_channel();
        let (to_dev, dev_rx) = mpsc::unbounded_channel();
        let (dev_tx, from_dev) = mpsc::unbounded_channel();

        let transport: IpTransport = Box::new(ChanTransport {
            rx: transport_rx,
            tx: transport_tx,
        });
        let dev = Arc::new(MockDev {
            to_pump: tokio::sync::Mutex::new(dev_rx),
            from_pump: dev_tx,
        });

        let learned: Arc<Mutex<Vec<Ipv4Addr>>> = Arc::new(Mutex::new(Vec::new()));
        let learned_clone = learned.clone();
        let learn: PeerLearner = Arc::new(move |ip| {
            let learned = learned_clone.clone();
            Box::pin(async move {
                learned.lock().unwrap().push(ip);
            })
        });

        let cancel = CancellationToken::new();
        let pump_task = tokio::spawn(pump(transport, dev, cancel.clone(), learn, 2048));

        Harness {
            to_transport,
            from_transport,
            to_dev,
            from_dev,
            learned,
            cancel,
            pump_task,
        }
    }

    async fn recv_with_timeout(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Option<Vec<u8>> {
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn pump_forwards_and_learns_and_answers_keepalive() {
        let mut h = start_pump();

        // 1. Client packet to a public dst is forwarded to the device, and the
        //    source address is learned exactly once.
        let pkt = ipv4_udp([10, 0, 85, 1], [8, 8, 8, 8], b"hello");
        h.to_transport.send(pkt.clone()).unwrap();
        assert_eq!(recv_with_timeout(&mut h.from_dev).await.unwrap(), pkt);

        let pkt2 = ipv4_udp([10, 0, 85, 1], [9, 9, 9, 9], b"again");
        h.to_transport.send(pkt2.clone()).unwrap();
        assert_eq!(recv_with_timeout(&mut h.from_dev).await.unwrap(), pkt2);
        assert_eq!(*h.learned.lock().unwrap(), vec![Ipv4Addr::new(10, 0, 85, 1)]);

        // 2. Keepalive ping to the synthetic private address is answered
        //    locally and never reaches the device.
        let ping = icmp_echo_request([10, 0, 0, 1], [10, 0, 0, 2], 0x5350, 3);
        h.to_transport.send(ping).unwrap();
        let reply = recv_with_timeout(&mut h.from_transport).await.unwrap();
        let ihl = ((reply[0] & 0x0F) as usize) * 4;
        assert_eq!(reply[ihl], 0, "expected echo reply type");
        assert_eq!(&reply[16..20], &[10, 0, 0, 1], "reply goes back to the pinger");

        // 3. Packet to a private dst is dropped (never reaches the device).
        h.to_transport
            .send(ipv4_udp([10, 0, 85, 1], [192, 168, 1, 1], b"lan"))
            .unwrap();

        // 4. Device-side packet flows back to the transport.
        let reply_pkt = ipv4_udp([8, 8, 8, 8], [10, 0, 85, 1], b"resp");
        h.to_dev.send(reply_pkt.clone()).unwrap();
        assert_eq!(
            recv_with_timeout(&mut h.from_transport).await.unwrap(),
            reply_pkt
        );

        // The LAN packet from step 3 must not have arrived at the device
        // (the step-4 round trip already proves ordering).
        assert!(
            h.from_dev.try_recv().is_err(),
            "packet to private destination leaked to the device"
        );

        // 5. Cancellation stops the pump.
        h.cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), h.pump_task)
            .await
            .expect("pump should end on cancel")
            .unwrap();
    }

    #[tokio::test]
    async fn pump_ends_when_transport_closes() {
        let h = start_pump();
        drop(h.to_transport); // transport stream yields None
        tokio::time::timeout(std::time::Duration::from_secs(2), h.pump_task)
            .await
            .expect("pump should end when transport closes")
            .unwrap();
    }

    #[test]
    fn options_parse_and_validate() {
        let opts = Options::parse("10.213.0.1/24", 1280, true).unwrap();
        assert_eq!(opts.addr, Ipv4Addr::new(10, 213, 0, 1));
        assert_eq!(opts.prefix_len, 24);
        assert_eq!(opts.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert!(Options::parse("10.213.0.1", 1280, true).is_err());
        assert!(Options::parse("10.213.0.1/31", 1280, true).is_err());
        assert!(Options::parse("not-an-ip/24", 1280, true).is_err());
        assert!(Options::parse("10.213.0.1/24", 100, true).is_err());
    }
}
