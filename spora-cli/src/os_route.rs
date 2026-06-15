//! Privileged exit-mode bypass: instead of terminating flows in the userland
//! netstack, write the client's IP packets to a TUN device and let the kernel
//! route (and NAT) them.
//!
//! What this module does per `spora share --os-routing` run:
//!  - creates a TUN device with the given v4/v6 addresses and MTU;
//!  - (unless `--no-nat`) enables v4/v6 forwarding and installs
//!    iptables/ip6tables rules: FORWARD accepts for the TUN and TCP MSS
//!    clamping to the TUN MTU;
//!  - learns each client's inner source address from the packets it sends and
//!    installs a host return route (`/32` v4, `/128` v6) plus a MASQUERADE
//!    rule for it — the client's TUN address is chosen by the client platform,
//!    so it can't be assumed to sit inside our TUN's subnet;
//!  - answers ICMP/ICMPv6 echo requests aimed at blocked (private)
//!    destinations. This is load-bearing: the client's keepalive layer pings a
//!    synthetic private address (10.0.0.2 by default) and declares the tunnel
//!    dead if nothing ever comes back. In netstack mode smoltcp answers those
//!    pings; here we must do it ourselves because the kernel has no route to
//!    them.
//!
//! Packets to private/local destinations are dropped (parity with the
//! netstack's `block_local`), so a client can't reach the sharer's LAN.
//!
//! Inner IPv6 rides alongside v4: a v6 client must source from ULA space
//! (fc00::/7 — the v6 twin of the RFC1918-only rule), and the kernel's
//! link-local/multicast autoconf chatter on the TUN (RS/NS/MLD/DAD) is
//! filtered out instead of being leaked to the peer.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
const IPV6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

pub struct Options {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    pub addr6: Ipv6Addr,
    pub prefix6_len: u8,
    pub mtu: u16,
    pub configure_nat: bool,
}

impl Options {
    /// Parse `--tun-addr` ("a.b.c.d/len") and `--tun-addr6` plus the other flags.
    pub fn parse(
        tun_addr: &str,
        tun_addr6: &str,
        mtu: u16,
        configure_nat: bool,
    ) -> Result<Self, String> {
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
        let (addr6, prefix6) = tun_addr6.split_once('/').ok_or_else(|| {
            format!("--tun-addr6 must be CIDR (e.g. fd00:5350::1/64), got {}", tun_addr6)
        })?;
        let addr6: Ipv6Addr = addr6
            .parse()
            .map_err(|e| format!("bad --tun-addr6 address: {}", e))?;
        let prefix6_len: u8 = prefix6
            .parse()
            .map_err(|e| format!("bad --tun-addr6 prefix length: {}", e))?;
        if !(16..=126).contains(&prefix6_len) {
            return Err(format!(
                "--tun-addr6 prefix length must be 16..=126, got {}",
                prefix6_len
            ));
        }
        // The v6 tunnel plane lives entirely in ULA space — clients may only
        // source from fc00::/7 (see is_ula_client_source) — so a global TUN
        // address would be unreachable from the tunnel while shadowing a real
        // v6 prefix on the host. Refuse it.
        if !is_ula_client_source(addr6) {
            return Err(format!("--tun-addr6 must be inside fc00::/7 (ULA), got {}", addr6));
        }
        if !(576..=9000).contains(&mtu) {
            return Err(format!("--tun-mtu must be 576..=9000, got {}", mtu));
        }
        Ok(Self {
            addr,
            prefix_len,
            addr6,
            prefix6_len,
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
    /// Learned client source addresses (both families) with their last-seen
    /// time, so the table can evict the least-recently-active peer instead of
    /// bricking once full.
    peers: Mutex<HashMap<IpAddr, Instant>>,
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
            "os-routing: TUN {} up, {}/{} + {}/{}, mtu {}",
            tun.name(),
            opts.addr,
            opts.prefix_len,
            opts.addr6,
            opts.prefix6_len,
            opts.mtu
        );

        // tokio-tun's builder only knows IPv4; add the ULA address by hand.
        // `nodad` because there is no other host on this point-to-point link to
        // duplicate. No undo needed: the address dies with the device.
        let addr6 = format!("{}/{}", opts.addr6, opts.prefix6_len);
        run_cmd("ip", &svec(&["-6", "addr", "add", &addr6, "dev", tun.name(), "nodad"]));
        // Quiet the kernel's v6 autoconf on the TUN (link-local generation,
        // router solicitations). Belt-and-braces — the pump filters link-scope
        // frames anyway — and best-effort: older kernels lack addr_gen_mode.
        for (knob, val) in [("addr_gen_mode", "1"), ("accept_ra", "0")] {
            let path = format!("/proc/sys/net/ipv6/conf/{}/{}", tun.name(), knob);
            if let Err(e) = std::fs::write(&path, val) {
                debug!("os-routing: could not write {}: {}", path, e);
            }
        }

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

    /// Enable IPv4/IPv6 forwarding and install the interface-scoped
    /// iptables/ip6tables rules. Failures are downgraded to warnings: the pump
    /// still works and the user may have equivalent rules of their own (e.g.
    /// native nftables).
    fn configure_forwarding(&self, opts: &Options) {
        self.enable_forwarding_knob(IP_FORWARD, "net.ipv4.ip_forward");
        self.enable_forwarding_knob(IPV6_FORWARD, "net.ipv6.conf.all.forwarding");

        let tun = self.shared.tun_name.clone();
        // Clamp TCP MSS in both directions to fit the TUN MTU. The flows are
        // end-to-end here (unlike the netstack, which terminates TCP), so
        // without this a client behind a 1500-MTU TUN negotiates an MSS that
        // overflows our QUIC datagram budget and relies on IP fragmentation.
        // v6 needs 20 more bytes of headroom for its 40-byte fixed header.
        let mss4 = opts.mtu.saturating_sub(40).max(536).to_string();
        let mss6 = opts.mtu.saturating_sub(60).max(536).to_string();
        for (cmd, mss) in [("iptables", mss4), ("ip6tables", mss6)] {
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
                        "-w", "-t", "mangle", "-A", "FORWARD", "-i", &tun, "-p", "tcp",
                        "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                    ]),
                    svec(&[
                        "-w", "-t", "mangle", "-D", "FORWARD", "-i", &tun, "-p", "tcp",
                        "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                    ]),
                ),
                (
                    svec(&[
                        "-w", "-t", "mangle", "-A", "FORWARD", "-o", &tun, "-p", "tcp",
                        "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                    ]),
                    svec(&[
                        "-w", "-t", "mangle", "-D", "FORWARD", "-o", &tun, "-p", "tcp",
                        "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss,
                    ]),
                ),
            ];
            for (add, del) in rules {
                if run_cmd(cmd, &add) {
                    self.shared.undo.lock().unwrap().push(Undo::Cmd(cmd, del));
                }
            }
        }
    }

    /// Set a forwarding sysctl to 1 (if not already), recording the previous
    /// value for cleanup() to restore.
    fn enable_forwarding_knob(&self, path: &'static str, label: &str) {
        match std::fs::read_to_string(path) {
            Ok(v) if v.trim() == "1" => debug!("os-routing: {} already enabled", label),
            Ok(v) => match std::fs::write(path, "1") {
                Ok(()) => {
                    info!("os-routing: enabled {}", label);
                    self.shared
                        .undo
                        .lock()
                        .unwrap()
                        .push(Undo::ProcWrite(path, v.trim().to_string()));
                }
                Err(e) => warn!("os-routing: could not enable {}: {}", label, e),
            },
            Err(e) => warn!("os-routing: could not read {}: {}", path, e),
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

type PeerLearner = Arc<dyn Fn(IpAddr) -> SessionFuture + Send + Sync>;

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
    async fn learn_peer(&self, ip: IpAddr) {
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
        // Even within private/ULA space, refuse to shadow an address the host
        // can already reach over a real route — whether directly-connected (the
        // sharer's own LAN) or via a gateway (a downstream router, nested VPN, or
        // corporate subnet behind the default route). A host route on the TUN
        // would override that route and divert the sharer's own egress to it
        // into the tunnel. Fail open: if we can't read the table, install.
        if host_has_conflicting_route(ip, &self.tun_name).await {
            warn!(
                "os-routing: client source {} collides with an existing host route; \
                 refusing to install a return route",
                ip
            );
            return;
        }
        info!("os-routing: learned client address {}, installing return route", ip);
        let dst = host_dst(ip);
        let nat = nat_cmd(ip);
        // No undo needed: the route is bound to the TUN device and dies with it.
        run_cmd_async("ip", ip_route_args(ip, "replace", &dst, &self.tun_name)).await;
        if self.configure_nat {
            let add = svec(&[
                "-w", "-t", "nat", "-I", "POSTROUTING", "1", "-s", &dst, "!", "-o",
                &self.tun_name, "-j", "MASQUERADE",
            ]);
            let del = svec(&[
                "-w", "-t", "nat", "-D", "POSTROUTING", "-s", &dst, "!", "-o", &self.tun_name,
                "-j", "MASQUERADE",
            ]);
            if run_cmd_async(nat, add).await {
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
                        Undo::Cmd(nat, del.clone()),
                    ),
                    Err(_) => true, // poisoned: remove defensively
                };
                if delete_now {
                    warn!("os-routing: shutting down, removing just-added MASQUERADE for {}", ip);
                    run_cmd_async(nat, del).await;
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
            let vdst = host_dst(victim);
            run_cmd_async("ip", ip_route_args(victim, "del", &vdst, &self.tun_name)).await;
            if self.configure_nat {
                run_cmd_async(
                    nat_cmd(victim),
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

/// The host-route/NAT-rule selector for a learned peer: `/32` v4, `/128` v6.
fn host_dst(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{}/32", ip),
        IpAddr::V6(ip) => format!("{}/128", ip),
    }
}

/// The NAT frontend for the peer's family; both take the same rule syntax.
fn nat_cmd(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "iptables" } else { "ip6tables" }
}

/// `ip route <verb> <dst> dev <tun>`, with the `-6` family selector for v6.
fn ip_route_args(ip: IpAddr, verb: &str, dst: &str, tun: &str) -> Vec<String> {
    let mut args = match ip {
        IpAddr::V4(_) => Vec::new(),
        IpAddr::V6(_) => svec(&["-6"]),
    };
    args.extend(svec(&["route", verb, dst, "dev", tun]));
    args
}

/// (Re)insert `ip` into the peer table with timestamp `now`, evicting the
/// least-recently-active peer if the table is at `cap`. Returns the evicted
/// address (whose host route and MASQUERADE the caller must remove), or None.
/// The cap is shared across both families.
fn reserve_peer_slot(
    peers: &mut HashMap<IpAddr, Instant>,
    ip: IpAddr,
    now: Instant,
    cap: usize,
) -> Option<IpAddr> {
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

/// True if the host already has a real path to `ip` that a host route on the
/// TUN would shadow. We must consult the whole route table, not just `ip route
/// get`: a client-chosen private source can collide not only with a
/// directly-connected subnet but with one the host reaches via a *gateway* (a
/// downstream router, a nested VPN, a corporate subnet). `ip route get` can't
/// distinguish such a specific gateway route from the default route, so we
/// parse the table (of `ip`'s family) and look for any non-default route
/// covering `ip` on an interface other than our TUN.
async fn host_has_conflicting_route(ip: IpAddr, tun: &str) -> bool {
    let tun = tun.to_string();
    let family = if ip.is_ipv4() { "-4" } else { "-6" };
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("ip")
            .args([family, "route", "show"])
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

/// Does `routes` (the output of `ip -4/-6 route show`) contain a non-default
/// route covering `ip` via an interface other than `tun`? The default route
/// (`default` / `::/0`) is ignored: a private/ULA destination "reached via
/// default" has no real path back (the default gateway won't route that
/// space), so a host route for it is safe.
fn route_table_conflicts(routes: &str, ip: IpAddr, tun: &str) -> bool {
    for line in routes.lines() {
        let mut toks = line.split_whitespace();
        let Some(prefix) = toks.next() else { continue };
        if prefix == "default" {
            continue;
        }
        let covers = match ip {
            IpAddr::V4(ip) => {
                let Some((net, plen)) = parse_ipv4_prefix(prefix) else { continue };
                plen != 0 && ipv4_in_prefix(ip, net, plen)
            }
            IpAddr::V6(ip) => {
                let Some((net, plen)) = parse_ipv6_prefix(prefix) else { continue };
                // The kernel puts fe80::/64 on every interface; it can never
                // cover a ULA client source, so don't let it read as one.
                if (net.segments()[0] & 0xFFC0) == 0xFE80 {
                    continue;
                }
                plen != 0 && ipv6_in_prefix(ip, net, plen)
            }
        };
        if !covers {
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

/// Parse an IPv6 route prefix like `fd00:5350::/64`, or a bare host `fd00::5`
/// (treated as `/128`).
fn parse_ipv6_prefix(s: &str) -> Option<(Ipv6Addr, u8)> {
    let (addr, plen) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (s, 128),
    };
    if plen > 128 {
        return None;
    }
    Some((addr.parse::<Ipv6Addr>().ok()?, plen))
}

fn ipv6_in_prefix(ip: Ipv6Addr, net: Ipv6Addr, plen: u8) -> bool {
    if plen == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - plen as u32);
    (u128::from(ip) & mask) == (u128::from(net) & mask)
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
    Forward(IpAddr),
    /// Locally-generated ICMP/ICMPv6 echo reply (keepalive ping to a private dst).
    ReplyEcho(Vec<u8>),
    Drop(&'static str),
}

fn classify(pkt: &[u8]) -> Verdict {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => classify_v4(pkt),
        Some(6) => classify_v6(pkt),
        _ => Verdict::Drop("not IP"),
    }
}

fn classify_v4(pkt: &[u8]) -> Verdict {
    if pkt.len() < 20 {
        return Verdict::Drop("truncated IPv4");
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
    Verdict::Forward(IpAddr::V4(src))
}

fn classify_v6(pkt: &[u8]) -> Verdict {
    if pkt.len() < 40 {
        return Verdict::Drop("truncated IPv6");
    }
    let dst = ipv6_at(pkt, 24);
    if is_local_address(IpAddr::V6(dst)) {
        if let Some(reply) = icmpv6_echo_reply_for(pkt) {
            return Verdict::ReplyEcho(reply);
        }
        return Verdict::Drop("local destination");
    }
    let src = ipv6_at(pkt, 8);
    if !is_ula_client_source(src) {
        // Same hijack hazard as classify_v4: the source earns a `/128` return
        // route, so a client-chosen *global* source would shadow the host's
        // real route to that address.
        return Verdict::Drop("non-ULA source");
    }
    Verdict::Forward(IpAddr::V6(src))
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

/// The v6 twin of [`is_private_client_source`]: only ULA space (fc00::/7) is
/// an acceptable inner v6 source. Global unicast is refused for the same
/// hijack reason as public v4; link-local, multicast, `::`, `::1` and v4-mapped
/// addresses have no business sourcing tunneled traffic and fall outside the
/// /7 as well.
fn is_ula_client_source(ip: Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xFE) == 0xFC
}

/// Read the 16-byte address at `off` (8 = src, 24 = dst in the fixed header).
fn ipv6_at(pkt: &[u8], off: usize) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[off..off + 16]).unwrap())
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
    let mut seen: HashSet<IpAddr> = HashSet::new();
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
                    if !tun_frame_to_client(&buf[..n]) {
                        trace!("os-routing: dropping link-scope/non-IP frame from TUN ({} bytes)", n);
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

/// Should a frame read from the TUN be forwarded to the client? IPv4 always
/// (classify polices the other direction). The kernel auto-assigns an IPv6
/// link-local to the TUN and emits Router Solicitation / NS / MLD / DAD
/// chatter — all of it sourced from or aimed at fe80::/10 or ff00::/8 — which
/// must keep dying here instead of leaking (and the link-local with it) to the
/// peer; real tunneled v6 (global <-> ULA) passes. Non-IP frames are dropped.
fn tun_frame_to_client(frame: &[u8]) -> bool {
    match frame.first().map(|b| b >> 4) {
        Some(4) => true,
        Some(6) if frame.len() >= 40 => {
            !is_v6_link_scope(ipv6_at(frame, 8)) && !is_v6_link_scope(ipv6_at(frame, 24))
        }
        _ => false,
    }
}

/// fe80::/10 or ff00::/8 — addresses that only have meaning on the local link.
fn is_v6_link_scope(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[0] == 0xFF || (o[0] == 0xFE && (o[1] & 0xC0) == 0x80)
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

/// Craft an ICMPv6 echo reply for an echo request, or `None` if `pkt` isn't a
/// plain ICMPv6 echo request. Extension headers (including fragments — v6
/// fragmentation is one) make next-header != 58 and are rejected, mirroring
/// the v4 refusal to answer fragments.
fn icmpv6_echo_reply_for(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 40 || pkt[6] != 58 {
        return None; // truncated, or not plain ICMPv6
    }
    let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    if payload_len < 8 || 40 + payload_len > pkt.len() {
        return None;
    }
    if pkt[40] != 128 || pkt[41] != 0 {
        return None; // not an echo request
    }

    let mut r = pkt[..40 + payload_len].to_vec();
    for i in 0..16 {
        r.swap(8 + i, 24 + i); // swap src/dst
    }
    r[7] = 64; // fresh hop limit
    r[40] = 129; // type: echo reply (id/seq/payload preserved)
    r[42] = 0;
    r[43] = 0;
    // Unlike v4, the ICMPv6 checksum covers a pseudo-header with the (now
    // swapped) addresses and is mandatory — it must be recomputed in full,
    // not patched incrementally.
    let csum = icmpv6_checksum(&r);
    r[42..44].copy_from_slice(&csum.to_be_bytes());
    Some(r)
}

/// ICMPv6 checksum (RFC 4443 §2.3) of a full, extension-header-free IPv6
/// packet: the pseudo-header (src, dst, upper-layer length, next-header 58)
/// plus the ICMPv6 message. Returns 0 when the packet's stored checksum is
/// already correct (the usual verify-by-summing property).
fn icmpv6_checksum(pkt: &[u8]) -> u16 {
    let ulen = (pkt.len() - 40) as u32;
    let mut sum = checksum_add(0, &pkt[8..40]); // src + dst
    sum = checksum_add(sum, &ulen.to_be_bytes());
    sum = checksum_add(sum, &[0, 0, 0, 58]);
    sum = checksum_add(sum, &pkt[40..]);
    checksum_fold(sum)
}

/// RFC 1071 internet checksum.
fn inet_checksum(data: &[u8]) -> u16 {
    checksum_fold(checksum_add(0, data))
}

fn checksum_add(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [b] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*b, 0]));
    }
    sum
}

fn checksum_fold(mut sum: u32) -> u16 {
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

// ---------- Connection-log egress enrichment ----------

/// Build the connection log's egress resolver for OS-routing mode: the kernel
/// MASQUERADEs each flow, so the post-SNAT source port (what the destination
/// actually saw — the single most attribution-critical field) only exists in
/// the kernel's conntrack table. Called from the connlog writer thread, once
/// per flow, within ~1s of the first packet — when the conntrack entry is
/// freshest. We're already root here (`--os-routing` requires it).
pub fn conntrack_egress_lookup() -> spora_core::connlog::EgressLookup {
    Arc::new(conntrack_egress)
}

fn conntrack_egress(
    proto: u8,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
) -> Option<std::net::SocketAddr> {
    // Only port-carrying protocols have a meaningful egress port.
    if proto != 6 && proto != 17 {
        return None;
    }
    let table = std::fs::read_to_string("/proc/net/nf_conntrack").ok()?;
    table
        .lines()
        .find_map(|line| conntrack_line_egress(line, proto, src, dst))
}

/// Parse one `/proc/net/nf_conntrack` line; if its ORIGINAL direction matches
/// the inner flow `(src, dst)`, return the REPLY direction's destination —
/// the post-SNAT address/port the remote server replies to, i.e. our egress.
///
/// Line shape (field positions of the state token vary by protocol, so we
/// collect the `src=/dst=/sport=/dport=` pairs positionally instead):
/// `ipv4 2 tcp 6 431999 ESTABLISHED src=A dst=B sport=a dport=b src=B dst=NAT sport=b dport=nat ...`
fn conntrack_line_egress(
    line: &str,
    proto: u8,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
) -> Option<std::net::SocketAddr> {
    let mut tokens = line.split_whitespace();
    let _l3_name = tokens.next()?;
    let _l3_num = tokens.next()?;
    let _l4_name = tokens.next()?;
    let l4_num: u8 = tokens.next()?.parse().ok()?;
    if l4_num != proto {
        return None;
    }
    let mut srcs: Vec<IpAddr> = Vec::with_capacity(2);
    let mut dsts: Vec<IpAddr> = Vec::with_capacity(2);
    let mut sports: Vec<u16> = Vec::with_capacity(2);
    let mut dports: Vec<u16> = Vec::with_capacity(2);
    for tok in tokens {
        if let Some(v) = tok.strip_prefix("src=") {
            srcs.push(v.parse().ok()?);
        } else if let Some(v) = tok.strip_prefix("dst=") {
            dsts.push(v.parse().ok()?);
        } else if let Some(v) = tok.strip_prefix("sport=") {
            sports.push(v.parse().ok()?);
        } else if let Some(v) = tok.strip_prefix("dport=") {
            dports.push(v.parse().ok()?);
        }
    }
    if srcs.len() < 2 || dsts.len() < 2 || sports.len() < 2 || dports.len() < 2 {
        return None;
    }
    let orig_matches = srcs[0] == src.ip()
        && sports[0] == src.port()
        && dsts[0] == dst.ip()
        && dports[0] == dst.port();
    if !orig_matches {
        return None;
    }
    Some(std::net::SocketAddr::new(dsts[1], dports[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{Sink, Stream};

    #[test]
    fn conntrack_line_yields_post_snat_egress() {
        let tcp_line = "ipv4     2 tcp      6 431999 ESTABLISHED src=10.213.0.2 dst=93.184.216.34 sport=50000 dport=443 src=93.184.216.34 dst=198.51.100.5 sport=443 dport=41200 [ASSURED] mark=0 zone=0 use=2";
        let src: std::net::SocketAddr = "10.213.0.2:50000".parse().unwrap();
        let dst: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert_eq!(
            conntrack_line_egress(tcp_line, 6, src, dst),
            Some("198.51.100.5:41200".parse().unwrap())
        );
        // Wrong protocol, port, or tuple → no match.
        assert_eq!(conntrack_line_egress(tcp_line, 17, src, dst), None);
        let other: std::net::SocketAddr = "10.213.0.2:50001".parse().unwrap();
        assert_eq!(conntrack_line_egress(tcp_line, 6, other, dst), None);

        // UDP lines carry no state token; field collection is positional.
        let udp_line = "ipv4     2 udp      17 29 src=10.213.0.2 dst=8.8.8.8 sport=40000 dport=53 src=8.8.8.8 dst=198.51.100.5 sport=53 dport=44444 mark=0 use=2";
        let usrc: std::net::SocketAddr = "10.213.0.2:40000".parse().unwrap();
        let udst: std::net::SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert_eq!(
            conntrack_line_egress(udp_line, 17, usrc, udst),
            Some("198.51.100.5:44444".parse().unwrap())
        );

        // With nf_conntrack_acct on, packets=/bytes= fields sit between the
        // tuples (after each one), and [UNREPLIED] sits mid-line: positional
        // collection of src=/dst=/sport=/dport= must survive both.
        let acct_line = "ipv4     2 tcp      6 102 SYN_SENT src=10.213.0.2 dst=93.184.216.34 sport=50000 dport=443 packets=1 bytes=60 [UNREPLIED] src=93.184.216.34 dst=198.51.100.5 sport=443 dport=41200 packets=0 bytes=0 mark=0 use=1";
        assert_eq!(
            conntrack_line_egress(acct_line, 6, src, dst),
            Some("198.51.100.5:41200".parse().unwrap())
        );

        // Unparseable / truncated lines are skipped, not errors.
        assert_eq!(conntrack_line_egress("ipv4 2 tcp 6", 6, src, dst), None);
        assert_eq!(conntrack_line_egress("", 6, src, dst), None);
    }
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

    fn v6(s: &str) -> [u8; 16] {
        s.parse::<Ipv6Addr>().unwrap().octets()
    }

    fn ipv6_udp(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv6(v6(src), v6(dst), 64)
            .udp(40000, 53)
            .write(&mut pkt, payload)
            .unwrap();
        pkt
    }

    fn icmpv6_echo_request(src: &str, dst: &str, id: u16, seq: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        etherparse::PacketBuilder::ipv6(v6(src), v6(dst), 64)
            .icmpv6_echo_request(id, seq)
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
    fn icmpv6_checksum_matches_etherparse() {
        // etherparse computes the mandatory pseudo-header checksum when
        // building; summing a packet whose stored checksum is correct yields 0.
        let req = icmpv6_echo_request("fd00::1", "fd00::2", 0x5350, 7);
        assert_eq!(icmpv6_checksum(&req), 0);
        // Corrupting any message byte must break verification.
        let mut bad = req;
        bad[44] ^= 1;
        assert_ne!(icmpv6_checksum(&bad), 0);
    }

    #[test]
    fn icmpv6_echo_reply_is_valid_and_mirrored() {
        let req = icmpv6_echo_request("fd00::1", "fd00::2", 0x5350, 7);
        let reply = icmpv6_echo_reply_for(&req).expect("should answer echo request");

        // Addresses swapped.
        assert_eq!(&reply[8..24], &v6("fd00::2"));
        assert_eq!(&reply[24..40], &v6("fd00::1"));
        // Type 129 (echo reply), code 0, id/seq/payload preserved.
        assert_eq!(reply[40], 129);
        assert_eq!(reply[41], 0);
        assert_eq!(&reply[44..48], &req[44..48]);
        assert_eq!(&reply[48..], &req[48..]);
        // The recomputed checksum verifies (the function itself is validated
        // against etherparse in icmpv6_checksum_matches_etherparse).
        assert_eq!(icmpv6_checksum(&reply), 0);
    }

    #[test]
    fn icmpv6_echo_reply_ignores_non_echo() {
        // UDP to a ULA address is not answered.
        assert!(icmpv6_echo_reply_for(&ipv6_udp("fd00::1", "fd00::2", b"x")).is_none());
        // Truncated packet.
        assert!(icmpv6_echo_reply_for(&[0x60, 0x00]).is_none());
        // An extension header in the way (next-header != 58) is not parsed.
        let mut req = icmpv6_echo_request("fd00::1", "fd00::2", 1, 1);
        req[6] = 0; // hop-by-hop
        assert!(icmpv6_echo_reply_for(&req).is_none());
        // Payload length lying past the end of the packet.
        let mut req = icmpv6_echo_request("fd00::1", "fd00::2", 1, 1);
        req[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(icmpv6_echo_reply_for(&req).is_none());
    }

    #[test]
    fn classify_verdicts() {
        // Public destination → forwarded, source learned.
        match classify(&ipv4_udp([10, 0, 85, 1], [8, 8, 8, 8], b"x")) {
            Verdict::Forward(src) => assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 85, 1))),
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
        // Truncated IPv6 / non-IP → dropped.
        assert!(matches!(classify(&[0x60, 0, 0, 0]), Verdict::Drop(_)));
        assert!(matches!(classify(&[]), Verdict::Drop(_)));
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
    fn classify_v6_verdicts() {
        // ULA source to a global destination → forwarded, source learned.
        match classify(&ipv6_udp("fd00:5350::2", "2001:4860:4860::8888", b"x")) {
            Verdict::Forward(src) => {
                assert_eq!(src, "fd00:5350::2".parse::<IpAddr>().unwrap())
            }
            _ => panic!("expected Forward"),
        }
        // ULA destination → blocked (is_local_address covers fc00::/7).
        assert!(matches!(
            classify(&ipv6_udp("fd00:5350::2", "fd12::1", b"x")),
            Verdict::Drop(_)
        ));
        // Keepalive ping to a ULA destination → answered locally.
        assert!(matches!(
            classify(&icmpv6_echo_request("fd00:5350::2", "fd00:5350::1", 0x5350, 1)),
            Verdict::ReplyEcho(_)
        ));
        // Ping to a global destination → forwarded like normal traffic.
        assert!(matches!(
            classify(&icmpv6_echo_request("fd00:5350::2", "2606:4700::1111", 1, 1)),
            Verdict::Forward(_)
        ));
        // Public (global) SOURCE → dropped: it would otherwise earn a /128
        // hijack route for the sharer's own egress to that address.
        assert!(matches!(
            classify(&ipv6_udp("2001:db8::1", "2606:4700::1111", b"x")),
            Verdict::Drop(_)
        ));
        // Link-local and v4-mapped sources → dropped.
        assert!(matches!(
            classify(&ipv6_udp("fe80::1", "2606:4700::1111", b"x")),
            Verdict::Drop(_)
        ));
        assert!(matches!(
            classify(&ipv6_udp("::ffff:10.0.0.1", "2606:4700::1111", b"x")),
            Verdict::Drop(_)
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
    fn ula_client_source_ranges() {
        for ip in ["fc00::1", "fd00::1", "fd00:5350::2", "fdff:ffff::1"] {
            assert!(is_ula_client_source(ip.parse().unwrap()), "{} should be allowed", ip);
        }
        for ip in ["2001:db8::1", "2606:4700::1111", "fe80::1", "febf::1", "ff02::1",
                   "::", "::1", "::ffff:10.0.0.1", "fbff::1", "fe00::1", "64:ff9b::1"] {
            assert!(!is_ula_client_source(ip.parse().unwrap()), "{} should be refused", ip);
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
        let mut peers: HashMap<IpAddr, Instant> = HashMap::new();
        let t0 = Instant::now();
        let ip = |a: u8| IpAddr::V4(Ipv4Addr::new(10, 0, 0, a));

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

        // The cap is shared across families: a v6 peer evicts a v4 one.
        let ula: IpAddr = "fd00:5350::2".parse().unwrap();
        assert_eq!(
            reserve_peer_slot(&mut peers, ula, t0 + Duration::from_secs(5), 3),
            Some(ip(3))
        );
        assert!(peers.contains_key(&ula));
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn route_table_conflict_detection() {
        let tun = "tun0";
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
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

    #[test]
    fn route_table_conflict_detection_v6() {
        let tun = "tun0";
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let table = "\
            fd00:5350::/64 dev tun0 proto kernel metric 256 pref medium\n\
            fdaa:1::/64 dev wg0 proto kernel metric 256 pref medium\n\
            fdbb::/48 via fdaa:1::1 dev eth0 metric 1024 pref medium\n\
            2001:db8:1::/64 dev eth0 proto ra metric 100 pref medium\n\
            fe80::/64 dev eth0 proto kernel metric 256 pref medium\n\
            default via fe80::1 dev eth0 proto ra metric 100 pref medium\n";

        // Directly-connected ULA subnet on another device → conflict.
        assert!(route_table_conflicts(table, ip("fdaa:1::7"), tun));
        // ULA subnet reached via a gateway → conflict.
        assert!(route_table_conflicts(table, ip("fdbb::9"), tun));
        // Covered only by our own TUN route → not a conflict.
        assert!(!route_table_conflicts(table, ip("fd00:5350::9"), tun));
        // Covered only by the default route → not a conflict.
        assert!(!route_table_conflicts(table, ip("fdcc::1"), tun));
        // The kernel's per-interface fe80::/64 is skipped outright (a client
        // source can't be link-local anyway, but don't let it read as a hit).
        assert!(!route_table_conflicts("fe80::/64 dev eth0 proto kernel\n", ip("fe80::5"), tun));
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
        learned: Arc<Mutex<Vec<IpAddr>>>,
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

        let learned: Arc<Mutex<Vec<IpAddr>>> = Arc::new(Mutex::new(Vec::new()));
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
        assert_eq!(
            *h.learned.lock().unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 85, 1))]
        );

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
    async fn pump_carries_v6_and_filters_link_chatter() {
        let mut h = start_pump();

        // 1. A public v6 SOURCE is refused: not forwarded, not learned.
        h.to_transport
            .send(ipv6_udp("2001:db8::bad", "2606:4700::1111", b"hijack"))
            .unwrap();

        // 2. ULA-sourced v6 to a global dst is forwarded and the source learned.
        let pkt = ipv6_udp("fd00:5350::2", "2606:4700::1111", b"hello");
        h.to_transport.send(pkt.clone()).unwrap();
        assert_eq!(recv_with_timeout(&mut h.from_dev).await.unwrap(), pkt);
        assert_eq!(
            *h.learned.lock().unwrap(),
            vec!["fd00:5350::2".parse::<IpAddr>().unwrap()],
            "only the ULA source may be learned"
        );

        // 3. v6 keepalive ping to the (blocked) ULA peer address is answered
        //    locally with a valid echo reply.
        h.to_transport
            .send(icmpv6_echo_request("fd00:5350::2", "fd00:5350::1", 0x5350, 3))
            .unwrap();
        let reply = recv_with_timeout(&mut h.from_transport).await.unwrap();
        assert_eq!(reply[40], 129, "expected ICMPv6 echo reply type");
        assert_eq!(&reply[24..40], &v6("fd00:5350::2"), "reply goes back to the pinger");

        // 4. Device-side link-scope chatter (RS/NS/MLD-shaped addressing) is
        //    filtered; a global-addressed v6 frame passes. Ordering of the two
        //    proves the first was dropped.
        h.to_dev.send(ipv6_udp("fe80::1", "ff02::2", b"rs")).unwrap();
        let v6_reply = ipv6_udp("2606:4700::1111", "fd00:5350::2", b"resp");
        h.to_dev.send(v6_reply.clone()).unwrap();
        assert_eq!(
            recv_with_timeout(&mut h.from_transport).await.unwrap(),
            v6_reply
        );

        h.cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), h.pump_task)
            .await
            .expect("pump should end on cancel")
            .unwrap();
    }

    #[test]
    fn tun_frames_filtered_by_scope() {
        // IPv4 always passes; non-IP and empty frames never do.
        assert!(tun_frame_to_client(&ipv4_udp([8, 8, 8, 8], [10, 0, 85, 1], b"x")));
        assert!(!tun_frame_to_client(&[]));
        assert!(!tun_frame_to_client(&[0x00, 0x01]));
        assert!(!tun_frame_to_client(&[0x60, 0, 0, 0])); // truncated v6
        // Global/ULA v6 passes.
        assert!(tun_frame_to_client(&ipv6_udp("2606:4700::1111", "fd00:5350::2", b"x")));
        // Anything link-local or multicast on either side is chatter.
        assert!(!tun_frame_to_client(&ipv6_udp("fe80::1", "fd00:5350::2", b"x")));
        assert!(!tun_frame_to_client(&ipv6_udp("fd00:5350::1", "ff02::1", b"x")));
        assert!(!tun_frame_to_client(&ipv6_udp("fe80::1", "ff02::2", b"x")));
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
        let v4 = "10.213.0.1/24";
        let v6_def = "fd00:5350::1/64";
        let opts = Options::parse(v4, v6_def, 1280, true).unwrap();
        assert_eq!(opts.addr, Ipv4Addr::new(10, 213, 0, 1));
        assert_eq!(opts.prefix_len, 24);
        assert_eq!(opts.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(opts.addr6, "fd00:5350::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(opts.prefix6_len, 64);
        assert!(Options::parse("10.213.0.1", v6_def, 1280, true).is_err());
        assert!(Options::parse("10.213.0.1/31", v6_def, 1280, true).is_err());
        assert!(Options::parse("not-an-ip/24", v6_def, 1280, true).is_err());
        assert!(Options::parse(v4, v6_def, 100, true).is_err());
        // v6: must be CIDR, parseable, prefix 16..=126, and inside fc00::/7.
        assert!(Options::parse(v4, "fd00:5350::1", 1280, true).is_err());
        assert!(Options::parse(v4, "not-an-ip/64", 1280, true).is_err());
        assert!(Options::parse(v4, "fd00:5350::1/8", 1280, true).is_err());
        assert!(Options::parse(v4, "fd00:5350::1/127", 1280, true).is_err());
        assert!(Options::parse(v4, "2001:db8::1/64", 1280, true).is_err(), "global refused");
        assert!(Options::parse(v4, "fe80::1/64", 1280, true).is_err(), "link-local refused");
    }
}
