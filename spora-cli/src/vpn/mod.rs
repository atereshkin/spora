//! Client-side VPN integration for `spora use`: bring up the TUN, give it an
//! address and an MTU, point the host's traffic at it, swap the resolver, keep
//! the tunnel's own outer sockets out of the tunnel, and undo all of it on exit.
//!
//! The composition mirrors the Android client (the functional reference,
//! `ConnectVpnService.kt`): a TUN with an address but no routes while the
//! relay session is dialed (so the dial and the STUN queries use the normal
//! network), then routes + DNS once the session is up, and an MTU that follows
//! spora-core's `mtu_callback` (the carrier's PMTUD-converged datagram budget).
//!
//! Per platform the mechanics differ only in how each step is expressed:
//!
//! | step                | Linux (`linux.rs`)                       | macOS (`macos.rs`)              | Windows (`windows.rs`)              |
//! |---------------------|------------------------------------------|---------------------------------|-------------------------------------|
//! | TUN                 | `/dev/net/tun` via tokio-tun             | `utun` control socket           | wintun adapter                      |
//! | address / MTU       | ioctl + `ip`                             | `ifconfig`                      | IP Helper (`CreateUnicastIpAddressEntry`, `SetIpInterfaceEntry`) |
//! | routes              | policy routing: own table + fwmark rules | `route add` `0/1`+`128/1`       | `CreateIpForwardEntry2` `0/1`+`128/1` |
//! | outer-socket bypass | `SO_MARK` (rule: marked → main table)    | `IP_BOUND_IF` to the uplink     | `IP_UNICAST_IF` to the uplink       |
//! | DNS                 | resolvectl / resolvconf / resolv.conf    | `networksetup -setdnsservers`   | `SetInterfaceDnsSettings`           |
//!
//! The outer-socket bypass is the piece that makes a full tunnel sound: every
//! socket spora-core opens toward the relay, the STUN servers, or the punched
//! peer goes through `Config.protector`, and the protector must keep it off the
//! tunnel *regardless of the peer's address* — the hole-punched peer is not
//! known when routes are installed, so address-based exclusions cannot cover
//! it. Linux marks the socket and routes marked traffic through the main table
//! (the wg-quick model); macOS and Windows bind the socket to the physical
//! uplink interface, re-detected on every reconnect.
//!
//! Everything this module changes on the host is recorded on an undo stack and
//! replayed in reverse by [`Session::shutdown`] (also from `Drop`, so an error
//! return or a panic still cleans up). What cannot be undone after a crash
//! (a replaced `resolv.conf`, macOS per-service DNS) is written with a marker
//! or a state file so the *next* start restores it first.
//!
//! `spora use --tun-name <name>` does not come through here at all: that is the
//! Linux-only attach mode (the caller owns the interface's address, MTU,
//! routes and cleanup), used by the in-tree `cli_vpn` lab test and left
//! untouched. The field lab drives the ordinary VPN mode through this module
//! (`--route <ip>/32` host routes plus `--no-dns`).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

/// `resolv.conf` handling (Linux's last-resort resolver tier).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod dns;
/// Parsers for host-tool output. Each has one platform consumer; all are
/// compiled and tested everywhere.
#[allow(dead_code)]
pub mod parsers;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod imp;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod imp;
#[cfg(windows)]
#[path = "windows.rs"]
mod imp;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[path = "unsupported.rs"]
mod imp;

/// Default client address inside the tunnel (matches the Android client).
/// Must be RFC1918/CGNAT: a sharer running `--os-routing` refuses other
/// client sources (see `os_route::is_private_client_source`).
pub const DEFAULT_TUN_ADDR: &str = "10.11.0.2/24";
/// Default client IPv6 address inside the tunnel: ULA, as `--os-routing`
/// sharers require for v6 client sources.
pub const DEFAULT_TUN_ADDR6: &str = "fd00:5350::2/64";
/// Default resolver pushed into the tunnel: the sharer's DNS forwarder at
/// its synthetic address (`spora_core::dns::PROXY_ADDR`), which answers
/// with the sharer's own resolvers. Any other resolver must be public: a
/// sharer drops inner traffic to private destinations.
pub const DEFAULT_DNS: [&str; 1] = ["100.64.0.53"];
/// TUN MTU before spora-core reports the path's budget (the Android default).
pub const INITIAL_MTU: u16 = 1280;
/// Smallest MTU the TUN is ever set to (the IPv4 minimum reassembly size).
pub const MIN_MTU: u16 = 576;
/// Largest MTU accepted for `--mtu`: the pump reads the TUN with a 1500-byte
/// buffer (`spora_core::tun_util::start`), and no carrier's budget exceeds it.
pub const MAX_MTU: u16 = 1500;
/// IPv6 requires every link to carry 1280-byte packets; an interface MTU below
/// that disables IPv6 on it (Linux drops the addresses). With v6 inside the
/// tunnel the TUN MTU is held at this floor and the tunnel layer fragments
/// what the carrier cannot carry whole.
pub const IPV6_MIN_MTU: u16 = 1280;

/// A routing prefix from the command line (`--route`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    pub const V4_DEFAULT: Prefix = Prefix {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        len: 0,
    };
    pub const V6_DEFAULT: Prefix = Prefix {
        addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        len: 0,
    };

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub fn is_default(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

/// Parse `addr/len`, requiring the host bits to be zero (so a typo like
/// `10.1.2.3/8` is rejected rather than silently meaning `10.0.0.0/8`).
pub fn parse_prefix(s: &str) -> Result<Prefix, String> {
    let (addr, len) = split_cidr(s)?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(format!("'{s}': prefix length {len} exceeds /{max}"));
    }
    let p = Prefix { addr, len };
    if network_of(p) != addr {
        return Err(format!(
            "'{s}' has host bits set; did you mean {}?",
            Prefix {
                addr: network_of(p),
                len
            }
        ));
    }
    Ok(p)
}

/// Parse an interface address in CIDR form (`addr/len`), where the host part
/// is the interface's own address and must not be the network or (v4)
/// broadcast address.
pub fn parse_interface_addr(s: &str) -> Result<(IpAddr, u8), String> {
    let (addr, len) = split_cidr(s)?;
    match addr {
        IpAddr::V4(a) => {
            if !(8..=30).contains(&len) {
                return Err(format!("'{s}': IPv4 prefix length must be 8..=30"));
            }
            let net = network_of(Prefix { addr, len });
            let bcast = u32::from(a) | (u32::MAX >> len);
            if net == addr || u32::from(a) == bcast {
                return Err(format!(
                    "'{s}' is the network or broadcast address, not a host address"
                ));
            }
        }
        IpAddr::V6(_) => {
            if !(16..=126).contains(&len) {
                return Err(format!("'{s}': IPv6 prefix length must be 16..=126"));
            }
            if network_of(Prefix { addr, len }) == addr {
                return Err(format!("'{s}' is the subnet address, not a host address"));
            }
        }
    }
    Ok((addr, len))
}

fn split_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (a, l) = s
        .split_once('/')
        .ok_or_else(|| format!("'{s}' is not in addr/prefix form"))?;
    let addr: IpAddr = a
        .parse()
        .map_err(|e| format!("'{s}': bad address '{a}': {e}"))?;
    let len: u8 = l
        .parse()
        .map_err(|_| format!("'{s}': bad prefix length '{l}'"))?;
    Ok((addr, len))
}

/// The network address of `p` (its address with the host bits cleared).
pub fn network_of(p: Prefix) -> IpAddr {
    match p.addr {
        IpAddr::V4(a) => {
            let mask = if p.len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(p.len))
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = if p.len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(p.len))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    }
}

/// Whether `ip` falls inside `p` (false across families).
pub fn prefix_contains(p: Prefix, ip: IpAddr) -> bool {
    if p.addr.is_ipv4() != ip.is_ipv4() {
        return false;
    }
    network_of(Prefix {
        addr: ip,
        len: p.len,
    }) == network_of(p)
}

/// Dotted netmask for a v4 prefix length.
#[cfg_attr(windows, allow(dead_code))]
pub fn v4_netmask(len: u8) -> Ipv4Addr {
    if len == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - u32::from(len)))
    }
}

/// RFC1918 or CGNAT (100.64/10): the only client sources an `--os-routing`
/// sharer accepts (`os_route::is_private_client_source`).
pub fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || (o[0] == 100 && (64..=127).contains(&o[1]))
}

/// ULA (fc00::/7): the only client v6 source an `--os-routing` sharer accepts.
pub fn is_ula(ip: Ipv6Addr) -> bool {
    ip.octets()[0] & 0xfe == 0xfc
}

/// Whether `ip` is a destination a sharer would refuse to carry traffic to
/// (private/link-local/loopback); used to warn about an unreachable resolver.
pub fn is_private_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            is_private_v4(a) || a.is_loopback() || a.is_link_local() || a.is_unspecified()
        }
        IpAddr::V6(a) => {
            is_ula(a)
                || a.is_loopback()
                || a.is_unspecified()
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// What the tunnel carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteSet {
    /// Everything: the IPv4 default route and, when the TUN has a v6 address,
    /// the IPv6 default route.
    Default,
    /// Only these prefixes (split tunnel). Prefixes of a family the TUN has no
    /// address for are rejected at parse time.
    Prefixes(Vec<Prefix>),
    /// Nothing: the TUN exists with its address and MTU, and the caller routes
    /// into it. Implies no resolver change.
    None,
}

/// How the TUN MTU is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtuPolicy {
    /// Start at [`INITIAL_MTU`], then follow spora-core's reports (the path's
    /// PMTUD-converged datagram budget, re-reported after a direct upgrade).
    Auto,
    /// Pin the TUN MTU; reports are logged but not applied.
    Fixed(u16),
}

/// Everything `spora use` decided before touching the host.
#[derive(Clone, Debug)]
pub struct Options {
    pub tun_addr: Ipv4Addr,
    pub tun_prefix: u8,
    /// `None` disables IPv6 inside the tunnel entirely (no address, no v6
    /// routes). NOTE: v6 traffic then bypasses the tunnel on a v6-capable host.
    pub tun_addr6: Option<(Ipv6Addr, u8)>,
    pub routes: RouteSet,
    /// Resolvers to push; empty means leave the host's resolver alone.
    pub dns: Vec<IpAddr>,
    pub mtu: MtuPolicy,
}

impl Options {
    /// Validate the raw command-line values into [`Options`]. `routes` is the
    /// list of `--route` prefixes (empty = full tunnel) unless `no_routes`.
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        tun_addr: &str,
        tun_addr6: &str,
        no_ipv6: bool,
        routes: &[String],
        no_routes: bool,
        dns: &[String],
        no_dns: bool,
        mtu: Option<u16>,
    ) -> Result<Options, String> {
        let (v4, v4len) = parse_interface_addr(tun_addr).map_err(|e| format!("--tun-addr: {e}"))?;
        let IpAddr::V4(tun_v4) = v4 else {
            return Err("--tun-addr: must be an IPv4 address".into());
        };
        if !is_private_v4(tun_v4) {
            return Err(format!(
                "--tun-addr: {tun_v4} is not a private (RFC1918/CGNAT) address; sharers only accept private client sources"
            ));
        }
        let tun_addr6 = if no_ipv6 {
            None
        } else {
            let (v6, v6len) =
                parse_interface_addr(tun_addr6).map_err(|e| format!("--tun-addr6: {e}"))?;
            let IpAddr::V6(a6) = v6 else {
                return Err("--tun-addr6: must be an IPv6 address".into());
            };
            if !is_ula(a6) {
                return Err(format!(
                    "--tun-addr6: {a6} is not a ULA (fc00::/7); sharers only accept ULA client sources"
                ));
            }
            Some((a6, v6len))
        };
        let routes = if no_routes {
            RouteSet::None
        } else if routes.is_empty() {
            RouteSet::Default
        } else {
            let mut out = Vec::with_capacity(routes.len());
            for r in routes {
                let p = parse_prefix(r).map_err(|e| format!("--route: {e}"))?;
                if !p.is_ipv4() && tun_addr6.is_none() {
                    return Err(format!(
                        "--route {p}: IPv6 route with --no-ipv6 (the tunnel carries no IPv6)"
                    ));
                }
                if !out.contains(&p) {
                    out.push(p);
                }
            }
            RouteSet::Prefixes(out)
        };
        let dns = if no_dns || routes == RouteSet::None {
            Vec::new()
        } else if dns.is_empty() {
            DEFAULT_DNS
                .iter()
                .map(|s| s.parse().expect("builtin resolver literal"))
                .collect()
        } else {
            let mut out = Vec::with_capacity(dns.len());
            for d in dns {
                let ip: IpAddr = d.parse().map_err(|e| format!("--dns: '{d}': {e}"))?;
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
            out
        };
        let mtu = match mtu {
            None => MtuPolicy::Auto,
            Some(m) if (MIN_MTU..=MAX_MTU).contains(&m) => MtuPolicy::Fixed(m),
            Some(m) => {
                return Err(format!("--mtu: {m} is outside {MIN_MTU}..={MAX_MTU}"));
            }
        };
        if let MtuPolicy::Fixed(m) = mtu
            && m < IPV6_MIN_MTU
            && tun_addr6.is_some()
        {
            return Err(format!(
                "--mtu: {m} is below IPv6's minimum of {IPV6_MIN_MTU} and the tunnel carries IPv6; pass --no-ipv6 for a v4-only tunnel at this MTU"
            ));
        }
        for ip in &dns {
            if ip.is_ipv6() && tun_addr6.is_none() {
                log::warn!(
                    "resolver {ip} is IPv6 but the tunnel carries no IPv6 (--no-ipv6): its queries will bypass the tunnel"
                );
            }
        }
        Ok(Options {
            tun_addr: tun_v4,
            tun_prefix: v4len,
            tun_addr6,
            routes,
            dns,
            mtu,
        })
    }

    /// The "other end" address on the point-to-point link (what macOS calls
    /// the destination and Android the `tunnelRemoteAddress`): the first host
    /// of the subnet, or the second when the TUN address is the first.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn peer_v4(&self) -> Ipv4Addr {
        let IpAddr::V4(net) = network_of(Prefix {
            addr: IpAddr::V4(self.tun_addr),
            len: self.tun_prefix,
        }) else {
            unreachable!("v4 in, v4 out");
        };
        let first = Ipv4Addr::from(u32::from(net) + 1);
        if first == self.tun_addr {
            Ipv4Addr::from(u32::from(net) + 2)
        } else {
            first
        }
    }

    pub fn ipv6_enabled(&self) -> bool {
        self.tun_addr6.is_some()
    }

    /// The initial TUN MTU: the pinned value, or the conservative default
    /// until spora-core reports the path's budget.
    pub fn initial_mtu(&self) -> u16 {
        match self.mtu {
            MtuPolicy::Auto => INITIAL_MTU,
            MtuPolicy::Fixed(m) => m,
        }
    }

    /// The concrete prefixes to route into the tunnel, per family.
    pub fn route_prefixes(&self) -> Vec<Prefix> {
        match &self.routes {
            RouteSet::None => Vec::new(),
            RouteSet::Default => {
                let mut v = vec![Prefix::V4_DEFAULT];
                if self.ipv6_enabled() {
                    v.push(Prefix::V6_DEFAULT);
                }
                v
            }
            RouteSet::Prefixes(p) => p.clone(),
        }
    }

    /// Host routes for the resolvers in split-tunnel mode: DNS is the one
    /// kind of traffic `--dns` promises to move into the tunnel, so the
    /// resolvers themselves are routed there even when the split prefixes do
    /// not cover them (otherwise every query would leave in cleartext over
    /// the uplink). Empty unless `RouteSet::Prefixes`.
    pub fn resolver_routes(&self) -> Vec<Prefix> {
        let RouteSet::Prefixes(prefixes) = &self.routes else {
            return Vec::new();
        };
        self.dns
            .iter()
            .filter(|ip| ip.is_ipv4() || self.ipv6_enabled())
            .map(|ip| Prefix {
                addr: *ip,
                len: if ip.is_ipv4() { 32 } else { 128 },
            })
            .filter(|host| !prefixes.iter().any(|p| prefix_contains(*p, host.addr)))
            .collect()
    }

    /// Resolvers that the sharer would never answer (private destinations,
    /// other than its DNS forwarder's own synthetic address) — a
    /// misconfiguration worth a loud warning, not an error (a split tunnel
    /// may well reach them locally).
    pub fn unreachable_resolvers(&self) -> Vec<IpAddr> {
        if self.routes != RouteSet::Default {
            return Vec::new();
        }
        self.dns
            .iter()
            .copied()
            .filter(|ip| {
                is_private_destination(*ip) && *ip != IpAddr::V4(spora_core::dns::PROXY_ADDR)
            })
            .collect()
    }
}

/// Decide the TUN MTU for a budget spora-core reported. `Fixed` pins it;
/// `Auto` follows the report, floored at [`MIN_MTU`] and — when the TUN
/// carries IPv6 — at [`IPV6_MIN_MTU`] (the tunnel layer fragments v6 packets
/// the carrier cannot fit). Returns `None` when nothing should change.
pub fn mtu_for_report(policy: MtuPolicy, ipv6: bool, current: u16, reported: u16) -> Option<u16> {
    let want = match policy {
        MtuPolicy::Fixed(_) => return None,
        MtuPolicy::Auto => {
            let floor = if ipv6 { IPV6_MIN_MTU } else { MIN_MTU };
            reported.clamp(floor, MAX_MTU)
        }
    };
    (want != current).then_some(want)
}

// ---------------------------------------------------------------------------
// host-side bookkeeping shared by the backends

/// One reversible change to the host, replayed in reverse on shutdown.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) enum Undo {
    /// Run this command line (program + args).
    Cmd(Vec<String>),
    /// Arbitrary cleanup (platform API calls).
    Fn(Box<dyn FnOnce() + Send>),
}

/// The undo stack, plus the "already shutting down" latch that makes
/// [`Session::shutdown`] idempotent.
#[derive(Default)]
pub(crate) struct UndoStack {
    items: Vec<Undo>,
    done: bool,
}

impl UndoStack {
    pub(crate) fn push(&mut self, u: Undo) {
        self.items.push(u);
    }

    /// Replay in reverse. Each step is best-effort: a failed undo is logged
    /// and the rest still runs — a half-cleaned host is worse than a warning.
    pub(crate) fn unwind(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        while let Some(u) = self.items.pop() {
            match u {
                Undo::Cmd(line) => {
                    if let Some((prog, args)) = line.split_first() {
                        run_cmd(prog, args);
                    }
                }
                Undo::Fn(f) => f(),
            }
        }
    }
}

/// The host integration for one `spora use` run. Platform-specific state
/// lives in `imp::Backend`; this wrapper owns the undo stack and the policy
/// (MTU, routes, DNS) so the backends stay mechanical.
pub struct Session {
    opts: Options,
    backend: imp::Backend,
    undo: Mutex<UndoStack>,
    /// The MTU currently set on the TUN.
    mtu: std::sync::atomic::AtomicU16,
}

/// What [`Session::activate`] did, for the user-facing summary.
#[derive(Clone, Debug, Default)]
pub struct Activation {
    pub routes: Vec<Prefix>,
    pub dns: Vec<IpAddr>,
    /// How the resolver was changed (`"resolvectl"`, `"resolv.conf"`, ...),
    /// `None` when DNS was left alone.
    pub dns_method: Option<&'static str>,
}

impl Session {
    /// Create the TUN and give it its address(es) and initial MTU. No routes,
    /// no DNS: the relay dial that follows must use the normal network.
    pub fn setup(opts: Options) -> Result<Session, String> {
        let mut undo = UndoStack::default();
        let backend = imp::Backend::setup(&opts, &mut undo).map_err(|e| {
            undo.unwind();
            e
        })?;
        Ok(Session {
            mtu: std::sync::atomic::AtomicU16::new(opts.initial_mtu()),
            opts,
            backend,
            undo: Mutex::new(undo),
        })
    }

    pub fn options(&self) -> &Options {
        &self.opts
    }

    pub fn tun_name(&self) -> &str {
        self.backend.tun_name()
    }

    pub fn current_mtu(&self) -> u16 {
        self.mtu.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The `Config.protector` for this platform: keeps every outer socket
    /// spora-core opens off the tunnel.
    pub fn protector(&self) -> spora_core::SocketProtector {
        self.backend.protector()
    }

    /// Install the routes and the resolver. Call once the relay session is up.
    pub fn activate(&self) -> Result<Activation, String> {
        let mut undo = self.undo.lock().unwrap();
        let mut routes = self.opts.route_prefixes();
        if routes.is_empty() {
            return Ok(Activation::default());
        }
        routes.extend(self.opts.resolver_routes());
        self.backend
            .install_routes(&self.opts, &routes, &mut undo)?;
        let mut act = Activation {
            routes,
            ..Activation::default()
        };
        if !self.opts.dns.is_empty() {
            act.dns_method = Some(self.backend.set_dns(&self.opts, &mut undo)?);
            act.dns = self.opts.dns.clone();
        }
        Ok(act)
    }

    /// spora-core reported the path's datagram budget. Returns the MTU now
    /// set on the TUN if it changed.
    pub fn on_mtu_report(&self, reported: u16) -> Result<Option<u16>, String> {
        let current = self.current_mtu();
        let Some(want) = mtu_for_report(self.opts.mtu, self.opts.ipv6_enabled(), current, reported)
        else {
            return Ok(None);
        };
        self.backend.set_mtu(want)?;
        self.mtu.store(want, std::sync::atomic::Ordering::Relaxed);
        Ok(Some(want))
    }

    /// Re-detect the physical uplink (macOS/Windows bind outer sockets to it;
    /// it may have changed while the tunnel was reconnecting). No-op on Linux.
    pub fn refresh_uplink(&self) {
        self.backend.refresh_uplink();
    }

    /// A handle for the packet pump. The pump owns what it needs to read and
    /// write the device; the session keeps what cleanup needs.
    pub fn pump_handle(&self) -> Result<imp::PumpHandle, String> {
        self.backend.pump_handle()
    }

    /// Undo every host change, in reverse. Idempotent; also runs from `Drop`.
    pub fn shutdown(&self) {
        self.undo.lock().unwrap().unwind();
        self.backend.closed();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Pump packets between the tunnel transport and the TUN until either ends.
pub async fn run_pump(
    transport: spora_core::IpTransport,
    handle: imp::PumpHandle,
) -> std::io::Result<()> {
    imp::run_pump(transport, handle).await
}

/// Hold an exclusive advisory lock for the life of the session. The startup
/// sweep of a crashed run's leftovers (policy rules, resolver backups) is
/// only safe when no other instance is live — without this, a second
/// `spora use` would tear the first one's routing down as "stale". flock(2)
/// is released by the kernel on any death, so a crashed run never wedges the
/// lock and its leftovers become sweepable exactly when sweeping is safe.
#[cfg(unix)]
pub(crate) fn acquire_instance_lock(path: &str) -> Result<std::fs::File, String> {
    use std::os::unix::io::AsRawFd as _;
    let p = std::path::Path::new(path);
    let needs_root = |e: &std::io::Error| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            "; the VPN mode needs root: run `sudo spora use ...`, or attach to a pre-configured interface with --tun-name"
        } else {
            ""
        }
    };
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}{}", dir.display(), needs_root(&e)))?;
    }
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(p)
        .map_err(|e| format!("cannot open {path}: {e}{}", needs_root(&e)))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!(
            "another `spora use` instance appears to be running ({path} is locked); stop it first, or use --tun-name for a second, self-managed tunnel"
        ));
    }
    Ok(f)
}

/// Run a host command, logging it at debug level and its failure at warn
/// level. Returns whether it succeeded.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn run_cmd(program: &str, args: &[String]) -> bool {
    match run_cmd_output(program, args) {
        Ok(_) => true,
        Err(e) => {
            log::warn!("{e}");
            false
        }
    }
}

/// Run a host command and return its stdout, or a message naming the command
/// and carrying its stderr.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn run_cmd_output(program: &str, args: &[String]) -> Result<String, String> {
    log::debug!("# {} {}", program, args.join(" "));
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{program}: cannot run: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{} {} failed ({}): {}",
            program,
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn svec(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_parse_and_reject_host_bits() {
        assert_eq!(
            parse_prefix("10.0.0.0/8").unwrap(),
            Prefix {
                addr: "10.0.0.0".parse().unwrap(),
                len: 8
            }
        );
        assert_eq!(parse_prefix("0.0.0.0/0").unwrap(), Prefix::V4_DEFAULT);
        assert_eq!(parse_prefix("::/0").unwrap(), Prefix::V6_DEFAULT);
        assert!(
            parse_prefix("10.1.2.3/8")
                .unwrap_err()
                .contains("10.0.0.0/8")
        );
        assert!(parse_prefix("10.0.0.0/33").is_err());
        assert!(parse_prefix("10.0.0.0").is_err());
        assert!(parse_prefix("2001:db8::1/32").is_err());
        assert!(parse_prefix("2001:db8::/32").is_ok());
    }

    #[test]
    fn interface_addrs_must_be_hosts() {
        assert!(parse_interface_addr("10.11.0.2/24").is_ok());
        assert!(parse_interface_addr("10.11.0.0/24").is_err());
        assert!(parse_interface_addr("10.11.0.255/24").is_err());
        assert!(parse_interface_addr("10.11.0.2/31").is_err());
        assert!(parse_interface_addr("fd00:5350::2/64").is_ok());
        assert!(parse_interface_addr("fd00:5350::/64").is_err());
    }

    #[test]
    fn options_defaults_match_the_android_client() {
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            false,
            &[],
            false,
            None,
        )
        .unwrap();
        assert_eq!(o.tun_addr, Ipv4Addr::new(10, 11, 0, 2));
        assert_eq!(o.tun_prefix, 24);
        assert_eq!(o.peer_v4(), Ipv4Addr::new(10, 11, 0, 1));
        assert_eq!(o.tun_addr6.unwrap().1, 64);
        assert_eq!(o.routes, RouteSet::Default);
        assert_eq!(
            o.route_prefixes(),
            vec![Prefix::V4_DEFAULT, Prefix::V6_DEFAULT]
        );
        assert_eq!(o.dns, vec![IpAddr::V4(spora_core::dns::PROXY_ADDR)]);
        assert_eq!(
            DEFAULT_DNS[0].parse::<Ipv4Addr>().unwrap(),
            spora_core::dns::PROXY_ADDR,
            "the literal default must stay the core's forwarder address"
        );
        assert_eq!(o.mtu, MtuPolicy::Auto);
        assert_eq!(o.initial_mtu(), INITIAL_MTU);
        assert!(
            o.unreachable_resolvers().is_empty(),
            "the forwarder address is private (CGNAT) but answered"
        );
    }

    #[test]
    fn options_reject_public_tun_addresses_and_non_ula_v6() {
        let e = Options::parse(
            "8.8.8.2/24",
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            false,
            &[],
            false,
            None,
        )
        .unwrap_err();
        assert!(e.contains("private"), "{e}");
        let e = Options::parse(
            DEFAULT_TUN_ADDR,
            "2001:db8::2/64",
            false,
            &[],
            false,
            &[],
            false,
            None,
        )
        .unwrap_err();
        assert!(e.contains("ULA"), "{e}");
        // CGNAT is private enough for the sharer.
        assert!(
            Options::parse(
                "100.64.0.2/24",
                DEFAULT_TUN_ADDR6,
                false,
                &[],
                false,
                &[],
                false,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn no_ipv6_drops_the_v6_default_and_rejects_v6_routes() {
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            true,
            &[],
            false,
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(!o.ipv6_enabled());
        assert_eq!(o.route_prefixes(), vec![Prefix::V4_DEFAULT]);
        let e = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            true,
            &["2001:db8::/32".into()],
            false,
            &[],
            false,
            None,
        )
        .unwrap_err();
        assert!(e.contains("--no-ipv6"), "{e}");
    }

    #[test]
    fn split_tunnel_routes_and_no_routes() {
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &[
                "10.0.0.0/8".into(),
                "10.0.0.0/8".into(),
                "2001:db8::/32".into(),
            ],
            false,
            &[],
            false,
            None,
        )
        .unwrap();
        assert_eq!(o.route_prefixes().len(), 2, "duplicates collapse");
        assert_eq!(o.dns.len(), 1, "split tunnels still get the resolver");
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            true,
            &[],
            false,
            None,
        )
        .unwrap();
        assert_eq!(o.routes, RouteSet::None);
        assert!(o.route_prefixes().is_empty());
        assert!(o.dns.is_empty(), "--no-routes implies no resolver change");
    }

    #[test]
    fn dns_overrides_and_private_resolver_warning() {
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            false,
            &["9.9.9.9".into(), "192.168.1.1".into()],
            false,
            None,
        )
        .unwrap();
        assert_eq!(o.dns.len(), 2);
        assert_eq!(
            o.unreachable_resolvers(),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            false,
            &[],
            true,
            None,
        )
        .unwrap();
        assert!(o.dns.is_empty());
        assert!(
            Options::parse(
                DEFAULT_TUN_ADDR,
                DEFAULT_TUN_ADDR6,
                false,
                &[],
                false,
                &["nope".into()],
                false,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn mtu_policy_follows_reports_with_the_v6_floor() {
        assert_eq!(
            mtu_for_report(MtuPolicy::Auto, false, 1280, 1414),
            Some(1414)
        );
        assert_eq!(mtu_for_report(MtuPolicy::Auto, false, 1414, 1414), None);
        // QUIC at its 1200 floor reports 1162: fine for a v4-only TUN...
        assert_eq!(
            mtu_for_report(MtuPolicy::Auto, false, 1280, 1162),
            Some(1162)
        );
        // ...but a TUN carrying v6 must not drop below 1280.
        assert_eq!(mtu_for_report(MtuPolicy::Auto, true, 1280, 1162), None);
        assert_eq!(
            mtu_for_report(MtuPolicy::Auto, true, 1414, 1162),
            Some(1280)
        );
        // nz's 1120 budget, v4-only: applied; below the v4 minimum: floored.
        assert_eq!(
            mtu_for_report(MtuPolicy::Auto, false, 1280, 1120),
            Some(1120)
        );
        assert_eq!(
            mtu_for_report(MtuPolicy::Auto, false, 1280, 100),
            Some(MIN_MTU)
        );
        // A pinned MTU never moves.
        assert_eq!(
            mtu_for_report(MtuPolicy::Fixed(1300), false, 1300, 1414),
            None
        );
        assert!(
            Options::parse(
                DEFAULT_TUN_ADDR,
                DEFAULT_TUN_ADDR6,
                false,
                &[],
                false,
                &[],
                false,
                Some(9000)
            )
            .is_err()
        );
        assert_eq!(
            Options::parse(
                DEFAULT_TUN_ADDR,
                DEFAULT_TUN_ADDR6,
                false,
                &[],
                false,
                &[],
                false,
                Some(1300)
            )
            .unwrap()
            .initial_mtu(),
            1300
        );
    }

    #[test]
    fn split_tunnel_routes_the_resolvers_too() {
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &["10.0.0.0/8".into(), "8.8.0.0/16".into()],
            false,
            &["8.8.8.8".into(), "1.1.1.1".into()],
            false,
            None,
        )
        .unwrap();
        // 8.8.8.8 is covered by 8.8.0.0/16 already; 1.1.1.1 gets a host route.
        assert_eq!(
            o.resolver_routes(),
            vec![Prefix {
                addr: "1.1.1.1".parse().unwrap(),
                len: 32
            }]
        );
        // The default resolver (the sharer's forwarder) gets one as well: a
        // split tunnel would otherwise send its queries out the uplink,
        // where nothing answers that address.
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &["10.0.0.0/8".into()],
            false,
            &[],
            false,
            None,
        )
        .unwrap();
        assert_eq!(
            o.resolver_routes(),
            vec![Prefix {
                addr: IpAddr::V4(spora_core::dns::PROXY_ADDR),
                len: 32
            }]
        );
        // Full tunnel and --no-routes need no resolver routes.
        let o = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            false,
            &[],
            false,
            None,
        )
        .unwrap();
        assert!(o.resolver_routes().is_empty());
        assert!(prefix_contains(
            parse_prefix("10.0.0.0/8").unwrap(),
            "10.1.2.3".parse().unwrap()
        ));
        assert!(!prefix_contains(
            parse_prefix("10.0.0.0/8").unwrap(),
            "11.0.0.1".parse().unwrap()
        ));
        assert!(!prefix_contains(
            parse_prefix("::/0").unwrap(),
            "1.2.3.4".parse().unwrap()
        ));
    }

    #[test]
    fn fixed_mtu_below_the_v6_floor_needs_no_ipv6() {
        let e = Options::parse(
            DEFAULT_TUN_ADDR,
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            false,
            &[],
            false,
            Some(1200),
        )
        .unwrap_err();
        assert!(e.contains("--no-ipv6"), "{e}");
        assert!(
            Options::parse(
                DEFAULT_TUN_ADDR,
                DEFAULT_TUN_ADDR6,
                true,
                &[],
                false,
                &[],
                false,
                Some(1200)
            )
            .is_ok()
        );
        assert!(
            Options::parse(
                DEFAULT_TUN_ADDR,
                DEFAULT_TUN_ADDR6,
                false,
                &[],
                false,
                &[],
                false,
                Some(1280)
            )
            .is_ok()
        );
    }

    #[test]
    fn peer_address_skips_the_tun_address() {
        let o = Options::parse(
            "10.11.0.1/24",
            DEFAULT_TUN_ADDR6,
            false,
            &[],
            false,
            &[],
            false,
            None,
        )
        .unwrap();
        assert_eq!(o.peer_v4(), Ipv4Addr::new(10, 11, 0, 2));
    }

    #[test]
    fn undo_stack_replays_in_reverse_once() {
        use std::sync::{Arc, Mutex};
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut stack = UndoStack::default();
        for i in 0..3 {
            let log = log.clone();
            stack.push(Undo::Fn(Box::new(move || log.lock().unwrap().push(i))));
        }
        stack.unwind();
        stack.unwind();
        assert_eq!(*log.lock().unwrap(), vec![2, 1, 0]);
    }
}
