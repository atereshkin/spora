//! The exit's DNS forwarder: clients resolve through the sharer's own
//! resolvers without ever learning what those are.
//!
//! The client points its resolver at [`PROXY_ADDR`] port 53 — a fixed
//! synthetic address inside the tunnel. Nothing about it is negotiated on the
//! wire; it is a convention both ends are built to. The exit intercepts
//! flows to that address ahead of its private-destination block and forwards
//! each query, byte for byte, to one of its own *upstreams*: by default the
//! host's system resolvers ([`DnsUpstream::System`]), else a list the
//! platform hands over ([`DnsUpstream::Servers`] — Android's
//! `LinkProperties.getDnsServers()`, the CLI's `--dns-upstream`). The
//! response goes back to the client from the synthetic address. No DNS
//! parsing happens anywhere: EDNS, DNSSEC, every record type and TTL survive,
//! and TCP/53 (truncation fallback) is the same rewrite on a stream.
//!
//! Why this shape:
//! - The sharer's resolvers are almost always *private* addresses (the home
//!   router, a carrier resolver on 10.x or a ULA, systemd-resolved on
//!   loopback), exactly what `is_local_address` blocks so a client cannot
//!   reach the sharer's LAN. Rewriting the destination on the exit — where
//!   the upstream is sharer-chosen, not client-chosen — keeps that policy
//!   intact without leaking a single LAN address to the client, and lets the
//!   upstreams change mid-session (network switch) with nothing to
//!   renegotiate.
//! - The synthetic address lives in CGNAT space (RFC 6598), which is never a
//!   LAN: a desktop client's own LAN routes stay ahead of the tunnel routes
//!   (the wg-quick model), so a `10.0.0.0/24` home network would have
//!   swallowed queries aimed at the keepalive's `10.0.0.2`.
//!
//! Failover lives on the exit, where the knowledge is. Each query is its own
//! attempt with a bounded timeout; an upstream that fails (ICMP unreachable,
//! send error) or strikes out on timeouts is quarantined for a while, the
//! query is retried on the next live upstream, and once every configured
//! upstream is out — or none is known — the public fallback list answers.
//! The client therefore always has a resolver that works, degrading to
//! today's public-resolver behaviour rather than to a dead one.
//!
//! Known defect — encrypted system DNS: on Android with Private DNS (DoT) in
//! strict mode, on iOS/macOS with an encrypted-DNS profile, and on Windows
//! with DoH configured per adapter, the OS resolver speaks TLS/HTTPS to the
//! same server addresses this forwarder sends *plain UDP* to. The queries
//! still resolve (the servers accept both), but the user's choice of
//! encrypted transport is bypassed. A resolver that ONLY speaks encrypted
//! DNS gets quarantined and the public fallback takes over. Linux with
//! systemd-resolved `DNSOverTLS=` is fine: the forwarder talks to the
//! loopback stub, which does the TLS. Faithful handling needs the OS's own
//! raw-query API (`DnsResolver.rawQuery` on Android, `DnsQueryRaw` on
//! Windows 11, `DNSServiceQueryRecord` on Apple) — future work.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::SocketProtector;

/// The synthetic resolver address a client sets as its DNS server. Inside the
/// tunnel only; the exit answers it by rewriting to a real upstream. CGNAT
/// space (RFC 6598) is deliberately not RFC1918: it is never a LAN, so a
/// client's own LAN routes cannot shadow it.
pub const PROXY_ADDR: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 53);
/// The synthetic resolver's port.
pub const PROXY_PORT: u16 = 53;

/// [`PROXY_ADDR`]:[`PROXY_PORT`] as a socket address.
pub const fn proxy_socket() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(PROXY_ADDR, PROXY_PORT))
}

/// Is this inner destination the forwarder's synthetic address? Judges the
/// v4-mapped form too, as `is_local_address` does, so a dual-stack inner
/// packet cannot dodge or spoof the match.
pub fn is_proxy_target(addr: SocketAddr) -> bool {
    if addr.port() != PROXY_PORT {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(v4) => v4 == PROXY_ADDR,
        IpAddr::V6(v6) => v6.to_ipv4_mapped() == Some(PROXY_ADDR),
    }
}

/// Public resolvers used when no upstream is known or none answers. The same
/// two operators the client used to be pointed at directly.
pub const PUBLIC_FALLBACK: [SocketAddr; 2] = [
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53)),
];

/// How often the system resolver list is re-read (network changes).
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// Consecutive unanswered attempts before an upstream is declared dead.
const STRIKES_TO_DEAD: u32 = 3;
/// How long a dead upstream is skipped before it is probed again.
const DEFAULT_QUARANTINE: Duration = Duration::from_secs(30);
/// Per-attempt wait for a UDP answer. Stub resolvers retry at 1–5s, so a
/// failover must land well inside that.
const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
/// Attempts (distinct upstreams) per query before giving up.
pub(crate) const MAX_ATTEMPTS: usize = 3;
/// Largest UDP query/response carried (the EDNS0 conventional maximum).
const MAX_DATAGRAM: usize = 4096;
/// Upstreams kept from the system configuration.
const MAX_SYSTEM_RESOLVERS: usize = 8;
/// Queries (UDP) or connections (TCP) in flight at once per serving socket —
/// the per-session rate cap; excess is dropped and the stub retries.
pub const MAX_INFLIGHT: usize = 256;
/// TCP connect budget toward an upstream.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the forwarder sends queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsUpstream {
    /// The host's own resolvers, discovered from the system configuration
    /// (`/etc/resolv.conf`; the adapters' DNS servers on Windows) and
    /// re-read periodically. Falls back to [`PUBLIC_FALLBACK`] when nothing
    /// is configured (Android has no resolv.conf: the app supplies the list
    /// with [`DnsForwarder::set_servers`] instead).
    System,
    /// Exactly these servers, in preference order.
    Servers(Vec<SocketAddr>),
}

struct Upstream {
    addr: SocketAddr,
    /// Consecutive attempts that got no answer; an answer clears it.
    strikes: u32,
    /// Set while the upstream is skipped; cleared by an answer or when the
    /// quarantine expires.
    dead_since: Option<Instant>,
}

impl Upstream {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            strikes: 0,
            dead_since: None,
        }
    }
}

struct Inner {
    mode: DnsUpstream,
    servers: Vec<Upstream>,
    fallback: Vec<Upstream>,
    /// Last system-configuration read (`System` mode only).
    refreshed: Option<Instant>,
    quarantine: Duration,
    attempt_timeout: Duration,
}

/// Upstream selection and health for the exit's DNS forwarder. Shared
/// (`Arc`) between the exit and the platform layer, which may swap the
/// upstream list at any time.
pub struct DnsForwarder {
    inner: Mutex<Inner>,
}

impl DnsForwarder {
    /// A forwarder with the public fallback list.
    pub fn new(mode: DnsUpstream) -> Arc<Self> {
        Self::with_fallback(mode, PUBLIC_FALLBACK.to_vec())
    }

    /// The default: the host's system resolvers, public fallback.
    pub fn system() -> Arc<Self> {
        Self::new(DnsUpstream::System)
    }

    /// A forwarder with an explicit fallback list (empty = none: when every
    /// upstream is out, queries go unanswered rather than to a resolver the
    /// operator did not choose).
    pub fn with_fallback(mode: DnsUpstream, fallback: Vec<SocketAddr>) -> Arc<Self> {
        let servers = match &mode {
            DnsUpstream::System => Vec::new(),
            DnsUpstream::Servers(list) => dedup(list.iter().copied()),
        };
        Arc::new(Self {
            inner: Mutex::new(Inner {
                mode,
                servers: servers.into_iter().map(Upstream::new).collect(),
                fallback: dedup(fallback.into_iter())
                    .into_iter()
                    .map(Upstream::new)
                    .collect(),
                refreshed: None,
                quarantine: DEFAULT_QUARANTINE,
                attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
            }),
        })
    }

    /// Replace the upstream list (the platform learned the network's
    /// resolvers, or they changed). An empty list means "unknown": back to
    /// [`DnsUpstream::System`]. Health state survives for addresses that
    /// stay in the list.
    pub fn set_servers(&self, servers: Vec<SocketAddr>) {
        let mut inner = self.inner.lock().unwrap();
        if servers.is_empty() {
            inner.mode = DnsUpstream::System;
            inner.refreshed = None;
            inner.refresh_if_stale(Instant::now());
        } else {
            let list = dedup(servers.into_iter());
            inner.mode = DnsUpstream::Servers(list.clone());
            inner.apply(list);
        }
        info!("dns forwarder: upstreams now {:?}", inner.addrs());
    }

    /// The current mode.
    pub fn mode(&self) -> DnsUpstream {
        self.inner.lock().unwrap().mode.clone()
    }

    /// The upstreams a query would be tried against right now, in order
    /// (system list re-read if stale). Informational: for status output.
    pub fn upstreams(&self) -> Vec<SocketAddr> {
        let mut inner = self.inner.lock().unwrap();
        inner.refresh_if_stale(Instant::now());
        inner.addrs()
    }

    /// The fallback list.
    pub fn fallback(&self) -> Vec<SocketAddr> {
        self.inner
            .lock()
            .unwrap()
            .fallback
            .iter()
            .map(|u| u.addr)
            .collect()
    }

    /// Per-attempt UDP answer timeout (default 2s). Tests and the lab scale
    /// it down.
    pub fn set_attempt_timeout(&self, timeout: Duration) {
        self.inner.lock().unwrap().attempt_timeout = timeout;
    }

    /// How long a dead upstream is skipped before being probed again
    /// (default 30s).
    pub fn set_quarantine(&self, quarantine: Duration) {
        self.inner.lock().unwrap().quarantine = quarantine;
    }

    pub fn attempt_timeout(&self) -> Duration {
        self.inner.lock().unwrap().attempt_timeout
    }

    /// The upstream to try next, skipping `tried` (this query's earlier
    /// attempts): the first live configured upstream, else the first live
    /// fallback, else — everything is out — the one that has been dead
    /// longest, as a probe. `None` only when there is nothing left to try.
    pub fn pick(&self, tried: &[SocketAddr]) -> Option<SocketAddr> {
        self.pick_at(Instant::now(), tried)
    }

    fn pick_at(&self, now: Instant, tried: &[SocketAddr]) -> Option<SocketAddr> {
        let mut inner = self.inner.lock().unwrap();
        inner.refresh_if_stale(now);
        let Inner {
            servers,
            fallback,
            quarantine,
            ..
        } = &mut *inner;
        for u in servers.iter_mut().chain(fallback.iter_mut()) {
            if let Some(since) = u.dead_since
                && now.duration_since(since) >= *quarantine
            {
                u.dead_since = None;
                u.strikes = 0;
            }
        }
        let untried = |u: &&Upstream| !tried.contains(&u.addr);
        servers
            .iter()
            .filter(untried)
            .find(|u| u.dead_since.is_none())
            .or_else(|| {
                fallback
                    .iter()
                    .filter(untried)
                    .find(|u| u.dead_since.is_none())
            })
            .or_else(|| {
                servers
                    .iter()
                    .chain(fallback.iter())
                    .filter(untried)
                    .min_by_key(|u| u.dead_since)
            })
            .map(|u| u.addr)
    }

    /// The upstream answered: healthy again.
    pub fn answered(&self, upstream: SocketAddr) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(u) = inner.find(upstream) {
            if u.dead_since.is_some() {
                info!("dns forwarder: upstream {upstream} is back");
            }
            u.strikes = 0;
            u.dead_since = None;
        }
    }

    /// An attempt got no answer in time. Strikes accumulate into quarantine.
    pub fn timed_out(&self, upstream: SocketAddr) {
        self.timed_out_at(Instant::now(), upstream);
    }

    fn timed_out_at(&self, now: Instant, upstream: SocketAddr) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(u) = inner.find(upstream)
            && u.dead_since.is_none()
        {
            u.strikes += 1;
            if u.strikes >= STRIKES_TO_DEAD {
                warn!(
                    "dns forwarder: upstream {upstream} unanswered {} times in a row; skipping it for a while",
                    u.strikes
                );
                u.dead_since = Some(now);
            }
        }
    }

    /// The upstream is unreachable right now (ICMP unreachable, a send or
    /// connect error): quarantined immediately.
    pub fn failed(&self, upstream: SocketAddr) {
        self.failed_at(Instant::now(), upstream);
    }

    fn failed_at(&self, now: Instant, upstream: SocketAddr) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(u) = inner.find(upstream)
            && u.dead_since.is_none()
        {
            warn!("dns forwarder: upstream {upstream} unreachable; skipping it for a while");
            u.strikes = 0;
            u.dead_since = Some(now);
        }
    }
}

impl Inner {
    fn find(&mut self, addr: SocketAddr) -> Option<&mut Upstream> {
        self.servers
            .iter_mut()
            .chain(self.fallback.iter_mut())
            .find(|u| u.addr == addr)
    }

    fn addrs(&self) -> Vec<SocketAddr> {
        self.servers.iter().map(|u| u.addr).collect()
    }

    /// Replace the server list, keeping health for addresses that persist.
    fn apply(&mut self, list: Vec<SocketAddr>) {
        let old = std::mem::take(&mut self.servers);
        self.servers = list
            .into_iter()
            .map(|addr| {
                old.iter()
                    .find(|u| u.addr == addr)
                    .map(|u| Upstream {
                        addr,
                        strikes: u.strikes,
                        dead_since: u.dead_since,
                    })
                    .unwrap_or_else(|| Upstream::new(addr))
            })
            .collect();
    }

    fn refresh_if_stale(&mut self, now: Instant) {
        if self.mode != DnsUpstream::System {
            return;
        }
        if let Some(at) = self.refreshed
            && now.duration_since(at) < REFRESH_INTERVAL
        {
            return;
        }
        self.refreshed = Some(now);
        let found = system_resolvers();
        if found
            .iter()
            .copied()
            .ne(self.servers.iter().map(|u| u.addr))
        {
            if found.is_empty() {
                info!(
                    "dns forwarder: no system resolvers found; using the public fallback {:?}",
                    self.fallback.iter().map(|u| u.addr).collect::<Vec<_>>()
                );
            } else {
                info!("dns forwarder: system resolvers {found:?}");
            }
            self.apply(found);
        }
    }
}

fn dedup(list: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in list {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// System resolver discovery

/// The host's configured resolvers, in order. Empty when none can be found
/// (Android; a host without resolv.conf).
pub fn system_resolvers() -> Vec<SocketAddr> {
    #[cfg(unix)]
    {
        match std::fs::read_to_string("/etc/resolv.conf") {
            Ok(text) => parse_resolv_conf(&text),
            Err(e) => {
                debug!("dns forwarder: /etc/resolv.conf: {e}");
                Vec::new()
            }
        }
    }
    #[cfg(windows)]
    {
        windows::resolvers()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

/// `nameserver` lines of a resolv.conf, in order, deduplicated and capped.
/// A v6 literal may carry a `%scope` (interface name or index) for a
/// link-local resolver; the name is resolved to an index on Unix.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(word) = words.next() else { continue };
        let Some(addr) = parse_nameserver(word) else {
            debug!("dns forwarder: ignoring unparseable nameserver {word:?}");
            continue;
        };
        if !out.contains(&addr) {
            out.push(addr);
        }
        if out.len() >= MAX_SYSTEM_RESOLVERS {
            break;
        }
    }
    out
}

#[cfg_attr(not(unix), allow(dead_code))]
fn parse_nameserver(word: &str) -> Option<SocketAddr> {
    if let Ok(v4) = word.parse::<Ipv4Addr>() {
        return Some(SocketAddr::new(IpAddr::V4(v4), 53));
    }
    let (lit, scope) = match word.split_once('%') {
        Some((lit, scope)) => (lit, Some(scope)),
        None => (word, None),
    };
    let v6: Ipv6Addr = lit.parse().ok()?;
    let scope_id = match scope {
        None => 0,
        Some(s) => s.parse::<u32>().ok().or_else(|| interface_index(s))?,
    };
    if scope_id == 0 && (v6.segments()[0] & 0xFFC0) == 0xFE80 {
        // A link-local resolver without a scope cannot be dialed.
        return None;
    }
    Some(SocketAddr::V6(std::net::SocketAddrV6::new(
        v6, 53, 0, scope_id,
    )))
}

#[cfg(unix)]
fn interface_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the call's duration.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

#[cfg(not(unix))]
fn interface_index(_name: &str) -> Option<u32> {
    None
}

#[cfg(windows)]
mod windows {
    //! The DNS servers of every adapter that is up, in adapter order, via
    //! `GetAdaptersAddresses`. Windows resolves per adapter (by metric); the
    //! union in adapter order is a fair stand-in for "the system's
    //! resolvers", and the health machinery sorts out the ones that do not
    //! answer from this host.

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
        GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    pub(super) fn resolvers() -> Vec<SocketAddr> {
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_FRIENDLY_NAME;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u8> = Vec::new();
        for _ in 0..4 {
            buf.resize(size as usize, 0);
            // SAFETY: `buf` has `size` bytes; the API writes at most that many
            // and reports the needed size on overflow.
            let ret = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                )
            };
            match ret {
                NO_ERROR => break,
                ERROR_BUFFER_OVERFLOW => continue,
                other => {
                    log::debug!("dns forwarder: GetAdaptersAddresses error {other}");
                    return Vec::new();
                }
            }
        }
        let mut out = Vec::new();
        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        // SAFETY: the buffer holds a linked list the API just filled in; every
        // pointer followed is either null or inside it.
        unsafe {
            while !adapter.is_null() {
                let a = &*adapter;
                if a.OperStatus == IfOperStatusUp && a.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
                    let mut dns = a.FirstDnsServerAddress;
                    while !dns.is_null() {
                        let d = &*dns;
                        if let Some(addr) = sockaddr_to_addr(
                            d.Address.lpSockaddr as *const u8,
                            d.Address.iSockaddrLength,
                        ) && !is_site_local(addr.ip())
                            && !out.contains(&addr)
                            && out.len() < super::MAX_SYSTEM_RESOLVERS
                        {
                            out.push(addr);
                        }
                        dns = d.Next;
                    }
                }
                adapter = a.Next;
            }
        }
        out
    }

    /// The deprecated site-local `fec0:0:0:ffff::1-3` entries Windows lists
    /// on adapters without real v6 resolvers; never reachable.
    fn is_site_local(ip: IpAddr) -> bool {
        matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xFFC0) == 0xFEC0)
    }

    unsafe fn sockaddr_to_addr(ptr: *const u8, len: i32) -> Option<SocketAddr> {
        if ptr.is_null() || len < 2 {
            return None;
        }
        // SAFETY: the caller guarantees `ptr` points at `len` bytes of a
        // sockaddr; the family field is read first and the cast follows it.
        let family = unsafe { *(ptr as *const u16) };
        if family == AF_INET && len as usize >= std::mem::size_of::<SOCKADDR_IN>() {
            let sa = unsafe { &*(ptr as *const SOCKADDR_IN) };
            let ip = Ipv4Addr::from(u32::from_be(unsafe { sa.sin_addr.S_un.S_addr }));
            Some(SocketAddr::new(IpAddr::V4(ip), 53))
        } else if family == AF_INET6 && len as usize >= std::mem::size_of::<SOCKADDR_IN6>() {
            let sa = unsafe { &*(ptr as *const SOCKADDR_IN6) };
            let ip = Ipv6Addr::from(unsafe { sa.sin6_addr.u.Byte });
            let scope = unsafe { sa.Anonymous.sin6_scope_id };
            Some(SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, scope)))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Forwarding

/// One forwarded query's outcome.
pub struct Answer {
    pub response: Vec<u8>,
    /// The upstream that answered.
    pub upstream: SocketAddr,
    /// The local address the query left from (the connection log's
    /// egress-source field).
    pub egress: Option<SocketAddr>,
    /// Upstreams tried, including the one that answered.
    pub attempts: u32,
}

#[derive(Debug)]
pub enum ForwardError {
    /// No upstream to try at all (empty lists).
    NoUpstream,
    /// Every attempt failed or timed out.
    Unanswered {
        attempts: u32,
        last_upstream: SocketAddr,
        last: Option<io::Error>,
    },
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoUpstream => write!(f, "no DNS upstream configured"),
            Self::Unanswered {
                attempts,
                last_upstream,
                last,
            } => match last {
                Some(e) => write!(
                    f,
                    "unanswered after {attempts} attempts (last {last_upstream}: {e})"
                ),
                None => write!(
                    f,
                    "unanswered after {attempts} attempts (last {last_upstream})"
                ),
            },
        }
    }
}

impl std::error::Error for ForwardError {}

enum Attempt {
    Timeout,
    Io(io::Error),
}

/// Forward one UDP query: try upstreams in [`DnsForwarder::pick`] order
/// until one answers within the attempt timeout, at most [`MAX_ATTEMPTS`]
/// of them, updating health as it goes. The response is returned verbatim.
pub async fn forward_query(
    fwd: &DnsForwarder,
    query: &[u8],
    protector: &SocketProtector,
) -> Result<Answer, ForwardError> {
    let timeout = fwd.attempt_timeout();
    let mut tried: Vec<SocketAddr> = Vec::with_capacity(MAX_ATTEMPTS);
    let mut last: Option<io::Error> = None;
    while tried.len() < MAX_ATTEMPTS {
        let Some(up) = fwd.pick(&tried) else { break };
        tried.push(up);
        match query_once(up, query, protector, timeout).await {
            Ok((response, egress)) => {
                fwd.answered(up);
                return Ok(Answer {
                    response,
                    upstream: up,
                    egress,
                    attempts: tried.len() as u32,
                });
            }
            Err(Attempt::Timeout) => {
                debug!("dns forwarder: {up} did not answer within {timeout:?}");
                fwd.timed_out(up);
                last = Some(io::Error::new(io::ErrorKind::TimedOut, "no answer"));
            }
            Err(Attempt::Io(e)) => {
                debug!("dns forwarder: {up}: {e}");
                fwd.failed(up);
                last = Some(e);
            }
        }
    }
    match tried.last() {
        None => Err(ForwardError::NoUpstream),
        Some(&last_upstream) => Err(ForwardError::Unanswered {
            attempts: tried.len() as u32,
            last_upstream,
            last,
        }),
    }
}

async fn query_once(
    upstream: SocketAddr,
    query: &[u8],
    protector: &SocketProtector,
    timeout: Duration,
) -> Result<(Vec<u8>, Option<SocketAddr>), Attempt> {
    let sock = crate::server::new_udp_packet(upstream, protector)
        .await
        .map_err(Attempt::Io)?;
    let egress = sock.local_addr().ok();
    sock.send(query).await.map_err(Attempt::Io)?;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Wait for error readiness too: an ICMP port/host unreachable lands as
        // a socket error (`ECONNREFUSED` on the connected socket) that a plain
        // `recv().await` never wakes for — tokio's readable interest excludes
        // it — and the refusal would cost a whole attempt timeout instead of
        // failing over at once.
        let ready = match tokio::time::timeout_at(
            deadline,
            sock.ready(tokio::io::Interest::READABLE | tokio::io::Interest::ERROR),
        )
        .await
        {
            Err(_) => return Err(Attempt::Timeout),
            Ok(Err(e)) => return Err(Attempt::Io(e)),
            Ok(Ok(ready)) => ready,
        };
        if ready.is_error()
            && let Ok(Some(e)) = sock.take_error()
        {
            return Err(Attempt::Io(e));
        }
        match sock.try_recv(&mut buf) {
            Ok(n) => {
                // A stale or spoofed datagram is one whose ID is not ours;
                // keep waiting for the real answer.
                if n >= 2 && query.len() >= 2 && buf[..2] != query[..2] {
                    continue;
                }
                return Ok((buf[..n].to_vec(), egress));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(Attempt::Io(e)),
        }
    }
}

/// Connect to an upstream for DNS over TCP, trying them in pick order (an
/// upstream that refuses or times out is quarantined). Returns the stream,
/// the upstream, and the egress address.
pub async fn dial_tcp(
    fwd: &DnsForwarder,
    protector: &SocketProtector,
) -> Result<(TcpStream, SocketAddr, SocketAddr), ForwardError> {
    let mut tried: Vec<SocketAddr> = Vec::with_capacity(MAX_ATTEMPTS);
    let mut last: Option<io::Error> = None;
    while tried.len() < MAX_ATTEMPTS {
        let Some(up) = fwd.pick(&tried) else { break };
        tried.push(up);
        match tokio::time::timeout(
            TCP_CONNECT_TIMEOUT,
            crate::server::new_tcp_stream(up, protector),
        )
        .await
        {
            Ok(Ok((stream, egress))) => {
                fwd.answered(up);
                return Ok((stream, up, egress));
            }
            Ok(Err(e)) => {
                debug!("dns forwarder: tcp {up}: {e}");
                fwd.failed(up);
                last = Some(e);
            }
            Err(_) => {
                debug!("dns forwarder: tcp {up}: connect timed out");
                fwd.timed_out(up);
                last = Some(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
        }
    }
    match tried.last() {
        None => Err(ForwardError::NoUpstream),
        Some(&last_upstream) => Err(ForwardError::Unanswered {
            attempts: tried.len() as u32,
            last_upstream,
            last,
        }),
    }
}

/// Serve the forwarder on an ordinary UDP socket: every datagram is a query,
/// answered from the same socket. For exits that receive the client's
/// queries through the OS (the CLI's `--os-routing` DNATs the synthetic
/// address to such a socket) rather than through the netstack. Runs until
/// aborted.
pub async fn serve_udp(sock: UdpSocket, fwd: Arc<DnsForwarder>, protector: SocketProtector) {
    let sock = Arc::new(sock);
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                warn!("dns forwarder: udp recv: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            debug!("dns forwarder: {MAX_INFLIGHT} queries in flight; dropping one from {src}");
            continue;
        };
        let query = buf[..n].to_vec();
        let (sock, fwd, protector) = (sock.clone(), fwd.clone(), protector.clone());
        tokio::spawn(async move {
            let _permit = permit;
            match forward_query(&fwd, &query, &protector).await {
                Ok(answer) => {
                    if let Err(e) = sock.send_to(&answer.response, src).await {
                        debug!("dns forwarder: reply to {src}: {e}");
                    }
                }
                Err(e) => debug!("dns forwarder: query from {src}: {e}"),
            }
        });
    }
}

/// Serve DNS over TCP on an ordinary listener: each accepted connection is
/// relayed to an upstream connection. Runs until aborted.
pub async fn serve_tcp(listener: TcpListener, fwd: Arc<DnsForwarder>, protector: SocketProtector) {
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT));
    loop {
        let (mut client, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("dns forwarder: tcp accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            debug!("dns forwarder: {MAX_INFLIGHT} tcp connections in flight; refusing {peer}");
            continue;
        };
        let (fwd, protector) = (fwd.clone(), protector.clone());
        tokio::spawn(async move {
            let _permit = permit;
            match dial_tcp(&fwd, &protector).await {
                Ok((mut upstream, up, _egress)) => {
                    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        debug!("dns forwarder: tcp relay {peer} <-> {up}: {e}");
                    }
                }
                Err(e) => debug!("dns forwarder: tcp from {peer}: {e}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn proxy_target_matches_exactly_and_v4_mapped() {
        assert!(is_proxy_target(sa("100.64.0.53:53")));
        assert!(is_proxy_target(sa("[::ffff:100.64.0.53]:53")));
        assert!(!is_proxy_target(sa("100.64.0.53:5353")));
        assert!(!is_proxy_target(sa("100.64.0.54:53")));
        assert!(!is_proxy_target(sa("[::1]:53")));
        // The synthetic address is inside the exit's private-destination
        // block: without the forwarder it is dropped like any LAN address.
        assert!(crate::server::is_local_address(IpAddr::V4(PROXY_ADDR)));
    }

    #[test]
    fn resolv_conf_parsing() {
        let text = "\
# Generated by NetworkManager
search example.net   # trailing comment
nameserver 192.168.1.1
nameserver 192.168.1.1
nameserver 2606:4700:4700::1111 ; comment
nameserver fe80::1%7
nameserver fe80::2
nameserver not-an-address
options edns0 trust-ad
nameserver 127.0.0.53
";
        let got = parse_resolv_conf(text);
        assert_eq!(
            got,
            vec![
                sa("192.168.1.1:53"),
                sa("[2606:4700:4700::1111]:53"),
                sa("[fe80::1%7]:53"),
                sa("127.0.0.53:53"),
            ],
            "dedup, numeric scope kept, unscoped link-local and garbage dropped"
        );
        assert!(parse_resolv_conf("").is_empty());
        assert!(parse_resolv_conf("nameserver\n").is_empty());
    }

    #[test]
    fn resolv_conf_cap() {
        let text: String = (1..=20)
            .map(|i| format!("nameserver 10.0.0.{i}\n"))
            .collect();
        assert_eq!(parse_resolv_conf(&text).len(), MAX_SYSTEM_RESOLVERS);
    }

    #[test]
    fn pick_prefers_live_configured_then_fallback_then_probes_oldest_dead() {
        let a = sa("10.0.0.1:53");
        let b = sa("10.0.0.2:53");
        let pub1 = PUBLIC_FALLBACK[0];
        let pub2 = PUBLIC_FALLBACK[1];
        let fwd = DnsForwarder::new(DnsUpstream::Servers(vec![a, b]));
        let t0 = Instant::now();

        assert_eq!(fwd.pick_at(t0, &[]), Some(a));
        assert_eq!(
            fwd.pick_at(t0, &[a]),
            Some(b),
            "skips what this query tried"
        );
        assert_eq!(fwd.pick_at(t0, &[a, b]), Some(pub1), "then the fallback");
        assert_eq!(fwd.pick_at(t0, &[a, b, pub1]), Some(pub2));
        assert_eq!(fwd.pick_at(t0, &[a, b, pub1, pub2]), None);

        // An unreachable upstream is skipped at once.
        fwd.failed_at(t0, a);
        assert_eq!(fwd.pick_at(t0, &[]), Some(b));
        // Timeouts need STRIKES_TO_DEAD in a row.
        fwd.timed_out_at(t0, b);
        fwd.timed_out_at(t0, b);
        assert_eq!(fwd.pick_at(t0, &[]), Some(b), "two strikes is not out");
        fwd.timed_out_at(t0, b);
        assert_eq!(fwd.pick_at(t0, &[]), Some(pub1), "three strikes: fallback");
        // An answer heals.
        fwd.answered(b);
        assert_eq!(fwd.pick_at(t0, &[]), Some(b));
        // Everything dead: probe the one dead longest, never nothing.
        fwd.failed_at(t0 + Duration::from_secs(1), b);
        fwd.failed_at(t0 + Duration::from_secs(2), pub1);
        fwd.failed_at(t0 + Duration::from_secs(3), pub2);
        let t = t0 + Duration::from_secs(5);
        assert_eq!(fwd.pick_at(t, &[]), Some(a), "a died first");
        assert_eq!(fwd.pick_at(t, &[a]), Some(b));
        // Quarantine expiry revives in place, restoring the preference order.
        let later = t0 + DEFAULT_QUARANTINE + Duration::from_secs(1);
        assert_eq!(fwd.pick_at(later, &[]), Some(a));
        assert_eq!(fwd.pick_at(later, &[a]), Some(b));
    }

    #[test]
    fn explicit_list_without_fallback_can_run_out() {
        let a = sa("10.0.0.1:53");
        let fwd = DnsForwarder::with_fallback(DnsUpstream::Servers(vec![a]), Vec::new());
        assert_eq!(fwd.pick(&[]), Some(a));
        assert_eq!(fwd.pick(&[a]), None);
        assert!(fwd.fallback().is_empty());
    }

    #[test]
    fn set_servers_swaps_and_keeps_health() {
        let a = sa("10.0.0.1:53");
        let b = sa("10.0.0.2:53");
        let c = sa("10.0.0.3:53");
        let fwd = DnsForwarder::new(DnsUpstream::Servers(vec![a, b]));
        fwd.failed(a);
        fwd.set_servers(vec![c, a, a]);
        assert_eq!(fwd.upstreams(), vec![c, a], "dedup, new order");
        assert_eq!(fwd.mode(), DnsUpstream::Servers(vec![c, a]));
        assert_eq!(fwd.pick(&[c]), Some(PUBLIC_FALLBACK[0]), "a is still dead");
        fwd.set_servers(Vec::new());
        assert_eq!(fwd.mode(), DnsUpstream::System, "empty = unknown = system");
    }

    #[test]
    fn system_mode_always_has_somewhere_to_send() {
        // Whatever this host's resolv.conf says (possibly nothing, e.g. in a
        // sandbox), a pick never comes back empty thanks to the fallback.
        let fwd = DnsForwarder::system();
        assert!(fwd.pick(&[]).is_some());
    }

    /// A fake resolver: echoes each query with the QR bit set, from the same
    /// socket. Returns its address.
    async fn fake_udp_resolver(answer: bool) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                if answer && n >= 3 {
                    buf[2] |= 0x80;
                    let _ = sock.send_to(&buf[..n], src).await;
                }
            }
        });
        addr
    }

    fn query(id: u16) -> Vec<u8> {
        let mut q = vec![0u8; 12];
        q[..2].copy_from_slice(&id.to_be_bytes());
        q[2] = 0x01; // RD
        q[5] = 1; // QDCOUNT
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        q
    }

    #[tokio::test]
    async fn forwards_and_fails_over_from_a_refused_upstream() {
        let _ = env_logger::builder().is_test(true).try_init();
        let live = fake_udp_resolver(true).await;
        // Nothing listens here: the kernel answers ICMP port unreachable and
        // the connected socket's recv fails at once.
        let refused = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap()
        };
        let fwd =
            DnsForwarder::with_fallback(DnsUpstream::Servers(vec![refused, live]), Vec::new());
        let q = query(0x1234);
        let started = Instant::now();
        let ans = forward_query(&fwd, &q, &None).await.unwrap();
        assert_eq!(ans.upstream, live);
        assert_eq!(ans.attempts, 2);
        assert_eq!(&ans.response[..2], &q[..2]);
        assert_eq!(ans.response[2] & 0x80, 0x80, "the fake set QR");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refusal must fail over immediately, not after the attempt timeout"
        );
        assert_eq!(fwd.pick(&[]), Some(live), "the refused one is quarantined");
    }

    #[tokio::test]
    async fn times_out_and_fails_over_from_a_silent_upstream() {
        let silent = fake_udp_resolver(false).await;
        let live = fake_udp_resolver(true).await;
        let fwd = DnsForwarder::with_fallback(DnsUpstream::Servers(vec![silent, live]), Vec::new());
        fwd.set_attempt_timeout(Duration::from_millis(100));
        let ans = forward_query(&fwd, &query(7), &None).await.unwrap();
        assert_eq!(ans.upstream, live);
        assert_eq!(ans.attempts, 2);
        // One strike is not a quarantine: the silent one is still preferred.
        assert_eq!(fwd.pick(&[]), Some(silent));
    }

    #[tokio::test]
    async fn no_upstream_answers() {
        let silent = fake_udp_resolver(false).await;
        let fwd = DnsForwarder::with_fallback(DnsUpstream::Servers(vec![silent]), Vec::new());
        fwd.set_attempt_timeout(Duration::from_millis(50));
        match forward_query(&fwd, &query(1), &None).await {
            Err(ForwardError::Unanswered {
                attempts: 1,
                last_upstream,
                ..
            }) => assert_eq!(last_upstream, silent),
            other => panic!("expected Unanswered, got {:?}", other.map(|a| a.attempts)),
        }
        let none = DnsForwarder::with_fallback(DnsUpstream::Servers(Vec::new()), Vec::new());
        assert!(matches!(
            forward_query(&none, &query(1), &None).await,
            Err(ForwardError::NoUpstream)
        ));
    }

    #[tokio::test]
    async fn serve_udp_answers_from_the_serving_socket() {
        let live = fake_udp_resolver(true).await;
        let fwd = DnsForwarder::with_fallback(DnsUpstream::Servers(vec![live]), Vec::new());
        let serving = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let serving_addr = serving.local_addr().unwrap();
        let task = tokio::spawn(serve_udp(serving, fwd, None));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let q = query(0xBEEF);
        client.send_to(&q, serving_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("answer in time")
            .unwrap();
        assert_eq!(from, serving_addr, "answered from the serving socket");
        assert_eq!(&buf[..2], &q[..2]);
        assert_eq!(n, q.len());
        task.abort();
    }

    #[tokio::test]
    async fn serve_tcp_relays_to_an_upstream_connection() {
        // Fake TCP resolver: read a length-prefixed query, write it back with
        // QR set, close.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = upstream.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if conn.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if conn.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    q[2] |= 0x80;
                    let _ = conn.write_all(&len).await;
                    let _ = conn.write_all(&q).await;
                    let _ = conn.shutdown().await;
                });
            }
        });
        let fwd =
            DnsForwarder::with_fallback(DnsUpstream::Servers(vec![upstream_addr]), Vec::new());
        let serving = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let serving_addr = serving.local_addr().unwrap();
        let task = tokio::spawn(serve_tcp(serving, fwd, None));

        let mut client = TcpStream::connect(serving_addr).await.unwrap();
        let q = query(0x4242);
        client
            .write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&q).await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut resp))
            .await
            .expect("response in time")
            .unwrap();
        assert_eq!(resp.len(), 2 + q.len());
        assert_eq!(&resp[2..4], &q[..2]);
        assert_eq!(resp[4] & 0x80, 0x80);
        task.abort();
    }
}
