//! macOS backend: a `utun` interface, BSD `ifconfig`/`route`, outer sockets
//! bound to the uplink with `IP_BOUND_IF`, and the resolver set per network
//! service with `networksetup`.
//!
//! Routing: the default route is never touched; the tunnel gets the two
//! half-defaults `0.0.0.0/1` + `128.0.0.0/1` (`::/1` + `8000::/1`), which win
//! by prefix length. That leaves the uplink's own `default` row in place,
//! which is how the uplink is (re)detected: `netstat -rn`'s `default` line
//! that is not ours.
//!
//! Outer-socket bypass: macOS does not keep a process's own sockets out of a
//! tunnel it created (the macOS app learned this the hard way — its ADR
//! assumed auto-bypass, and excluded routes proved unreliable), so every
//! socket spora-core opens is bound to the uplink interface index with
//! `IP_BOUND_IF`/`IPV6_BOUND_IF`, the same mechanism the NetworkExtension
//! client uses. Binding alone is not enough, though. A bound socket gets a
//! *scoped* route lookup, which insists that the best match lie on the bound
//! interface, and once `0.0.0.0/1` exists it IS the best match for every
//! public address — XNU's "fall back to the default route" step even resolves
//! `0.0.0.0` to it. Every send then fails with ENETUNREACH, and because the
//! kernel invalidates all cached routes on any table change, that includes
//! the sockets that were already talking. The cure is a default route
//! *scoped to the uplink* (`route add default <gw> -ifscope en0`), which the
//! scoped lookup finds before anything else: it is put in place (or, if one
//! is already there, re-pointed at the current gateway — a killed run may
//! have left a stale one) before the relay dial, again before the tunnel
//! routes, and whenever the tunnel reconnects (a new uplink gets its own);
//! ours is deleted on exit. The index is
//! re-read at the same moments, so a Wi-Fi → Ethernet change is picked up on
//! the next redial.
//!
//! Resolver: `networksetup -setdnsservers` on every enabled network service,
//! with the previous values saved to a state file first — after a crash, the
//! next start puts them back before doing anything else.
//!
//! Needs root (`sudo spora use …`): utun creation, routes, networksetup.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use super::parsers::RouteOutcome;
use super::{Options, Prefix, Undo, UndoStack, parsers, run_cmd_output, svec};

/// Where the pre-change resolver settings are kept while we run, so a later
/// start can restore them if this one never got to. A fixed system path:
/// `sudo` changes `$HOME`, and the file must be found regardless.
const DNS_STATE: &str = "/var/db/spora/dns-restore.json";
/// The default routes scoped to the uplink that this run added, so a start
/// after a SIGKILL can remove them: they live on the uplink, not the utun,
/// and would otherwise outlive every run (same pattern as `DNS_STATE`).
const UPLINK_ROUTE_STATE: &str = "/var/db/spora/uplink-routes.json";
/// Held (locked) for the whole session; see `super::acquire_instance_lock`.
const INSTANCE_LOCK: &str = "/var/db/spora/use.lock";
const UTUN_CONTROL: &str = "com.apple.net.utun_control";

pub struct Backend {
    name: String,
    /// Keeps the interface alive; the pump works on a dup.
    fd: OwnedFd,
    uplink4: Arc<AtomicU32>,
    uplink6: Arc<AtomicU32>,
    /// The default routes scoped to the uplink that keep bound sockets
    /// routable (see the module docs).
    uplink_routes: Mutex<Vec<UplinkRoute>>,
    /// The instance lock, held until the session ends.
    _lock: std::fs::File,
}

/// A default route scoped to the uplink interface.
#[derive(Clone, Debug, PartialEq, Eq)]
struct UplinkRoute {
    /// `-inet` or `-inet6`.
    family: &'static str,
    /// The gateway arguments: `[address]`, or `["-interface", ifname]` for a
    /// directly attached default (`link#N` in netstat).
    via: Vec<String>,
    /// The uplink interface the route is scoped to.
    ifscope: String,
    /// Whether this run created it (deleted on exit) or found it (left as is).
    ours: bool,
}

pub type PumpHandle = OwnedFd;

impl Backend {
    pub fn setup(opts: &Options, _undo: &mut UndoStack) -> Result<Backend, String> {
        let lock = super::acquire_instance_lock(INSTANCE_LOCK)?;
        restore_stale_dns();
        sweep_stale_uplink_routes();
        let (fd, name) = open_utun().map_err(friendly_utun_error)?;
        let mask = super::v4_netmask(opts.tun_prefix).to_string();
        run_cmd_output(
            "ifconfig",
            &svec(&[
                &name,
                "inet",
                &opts.tun_addr.to_string(),
                &opts.peer_v4().to_string(),
                "netmask",
                &mask,
                "mtu",
                &opts.initial_mtu().to_string(),
                "up",
            ]),
        )
        .map_err(|e| format!("cannot configure {name}: {e}"))?;
        if let Some((a6, p6)) = opts.tun_addr6 {
            run_cmd_output(
                "ifconfig",
                &svec(&[
                    &name,
                    "inet6",
                    &a6.to_string(),
                    "prefixlen",
                    &p6.to_string(),
                ]),
            )
            .map_err(|e| format!("cannot add the IPv6 address to {name}: {e}"))?;
        }
        let backend = Backend {
            name,
            fd,
            uplink4: Arc::new(AtomicU32::new(0)),
            uplink6: Arc::new(AtomicU32::new(0)),
            uplink_routes: Mutex::new(Vec::new()),
            _lock: lock,
        };
        // Before the relay dial: bound sockets consult a scoped default from
        // the start, and one left behind by a killed run may name a gateway
        // this network no longer has.
        backend.refresh_uplink();
        if backend.uplink4.load(Ordering::Relaxed) == 0 {
            log::warn!(
                "no IPv4 default route found: the tunnel's own sockets cannot be bound to an uplink and may loop into the tunnel"
            );
        }
        log::info!(
            "utun {} up: {}/{} mtu {}",
            backend.name,
            opts.tun_addr,
            opts.tun_prefix,
            opts.initial_mtu()
        );
        Ok(backend)
    }

    pub fn tun_name(&self) -> &str {
        &self.name
    }

    pub fn protector(&self) -> spora_core::SocketProtector {
        let uplink4 = self.uplink4.clone();
        let uplink6 = self.uplink6.clone();
        let name = self.name.clone();
        Some(Arc::new(move |fd: spora_core::SocketHandle| {
            let mut refreshed = false;
            loop {
                let idx4 = uplink4.load(Ordering::Relaxed);
                let idx6 = match uplink6.load(Ordering::Relaxed) {
                    0 => idx4,
                    i => i,
                };
                // One of the two applies (the socket is v4 or v6); the other
                // fails with EINVAL/ENOPROTOOPT and is ignored.
                let ok4 = idx4 != 0 && bound_if(fd, libc::IPPROTO_IP, libc::IP_BOUND_IF, idx4);
                let ok6 = idx6 != 0 && bound_if(fd, libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF, idx6);
                if ok4 || ok6 {
                    return;
                }
                if refreshed {
                    log::warn!(
                        "could not bind socket {fd} to the uplink interface: it may be routed into the tunnel"
                    );
                    return;
                }
                // The cached index may name an interface that no longer
                // exists (uplink change since the last refresh): re-detect
                // once and retry.
                refresh_uplinks(&name, &uplink4, &uplink6);
                refreshed = true;
            }
        }))
    }

    pub fn install_routes(
        &self,
        _opts: &Options,
        routes: &[Prefix],
        undo: &mut UndoStack,
    ) -> Result<(), String> {
        // Make sure the uplink routes are in place before the first tunnel
        // route: that add invalidates every cached route in the kernel, and
        // the relay socket must find its scoped default on the very next send.
        self.ensure_uplink_routes();
        for p in routes {
            for target in half_defaults(*p) {
                let family = if p.is_ipv4() { "-inet" } else { "-inet6" };
                match route_cmd(&svec(&[
                    "-n",
                    "add",
                    family,
                    &target,
                    "-interface",
                    &self.name,
                ]))
                .map_err(|e| format!("cannot route {target} into {}: {e}", self.name))?
                {
                    RouteOutcome::Done => {}
                    RouteOutcome::Exists => {
                        return Err(format!(
                            "cannot route {target} into {}: a route for {target} already exists (another VPN?)",
                            self.name
                        ));
                    }
                    RouteOutcome::Missing => {
                        return Err(format!(
                            "cannot route {target} into {}: the routing socket reported it missing",
                            self.name
                        ));
                    }
                }
                undo.push(Undo::Cmd(svec(&[
                    "route",
                    "-q",
                    "-n",
                    "delete",
                    family,
                    &target,
                    "-interface",
                    &self.name,
                ])));
            }
        }
        Ok(())
    }

    pub fn set_dns(&self, opts: &Options, undo: &mut UndoStack) -> Result<&'static str, String> {
        let services = parsers::darwin_network_services(
            &run_cmd_output("networksetup", &svec(&["-listallnetworkservices"]))
                .map_err(|e| format!("cannot list network services: {e}"))?,
        );
        if services.is_empty() {
            return Err("networksetup reported no enabled network services".into());
        }
        // Snapshot every service's resolvers BEFORE changing any, and
        // persist the snapshot first: the state file is the crash recovery.
        let mut previous: Vec<(String, Vec<String>)> = Vec::with_capacity(services.len());
        for svc in &services {
            let out = run_cmd_output("networksetup", &svec(&["-getdnsservers", svc]))
                .map_err(|e| format!("cannot read the resolvers of {svc}: {e}"))?;
            previous.push((svc.clone(), parsers::darwin_dns_servers(&out)));
        }
        write_dns_state(&previous)?;
        let wanted: Vec<String> = opts.dns.iter().map(ToString::to_string).collect();
        let mut changed = Vec::new();
        for svc in &services {
            let mut args = svec(&["-setdnsservers", svc]);
            args.extend(wanted.iter().cloned());
            match run_cmd_output("networksetup", &args) {
                Ok(_) => changed.push(svc.clone()),
                Err(e) => log::warn!("{e}"),
            }
        }
        undo.push(Undo::Fn(Box::new(move || {
            restore_dns(&previous);
            let _ = std::fs::remove_file(DNS_STATE);
        })));
        if changed.is_empty() {
            return Err("could not set the resolver on any network service".into());
        }
        Ok("networksetup")
    }

    pub fn set_mtu(&self, mtu: u16) -> Result<(), String> {
        run_cmd_output("ifconfig", &svec(&[&self.name, "mtu", &mtu.to_string()]))
            .map(|_| ())
            .map_err(|e| format!("cannot set the MTU of {}: {e}", self.name))
    }

    /// Re-read which interface carries the system's default route(s), for
    /// the protector to bind new sockets to, and give a changed uplink its
    /// scoped default route.
    pub fn refresh_uplink(&self) {
        refresh_uplinks(&self.name, &self.uplink4, &self.uplink6);
        self.ensure_uplink_routes();
    }

    /// Keep one default route scoped to the uplink, per address family that
    /// has an uplink, so sockets bound with `IP_BOUND_IF` still resolve a
    /// route once the tunnel's half-defaults shadow the primary default (see
    /// the module docs). Idempotent, and driven by the routing TABLE rather
    /// than by memory: the kernel drops the scoped route together with the
    /// interface's address (Wi-Fi bounce, sleep/wake), so every call checks
    /// what is actually there. Runs at setup, before the tunnel routes, and
    /// after every reconnect; a new uplink gets its own route and the old
    /// one keeps its (still-bound sockets may need it) until exit.
    fn ensure_uplink_routes(&self) {
        let mut routes = self.uplink_routes.lock().unwrap();
        let mut added = false;
        for (family, netstat_family) in [("-inet", "inet"), ("-inet6", "inet6")] {
            let Ok(table) = run_cmd_output("netstat", &svec(&["-rn", "-f", netstat_family])) else {
                continue;
            };
            let Some((gateway, netif)) = parsers::darwin_netstat_default_route(&table, &self.name)
            else {
                continue;
            };
            let via = parsers::darwin_uplink_route_via(&gateway, &netif);
            let present = parsers::darwin_netstat_scoped_default(&table, &netif)
                .map(|gw| parsers::darwin_uplink_route_via(&gw, &netif));
            let tracked = routes
                .iter()
                .position(|r| r.family == family && r.ifscope == netif);
            let (verb, ours) = match (present, tracked) {
                // In place and pointing at the current gateway.
                (Some(p), Some(i)) if p == via => {
                    routes[i].via = via;
                    continue;
                }
                // The system (or an earlier run) keeps one: adopt it, leave it on exit.
                (Some(p), None) if p == via => ("", false),
                // There, but at another gateway (a stale one from a killed run,
                // or a DHCP change): re-point it, ownership unchanged.
                (Some(_), tracked) => ("change", tracked.is_some_and(|i| routes[i].ours)),
                // Missing (never there, or flushed with the address): ours now.
                (None, _) => ("add", true),
            };
            if !verb.is_empty() {
                let args = parsers::darwin_uplink_route_args(verb, family, &via, &netif);
                match route_cmd(&args) {
                    Ok(RouteOutcome::Done) => {}
                    Ok(RouteOutcome::Exists) => {
                        // Raced into the table between the read and the add.
                        let args =
                            parsers::darwin_uplink_route_args("change", family, &via, &netif);
                        if let Err(e) = route_cmd(&args) {
                            log::warn!("uplink route: {e}");
                        }
                    }
                    Ok(RouteOutcome::Missing) => {
                        log::warn!(
                            "uplink route for {netstat_family}: the routing socket rejected it"
                        );
                        continue;
                    }
                    Err(e) => {
                        log::warn!("uplink route for {netstat_family}: {e}");
                        continue;
                    }
                }
            }
            log::info!(
                "{netstat_family} uplink route: default via {} scoped to {netif} ({})",
                via.join(" "),
                match verb {
                    "add" => "added",
                    "change" => "re-pointed",
                    _ => "already present",
                }
            );
            let entry = UplinkRoute {
                family,
                via,
                ifscope: netif,
                ours,
            };
            match tracked {
                Some(i) => routes[i] = entry,
                None => routes.push(entry),
            }
            added |= ours;
        }
        if added {
            write_uplink_state(&routes);
        }
    }

    pub fn pump_handle(&self) -> Result<PumpHandle, String> {
        self.fd
            .try_clone()
            .map_err(|e| format!("cannot dup the utun descriptor: {e}"))
    }

    /// Runs after the undo stack (tunnel routes, resolver) has unwound:
    /// remove the uplink routes this run added.
    pub fn closed(&self) {
        let mut routes = self.uplink_routes.lock().unwrap();
        for r in routes.drain(..) {
            if r.ours
                && let Err(e) = route_cmd(&parsers::darwin_uplink_route_args(
                    "delete", r.family, &r.via, &r.ifscope,
                ))
            {
                log::warn!("cleanup: {e}");
            }
        }
        let _ = std::fs::remove_file(UPLINK_ROUTE_STATE);
    }
}

/// Run `route -n <args>` and judge it by its output (see
/// `parsers::darwin_route_outcome`).
fn route_cmd(args: &[String]) -> Result<RouteOutcome, String> {
    log::debug!("# route {}", args.join(" "));
    let out = std::process::Command::new("route")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("route: cannot run: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    parsers::darwin_route_outcome(out.status.success(), &text)
        .map_err(|detail| format!("route {} failed ({}): {detail}", args.join(" "), out.status))
}

/// Persist which scoped defaults are ours: `[{"family": "-inet", "ifscope":
/// "en0"}, …]`.
fn write_uplink_state(routes: &[UplinkRoute]) {
    let list: Vec<serde_json::Value> = routes
        .iter()
        .filter(|r| r.ours)
        .map(|r| serde_json::json!({"family": r.family, "ifscope": r.ifscope}))
        .collect();
    if let Some(dir) = Path::new(UPLINK_ROUTE_STATE).parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        log::warn!("cannot create {}: {e}", dir.display());
        return;
    }
    if let Err(e) = std::fs::write(
        UPLINK_ROUTE_STATE,
        serde_json::Value::Array(list).to_string(),
    ) {
        log::warn!("cannot write {UPLINK_ROUTE_STATE}: {e}");
    }
}

/// A killed run cannot delete its scoped defaults; the next start (under
/// the instance lock, so no other run is live) removes what the state file
/// names. `ensure_uplink_routes` then puts a fresh one in place.
fn sweep_stale_uplink_routes() {
    let Ok(text) = std::fs::read_to_string(UPLINK_ROUTE_STATE) else {
        return;
    };
    log::warn!("removing the uplink routes an earlier run left behind ({UPLINK_ROUTE_STATE})");
    if let Ok(serde_json::Value::Array(list)) = serde_json::from_str::<serde_json::Value>(&text) {
        for item in list {
            let (Some(family), Some(ifscope)) = (item["family"].as_str(), item["ifscope"].as_str())
            else {
                continue;
            };
            if family != "-inet" && family != "-inet6" {
                continue;
            }
            if let Err(e) = route_cmd(&parsers::darwin_uplink_route_args(
                "delete",
                family,
                &[],
                ifscope,
            )) {
                log::warn!("stale uplink route: {e}");
            }
        }
    }
    let _ = std::fs::remove_file(UPLINK_ROUTE_STATE);
}

pub async fn run_pump(transport: spora_core::IpTransport, fd: PumpHandle) -> io::Result<()> {
    spora_core::tun_util::start_fd_utun(transport, fd).await
}

/// Re-detect the default-route interfaces (excluding our own tunnel) into
/// the shared slots the protector reads.
fn refresh_uplinks(tun: &str, uplink4: &Arc<AtomicU32>, uplink6: &Arc<AtomicU32>) {
    for (family, slot) in [("inet", uplink4), ("inet6", uplink6)] {
        let idx = run_cmd_output("netstat", &svec(&["-rn", "-f", family]))
            .ok()
            .and_then(|out| parsers::darwin_netstat_default_interface(&out, tun))
            .map(|ifname| if_index(&ifname))
            .unwrap_or(0);
        let before = slot.swap(idx, Ordering::Relaxed);
        if before != idx {
            log::info!("{family} uplink interface index: {before} -> {idx}");
        }
    }
}

/// The concrete route targets for a prefix: a default route is expressed as
/// the two half-defaults so the uplink's own default stays in place.
fn half_defaults(p: Prefix) -> Vec<String> {
    if !p.is_default() {
        return vec![p.to_string()];
    }
    if p.is_ipv4() {
        vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()]
    } else {
        vec!["::/1".into(), "8000::/1".into()]
    }
}

fn bound_if(fd: i32, level: libc::c_int, opt: libc::c_int, idx: u32) -> bool {
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &idx as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    r == 0
}

fn if_index(name: &str) -> u32 {
    let Ok(c) = std::ffi::CString::new(name) else {
        return 0;
    };
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

/// Open a fresh `utun` through the kernel control socket and return its
/// descriptor and name. `sc_unit = 0` lets the kernel pick the lowest free
/// unit number.
fn open_utun() -> io::Result<(OwnedFd, String)> {
    unsafe {
        let raw = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(raw);
        let mut info: libc::ctl_info = std::mem::zeroed();
        for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL.bytes()) {
            *dst = src as libc::c_char;
        }
        if libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_ctl = std::mem::zeroed();
        addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0;
        if libc::connect(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut name = [0u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        if libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            name.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let name = String::from_utf8_lossy(&name[..end]).into_owned();
        if name.is_empty() {
            return Err(io::Error::other("utun reported an empty interface name"));
        }
        libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
        Ok((fd, name))
    }
}

fn friendly_utun_error(e: io::Error) -> String {
    if e.kind() == io::ErrorKind::PermissionDenied {
        format!("cannot create a utun interface ({e}): this needs root — run `sudo spora use …`")
    } else {
        format!("cannot create a utun interface: {e}")
    }
}

// ---------------------------------------------------------------------------
// resolver state: a small hand-rolled JSON object {"<service>": ["ip", ...]}

fn write_dns_state(previous: &[(String, Vec<String>)]) -> Result<(), String> {
    let map: serde_json::Map<String, serde_json::Value> = previous
        .iter()
        .map(|(svc, ips)| {
            (
                svc.clone(),
                serde_json::Value::Array(
                    ips.iter()
                        .map(|ip| serde_json::Value::String(ip.clone()))
                        .collect(),
                ),
            )
        })
        .collect();
    if let Some(dir) = Path::new(DNS_STATE).parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    std::fs::write(DNS_STATE, serde_json::Value::Object(map).to_string())
        .map_err(|e| format!("cannot write {DNS_STATE}: {e}"))
}

fn read_dns_state() -> Option<Vec<(String, Vec<String>)>> {
    let text = std::fs::read_to_string(DNS_STATE).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let map = value.as_object()?;
    Some(
        map.iter()
            .map(|(svc, ips)| {
                let ips = ips
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                (svc.clone(), ips)
            })
            .collect(),
    )
}

/// Put every service's resolvers back (`empty` = DHCP-supplied again).
fn restore_dns(previous: &[(String, Vec<String>)]) {
    for (svc, ips) in previous {
        let mut args = svec(&["-setdnsservers", svc]);
        if ips.is_empty() {
            args.push("empty".into());
        } else {
            args.extend(ips.iter().cloned());
        }
        if let Err(e) = run_cmd_output("networksetup", &args) {
            log::warn!("cleanup: {e}");
        }
    }
}

fn restore_stale_dns() {
    if let Some(previous) = read_dns_state() {
        log::warn!("restoring the resolver settings an earlier run left behind ({DNS_STATE})");
        restore_dns(&previous);
        let _ = std::fs::remove_file(DNS_STATE);
    }
}
