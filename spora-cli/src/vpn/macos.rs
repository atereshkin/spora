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
//! client uses. The index is re-read whenever the tunnel reconnects, so a
//! Wi-Fi → Ethernet change is picked up on the next redial.
//!
//! Resolver: `networksetup -setdnsservers` on every enabled network service,
//! with the previous values saved to a state file first — after a crash, the
//! next start puts them back before doing anything else.
//!
//! Needs root (`sudo spora use …`): utun creation, routes, networksetup.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use super::{Options, Prefix, Undo, UndoStack, parsers, run_cmd_output, svec};

/// Where the pre-change resolver settings are kept while we run, so a later
/// start can restore them if this one never got to. A fixed system path:
/// `sudo` changes `$HOME`, and the file must be found regardless.
const DNS_STATE: &str = "/var/db/spora/dns-restore.json";
/// Held (locked) for the whole session; see `super::acquire_instance_lock`.
const INSTANCE_LOCK: &str = "/var/db/spora/use.lock";
const UTUN_CONTROL: &str = "com.apple.net.utun_control";

pub struct Backend {
    name: String,
    /// Keeps the interface alive; the pump works on a dup.
    fd: OwnedFd,
    uplink4: Arc<AtomicU32>,
    uplink6: Arc<AtomicU32>,
    /// The instance lock, held until the session ends.
    _lock: std::fs::File,
}

pub type PumpHandle = OwnedFd;

impl Backend {
    pub fn setup(opts: &Options, _undo: &mut UndoStack) -> Result<Backend, String> {
        let lock = super::acquire_instance_lock(INSTANCE_LOCK)?;
        restore_stale_dns();
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
            _lock: lock,
        };
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
        for p in routes {
            for target in half_defaults(*p) {
                let family = if p.is_ipv4() { "-inet" } else { "-inet6" };
                run_cmd_output(
                    "route",
                    &svec(&["-q", "-n", "add", family, &target, "-interface", &self.name]),
                )
                .map_err(|e| format!("cannot route {target} into {}: {e}", self.name))?;
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
    /// the protector to bind new sockets to.
    pub fn refresh_uplink(&self) {
        refresh_uplinks(&self.name, &self.uplink4, &self.uplink6);
    }

    pub fn pump_handle(&self) -> Result<PumpHandle, String> {
        self.fd
            .try_clone()
            .map_err(|e| format!("cannot dup the utun descriptor: {e}"))
    }

    pub fn closed(&self) {}
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
