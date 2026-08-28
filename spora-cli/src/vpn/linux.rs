//! Linux backend: a `/dev/net/tun` interface plus the wg-quick routing model.
//!
//! Routing: the tunnel routes live in their own table, and two policy rules
//! put them ahead of the main table's default route without touching it:
//!
//! ```text
//! 21327: from all lookup main suppress_prefixlength 0    # LAN etc. stay local
//! 21328: not from all fwmark 0x5350 lookup 21328         # everything else → tunnel
//! 32766: from all lookup main                            # (marked traffic lands here)
//! ```
//!
//! Outer-socket bypass: every socket spora-core opens gets `SO_MARK 0x5350`,
//! so rule 21328 skips it and it is routed by the main table — whatever its
//! destination (relay, STUN server, or the hole-punched peer). The host's own
//! default route is never modified, so the lab's "never changes a default
//! route" contract holds here too (see `docs/field-lab.md` in the lab repo).
//!
//! Resolver, best available first: systemd-resolved (`resolvectl`, per-link,
//! nothing on disk), `resolvconf` (openresolv or Debian), else `resolv.conf`
//! replaced in place with a backup (see `dns.rs`).
//!
//! Needs root (or `CAP_NET_ADMIN`, which also covers `SO_MARK`).

use std::io;
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::{Options, Prefix, Undo, UndoStack, dns, parsers, run_cmd_output, svec};

/// Mark on every outer socket; also the routing table id and the rule
/// preferences (0x5350 = "SP").
pub const FWMARK: u32 = 0x5350;
pub const TABLE: u32 = 0x5350;
pub const RULE_PREF_MAIN: u32 = 21327;
pub const RULE_PREF_TABLE: u32 = 21328;
const SRC_VALID_MARK: &str = "/proc/sys/net/ipv4/conf/all/src_valid_mark";

/// Held (locked) for the whole session; see `super::acquire_instance_lock`.
const INSTANCE_LOCK: &str = "/run/spora/use.lock";

pub struct Backend {
    name: String,
    /// The device, until the pump takes it. Closing it removes the interface.
    tun: Mutex<Option<tokio_tun::Tun>>,
    /// The instance lock, held until the session ends.
    _lock: std::fs::File,
}

pub type PumpHandle = tokio_tun::Tun;

impl Backend {
    pub fn setup(opts: &Options, _undo: &mut UndoStack) -> Result<Backend, String> {
        let lock = super::acquire_instance_lock(INSTANCE_LOCK)?;
        sweep_stale_state();
        let tun = tokio_tun::Tun::builder()
            .name("spora%d")
            .address(opts.tun_addr)
            .netmask(super::v4_netmask(opts.tun_prefix))
            .mtu(i32::from(opts.initial_mtu()))
            .up()
            .try_build()
            .map_err(friendly_tun_error)?;
        let name = tun.name().to_string();
        if let Some((a6, p6)) = opts.tun_addr6 {
            // No router on a point-to-point tunnel, and no MAC to derive a
            // link-local address from: keep the kernel's v6 autoconf quiet.
            write_sysctl(&format!("/proc/sys/net/ipv6/conf/{name}/accept_ra"), "0");
            write_sysctl(
                &format!("/proc/sys/net/ipv6/conf/{name}/addr_gen_mode"),
                "1",
            );
            run_cmd_output(
                "ip",
                &svec(&[
                    "-6",
                    "addr",
                    "add",
                    &format!("{a6}/{p6}"),
                    "dev",
                    &name,
                    "nodad",
                ]),
            )
            .map_err(|e| format!("cannot add the IPv6 address to {name}: {e}"))?;
        }
        log::info!(
            "TUN {name} up: {}/{} mtu {}",
            opts.tun_addr,
            opts.tun_prefix,
            opts.initial_mtu()
        );
        Ok(Backend {
            name,
            tun: Mutex::new(Some(tun)),
            _lock: lock,
        })
    }

    pub fn tun_name(&self) -> &str {
        &self.name
    }

    pub fn protector(&self) -> spora_core::SocketProtector {
        Some(Arc::new(|fd: spora_core::SocketHandle| {
            let mark: u32 = FWMARK;
            let r = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if r != 0 {
                log::warn!(
                    "SO_MARK on fd {fd} failed ({}): this socket may be routed into the tunnel",
                    io::Error::last_os_error()
                );
            }
        }))
    }

    pub fn install_routes(
        &self,
        _opts: &Options,
        routes: &[Prefix],
        undo: &mut UndoStack,
    ) -> Result<(), String> {
        // Reverse-path filtering must take the mark into account, or the
        // marked sockets' replies arriving on the uplink fail the check.
        // Set but — like wg-quick — never restored: it is global shared
        // state, and flipping it back would break any other mark-routing
        // VPN brought up while we ran.
        match std::fs::read_to_string(SRC_VALID_MARK) {
            Ok(cur) if cur.trim() != "1" => {
                if let Err(e) = std::fs::write(SRC_VALID_MARK, "1") {
                    log::warn!("cannot set {SRC_VALID_MARK}=1: {e}");
                }
            }
            _ => {}
        }
        let table = TABLE.to_string();
        for family in ["-4", "-6"] {
            let mine: Vec<&Prefix> = routes
                .iter()
                .filter(|p| (family == "-4") == p.is_ipv4())
                .collect();
            if mine.is_empty() {
                continue;
            }
            for p in mine {
                run_cmd_output(
                    "ip",
                    &svec(&[
                        family,
                        "route",
                        "add",
                        &p.to_string(),
                        "dev",
                        &self.name,
                        "table",
                        &table,
                    ]),
                )
                .map_err(|e| format!("cannot route {p} into {}: {e}", self.name))?;
            }
            undo.push(Undo::Cmd(svec(&[
                "ip", family, "route", "flush", "table", &table,
            ])));
            run_cmd_output(
                "ip",
                &svec(&[
                    family,
                    "rule",
                    "add",
                    "pref",
                    &RULE_PREF_MAIN.to_string(),
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ]),
            )
            .map_err(|e| format!("cannot add the policy rule: {e}"))?;
            undo.push(Undo::Cmd(svec(&[
                "ip",
                family,
                "rule",
                "del",
                "pref",
                &RULE_PREF_MAIN.to_string(),
            ])));
            run_cmd_output(
                "ip",
                &svec(&[
                    family,
                    "rule",
                    "add",
                    "pref",
                    &RULE_PREF_TABLE.to_string(),
                    "not",
                    "fwmark",
                    &format!("{FWMARK:#x}"),
                    "table",
                    &table,
                ]),
            )
            .map_err(|e| format!("cannot add the policy rule: {e}"))?;
            undo.push(Undo::Cmd(svec(&[
                "ip",
                family,
                "rule",
                "del",
                "pref",
                &RULE_PREF_TABLE.to_string(),
            ])));
        }
        Ok(())
    }

    pub fn set_dns(&self, opts: &Options, undo: &mut UndoStack) -> Result<&'static str, String> {
        let servers: Vec<String> = opts.dns.iter().map(ToString::to_string).collect();

        // 1. systemd-resolved: per-link resolvers, every domain routed to
        //    this link, nothing on disk; `revert` undoes it. Only when
        //    resolved actually serves the host's lookups — resolvectl
        //    "succeeds" even when an admin replaced resolv.conf with a
        //    static file, and our setting would then change nothing.
        if Path::new("/run/systemd/resolve").is_dir()
            && has_cmd("resolvectl")
            && resolved_owns_resolv_conf()
        {
            let mut args = svec(&["dns", &self.name]);
            args.extend(servers.iter().cloned());
            match run_cmd_output("resolvectl", &args) {
                Ok(_) => {
                    undo.push(Undo::Cmd(svec(&["resolvectl", "revert", &self.name])));
                    run_cmd_output("resolvectl", &svec(&["domain", &self.name, "~."]))
                        .map_err(|e| format!("resolvectl domain: {e}"))?;
                    // Newer systemd; older ones infer it from `~.`.
                    if let Err(e) =
                        run_cmd_output("resolvectl", &svec(&["default-route", &self.name, "yes"]))
                    {
                        log::debug!("resolvectl default-route not supported: {e}");
                    }
                    return Ok("resolvectl");
                }
                Err(e) => log::warn!(
                    "systemd-resolved is present but unusable ({e}); trying the next resolver method"
                ),
            }
        }

        // 2. resolvconf (openresolv, or Debian's): a record for this
        //    interface, removed with `-d`.
        if has_cmd("resolvconf") {
            let record = format!("{}{}", resolvconf_record_prefix(), self.name);
            let mut args = svec(&["-a", &record]);
            if is_openresolv() {
                // Metric 0 and exclusive: ours win over the uplink's.
                args.extend(svec(&["-m", "0", "-x"]));
            }
            let stdin: String = servers
                .iter()
                .map(|s| format!("nameserver {s}\n"))
                .collect();
            match run_with_stdin("resolvconf", &args, &stdin) {
                // resolvconf can "succeed" without effect when resolv.conf
                // is not actually under its management (a plain file written
                // by something else): check that our resolvers landed.
                Ok(()) if resolv_conf_lists(&servers) => {
                    undo.push(Undo::Cmd(svec(&["resolvconf", "-d", &record])));
                    return Ok("resolvconf");
                }
                Ok(()) => {
                    log::info!(
                        "resolvconf accepted the record but {} did not change (not managed by it); rewriting the file instead",
                        dns::RESOLV_CONF
                    );
                    let _ = run_cmd_output("resolvconf", &svec(&["-d", &record]));
                }
                Err(e) => log::warn!(
                    "resolvconf is present but unusable ({e}); rewriting resolv.conf instead"
                ),
            }
        }

        // 3. The file itself.
        let backups: Vec<&Path> = dns::RESOLV_BACKUPS.iter().map(Path::new).collect();
        let u = dns::replace_resolv_conf(Path::new(dns::RESOLV_CONF), &backups, &opts.dns)
            .map_err(|e| format!("cannot rewrite {}: {e}", dns::RESOLV_CONF))?;
        undo.push(u);
        Ok("resolv.conf")
    }

    pub fn set_mtu(&self, mtu: u16) -> Result<(), String> {
        run_cmd_output(
            "ip",
            &svec(&["link", "set", "dev", &self.name, "mtu", &mtu.to_string()]),
        )
        .map(|_| ())
        .map_err(|e| format!("cannot set the MTU of {}: {e}", self.name))
    }

    pub fn refresh_uplink(&self) {}

    pub fn pump_handle(&self) -> Result<PumpHandle, String> {
        self.tun
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| "the TUN device was already handed to a pump".to_string())
    }

    pub fn closed(&self) {
        // Drop the device if the pump never took it, so the interface goes
        // away with the session rather than at process exit.
        self.tun.lock().unwrap().take();
    }
}

pub async fn run_pump(transport: spora_core::IpTransport, tun: PumpHandle) -> io::Result<()> {
    spora_core::tun_util::start(transport, tun).await
}

/// Remove what an earlier run that died without cleaning up left behind:
/// our policy rules and table (the interface itself dies with its process),
/// and a replaced resolv.conf.
fn sweep_stale_state() {
    let table = TABLE.to_string();
    for family in ["-4", "-6"] {
        if let Ok(out) = run_cmd_output("ip", &svec(&[family, "rule", "show"])) {
            // Match the rule BODY as well as the preference: deleting by
            // pref alone would take out an unrelated tool's rule that
            // happens to sit at the same number.
            for (pref, body) in parsers::ip_rules(&out) {
                let ours = (pref == RULE_PREF_MAIN && body.contains("suppress_prefixlength 0"))
                    || (pref == RULE_PREF_TABLE && body.contains("0x5350"));
                if ours {
                    log::warn!("removing a stale policy rule (pref {pref}) from an earlier run");
                    let _ = run_cmd_output(
                        "ip",
                        &svec(&[family, "rule", "del", "pref", &pref.to_string()]),
                    );
                }
            }
        }
        let _ = std::process::Command::new("ip")
            .args([family, "route", "flush", "table", &table])
            .stdin(std::process::Stdio::null())
            .output();
    }
    for backup in dns::RESOLV_BACKUPS {
        match dns::restore_stale_backup(Path::new(dns::RESOLV_CONF), Path::new(backup)) {
            Ok(true) => log::warn!(
                "restored {} from the backup an earlier run left behind at {backup}",
                dns::RESOLV_CONF
            ),
            Ok(false) => {}
            Err(e) => log::warn!("checking for a stale {} backup: {e}", dns::RESOLV_CONF),
        }
    }
}

fn friendly_tun_error(e: tokio_tun::Error) -> String {
    let text = e.to_string();
    if text.contains("Operation not permitted") || text.contains("Permission denied") {
        format!(
            "cannot create a TUN device ({text}): this needs root (CAP_NET_ADMIN) — run `sudo spora use …`, or attach to a pre-configured interface with --tun-name"
        )
    } else {
        format!("cannot create a TUN device: {text}")
    }
}

fn write_sysctl(path: &str, value: &str) {
    if let Err(e) = std::fs::write(path, value) {
        log::debug!("sysctl {path}={value}: {e}");
    }
}

/// Whether `name` is an executable somewhere on PATH (plus the sbin
/// directories a reduced `sudo` PATH may lack).
fn has_cmd(name: &str) -> bool {
    let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    for extra in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
        dirs.push(extra.into());
    }
    dirs.iter().any(|d| d.join(name).is_file())
}

/// Debian's resolvconf orders records by `/etc/resolvconf/interface-order`,
/// where `tun*` outranks the uplink; naming ours `tun.<iface>` makes our
/// resolvers come first (the wg-quick trick). openresolv ignores the name.
fn resolvconf_record_prefix() -> &'static str {
    match std::fs::read_to_string("/etc/resolvconf/interface-order") {
        Ok(text) if text.lines().any(|l| l.trim() == "tun*") => "tun.",
        _ => "",
    }
}

/// Whether `/etc/resolv.conf` currently names every one of `servers` — or
/// only loopback resolvers, which is what a resolvconf-fed local forwarder
/// (dnsmasq/unbound) looks like: the forwarder's upstreams were just set to
/// our servers, and the file legitimately keeps pointing at 127.0.0.1.
fn resolv_conf_lists(servers: &[String]) -> bool {
    let Ok(text) = std::fs::read_to_string(dns::RESOLV_CONF) else {
        return false;
    };
    let listed: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(str::trim)
        .collect();
    if servers.iter().all(|s| listed.contains(&s.as_str())) {
        return true;
    }
    !listed.is_empty()
        && listed.iter().all(|l| {
            l.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
}

/// Whether the host's lookups actually go through systemd-resolved: its
/// resolv.conf resolves into `/run/systemd/resolve/`, or names the
/// 127.0.0.53 stub.
fn resolved_owns_resolv_conf() -> bool {
    let by_link = match std::fs::canonicalize(dns::RESOLV_CONF) {
        Ok(real) => real.starts_with("/run/systemd/resolve"),
        Err(_) => std::fs::read_link(dns::RESOLV_CONF)
            .map(|t| t.to_string_lossy().contains("systemd/resolve"))
            .unwrap_or(false),
    };
    by_link
        || std::fs::read_to_string(dns::RESOLV_CONF)
            .map(|text| {
                text.lines()
                    .filter_map(|l| l.trim().strip_prefix("nameserver"))
                    .any(|v| v.trim() == "127.0.0.53")
            })
            .unwrap_or(false)
}

fn is_openresolv() -> bool {
    run_cmd_output("resolvconf", &svec(&["--version"]))
        .map(|out| out.to_ascii_lowercase().contains("openresolv"))
        .unwrap_or(false)
}

fn run_with_stdin(program: &str, args: &[String], stdin: &str) -> Result<(), String> {
    log::debug!("# {} {} <<< {:?}", program, args.join(" "), stdin);
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: cannot run: {e}"))?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin.as_bytes())
            .map_err(|e| format!("{program}: writing stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(())
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
