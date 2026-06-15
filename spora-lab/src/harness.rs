//! Suite entry point: enters the lab namespaces and runs scenarios.
//!
//! Must be called first thing from a `harness = false` test main(), while the
//! process is still single-threaded (CLONE_NEWUSER requires it).

use std::ffi::CString;
use std::io::Write as _;
use std::time::Instant;

pub struct Scenario {
    pub name: &'static str,
    pub run: fn() -> Result<(), String>,
}

/// Convenience: build a `Scenario` slice entry from a function item.
#[macro_export]
macro_rules! scenarios {
    ($($f:path),* $(,)?) => {
        &[ $( $crate::harness::Scenario { name: stringify!($f), run: $f } ),* ]
    };
}

/// Run a future to completion on a transient current-thread runtime.
/// For scenario orchestration on the main thread (channel awaits, sleeps);
/// hosts with sockets must use [`crate::netns::Netns::spawn_host`] instead.
pub fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build scenario runtime")
        .block_on(fut)
}

/// Enter the lab namespaces, then run every scenario (optionally filtered by
/// substring args), reporting results libtest-style. Returns `false` if any
/// scenario failed — the caller decides the exit code, so suites with
/// end-of-run work (the perf suite's metrics table/JSON) can still do it on
/// failure. A skip (environment cannot host the lab, or `SPORA_LAB=skip`)
/// returns `true` so `cargo test` passes — unless `SPORA_LAB=require` is set
/// (CI), in which case a skip exits 1 immediately: a silently-skipping lab
/// would certify nothing while staying green.
#[must_use = "exit non-zero when this returns false"]
pub fn lab_main(suite: &str, scenarios: &[Scenario]) -> bool {
    lab_main_with_tools(suite, scenarios, &[])
}

/// [`lab_main`] for suites needing tools beyond the baseline ip/tc/iptables
/// (e.g. the ipv6 suite's `ip6tables`); a missing extra tool skips the suite
/// the same way a missing baseline tool does.
#[must_use = "exit non-zero when this returns false"]
pub fn lab_main_with_tools(suite: &str, scenarios: &[Scenario], extra_tools: &[&str]) -> bool {
    let require = std::env::var("SPORA_LAB").as_deref() == Ok("require");
    let skip = |reason: &str| {
        if require {
            eprintln!("{suite}: cannot run but SPORA_LAB=require is set: {reason}");
            std::process::exit(1);
        }
        println!("{suite}: SKIPPED ({reason})");
    };
    if std::env::var("SPORA_LAB").as_deref() == Ok("skip") {
        println!("{suite}: SKIPPED (SPORA_LAB=skip)");
        return true;
    }
    // Make sbin tools (tc, iptables) visible regardless of the user's PATH.
    // Safe: we are single-threaded here.
    let path = std::env::var("PATH").unwrap_or_default();
    unsafe { std::env::set_var("PATH", format!("/usr/sbin:/sbin:{path}")) };

    let _ = env_logger::builder().format_timestamp_millis().try_init();

    match enter_lab_namespaces() {
        Ok(()) => {}
        // A multi-threaded process is a bug in the suite (something ran
        // before lab_main), not an environment limitation — always fail
        // loudly rather than degrade to a green skip.
        Err(NamespaceError::AlreadyThreaded(n)) => {
            eprintln!(
                "{suite}: FATAL: process already has {n} threads; lab_main must be the \
                 first thing main() does"
            );
            std::process::exit(1);
        }
        Err(NamespaceError::Environment(e)) => {
            skip(&format!("cannot enter namespaces: {e}"));
            return true;
        }
    }
    for tool in ["ip", "tc", "iptables"].iter().chain(extra_tools) {
        if !tool_exists(tool) {
            skip(&format!("missing required tool: {tool}"));
            return true;
        }
    }

    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let selected: Vec<&Scenario> = scenarios
        .iter()
        .filter(|s| filters.is_empty() || filters.iter().any(|f| s.name.contains(f.as_str())))
        .collect();

    println!("\nrunning {} scenarios ({suite})", selected.len());
    let mut failures: Vec<(String, String)> = Vec::new();
    for s in &selected {
        print!("scenario {} ... ", s.name);
        std::io::stdout().flush().ok();
        let start = Instant::now();
        let outcome = std::panic::catch_unwind(s.run)
            .unwrap_or_else(|p| Err(format!("panicked: {}", panic_msg(&p))));
        match outcome {
            Ok(()) => println!("ok ({:.1}s)", start.elapsed().as_secs_f64()),
            Err(e) => {
                println!("FAILED ({:.1}s)", start.elapsed().as_secs_f64());
                failures.push((s.name.to_string(), e));
            }
        }
    }

    if failures.is_empty() {
        println!("\n{suite}: ok. {} passed", selected.len());
        true
    } else {
        println!("\nfailures:");
        for (name, err) in &failures {
            println!("---- {name} ----\n{err}\n");
        }
        println!(
            "{suite}: FAILED. {} passed; {} failed",
            selected.len() - failures.len(),
            failures.len()
        );
        false
    }
}

fn panic_msg(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".into()
    }
}

fn tool_exists(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

enum NamespaceError {
    /// The process spawned threads before lab_main — a suite bug, not an
    /// environment limitation.
    AlreadyThreaded(usize),
    /// The environment genuinely cannot host the lab (no userns, etc.).
    Environment(String),
}

/// unshare into (user +) mount + net namespaces and prepare them:
/// - map uid/gid 0 (rootless path),
/// - make mounts private and put a tmpfs over /run so `ip netns add` works,
/// - bring up loopback in the lab root namespace.
fn enter_lab_namespaces() -> Result<(), NamespaceError> {
    let env = NamespaceError::Environment;
    let tasks = std::fs::read_dir("/proc/self/task")
        .map_err(|e| env(format!("read /proc/self/task: {e}")))?
        .count();
    if tasks != 1 {
        return Err(NamespaceError::AlreadyThreaded(tasks));
    }

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWNET;
    if euid != 0 {
        flags |= libc::CLONE_NEWUSER;
    }
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(env(format!("unshare: {}", std::io::Error::last_os_error())));
    }
    if euid != 0 {
        std::fs::write("/proc/self/setgroups", "deny")
            .map_err(|e| env(format!("write setgroups: {e}")))?;
        std::fs::write("/proc/self/uid_map", format!("0 {euid} 1"))
            .map_err(|e| env(format!("write uid_map: {e}")))?;
        std::fs::write("/proc/self/gid_map", format!("0 {egid} 1"))
            .map_err(|e| env(format!("write gid_map: {e}")))?;
    }

    // Mount changes must not propagate back to the real system.
    mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)
        .map_err(|e| env(format!("make-rprivate /: {e}")))?;
    mount(Some("tmpfs"), "/run", Some("tmpfs"), 0, None)
        .map_err(|e| env(format!("mount tmpfs /run: {e}")))?;

    let status = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .map_err(|e| env(format!("run ip: {e}")))?;
    if !status.success() {
        return Err(env("ip link set lo up failed".into()));
    }
    Ok(())
}

fn mount(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> std::io::Result<()> {
    let src = src.map(|s| CString::new(s).unwrap());
    let target = CString::new(target).unwrap();
    let fstype = fstype.map(|s| CString::new(s).unwrap());
    let data = data.map(|s| CString::new(s).unwrap());
    let r = unsafe {
        libc::mount(
            src.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            target.as_ptr(),
            fstype.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |c| c.as_ptr() as *const libc::c_void),
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
