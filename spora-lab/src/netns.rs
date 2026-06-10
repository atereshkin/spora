//! Named network namespaces: shell commands inside them, and "host" threads
//! pinned into them running current-thread tokio runtimes.
//!
//! Socket-binding rule: a socket lives in the netns of the thread that
//! creates it. spora-core binds sockets only from tokio tasks (verified —
//! no spawn_blocking/std::thread escape hatches), so running a peer on a
//! current-thread runtime whose thread has `setns`'d into a namespace pins
//! every socket that peer will ever create — including direct-upgrade punch
//! sockets and reconnect re-dials — into that namespace. Threads (and tokio's
//! lazily-spawned blocking pool) inherit the spawning thread's netns.

use std::ffi::CString;
use std::future::Future;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use tokio_util::sync::CancellationToken;

pub struct Netns {
    name: String,
}

impl Netns {
    /// `ip netns add <name>` — requires the harness namespaces to be set up.
    pub fn add(name: &str) -> Result<Netns, String> {
        run_checked(Command::new("ip").args(["netns", "add", name]))?;
        let ns = Netns { name: name.to_string() };
        // Every namespace gets loopback up; lots of tools assume it.
        ns.run("ip link set lo up")?;
        Ok(ns)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> String {
        format!("/run/netns/{}", self.name)
    }

    /// A `Command` that will execute inside this namespace (setns in the
    /// child between fork and exec — no `ip netns exec` indirection).
    pub fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        // Pre-build the CString: allocating after fork in a threaded process
        // can deadlock on the allocator lock.
        let path = CString::new(self.path()).unwrap();
        unsafe {
            cmd.pre_exec(move || {
                let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(fd);
                Ok(())
            });
        }
        cmd
    }

    /// Run a whitespace-splittable command line inside the namespace,
    /// returning stdout. Errors carry the command and stderr.
    pub fn run(&self, line: &str) -> Result<String, String> {
        let mut parts = line.split_whitespace();
        let prog = parts.next().ok_or("empty command")?;
        let mut cmd = self.command(prog);
        cmd.args(parts);
        run_checked(&mut cmd).map_err(|e| format!("[ns {}] {line}: {e}", self.name))
    }

    /// Move the *current thread* into this namespace. Only for dedicated
    /// host threads — never call on a thread that will outlive its purpose.
    pub fn enter(&self) -> Result<(), String> {
        enter_by_path(&self.path())
    }

    /// Spawn a "host": an OS thread pinned into this namespace running a
    /// current-thread tokio runtime. `make` receives a token cancelled by
    /// [`HostHandle::stop`]/drop; the runtime exits when either the token
    /// fires or the produced future completes.
    pub fn spawn_host<F, Fut>(&self, label: &str, make: F) -> Result<HostHandle, String>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        // The thread must NOT hold an owning `Netns`: if entry (or the spawn
        // itself) fails, dropping one would `ip netns del` a namespace the
        // topology still owns. Capture only the path.
        let ns_path = self.path();
        let label = format!("{}@{}", label, self.name);
        let thread = std::thread::Builder::new()
            .name(label.clone())
            .spawn(move || {
                if let Err(e) = enter_by_path(&ns_path) {
                    log::error!("host {label}: {e}");
                    return;
                }
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build host runtime");
                rt.block_on(async move {
                    let fut = make(token.clone());
                    tokio::select! {
                        _ = token.cancelled() => {}
                        _ = fut => {}
                    }
                });
            })
            .map_err(|e| format!("spawn host thread: {e}"))?;
        Ok(HostHandle { cancel, thread: Some(thread) })
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
    }
}

/// Owns a host thread; cancels and joins it on `stop()`/drop.
pub struct HostHandle {
    cancel: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HostHandle {
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.cancel.cancel();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// setns(CLONE_NEWNET) the current thread into the namespace at `path`.
fn enter_by_path(path: &str) -> Result<(), String> {
    let cpath = CString::new(path).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("open {}: {}", path, std::io::Error::last_os_error()));
    }
    let r = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    unsafe { libc::close(fd) };
    if r != 0 {
        return Err(format!("setns {}: {}", path, std::io::Error::last_os_error()));
    }
    Ok(())
}

fn run_checked(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
