//! Embed an honest source/build identity in the relay binary. Field-lab runs
//! treat the relay as a first-class artifact, so it needs the same provenance
//! guarantees as the peer executable.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SPORA_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=SPORA_BUILD_DIRTY");
    println!("cargo:rustc-env=SPORA_BUILD_TARGET={}", env("TARGET"));

    if let Ok(commit) = std::env::var("SPORA_BUILD_COMMIT") {
        println!("cargo:rustc-env=SPORA_BUILD_COMMIT={commit}");
        let dirty = std::env::var("SPORA_BUILD_DIRTY").unwrap_or_else(|_| "0".into());
        println!("cargo:rustc-env=SPORA_BUILD_DIRTY={dirty}");
        return;
    }

    for path in ["../.git/HEAD", "../.git/index"] {
        if std::path::Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(files) = git(&["ls-files"]) {
        for file in files.lines().filter(|line| !line.is_empty()) {
            println!("cargo:rerun-if-changed=../{file}");
        }
    }

    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=SPORA_BUILD_COMMIT={commit}");
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .map(|out| !out.is_empty())
        .unwrap_or(false);
    println!("cargo:rustc-env=SPORA_BUILD_DIRTY={}", u8::from(dirty));
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
