//! Stamps the build's identity into the binary so every connection record can
//! name exactly what produced it. Comparing results across time is worthless
//! without it — and a build made from a dirty working tree has to say so, or
//! it quietly pollutes comparisons for months.
//!
//! Everything here is best-effort: a source tree with no git, or no git
//! binary, builds fine and simply records no commit.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SPORA_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=SPORA_BUILD_DIRTY");
    println!("cargo:rustc-env=SPORA_BUILD_TARGET={}", env("TARGET"));

    // A release pipeline that builds from an archive can supply these itself.
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

    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=SPORA_BUILD_COMMIT={commit}");

    // `--porcelain` prints one line per modified path; any output at all
    // means this build does not correspond to the commit above.
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
