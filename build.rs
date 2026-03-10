use std::process::Command;

fn main() {
    // Version resolution priority:
    // 1. RUNOK_NIGHTLY_VERSION env var (CI nightly builds)
    // 2. Git-derived nightly version (local builds from non-release commits)
    // 3. CARGO_PKG_VERSION (crates.io installs, release-tagged commits)
    #[expect(
        clippy::expect_used,
        reason = "CARGO_PKG_VERSION is guaranteed by Cargo"
    )]
    let cargo_version =
        std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION must be set by Cargo");

    let version = std::env::var("RUNOK_NIGHTLY_VERSION")
        .ok()
        .or_else(|| git_nightly_version(&cargo_version))
        .unwrap_or(cargo_version);

    // Sanitize newlines to prevent Cargo instruction injection via env vars
    let version = version.replace(['\n', '\r'], "");
    println!("cargo::rustc-env=RUNOK_VERSION={version}");
    println!("cargo::rerun-if-env-changed=RUNOK_NIGHTLY_VERSION");
    println!("cargo::rerun-if-env-changed=CARGO_PKG_VERSION");
    println!("cargo::rerun-if-changed=.git/HEAD");
    println!("cargo::rerun-if-changed=.git/refs/tags");
    println!("cargo::rerun-if-changed=.git/packed-refs");
}

/// If we're in a git repo and HEAD is not a release-tagged commit,
/// return `{cargo_version}-nightly+{short_sha}`.
fn git_nightly_version(cargo_version: &str) -> Option<String> {
    let short_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

    // Check if HEAD is tagged with a release tag (e.g. v0.1.3)
    let release_tag = format!("v{cargo_version}");
    let is_release = Command::new("git")
        .args(["tag", "--points-at", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|line| line.trim() == release_tag)
        })
        .unwrap_or(false);

    if is_release {
        return None;
    }

    Some(format!("{cargo_version}-nightly+{short_sha}"))
}
