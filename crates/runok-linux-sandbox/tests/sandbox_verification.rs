//! Integration tests that verify the Linux sandbox actually enforces restrictions.
//!
//! These tests build and run the `runok-linux-sandbox` helper binary with various
//! policies, verifying that filesystem writes, read-only subpaths, and network
//! access are properly restricted by the bubblewrap + landlock + seccomp stack.
//!
//! Requirements:
//! - Linux (tests are `#[cfg(target_os = "linux")]`)
//! - `bwrap` (bubblewrap) must be installed
//! - Kernel support for landlock (5.13+) and seccomp

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

use rstest::{fixture, rstest};

/// Path to the helper binary, provided by Cargo for integration tests.
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_runok-linux-sandbox"))
}

/// Check if bubblewrap is available on the system.
fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command inside the sandbox with the given policy JSON.
///
/// Returns the exit code of the helper binary.
fn run_sandboxed(policy_json: &str, command: &[&str]) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));

    let mut args = vec![
        "--policy".to_string(),
        policy_json.to_string(),
        "--cwd".to_string(),
        cwd.to_string_lossy().to_string(),
        "--".to_string(),
    ];
    args.extend(command.iter().map(|s| s.to_string()));

    let output = Command::new(helper_binary())
        .args(&args)
        .output()
        .expect("failed to execute helper binary");

    output.status.code().unwrap_or(1)
}

#[fixture]
fn require_bwrap() {
    if !bwrap_available() {
        eprintln!("skipping: bwrap not available");
        return;
    }
}

// === Filesystem write restrictions ===

#[rstest]
fn sandbox_denies_write_outside_writable_roots(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    // Create a subdirectory as the only writable root, so the parent tmpdir
    // is visible inside the sandbox (bwrap bind-mounts it) but not writable.
    let allowed_dir = canonical_dir.join("allowed");
    std::fs::create_dir(&allowed_dir).unwrap();

    let test_file = canonical_dir.join("should_not_exist");

    let policy = format!(
        r#"{{"writable_roots":["{}"],"read_only_subpaths":[],"network_allowed":true}}"#,
        allowed_dir.display()
    );

    let command = &["sh", "-c", &format!("touch {}", test_file.display())];
    let exit_code = run_sandboxed(&policy, command);

    assert_ne!(exit_code, 0, "write should fail outside writable_roots");
    assert!(
        !test_file.exists(),
        "file should not be created outside writable_roots"
    );
}

#[rstest]
fn sandbox_allows_write_to_writable_root(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();
    let test_file = canonical_dir.join("allowed_write_file");

    let policy = format!(
        r#"{{"writable_roots":["{}"],"read_only_subpaths":[],"network_allowed":true}}"#,
        canonical_dir.display()
    );

    let command = &["sh", "-c", &format!("touch {}", test_file.display())];
    let exit_code = run_sandboxed(&policy, command);

    assert_eq!(exit_code, 0, "write should succeed in writable_root");
    assert!(
        test_file.exists(),
        "file should be created in writable_root"
    );
}

#[rstest]
fn sandbox_denies_write_to_read_only_subpath(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    // Create a .git directory inside the writable root
    let git_dir = canonical_dir.join(".git");
    std::fs::create_dir(&git_dir).unwrap();

    let test_file = git_dir.join("should_not_write");

    // .git is an absolute path that exists; bwrap will re-bind it as read-only
    let policy = format!(
        r#"{{"writable_roots":["{}"],"read_only_subpaths":["{}"],"network_allowed":true}}"#,
        canonical_dir.display(),
        git_dir.display()
    );

    let command = &["sh", "-c", &format!("touch {}", test_file.display())];
    let exit_code = run_sandboxed(&policy, command);

    assert_ne!(
        exit_code, 0,
        "write to read_only_subpath (.git) should be denied"
    );
    assert!(
        !test_file.exists(),
        "file should not be created in read_only_subpath"
    );
}

#[rstest]
fn sandbox_allows_write_outside_read_only_subpath(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    // Create directories
    let git_dir = canonical_dir.join(".git");
    std::fs::create_dir(&git_dir).unwrap();
    let src_dir = canonical_dir.join("src");
    std::fs::create_dir(&src_dir).unwrap();

    let test_file = src_dir.join("allowed_file");

    let policy = format!(
        r#"{{"writable_roots":["{}"],"read_only_subpaths":["{}"],"network_allowed":true}}"#,
        canonical_dir.display(),
        git_dir.display()
    );

    let command = &["sh", "-c", &format!("touch {}", test_file.display())];
    let exit_code = run_sandboxed(&policy, command);

    assert_eq!(
        exit_code, 0,
        "write outside read_only_subpath should succeed"
    );
    assert!(test_file.exists(), "file should be created in src/");
}

// === Network restrictions ===

#[rstest]
fn sandbox_denies_network_when_not_allowed(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let policy = format!(
        r#"{{"writable_roots":["{}"],"read_only_subpaths":[],"network_allowed":false}}"#,
        canonical_dir.display()
    );

    // Attempt a TCP connection. With seccomp blocking socket(AF_INET, ...),
    // this should fail with EPERM.
    let command = &[
        "sh",
        "-c",
        // Use /dev/tcp which is a bash feature, or nc/curl.
        // Prefer a simple Python one-liner that attempts a socket connection
        // since it's more portable and gives clear error messages.
        "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect((\"1.1.1.1\", 80))' 2>/dev/null || exit 1",
    ];
    let exit_code = run_sandboxed(&policy, command);

    assert_ne!(
        exit_code, 0,
        "network connection should fail when network_allowed=false"
    );
}

#[rstest]
fn sandbox_allows_read_when_writes_denied(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    // Read /etc/hostname which is bind-mounted read-only by bwrap (--ro-bind / /).
    // Using a host-filesystem file avoids the --tmpfs /tmp issue where tmpdir
    // contents are hidden inside the sandbox.
    let policy = r#"{"writable_roots":[],"read_only_subpaths":[],"network_allowed":true}"#;

    let command = &["sh", "-c", "cat /etc/hostname"];
    let exit_code = run_sandboxed(policy, command);

    assert_eq!(
        exit_code, 0,
        "reading files should succeed even when writes are denied"
    );
}

// === Basic execution ===

#[rstest]
fn sandbox_runs_command_successfully(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let policy = format!(
        r#"{{"writable_roots":["{}"],"read_only_subpaths":[],"network_allowed":true}}"#,
        canonical_dir.display()
    );

    let exit_code = run_sandboxed(&policy, &["true"]);
    assert_eq!(exit_code, 0, "simple command should succeed in sandbox");
}

#[rstest]
fn sandbox_preserves_nonzero_exit_code(_require_bwrap: ()) {
    if !bwrap_available() {
        return;
    }

    let policy = r#"{"writable_roots":[],"read_only_subpaths":[],"network_allowed":true}"#;

    let exit_code = run_sandboxed(policy, &["false"]);
    assert_eq!(
        exit_code, 1,
        "should preserve exit code 1 from false command"
    );
}
