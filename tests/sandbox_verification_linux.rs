//! Integration tests that verify the Linux sandbox actually enforces restrictions.
//!
//! These tests build and run the `runok` binary with the `__sandbox-exec`
//! subcommand, verifying that filesystem writes, read-only subpaths, read-deny
//! paths, and network access are properly restricted by the bubblewrap +
//! landlock + seccomp stack.
//!
//! Requirements:
//! - Linux (tests are `#[cfg(target_os = "linux")]`)
//! - `bwrap` (bubblewrap) must be installed
//! - Kernel support for landlock (5.13+) and seccomp

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration test helpers use expect/unwrap for brevity"
)]

use std::path::PathBuf;
use std::process::Command;

use rstest::rstest;
use runok::exec::command_executor::SandboxPolicy;

/// Path to the runok binary, provided by Cargo for integration tests.
fn runok_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_runok"))
}

/// Check if bubblewrap is available on the system.
fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command inside the sandbox with the given policy.
///
/// Returns the exit code of the runok binary.
fn run_sandboxed(policy: &SandboxPolicy, command: &[&str]) -> i32 {
    let policy_json = serde_json::to_string(policy).expect("failed to serialize policy");
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));

    let mut args = vec![
        "__sandbox-exec".to_string(),
        "--policy".to_string(),
        policy_json,
        "--cwd".to_string(),
        cwd.to_string_lossy().to_string(),
        "--".to_string(),
    ];
    args.extend(command.iter().map(|s| s.to_string()));

    let output = Command::new(runok_binary())
        .args(&args)
        .output()
        .expect("failed to execute runok binary");

    output.status.code().unwrap_or(1)
}

// === Filesystem write restrictions ===

#[rstest]
fn sandbox_denies_write_outside_writable_roots() {
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

    let policy = SandboxPolicy {
        writable_roots: vec![allowed_dir],
        read_only_subpaths: vec![],
        read_deny_paths: vec![],
        network_allowed: true,
    };

    let command = &["sh", "-c", &format!("touch {}", test_file.display())];
    let exit_code = run_sandboxed(&policy, command);

    assert_ne!(exit_code, 0, "write should fail outside writable_roots");
    assert!(
        !test_file.exists(),
        "file should not be created outside writable_roots"
    );
}

#[rstest]
fn sandbox_allows_write_to_writable_root() {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();
    let test_file = canonical_dir.join("allowed_write_file");

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![],
        read_deny_paths: vec![],
        network_allowed: true,
    };

    let command = &["sh", "-c", &format!("touch {}", test_file.display())];
    let exit_code = run_sandboxed(&policy, command);

    assert_eq!(exit_code, 0, "write should succeed in writable_root");
    assert!(
        test_file.exists(),
        "file should be created in writable_root"
    );
}

#[rstest]
fn sandbox_denies_write_to_read_only_subpath() {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    // Create a .git directory inside the writable root
    let git_dir = canonical_dir.join(".git");
    std::fs::create_dir(&git_dir).unwrap();

    let test_file = git_dir.join("should_not_write");

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![git_dir],
        read_deny_paths: vec![],
        network_allowed: true,
    };

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
fn sandbox_allows_write_outside_read_only_subpath() {
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

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![git_dir],
        read_deny_paths: vec![],
        network_allowed: true,
    };

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
fn sandbox_denies_network_when_not_allowed() {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![],
        read_deny_paths: vec![],
        network_allowed: false,
    };

    // First verify python3 is available inside the sandbox, otherwise the
    // network test would pass vacuously (command-not-found != sandbox denial).
    let check_python = run_sandboxed(&policy, &["python3", "--version"]);
    if check_python != 0 {
        eprintln!("skipping: python3 not available inside sandbox");
        return;
    }

    // Attempt a TCP connection. With seccomp blocking socket(AF_INET, ...),
    // this should fail with EPERM.
    let command = &[
        "python3",
        "-c",
        "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('1.1.1.1', 80))",
    ];
    let exit_code = run_sandboxed(&policy, command);

    assert_ne!(
        exit_code, 0,
        "network connection should fail when network_allowed=false"
    );
}

// === Read access ===

#[rstest]
fn sandbox_allows_read_when_writes_denied() {
    if !bwrap_available() {
        return;
    }

    // Read /etc/hostname which is bind-mounted read-only by bwrap (--ro-bind / /).
    // Using a host-filesystem file avoids the --tmpfs /tmp issue where tmpdir
    // contents are hidden inside the sandbox.
    let policy = SandboxPolicy {
        writable_roots: vec![],
        read_only_subpaths: vec![],
        read_deny_paths: vec![],
        network_allowed: true,
    };

    let command = &["sh", "-c", "cat /etc/hostname"];
    let exit_code = run_sandboxed(&policy, command);

    assert_eq!(
        exit_code, 0,
        "reading files should succeed even when writes are denied"
    );
}

// === Read deny ===

#[rstest]
fn sandbox_read_deny_blocks_file_read() {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let secret_dir = canonical_dir.join("secrets");
    std::fs::create_dir(&secret_dir).unwrap();
    let secret_file = secret_dir.join("key.pem");
    std::fs::write(&secret_file, "secret-content").unwrap();

    let normal_file = canonical_dir.join("normal.txt");
    std::fs::write(&normal_file, "normal-content").unwrap();

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![],
        read_deny_paths: vec![secret_dir],
        network_allowed: true,
    };

    // Normal file is readable
    let exit_code = run_sandboxed(
        &policy,
        &["sh", "-c", &format!("cat {}", normal_file.display())],
    );
    assert_eq!(exit_code, 0, "reading normal file should succeed");

    // Secret file is NOT readable
    let exit_code = run_sandboxed(
        &policy,
        &["sh", "-c", &format!("cat {}", secret_file.display())],
    );
    assert_ne!(exit_code, 0, "reading read-denied file should fail");
}

#[rstest]
fn sandbox_read_deny_blocks_directory_listing() {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let protected_dir = canonical_dir.join(".ssh");
    std::fs::create_dir(&protected_dir).unwrap();
    std::fs::write(protected_dir.join("id_rsa"), "private-key").unwrap();

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![],
        read_deny_paths: vec![protected_dir.clone()],
        network_allowed: true,
    };

    let exit_code = run_sandboxed(
        &policy,
        &["sh", "-c", &format!("ls {}", protected_dir.display())],
    );
    assert_ne!(exit_code, 0, "listing read-denied directory should fail");
}

#[rstest]
fn sandbox_read_deny_does_not_affect_other_paths() {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let secret_dir = canonical_dir.join("secrets");
    std::fs::create_dir(&secret_dir).unwrap();

    let src_dir = canonical_dir.join("src");
    std::fs::create_dir(&src_dir).unwrap();
    let readable_file = src_dir.join("main.rs");
    std::fs::write(&readable_file, "fn main() {}").unwrap();

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![],
        read_deny_paths: vec![secret_dir],
        network_allowed: true,
    };

    // Files outside read-deny paths are still readable
    let exit_code = run_sandboxed(
        &policy,
        &["sh", "-c", &format!("cat {}", readable_file.display())],
    );
    assert_eq!(
        exit_code, 0,
        "reading files outside read-deny paths should succeed"
    );
}

// === Basic execution ===

#[rstest]
fn sandbox_runs_command_successfully() {
    if !bwrap_available() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let policy = SandboxPolicy {
        writable_roots: vec![canonical_dir],
        read_only_subpaths: vec![],
        read_deny_paths: vec![],
        network_allowed: true,
    };

    let exit_code = run_sandboxed(&policy, &["true"]);
    assert_eq!(exit_code, 0, "simple command should succeed in sandbox");
}

#[rstest]
fn sandbox_preserves_nonzero_exit_code() {
    if !bwrap_available() {
        return;
    }

    let policy = SandboxPolicy {
        writable_roots: vec![],
        read_only_subpaths: vec![],
        read_deny_paths: vec![],
        network_allowed: true,
    };

    let exit_code = run_sandboxed(&policy, &["false"]);
    assert_eq!(
        exit_code, 1,
        "should preserve exit code 1 from false command"
    );
}
