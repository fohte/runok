//! Integration tests that verify the macOS sandbox actually enforces restrictions.
//!
//! These tests use `runok exec` with sandbox presets to verify that
//! sandbox-exec (Seatbelt/SBPL) correctly enforces write restrictions,
//! write-deny paths, and read-deny paths.
//!
//! Requirements:
//! - macOS (tests are `#[cfg(target_os = "macos")]`)
//! - `/usr/bin/sandbox-exec` must be available

#![cfg(target_os = "macos")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration test helpers use expect/unwrap for brevity"
)]

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

fn skip_if_nested_sandbox() -> bool {
    std::env::var("SANDBOX_RUNTIME").is_ok()
}

/// Test environment that manages a temporary directory with a `runok.yml`
/// config file and provides a pre-configured `Command` for running the
/// `runok` binary.
struct TestEnv {
    _tmp: TempDir,
    cwd: PathBuf,
    home: PathBuf,
}

impl TestEnv {
    fn new(config_yaml: &str) -> Self {
        let tmp = TempDir::new().unwrap();
        let cwd = tmp.path().join("project");
        let home = tmp.path().join("home");
        fs::create_dir_all(&cwd).unwrap();
        fs::create_dir_all(&home).unwrap();
        fs::write(cwd.join("runok.yml"), config_yaml).unwrap();
        Self {
            _tmp: tmp,
            cwd,
            home,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = assert_cmd::cargo_bin_cmd!("runok");
        cmd.current_dir(&self.cwd);
        cmd.env("HOME", &self.home);
        cmd.env_remove("XDG_CONFIG_HOME");
        cmd.env_remove("XDG_CACHE_HOME");
        cmd
    }
}

// === write.allow: allows writes to writable root ===

#[rstest]
fn sandbox_allows_write_to_writable_root() {
    if skip_if_nested_sandbox() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();
    let test_file = canonical_dir.join("allowed_write");

    let env = TestEnv::new(&format!(
        indoc! {"
            rules:
              - allow: 'sh *'
                sandbox: writable
            definitions:
              sandbox:
                writable:
                  fs:
                    write:
                      allow:
                        - {}
        "},
        canonical_dir.display(),
    ));

    env.command()
        .args([
            "exec",
            "--",
            "sh",
            "-c",
            &format!("touch {}", test_file.display()),
        ])
        .assert()
        .code(0);

    assert!(
        test_file.exists(),
        "file should be created in writable root"
    );
}

// === write.allow: denies writes outside writable root ===

#[rstest]
fn sandbox_denies_write_outside_writable_root() {
    if skip_if_nested_sandbox() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let allowed_dir = canonical_dir.join("allowed");
    fs::create_dir(&allowed_dir).unwrap();

    let forbidden_file = canonical_dir.join("forbidden_write");

    let env = TestEnv::new(&format!(
        indoc! {"
            rules:
              - allow: 'sh *'
                sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    write:
                      allow:
                        - {}
        "},
        allowed_dir.display(),
    ));

    env.command()
        .args([
            "exec",
            "--",
            "sh",
            "-c",
            &format!("touch {}", forbidden_file.display()),
        ])
        .assert()
        .code(predicates::ord::ne(0));

    assert!(
        !forbidden_file.exists(),
        "file should not be created outside writable root"
    );
}

// === write.deny: denies writes to deny path within writable root ===

#[rstest]
fn sandbox_denies_write_to_write_deny_path() {
    if skip_if_nested_sandbox() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let git_dir = canonical_dir.join(".git");
    fs::create_dir(&git_dir).unwrap();
    let forbidden_file = git_dir.join("should_not_write");

    let env = TestEnv::new(&format!(
        indoc! {"
            rules:
              - allow: 'sh *'
                sandbox: protected
            definitions:
              sandbox:
                protected:
                  fs:
                    write:
                      allow:
                        - {}
                      deny:
                        - {}
        "},
        canonical_dir.display(),
        git_dir.display(),
    ));

    env.command()
        .args([
            "exec",
            "--",
            "sh",
            "-c",
            &format!("touch {}", forbidden_file.display()),
        ])
        .assert()
        .code(predicates::ord::ne(0));

    assert!(
        !forbidden_file.exists(),
        "file should not be created in write.deny path"
    );
}

// === read.deny: blocks file reads ===

#[rstest]
fn sandbox_read_deny_blocks_file_read() {
    if skip_if_nested_sandbox() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let secret_dir = canonical_dir.join("secrets");
    fs::create_dir(&secret_dir).unwrap();
    fs::write(secret_dir.join("key.pem"), "secret-content").unwrap();

    let normal_file = canonical_dir.join("normal.txt");
    fs::write(&normal_file, "normal-content").unwrap();

    let env = TestEnv::new(&format!(
        indoc! {"
            rules:
              - allow: 'cat *'
                sandbox: read_restricted
              - allow: 'sh *'
                sandbox: read_restricted
            definitions:
              sandbox:
                read_restricted:
                  fs:
                    read:
                      deny:
                        - {}
                    write:
                      allow:
                        - {}
        "},
        secret_dir.display(),
        canonical_dir.display(),
    ));

    // Normal file is readable
    env.command()
        .args(["exec", "--", "cat", normal_file.to_str().unwrap()])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("normal-content"));

    // Secret file is NOT readable
    env.command()
        .args([
            "exec",
            "--",
            "cat",
            secret_dir.join("key.pem").to_str().unwrap(),
        ])
        .assert()
        .code(predicates::ord::ne(0));
}

// === read.deny: blocks directory listing ===

#[rstest]
fn sandbox_read_deny_blocks_directory_listing() {
    if skip_if_nested_sandbox() {
        return;
    }

    let tmpdir = tempfile::tempdir().unwrap();
    let canonical_dir = tmpdir.path().canonicalize().unwrap();

    let protected_dir = canonical_dir.join(".ssh");
    fs::create_dir(&protected_dir).unwrap();
    fs::write(protected_dir.join("id_rsa"), "private-key").unwrap();

    let env = TestEnv::new(&format!(
        indoc! {"
            rules:
              - allow: 'ls *'
                sandbox: deny_ssh
              - allow: 'sh *'
                sandbox: deny_ssh
            definitions:
              sandbox:
                deny_ssh:
                  fs:
                    read:
                      deny:
                        - {}
        "},
        protected_dir.display(),
    ));

    env.command()
        .args(["exec", "--", "ls", protected_dir.to_str().unwrap()])
        .assert()
        .code(predicates::ord::ne(0));
}
