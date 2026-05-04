// Test helpers use panic! for setup failures, which is standard practice.
#![allow(clippy::panic, reason = "test helper")]

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::process::{Command as StdCommand, Stdio};

use chrono::Utc;
use indoc::indoc;
use rstest::{fixture, rstest};

use super::helpers::TestEnv;

struct AuditTestEnv {
    env: TestEnv,
    audit_dir: std::path::PathBuf,
}

impl AuditTestEnv {
    /// Create a test environment with audit logging configured.
    /// `rules_yaml` should contain only the project-level config (rules, defaults, etc).
    /// Audit config is placed in the global config file at $HOME/.config/runok/runok.yml.
    fn new(rules_yaml: &str) -> Self {
        let env = TestEnv::new(rules_yaml);
        let audit_dir = env.cwd.join("audit-logs");

        let result = Self { env, audit_dir };

        let global_config = format!(
            indoc! {"
                audit:
                  path: '{}'
            "},
            result.audit_dir.to_string_lossy()
        );
        result.write_global_config(&global_config);

        result
    }

    /// Write content to the global config file at $HOME/.config/runok/runok.yml.
    /// Creates the directory if it does not exist.
    fn write_global_config(&self, yaml: &str) {
        let global_config_dir = self
            .env
            .cwd
            .parent()
            .unwrap_or_else(|| panic!("cwd has no parent"))
            .join("home/.config/runok");
        fs::create_dir_all(&global_config_dir)
            .unwrap_or_else(|e| panic!("failed to create global config dir: {e}"));
        fs::write(global_config_dir.join("runok.yml"), yaml)
            .unwrap_or_else(|e| panic!("failed to write global config: {e}"));
    }

    fn command(&self) -> assert_cmd::Command {
        self.env.command()
    }

    fn read_audit_entries(&self) -> Vec<serde_json::Value> {
        if !self.audit_dir.exists() {
            return Vec::new();
        }
        let mut entries = Vec::new();
        let dir_entries = fs::read_dir(&self.audit_dir)
            .unwrap_or_else(|e| panic!("failed to read audit dir: {e}"));
        for entry in dir_entries {
            let entry = entry.unwrap_or_else(|e| panic!("failed to read dir entry: {e}"));
            let name = entry.file_name();
            let name = name.to_str().unwrap_or("");
            if name.starts_with("audit-") && name.ends_with(".jsonl") {
                let content = fs::read_to_string(entry.path())
                    .unwrap_or_else(|e| panic!("failed to read audit file: {e}"));
                for line in content.lines() {
                    if !line.trim().is_empty() {
                        entries.push(
                            serde_json::from_str(line)
                                .unwrap_or_else(|e| panic!("failed to parse JSONL: {e}")),
                        );
                    }
                }
            }
        }
        entries
    }

    fn audit_file_exists(&self) -> bool {
        if !self.audit_dir.exists() {
            return false;
        }
        let dir_entries = match fs::read_dir(&self.audit_dir) {
            Ok(entries) => entries,
            Err(_) => return false,
        };
        dir_entries.filter_map(Result::ok).any(|entry| {
            let name = entry.file_name();
            let name = name.to_str().unwrap_or("");
            name.starts_with("audit-") && name.ends_with(".jsonl")
        })
    }
}

fn parse_json_stdout(output: &assert_cmd::assert::Assert) -> Vec<serde_json::Value> {
    let stdout = String::from_utf8(output.get_output().stdout.clone())
        .unwrap_or_else(|e| panic!("stdout is not UTF-8: {e}"));
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("failed to parse JSON: {e}")))
        .collect()
}

// ========================================
// Fixtures
// ========================================

#[fixture]
fn allow_echo_env() -> AuditTestEnv {
    AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "})
}

#[fixture]
fn exec_audit_env() -> AuditTestEnv {
    AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm *'
    "})
}

// ========================================
// exec generates audit log
// ========================================

#[rstest]
#[case::allow(&["exec", "--", "echo", "hello"], 0, "echo hello", "allow")]
#[case::deny(&["exec", "--", "rm", "-rf", "/"], 3, "rm -rf /", "deny")]
fn exec_creates_audit_log(
    exec_audit_env: AuditTestEnv,
    #[case] args: &[&str],
    #[case] expected_code: i32,
    #[case] expected_command: &str,
    #[case] expected_action: &str,
) {
    exec_audit_env
        .command()
        .args(args)
        .assert()
        .code(expected_code);

    let entries = exec_audit_env.read_audit_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["command"], expected_command);
    assert_eq!(entries[0]["action"]["type"], expected_action);
    assert_eq!(entries[0]["metadata"]["endpoint_type"], "exec");
}

// ========================================
// audit subcommand
// ========================================

#[fixture]
fn audit_view_env() -> AuditTestEnv {
    let env = AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm *'
    "});

    // Generate some audit log entries by running commands
    env.command()
        .args(["exec", "--", "echo", "first"])
        .assert()
        .code(0);

    env.command()
        .args(["exec", "--", "rm", "-rf", "/tmp"])
        .assert()
        .code(3);

    env.command()
        .args(["exec", "--", "echo", "second"])
        .assert()
        .code(0);

    env
}

#[rstest]
fn audit_subcommand_human_format(audit_view_env: AuditTestEnv) {
    let assert = audit_view_env.command().args(["audit"]).assert().code(0);

    // Use JSON format to verify content precisely
    let json_assert = audit_view_env
        .command()
        .args(["audit", "--json"])
        .assert()
        .code(0);
    let json_entries = parse_json_stdout(&json_assert);
    assert_eq!(json_entries.len(), 3);

    // Verify human format output contains expected lines (TSV in non-TTY)
    let output = &assert.get_output().stdout;
    let stdout = String::from_utf8_lossy(output);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    // Non-TTY output is TSV: <timestamp>\t<action>\t<command>
    // Oldest first (ascending order)
    assert!(lines[0].ends_with("echo first"));
    assert!(lines[1].ends_with("rm -rf /tmp"));
    assert!(lines[2].ends_with("echo second"));
}

#[rstest]
fn audit_subcommand_json_format(audit_view_env: AuditTestEnv) {
    let assert = audit_view_env
        .command()
        .args(["audit", "--json"])
        .assert()
        .code(0);

    let json_entries = parse_json_stdout(&assert);
    assert_eq!(json_entries.len(), 3);

    // Entries are in ascending order (oldest first, newest last)
    assert_eq!(json_entries[0]["command"], "echo first");
    assert_eq!(json_entries[2]["command"], "echo second");
}

// ========================================
// Filter tests
// ========================================

#[rstest]
#[case::deny("deny", 1)]
#[case::allow("allow", 2)]
fn audit_filter_by_action(
    audit_view_env: AuditTestEnv,
    #[case] action: &str,
    #[case] expected_count: usize,
) {
    let assert = audit_view_env
        .command()
        .args(["audit", "--action", action, "--json"])
        .assert()
        .code(0);

    let json_entries = parse_json_stdout(&assert);
    assert_eq!(json_entries.len(), expected_count);
    for entry in &json_entries {
        assert_eq!(entry["action"]["type"], action);
    }
}

#[rstest]
fn audit_filter_by_command(audit_view_env: AuditTestEnv) {
    let assert = audit_view_env
        .command()
        .args(["audit", "--command", "echo", "--json"])
        .assert()
        .code(0);

    let json_entries = parse_json_stdout(&assert);
    assert_eq!(json_entries.len(), 2);
    // Both entries should be echo commands
    assert_eq!(json_entries[0]["command"], "echo first");
    assert_eq!(json_entries[1]["command"], "echo second");
}

#[rstest]
fn audit_filter_by_limit(audit_view_env: AuditTestEnv) {
    let assert = audit_view_env
        .command()
        .args(["audit", "--limit", "2", "--json"])
        .assert()
        .code(0);

    let json_entries = parse_json_stdout(&assert);
    assert_eq!(json_entries.len(), 2);
}

#[rstest]
fn audit_filter_by_since(allow_echo_env: AuditTestEnv) {
    // Run a command to generate an audit entry
    allow_echo_env
        .command()
        .args(["exec", "--", "echo", "recent"])
        .assert()
        .code(0);

    // --since 1h should include the entry we just created
    let assert = allow_echo_env
        .command()
        .args(["audit", "--since", "1h", "--json"])
        .assert()
        .code(0);

    let json_entries = parse_json_stdout(&assert);
    assert_eq!(json_entries.len(), 1);
    assert_eq!(json_entries[0]["command"], "echo recent");
}

// ========================================
// Log rotation E2E
// ========================================

#[rstest]
fn audit_rotation_deletes_old_files(allow_echo_env: AuditTestEnv) {
    let env = allow_echo_env;

    // Rewrite global config with short retention
    env.write_global_config(&format!(
        indoc! {"
            audit:
              path: '{}'
              rotation:
                retention_days: 1
        "},
        env.audit_dir.to_string_lossy()
    ));

    // Create an old audit file manually
    fs::create_dir_all(&env.audit_dir)
        .unwrap_or_else(|e| panic!("failed to create audit dir: {e}"));
    let old_date = (Utc::now() - chrono::Duration::days(5)).format("%Y-%m-%d");
    let old_file = env.audit_dir.join(format!("audit-{old_date}.jsonl"));
    let dummy_entry = r#"{"timestamp":"old","command":"echo old","action":{"type":"allow"},"sandbox_preset":null,"default_action":null,"metadata":{"endpoint_type":"exec"},"command_evaluations":[]}"#;
    fs::write(&old_file, format!("{dummy_entry}\n"))
        .unwrap_or_else(|e| panic!("failed to write old audit file: {e}"));

    assert!(old_file.exists(), "old file should exist before rotation");

    // Run a command to trigger rotation
    env.command()
        .args(["exec", "--", "echo", "trigger-rotation"])
        .assert()
        .code(0);

    // Old file should be deleted
    assert!(
        !old_file.exists(),
        "old audit file should be deleted after rotation"
    );

    // Today's file should still exist
    let today = Utc::now().format("%Y-%m-%d");
    let today_file = env.audit_dir.join(format!("audit-{today}.jsonl"));
    assert!(today_file.exists(), "today's audit file should exist");
}

// ========================================
// Non-auditable commands (E2E)
// ========================================

#[rstest]
#[case::check(&["check", "--", "echo", "hello"])]
fn non_exec_does_not_create_audit_log(allow_echo_env: AuditTestEnv, #[case] args: &[&str]) {
    allow_echo_env.command().args(args).assert().code(0);

    assert!(
        !allow_echo_env.audit_file_exists(),
        "should not create audit log files"
    );
}

// ========================================
// audit disabled E2E
// ========================================

#[rstest]
fn audit_disabled_no_log_created() {
    let env = AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "});

    env.write_global_config(&format!(
        indoc! {"
            audit:
              enabled: false
              path: '{}'
        "},
        env.audit_dir.to_string_lossy()
    ));

    env.command()
        .args(["exec", "--", "echo", "hello"])
        .assert()
        .code(0);

    assert!(
        !env.audit_file_exists(),
        "audit log should not be created when disabled"
    );
}

// ========================================
// Compound command E2E
// ========================================

#[rstest]
fn exec_compound_command_audit_log(exec_audit_env: AuditTestEnv) {
    // Pass compound command as a single argument so the parser detects &&
    exec_audit_env
        .command()
        .args(["exec", "--", "echo hello && rm -rf /tmp"])
        .assert()
        .code(3);

    let entries = exec_audit_env.read_audit_entries();
    assert_eq!(entries.len(), 1);

    let evals = entries[0]["command_evaluations"]
        .as_array()
        .unwrap_or_else(|| panic!("command_evaluations should be an array"));
    assert!(evals.len() >= 2);

    let echo_eval = evals
        .iter()
        .find(|e| e["command"].as_str().is_some_and(|c| c.starts_with("echo")));
    assert!(echo_eval.is_some(), "should have echo branch");

    let rm_eval = evals
        .iter()
        .find(|e| e["command"].as_str().is_some_and(|c| c.starts_with("rm")));
    assert!(rm_eval.is_some(), "should have rm branch");
}

// ========================================
// No config audit section defaults
// ========================================

#[rstest]
fn no_audit_config_still_works() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "});

    // Without an explicit audit config, it should still run fine
    env.command()
        .args(["exec", "--", "echo", "hello"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("hello"));
}

// ========================================
// Broken pipe handling (regression)
// ========================================

/// Regression test: closing the downstream of `runok audit --json` early
/// (e.g. piping into `head -1`) must not cause runok to panic with
/// "failed printing to stdout: Broken pipe". The process should exit
/// quietly instead.
#[rstest]
fn audit_json_does_not_panic_on_broken_pipe(allow_echo_env: AuditTestEnv) {
    // Write many audit entries directly so the JSON output is large enough
    // that the pipe buffer fills before the program finishes writing,
    // forcing an EPIPE on the second-or-later `println!`. Each entry carries
    // a ~1 KiB padded `command` field so 5000 entries produce ~5 MiB of
    // output — well above the largest default pipe buffer (Linux 64 KiB,
    // macOS 16 KiB) even after a slow process start.
    fs::create_dir_all(&allow_echo_env.audit_dir)
        .unwrap_or_else(|e| panic!("failed to create audit dir: {e}"));
    let today = Utc::now().format("%Y-%m-%d");
    let path = allow_echo_env
        .audit_dir
        .join(format!("audit-{today}.jsonl"));
    let padding: String = "x".repeat(1024);
    let mut content = String::with_capacity(5000 * 1200);
    for i in 0..5000 {
        let _ = writeln!(
            content,
            r#"{{"timestamp":"2026-01-01T00:00:00Z","command":"echo {i} {padding}","action":{{"type":"allow"}},"matched_rules":[],"sandbox_preset":null,"default_action":null,"metadata":{{"endpoint_type":"exec"}},"sub_evaluations":null}}"#
        );
    }
    fs::write(&path, content).unwrap_or_else(|e| panic!("failed to write audit file: {e}"));

    // Spawn `runok audit --json` directly (assert_cmd does not expose stdio
    // piping in a way that lets us close stdout mid-stream).
    let bin = assert_cmd::cargo::cargo_bin("runok");
    let mut child = StdCommand::new(bin)
        .args(["audit", "--json"])
        .current_dir(&allow_echo_env.env.cwd)
        .env("HOME", &allow_echo_env.env.home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn runok: {e}"));

    // Read just one byte and drop stdout so the child sees EPIPE.
    {
        let mut stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("missing stdout pipe"));
        let mut buf = [0u8; 1];
        let _ = stdout.read(&mut buf);
        // dropping stdout closes the read end of the pipe
    }

    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("failed to wait on runok: {e}"));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("panicked"),
        "runok must not panic on broken pipe; stderr was:\n{stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "runok must not surface 'Broken pipe' to the user; stderr was:\n{stderr}"
    );
}
