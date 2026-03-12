// Test helpers use panic! for setup failures, which is standard practice.
#![allow(clippy::panic, reason = "test helper")]

use std::fs;

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

        // Write audit config to the global config location.
        // TestEnv creates: tmp/project (cwd) and tmp/home (HOME).
        let global_config_dir = env
            .cwd
            .parent()
            .unwrap_or_else(|| panic!("cwd has no parent"))
            .join("home/.config/runok");
        fs::create_dir_all(&global_config_dir)
            .unwrap_or_else(|e| panic!("failed to create global config dir: {e}"));
        let global_config = format!("audit:\n  path: '{}'", audit_dir.to_string_lossy());
        fs::write(global_config_dir.join("runok.yml"), global_config)
            .unwrap_or_else(|e| panic!("failed to write global config: {e}"));

        Self { env, audit_dir }
    }

    /// Create with custom global config YAML (for audit-specific settings).
    fn with_global_config(rules_yaml: &str, global_yaml: &str) -> Self {
        let env = TestEnv::new(rules_yaml);
        let audit_dir = env.cwd.join("audit-logs");

        let global_config_dir = env
            .cwd
            .parent()
            .unwrap_or_else(|| panic!("cwd has no parent"))
            .join("home/.config/runok");
        fs::create_dir_all(&global_config_dir)
            .unwrap_or_else(|e| panic!("failed to create global config dir: {e}"));
        fs::write(global_config_dir.join("runok.yml"), global_yaml)
            .unwrap_or_else(|e| panic!("failed to write global config: {e}"));

        Self { env, audit_dir }
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
// exec generates audit log
// ========================================

#[fixture]
fn exec_audit_env() -> AuditTestEnv {
    AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm *'
    "})
}

#[rstest]
fn exec_creates_audit_log_file(exec_audit_env: AuditTestEnv) {
    exec_audit_env
        .command()
        .args(["exec", "--", "echo", "hello"])
        .assert()
        .code(0);

    let today = Utc::now().format("%Y-%m-%d");
    let log_path = exec_audit_env
        .audit_dir
        .join(format!("audit-{today}.jsonl"));
    assert!(log_path.exists(), "audit log file should be created");

    let entries = exec_audit_env.read_audit_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["command"], "echo hello");
    assert_eq!(entries[0]["action"]["type"], "allow");
    assert_eq!(entries[0]["metadata"]["endpoint_type"], "exec");
}

#[rstest]
fn exec_deny_creates_audit_log(exec_audit_env: AuditTestEnv) {
    exec_audit_env
        .command()
        .args(["exec", "--", "rm", "-rf", "/"])
        .assert()
        .code(3);

    let entries = exec_audit_env.read_audit_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["command"], "rm -rf /");
    assert_eq!(entries[0]["action"]["type"], "deny");
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

    // Verify human format output contains expected lines
    let output = &assert.get_output().stdout;
    let stdout = String::from_utf8_lossy(output);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    // Each line follows the format: <timestamp> [<action>] <command>
    // Newest first: echo second, rm -rf /tmp, echo first
    assert_eq!(
        lines.iter().filter(|l| l.ends_with("echo second")).count(),
        1,
    );
    assert_eq!(
        lines.iter().filter(|l| l.ends_with("rm -rf /tmp")).count(),
        1,
    );
    assert_eq!(
        lines.iter().filter(|l| l.ends_with("echo first")).count(),
        1,
    );
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

    // Entries are in descending order (newest first)
    assert_eq!(json_entries[0]["command"], "echo second");
    assert_eq!(json_entries[2]["command"], "echo first");
}

// ========================================
// Filter tests
// ========================================

#[rstest]
fn audit_filter_by_action_deny(audit_view_env: AuditTestEnv) {
    let assert = audit_view_env
        .command()
        .args(["audit", "--action", "deny", "--json"])
        .assert()
        .code(0);

    let json_entries = parse_json_stdout(&assert);
    assert_eq!(json_entries.len(), 1);
    assert_eq!(json_entries[0]["action"]["type"], "deny");
    assert_eq!(json_entries[0]["command"], "rm -rf /tmp");
}

#[rstest]
fn audit_filter_by_action_allow(audit_view_env: AuditTestEnv) {
    let assert = audit_view_env
        .command()
        .args(["audit", "--action", "allow", "--json"])
        .assert()
        .code(0);

    let json_entries = parse_json_stdout(&assert);
    assert_eq!(json_entries.len(), 2);
    for entry in &json_entries {
        assert_eq!(entry["action"]["type"], "allow");
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
    assert_eq!(json_entries[0]["command"], "echo second");
    assert_eq!(json_entries[1]["command"], "echo first");
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
fn audit_filter_by_since() {
    let env = AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "});

    // Run a command to generate an audit entry
    env.command()
        .args(["exec", "--", "echo", "recent"])
        .assert()
        .code(0);

    // --since 1h should include the entry we just created
    let assert = env
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
fn audit_rotation_deletes_old_files() {
    let env = AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "});

    // Rewrite global config with short retention
    let global_config_dir = env
        .env
        .cwd
        .parent()
        .unwrap_or_else(|| panic!("cwd has no parent"))
        .join("home/.config/runok");
    let config = format!(
        indoc! {"
            audit:
              path: '{}'
              rotation:
                retention_days: 1
        "},
        env.audit_dir.to_string_lossy()
    );
    fs::write(global_config_dir.join("runok.yml"), config)
        .unwrap_or_else(|e| panic!("failed to write global config: {e}"));

    // Create an old audit file manually
    fs::create_dir_all(&env.audit_dir)
        .unwrap_or_else(|e| panic!("failed to create audit dir: {e}"));
    let old_date = (Utc::now() - chrono::Duration::days(5)).format("%Y-%m-%d");
    let old_file = env.audit_dir.join(format!("audit-{old_date}.jsonl"));
    let dummy_entry = r#"{"timestamp":"old","command":"echo old","action":{"type":"allow"},"matched_rules":[],"sandbox_preset":null,"default_action":null,"metadata":{"endpoint_type":"exec"},"sub_evaluations":null}"#;
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
// check does not generate audit log (E2E)
// ========================================

#[rstest]
fn check_subcommand_does_not_create_audit_log() {
    let env = AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "});

    env.command()
        .args(["check", "--", "echo", "hello"])
        .assert()
        .code(0);

    assert!(
        !env.audit_file_exists(),
        "check should not create audit log files"
    );
}

// ========================================
// audit disabled E2E
// ========================================

#[rstest]
fn audit_disabled_no_log_created() {
    let env = AuditTestEnv::with_global_config(
        indoc! {"
            rules:
              - allow: 'echo *'
        "},
        &format!(
            indoc! {"
                audit:
                  enabled: false
                  path: '{}'
            "},
            "/tmp/runok-test-disabled-audit",
        ),
    );

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
fn exec_compound_command_audit_log() {
    let env = AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm *'
    "});

    // Pass compound command as a single argument so the parser detects &&
    env.command()
        .args(["exec", "--", "echo hello && rm -rf /tmp"])
        .assert()
        .code(3);

    let entries = env.read_audit_entries();
    assert_eq!(entries.len(), 1);

    let sub_evals = entries[0]["sub_evaluations"]
        .as_array()
        .unwrap_or_else(|| panic!("sub_evaluations should be an array"));
    assert!(sub_evals.len() >= 2);

    let echo_sub = sub_evals
        .iter()
        .find(|s| s["command"].as_str().is_some_and(|c| c.starts_with("echo")));
    assert!(echo_sub.is_some(), "should have echo sub-evaluation");

    let rm_sub = sub_evals
        .iter()
        .find(|s| s["command"].as_str().is_some_and(|c| c.starts_with("rm")));
    assert!(rm_sub.is_some(), "should have rm sub-evaluation");
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
// Dry-run does not generate audit log (E2E)
// ========================================

#[rstest]
fn exec_dry_run_does_not_create_audit_log() {
    let env = AuditTestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "});

    env.command()
        .args(["exec", "--dry-run", "--", "echo", "hello"])
        .assert()
        .code(0);

    assert!(
        !env.audit_file_exists(),
        "dry-run should not create audit log files"
    );
}
