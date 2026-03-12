// Test helpers use panic! for setup failures, which is standard practice.
#![allow(clippy::panic, reason = "test helper")]

use std::fs;

use chrono::Utc;
use indoc::indoc;
use rstest::{fixture, rstest};
use tempfile::TempDir;

use runok::adapter::exec_adapter::ExecAdapter;
use runok::adapter::{self, RunOptions};
use runok::audit::AuditEntry;
use runok::config::parse_config;
use runok::exec::ExecError;
use runok::exec::command_executor::{
    CommandExecutor, CommandInput, DryRunResult, ExecMode, SandboxPolicy,
};

/// Mock executor that records exec calls without actually running commands.
/// This avoids the transparent-proxy exec() syscall that replaces the process.
struct MockExecutor {
    exit_code: i32,
}

impl MockExecutor {
    fn new(exit_code: i32) -> Self {
        Self { exit_code }
    }
}

impl CommandExecutor for MockExecutor {
    fn exec(
        &self,
        _command: &CommandInput,
        _sandbox: Option<&SandboxPolicy>,
    ) -> Result<i32, ExecError> {
        Ok(self.exit_code)
    }

    fn validate(&self, _command: &[String]) -> Result<(), ExecError> {
        Ok(())
    }

    fn dry_run(&self, _command: &CommandInput, _sandbox: Option<&SandboxPolicy>) -> DryRunResult {
        DryRunResult {
            program: String::new(),
            exec_mode: ExecMode::SpawnAndWait,
            is_valid: true,
            error: None,
        }
    }

    fn determine_exec_mode(
        &self,
        _sandbox: Option<&SandboxPolicy>,
        _is_compound: bool,
    ) -> ExecMode {
        ExecMode::SpawnAndWait
    }
}

#[fixture]
fn audit_dir() -> TempDir {
    TempDir::new().unwrap_or_else(|e| panic!("failed to create tempdir: {e}"))
}

fn read_audit_entries(dir: &std::path::Path) -> Vec<AuditEntry> {
    let today = Utc::now().format("%Y-%m-%d");
    let log_path = dir.join(format!("audit-{today}.jsonl"));
    if !log_path.exists() {
        return Vec::new();
    }
    let content =
        fs::read_to_string(&log_path).unwrap_or_else(|e| panic!("failed to read log file: {e}"));
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("failed to parse JSONL: {e}")))
        .collect()
}

struct AuditTestConfig {
    config: runok::config::Config,
    audit_dir: TempDir,
}

#[fixture]
fn allow_echo_audit_config(audit_dir: TempDir) -> AuditTestConfig {
    let audit_path = audit_dir.path().to_string_lossy().to_string();
    let config = parse_config(&format!(
        indoc! {"
            rules:
              - allow: 'echo *'
            audit:
              path: '{}'
        "},
        audit_path
    ))
    .unwrap_or_else(|e| panic!("failed to parse config: {e}"));
    AuditTestConfig { config, audit_dir }
}

fn echo_hello_endpoint() -> ExecAdapter {
    ExecAdapter::new(
        vec!["echo".into(), "hello".into()],
        None,
        Box::new(MockExecutor::new(0)),
    )
}

fn audit_file_exists(dir: &std::path::Path) -> bool {
    if !dir.exists() {
        return false;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    entries.filter_map(Result::ok).any(|entry| {
        let name = entry.file_name();
        let name = name.to_str().unwrap_or("");
        name.starts_with("audit-") && name.ends_with(".jsonl")
    })
}

#[rstest]
#[case::allow(
    indoc! {"
        rules:
          - allow: 'echo *'
        audit:
          path: '{}'
    "},
    vec!["echo".into(), "hello".into()],
    0,
    "echo hello",
    "allow",
)]
#[case::deny(
    indoc! {"
        rules:
          - deny: 'rm *'
        audit:
          path: '{}'
    "},
    vec!["rm".into(), "-rf".into(), "/".into()],
    3,
    "rm -rf /",
    "deny",
)]
fn exec_generates_audit_log(
    audit_dir: TempDir,
    #[case] config_template: &str,
    #[case] command_args: Vec<String>,
    #[case] expected_exit_code: i32,
    #[case] expected_command: &str,
    #[case] expected_action: &str,
) {
    let audit_path = audit_dir.path().to_string_lossy().to_string();
    let config = parse_config(&config_template.replace("{}", &audit_path))
        .unwrap_or_else(|e| panic!("failed to parse config: {e}"));

    let endpoint = ExecAdapter::new(command_args, None, Box::new(MockExecutor::new(0)));
    let options = RunOptions::default();

    let exit_code = adapter::run_with_options(&endpoint, &config, &options);
    assert_eq!(exit_code, expected_exit_code);

    let entries = read_audit_entries(audit_dir.path());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command, expected_command);
    assert_eq!(entries[0].metadata.endpoint_type, "exec");
    match expected_action {
        "allow" => assert_eq!(entries[0].action, runok::audit::SerializableAction::Allow),
        "deny" => assert!(matches!(
            entries[0].action,
            runok::audit::SerializableAction::Deny { .. }
        )),
        other => panic!("unexpected action: {other}"),
    }
}

#[rstest]
fn check_does_not_generate_audit_log(allow_echo_audit_config: AuditTestConfig) {
    let endpoint =
        runok::adapter::check_adapter::CheckAdapter::from_command("echo hello".to_owned());
    let options = RunOptions::default();

    let exit_code = adapter::run_with_options(&endpoint, &allow_echo_audit_config.config, &options);
    assert_eq!(exit_code, 0);

    assert!(!audit_file_exists(allow_echo_audit_config.audit_dir.path()));
}

#[rstest]
fn compound_command_records_sub_evaluations(audit_dir: TempDir) {
    let audit_path = audit_dir.path().to_string_lossy().to_string();
    let config = parse_config(&format!(
        indoc! {"
            rules:
              - allow: 'echo *'
              - deny: 'rm *'
            audit:
              path: '{}'
        "},
        audit_path
    ))
    .unwrap_or_else(|e| panic!("failed to parse config: {e}"));

    // Pass compound command as a single string so the parser detects &&
    let endpoint = ExecAdapter::new(
        vec!["echo hello && rm -rf /tmp".into()],
        None,
        Box::new(MockExecutor::new(0)),
    );
    let options = RunOptions::default();

    let exit_code = adapter::run_with_options(&endpoint, &config, &options);
    // Compound with a deny sub-command should result in deny
    assert_eq!(exit_code, 3);

    let entries = read_audit_entries(audit_dir.path());
    assert_eq!(entries.len(), 1);

    let sub_evals = entries[0]
        .sub_evaluations
        .as_ref()
        .unwrap_or_else(|| panic!("sub_evaluations should be Some"));
    assert!(sub_evals.len() >= 2);

    let echo_sub = sub_evals.iter().find(|s| s.command.starts_with("echo"));
    let echo_sub = echo_sub.unwrap_or_else(|| panic!("expected echo sub-evaluation"));
    assert_eq!(echo_sub.action, runok::audit::SerializableAction::Allow);

    let rm_sub = sub_evals.iter().find(|s| s.command.starts_with("rm"));
    let rm_sub = rm_sub.unwrap_or_else(|| panic!("expected rm sub-evaluation"));
    assert!(matches!(
        rm_sub.action,
        runok::audit::SerializableAction::Deny { .. }
    ));
}

#[rstest]
fn audit_disabled_does_not_generate_log(audit_dir: TempDir) {
    let audit_path = audit_dir.path().to_string_lossy().to_string();
    let config = parse_config(&format!(
        indoc! {"
            rules:
              - allow: 'echo *'
            audit:
              enabled: false
              path: '{}'
        "},
        audit_path
    ))
    .unwrap_or_else(|e| panic!("failed to parse config: {e}"));

    let endpoint = echo_hello_endpoint();
    let options = RunOptions::default();

    let exit_code = adapter::run_with_options(&endpoint, &config, &options);
    assert_eq!(exit_code, 0);

    assert!(!audit_file_exists(audit_dir.path()));
}

#[rstest]
fn no_audit_section_uses_default_behavior() {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
    "})
    .unwrap_or_else(|e| panic!("failed to parse config: {e}"));

    let endpoint = echo_hello_endpoint();
    let options = RunOptions::default();

    // Should succeed without errors even without an audit section
    let exit_code = adapter::run_with_options(&endpoint, &config, &options);
    assert_eq!(exit_code, 0);
}

#[rstest]
fn dry_run_does_not_generate_audit_log(allow_echo_audit_config: AuditTestConfig) {
    let endpoint = echo_hello_endpoint();
    let options = RunOptions {
        dry_run: true,
        verbose: false,
    };

    let exit_code = adapter::run_with_options(&endpoint, &allow_echo_audit_config.config, &options);
    assert_eq!(exit_code, 0);

    assert!(!audit_file_exists(allow_echo_audit_config.audit_dir.path()));
}

#[rstest]
fn audit_log_records_matched_rules(allow_echo_audit_config: AuditTestConfig) {
    let endpoint = echo_hello_endpoint();
    let options = RunOptions::default();

    adapter::run_with_options(&endpoint, &allow_echo_audit_config.config, &options);

    let entries = read_audit_entries(allow_echo_audit_config.audit_dir.path());
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].matched_rules.is_empty());
    assert_eq!(entries[0].matched_rules[0].action_kind, "allow");
    assert_eq!(entries[0].matched_rules[0].pattern, "echo *");
}

#[rstest]
fn audit_log_records_default_action(audit_dir: TempDir) {
    let audit_path = audit_dir.path().to_string_lossy().to_string();
    let config = parse_config(&format!(
        indoc! {"
            rules:
              - allow: 'echo *'
            defaults:
              action: deny
            audit:
              path: '{}'
        "},
        audit_path
    ))
    .unwrap_or_else(|e| panic!("failed to parse config: {e}"));

    let endpoint = ExecAdapter::new(
        vec!["ls".into(), "-la".into()],
        None,
        Box::new(MockExecutor::new(0)),
    );
    let options = RunOptions::default();

    let exit_code = adapter::run_with_options(&endpoint, &config, &options);
    assert_eq!(exit_code, 3);

    let entries = read_audit_entries(audit_dir.path());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].default_action.as_deref(), Some("deny"));
}
