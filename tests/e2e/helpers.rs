// Test helpers are always called from #[test] functions but are not themselves
// annotated with #[test], so clippy's allow-*-in-tests doesn't apply.
#![allow(clippy::panic, reason = "test helper")]

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use indoc::indoc;
use tempfile::TempDir;

/// Test environment that manages a temporary directory with a `runok.yml`
/// config file and provides a pre-configured `Command` for running the
/// `runok` binary.
pub struct TestEnv {
    _tmp: TempDir,
    pub cwd: PathBuf,
    /// Isolated HOME directory to prevent global config interference.
    pub home: PathBuf,
}

impl TestEnv {
    /// Create a new test environment with the given `runok.yml` content.
    pub fn new(config_yaml: &str) -> Self {
        let tmp = TempDir::new().unwrap_or_else(|e| panic!("failed to create tempdir: {e}"));
        let cwd = tmp.path().join("project");
        let home = tmp.path().join("home");
        fs::create_dir_all(&cwd).unwrap_or_else(|e| panic!("failed to create cwd: {e}"));
        fs::create_dir_all(&home).unwrap_or_else(|e| panic!("failed to create home: {e}"));
        fs::write(cwd.join("runok.yml"), config_yaml)
            .unwrap_or_else(|e| panic!("failed to write config: {e}"));
        Self {
            _tmp: tmp,
            cwd,
            home,
        }
    }

    /// Build a `Command` for the `runok` binary, configured to run in the
    /// test environment's working directory with an isolated HOME.
    pub fn command(&self) -> Command {
        let mut cmd = assert_cmd::cargo_bin_cmd!("runok");
        cmd.current_dir(&self.cwd);
        cmd.env("HOME", &self.home);
        // Clear XDG dirs so config_dir() falls back to $HOME/.config
        cmd.env_remove("XDG_CONFIG_HOME");
        cmd.env_remove("XDG_CACHE_HOME");
        cmd
    }
}

pub fn claude_bash_hook_json(command: &str) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "transcript_path": "/tmp/transcript",
        "cwd": "/tmp",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "test-123"
    })
    .to_string()
}

pub fn codex_bash_hook_json(command: &str, hook_event_name: &str) -> String {
    let mut input = serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": hook_event_name,
        "tool_name": "Bash",
        "tool_input": {"command": command}
    });
    if hook_event_name == "PreToolUse" {
        input["tool_use_id"] = serde_json::json!("test-123");
    }
    input.to_string()
}

pub fn normalized_hook_output(output: &[u8]) -> serde_json::Value {
    let mut result: serde_json::Value =
        serde_json::from_slice(output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    let command = result
        .pointer("/hookSpecificOutput/updatedInput/command")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if let Some(command) = command {
        result["hookSpecificOutput"]["updatedInput"]["command"] =
            serde_json::Value::String(normalize_hook_origin_token(&command));
    }
    result
}

pub fn sandbox_contradiction_env() -> TestEnv {
    TestEnv::new(indoc! {"
        rules:
          - allow: 'write_tool *'
            sandbox: writable
          - allow: 'read_tool *'
            sandbox: readonly
          - allow: 'cd *'
            sandbox: writable
        definitions:
          sandbox:
            writable:
              fs:
                write:
                  allow: [./output]
            readonly:
              fs:
                write:
                  allow: []
    "})
}

/// `runok exec --hook-origin <token> --sandbox <preset> -- ...` embeds a
/// fresh token on every call, once per wrapped sub-command. Replace each with
/// a fixed placeholder so tests can still assert the wrapped command with a
/// single equality check.
pub fn normalize_hook_origin_token(command: &str) -> String {
    let re =
        regex::Regex::new(r"--hook-origin \S+").unwrap_or_else(|e| panic!("invalid regex: {e}"));
    re.replace_all(command, "--hook-origin <token>")
        .into_owned()
}
