use indoc::indoc;
use rstest::{fixture, rstest};

use super::helpers::TestEnv;

#[fixture]
fn hook_env() -> TestEnv {
    TestEnv::new(indoc! {"
        rules:
          - deny: 'rm -rf /'
            message: 'Dangerous command'
          - allow: 'git status'
          - allow: 'echo *'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
              network:
                allow: true
    "})
}

fn bash_hook_json(command: &str) -> String {
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

fn non_bash_hook_json(tool_name: &str) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "transcript_path": "/tmp/transcript",
        "cwd": "/tmp",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {},
        "tool_use_id": "test-456"
    })
    .to_string()
}

// --- Bash tool: deny ---

#[rstest]
fn hook_bash_deny(hook_env: TestEnv) {
    let assert = hook_env
        .command()
        .args(["check", "--format", "claude-code-hook"])
        .write_stdin(bash_hook_json("rm -rf /"))
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

// --- Bash tool: allow ---

#[rstest]
fn hook_bash_allow(hook_env: TestEnv) {
    let assert = hook_env
        .command()
        .args(["check", "--format", "claude-code-hook"])
        .write_stdin(bash_hook_json("git status"))
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
    // No updatedInput for non-sandbox allow
    assert!(json["hookSpecificOutput"]["updatedInput"].is_null());
}

// --- Non-Bash tool: exit 0, no output ---

#[rstest]
#[case::read("Read")]
#[case::write("Write")]
#[case::edit("Edit")]
fn hook_non_bash_tool_no_output(hook_env: TestEnv, #[case] tool_name: &str) {
    let assert = hook_env
        .command()
        .args(["check", "--format", "claude-code-hook"])
        .write_stdin(non_bash_hook_json(tool_name))
        .assert();
    assert.code(0).stdout(predicates::str::is_empty());
}

// --- Invalid JSON: exit 2 ---

#[rstest]
fn hook_invalid_json_exits_2(hook_env: TestEnv) {
    let assert = hook_env
        .command()
        .args(["check", "--format", "claude-code-hook"])
        .write_stdin("invalid json")
        .assert();
    assert.code(2);
}

// --- Sandbox allow: updatedInput rewrite ---

#[rstest]
fn hook_sandbox_allow_rewrites_command(hook_env: TestEnv) {
    let assert = hook_env
        .command()
        .args(["check", "--format", "claude-code-hook"])
        .write_stdin(bash_hook_json("echo hello"))
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
    let updated_input = &json["hookSpecificOutput"]["updatedInput"];
    assert!(
        updated_input.is_object(),
        "updatedInput should be present for sandbox allow"
    );
    let rewritten_command = updated_input["command"]
        .as_str()
        .unwrap_or_else(|| panic!("updatedInput.command should be a string"));
    assert_eq!(
        rewritten_command,
        "runok exec --sandbox restricted -- 'echo hello'"
    );
}

// --- Bash tool: no matching rule → ask ---

#[rstest]
fn hook_bash_no_match_returns_ask(hook_env: TestEnv) {
    let assert = hook_env
        .command()
        .args(["check", "--format", "claude-code-hook"])
        .write_stdin(bash_hook_json("unknown-command --flag"))
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
}

// --- Hook event name ---

#[rstest]
fn hook_output_contains_event_name(hook_env: TestEnv) {
    let assert = hook_env
        .command()
        .args(["check", "--format", "claude-code-hook"])
        .write_stdin(bash_hook_json("git status"))
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
}
