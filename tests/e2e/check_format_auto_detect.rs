use indoc::indoc;
use rstest::{fixture, rstest};

use super::helpers::TestEnv;

#[fixture]
fn auto_detect_env() -> TestEnv {
    TestEnv::new(indoc! {"
        rules:
          - deny: 'rm -rf /'
            message: 'Dangerous command'
          - allow: 'git status'
    "})
}

// --- Auto-detect Claude Code hook format (toolName field present) ---

#[rstest]
fn auto_detect_claude_code_hook_format(auto_detect_env: TestEnv) {
    let hook_json = serde_json::json!({
        "sessionId": "test-session",
        "transcriptPath": "/tmp/transcript",
        "cwd": "/tmp",
        "permissionMode": "default",
        "hookEventName": "PreToolUse",
        "toolName": "Bash",
        "toolInput": {"command": "rm -rf /"},
        "toolUseId": "test-789"
    })
    .to_string();

    let assert = auto_detect_env
        .command()
        .arg("check")
        .write_stdin(hook_json)
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));

    // Should be detected as Claude Code hook format (has hookSpecificOutput)
    assert!(
        json["hookSpecificOutput"].is_object(),
        "should auto-detect as Claude Code hook format: {json}"
    );
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

// --- Auto-detect generic format (command field present, no toolName) ---

#[rstest]
fn auto_detect_generic_format(auto_detect_env: TestEnv) {
    let assert = auto_detect_env
        .command()
        .arg("check")
        .write_stdin(r#"{"command":"rm -rf /"}"#)
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));

    // Should be detected as generic format (has decision field)
    assert!(
        json["decision"].is_string(),
        "should auto-detect as generic format: {json}"
    );
    assert_eq!(json["decision"], "deny");
}

// --- Unknown JSON format (neither toolName nor command) ---

#[rstest]
fn auto_detect_unknown_json_exits_2(auto_detect_env: TestEnv) {
    let assert = auto_detect_env
        .command()
        .arg("check")
        .write_stdin(r#"{"unknown":"value"}"#)
        .assert();
    assert.code(2);
}
