use super::helpers::{normalize_hook_origin_token, sandbox_contradiction_env};
use rstest::rstest;

fn bash_hook_json(command: &str) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "cwd": "/tmp",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "test-123"
    })
    .to_string()
}

#[rstest]
fn codex_hook_allows_contradictory_presets_when_each_sub_command_is_wrapped() {
    let env = sandbox_contradiction_env();
    let assert = env
        .command()
        .args(["hook", "--agent", "codex"])
        .write_stdin(bash_hook_json("write_tool run && read_tool run"))
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let mut actual: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    let command = actual["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap_or_else(|| panic!("updatedInput.command should be a string"));
    actual["hookSpecificOutput"]["updatedInput"]["command"] =
        serde_json::Value::String(normalize_hook_origin_token(command));

    assert_eq!(
        actual,
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {
                    "command": "runok exec --hook-origin <token> --sandbox writable -- 'write_tool run' && runok exec --hook-origin <token> --sandbox readonly -- 'read_tool run'"
                }
            }
        })
    );
}
