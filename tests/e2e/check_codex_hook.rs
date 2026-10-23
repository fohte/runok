use super::helpers::{codex_bash_hook_json, normalized_hook_output, sandbox_contradiction_env};
use rstest::rstest;

#[rstest]
fn codex_hook_allows_contradictory_presets_when_each_sub_command_is_wrapped() {
    let env = sandbox_contradiction_env();
    let assert = env
        .command()
        .args(["hook", "--agent", "codex"])
        .write_stdin(codex_bash_hook_json(
            "write_tool run && read_tool run",
            "PreToolUse",
        ))
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let actual = normalized_hook_output(&output);

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

#[rstest]
fn codex_permission_request_keeps_contradiction_ask_deferred() {
    let env = sandbox_contradiction_env();
    let output = env
        .command()
        .args(["hook", "--agent", "codex"])
        .write_stdin(codex_bash_hook_json(
            "write_tool run && read_tool run",
            "PermissionRequest",
        ))
        .output()
        .unwrap_or_else(|e| panic!("failed to run Codex hook: {e}"));

    assert_eq!(
        (output.status.code(), output.stdout, output.stderr),
        (Some(0), Vec::new(), Vec::new()),
    );
}

#[rstest]
fn codex_pass_keeps_contradiction_ask() {
    let env = sandbox_contradiction_env();
    let output = env
        .command()
        .args(["hook", "--agent", "codex"])
        .write_stdin(codex_bash_hook_json(
            "write_tool run && read_tool run && inspect_tool run",
            "PreToolUse",
        ))
        .output()
        .unwrap_or_else(|e| panic!("failed to run Codex hook: {e}"));
    let actual = (
        output.status.code(),
        normalized_hook_output(&output.stdout),
        output.stderr,
    );

    assert_eq!(
        actual,
        (
            Some(0),
            serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": {
                        "command": "runok exec --ask --hook-origin <token> --sandbox writable -- 'write_tool run' && runok exec --ask --hook-origin <token> --sandbox readonly -- 'read_tool run' && inspect_tool run"
                    }
                }
            }),
            Vec::new(),
        )
    );
}
