use crate::adapter::Endpoint;
use crate::adapter::check_adapter::{CheckAdapter, CheckInput};
use crate::adapter::hook_adapter::{ClaudeCodeHookAdapter, HookInput};

use super::CheckArgs;

/// Route `runok check` to the appropriate adapter based on CLI args and stdin content.
pub fn route_check(
    args: &CheckArgs,
    mut stdin: impl std::io::Read,
) -> Result<Box<dyn Endpoint>, anyhow::Error> {
    // 1. --command CLI argument → always generic mode (no stdin)
    if let Some(command) = &args.command {
        return Ok(Box::new(CheckAdapter::from_command(command.clone())));
    }

    // 2. Read stdin JSON once
    let mut stdin_input = String::new();
    stdin.read_to_string(&mut stdin_input)?;
    let json_value: serde_json::Value =
        serde_json::from_str(&stdin_input).map_err(|e| anyhow::anyhow!("JSON parse error: {e}"))?;

    // 3. --format is explicitly specified → use that format
    if let Some(format) = &args.format {
        return match format.as_str() {
            "claude-code-hook" => {
                let hook_input: HookInput = serde_json::from_value(json_value)?;
                Ok(Box::new(ClaudeCodeHookAdapter::new(hook_input)))
            }
            unknown => Err(anyhow::anyhow!(
                "Unknown format: '{unknown}'. Valid formats: claude-code-hook"
            )),
        };
    }

    // 4. --format omitted → auto-detect by JSON field presence
    //    HookInput uses #[serde(rename_all = "camelCase")], so the actual JSON key is "toolName"
    if json_value.get("toolName").is_some() {
        let hook_input: HookInput = serde_json::from_value(json_value)?;
        Ok(Box::new(ClaudeCodeHookAdapter::new(hook_input)))
    } else if json_value.get("command").is_some() {
        let check_input: CheckInput = serde_json::from_value(json_value)?;
        Ok(Box::new(CheckAdapter::from_stdin(check_input)))
    } else {
        Err(anyhow::anyhow!(
            "Unknown input format: expected 'toolName' (Claude Code hook) or 'command' (generic) field"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    /// Helper: build CheckArgs for testing
    fn check_args(command: Option<&str>, format: Option<&str>) -> CheckArgs {
        CheckArgs {
            command: command.map(String::from),
            format: format.map(String::from),
            dry_run: false,
            verbose: false,
        }
    }

    // === route_check: --command flag ===

    #[rstest]
    #[case::simple_command("git status")]
    #[case::command_with_flags("ls -la /tmp")]
    fn route_check_with_command_arg(#[case] cmd: &str) {
        let args = check_args(Some(cmd), None);
        let endpoint = route_check(&args, std::io::empty()).unwrap();
        assert_eq!(endpoint.extract_command().unwrap(), Some(cmd.to_string()));
    }

    // === route_check: stdin auto-detection ===

    #[rstest]
    #[case::claude_code_hook(
        indoc! {r#"
            {
                "toolName": "Bash",
                "sessionId": "s",
                "transcriptPath": "/tmp",
                "cwd": "/tmp",
                "permissionMode": "default",
                "hookEventName": "PreToolUse",
                "toolInput": {"command": "git status"},
                "toolUseId": "123"
            }
        "#},
        Some("git status"),
    )]
    #[case::generic_check(r#"{"command": "git status"}"#, Some("git status"))]
    fn route_check_stdin_auto_detect(
        #[case] stdin_json: &str,
        #[case] expected_command: Option<&str>,
    ) {
        let args = check_args(None, None);
        let endpoint = route_check(&args, stdin_json.as_bytes()).unwrap();
        assert_eq!(
            endpoint.extract_command().unwrap(),
            expected_command.map(String::from)
        );
    }

    #[rstest]
    fn route_check_stdin_unknown_format_returns_error() {
        let args = check_args(None, None);
        let result = route_check(&args, r#"{"unknown_field": "value"}"#.as_bytes());
        match result {
            Err(e) => assert!(
                e.to_string().contains("Unknown input format"),
                "error was: {e}"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[rstest]
    fn route_check_stdin_invalid_json_returns_error() {
        let args = check_args(None, None);
        let result = route_check(&args, "not valid json".as_bytes());
        match result {
            Err(e) => assert!(e.to_string().contains("JSON parse error"), "error was: {e}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[rstest]
    fn route_check_command_flag_takes_precedence_over_stdin() {
        // --command is specified, so stdin content is irrelevant
        let args = check_args(Some("echo hello"), Some("claude-code-hook"));
        let endpoint = route_check(&args, std::io::empty()).unwrap();
        assert_eq!(
            endpoint.extract_command().unwrap(),
            Some("echo hello".to_string())
        );
    }

    // === route_check: --format flag ===

    #[rstest]
    fn route_check_explicit_format_claude_code_hook() {
        let args = check_args(None, Some("claude-code-hook"));
        let stdin_json = indoc! {r#"
            {
                "toolName": "Bash",
                "sessionId": "s",
                "transcriptPath": "/tmp",
                "cwd": "/tmp",
                "permissionMode": "default",
                "hookEventName": "PreToolUse",
                "toolInput": {"command": "ls"},
                "toolUseId": "456"
            }
        "#};
        let endpoint = route_check(&args, stdin_json.as_bytes()).unwrap();
        assert_eq!(endpoint.extract_command().unwrap(), Some("ls".to_string()));
    }

    #[rstest]
    fn route_check_unknown_format_returns_error() {
        let args = check_args(None, Some("invalid-format"));
        let result = route_check(&args, r#"{"command": "ls"}"#.as_bytes());
        match result {
            Err(e) => assert!(
                e.to_string().contains("Unknown format: 'invalid-format'"),
                "error was: {e}"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }
}
