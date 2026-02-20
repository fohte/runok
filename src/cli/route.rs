use crate::adapter::Endpoint;
use crate::adapter::check_adapter::{CheckAdapter, CheckInput};
use crate::adapter::hook_adapter::{ClaudeCodeHookAdapter, HookInput};

use super::CheckArgs;

/// Result of routing `runok check`: either a single endpoint or multiple commands.
pub enum CheckRoute {
    /// Single endpoint (--command, JSON stdin, or single-line plaintext).
    Single(Box<dyn Endpoint>),
    /// Multiple commands from multi-line plaintext stdin.
    Multi(Vec<CheckAdapter>),
}

/// Route `runok check` to the appropriate adapter based on CLI args and stdin content.
pub fn route_check(
    args: &CheckArgs,
    mut stdin: impl std::io::Read,
) -> Result<CheckRoute, anyhow::Error> {
    // 1. --command CLI argument → always generic mode (no stdin)
    if let Some(command) = &args.command {
        return Ok(CheckRoute::Single(Box::new(CheckAdapter::from_command(
            command.clone(),
        ))));
    }

    // 2. Read stdin once
    let mut stdin_input = String::new();
    stdin.read_to_string(&mut stdin_input)?;

    // 3. Try JSON object parse first (backwards-compatible).
    //    Only JSON objects are valid protocol inputs (HookInput, CheckInput).
    //    Non-object JSON values (true, 42, "hello", []) fall through to plaintext.
    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&stdin_input)
        && json_value.is_object()
    {
        return route_json(args, json_value);
    }

    // 4. --format requires JSON; plaintext fallback is not allowed when --format is specified
    if let Some(format) = &args.format {
        return Err(anyhow::anyhow!(
            "JSON parse error: input must be valid JSON when --format '{format}' is specified"
        ));
    }

    // 5. JSON parse failed, no --format → treat as plaintext (one command per line, skip empty lines)
    let commands: Vec<String> = stdin_input
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect();

    if commands.is_empty() {
        return Err(anyhow::anyhow!("no commands provided on stdin"));
    }

    if commands.len() == 1 {
        return Ok(CheckRoute::Single(Box::new(CheckAdapter::from_command(
            commands.into_iter().next().unwrap_or_default(),
        ))));
    }

    Ok(CheckRoute::Multi(
        commands
            .into_iter()
            .map(CheckAdapter::from_command)
            .collect(),
    ))
}

/// Route JSON stdin input to the appropriate adapter.
fn route_json(
    args: &CheckArgs,
    json_value: serde_json::Value,
) -> Result<CheckRoute, anyhow::Error> {
    // --format is explicitly specified → use that format
    if let Some(format) = &args.format {
        return match format.as_str() {
            "claude-code-hook" => {
                let hook_input: HookInput = serde_json::from_value(json_value)?;
                Ok(CheckRoute::Single(Box::new(ClaudeCodeHookAdapter::new(
                    hook_input,
                ))))
            }
            unknown => Err(anyhow::anyhow!(
                "Unknown format: '{unknown}'. Valid formats: claude-code-hook"
            )),
        };
    }

    // --format omitted → auto-detect by JSON field presence
    // HookInput uses #[serde(rename_all = "camelCase")], so the actual JSON key is "toolName"
    if json_value.get("toolName").is_some() {
        let hook_input: HookInput = serde_json::from_value(json_value)?;
        Ok(CheckRoute::Single(Box::new(ClaudeCodeHookAdapter::new(
            hook_input,
        ))))
    } else if json_value.get("command").is_some() {
        let check_input: CheckInput = serde_json::from_value(json_value)?;
        Ok(CheckRoute::Single(Box::new(CheckAdapter::from_stdin(
            check_input,
        ))))
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
        }
    }

    /// Helper: extract endpoint from Single variant
    fn unwrap_single(route: CheckRoute) -> Box<dyn Endpoint> {
        match route {
            CheckRoute::Single(ep) => ep,
            CheckRoute::Multi(_) => panic!("expected Single, got Multi"),
        }
    }

    /// Helper: extract adapters from Multi variant
    fn unwrap_multi(route: CheckRoute) -> Vec<CheckAdapter> {
        match route {
            CheckRoute::Multi(adapters) => adapters,
            CheckRoute::Single(_) => panic!("expected Multi, got Single"),
        }
    }

    // === route_check: --command flag ===

    #[rstest]
    #[case::simple_command("git status")]
    #[case::command_with_flags("ls -la /tmp")]
    fn route_check_with_command_arg(#[case] cmd: &str) {
        let args = check_args(Some(cmd), None);
        let route = route_check(&args, std::io::empty());
        let endpoint = unwrap_single(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            Some(cmd.to_string())
        );
    }

    // === route_check: stdin JSON auto-detection ===

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
    fn route_check_stdin_json_auto_detect(
        #[case] stdin_json: &str,
        #[case] expected_command: Option<&str>,
    ) {
        let args = check_args(None, None);
        let route = route_check(&args, stdin_json.as_bytes());
        let endpoint = unwrap_single(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            expected_command.map(String::from)
        );
    }

    #[rstest]
    fn route_check_stdin_unknown_json_format_returns_error() {
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

    // === route_check: --format with non-JSON stdin ===

    #[rstest]
    fn route_check_format_with_non_json_stdin_returns_error() {
        let args = check_args(None, Some("claude-code-hook"));
        let result = route_check(&args, "not valid json".as_bytes());
        match result {
            Err(e) => assert!(
                e.to_string().contains("JSON parse error") && e.to_string().contains("--format"),
                "error was: {e}"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    // === route_check: non-object JSON falls through to plaintext ===

    #[rstest]
    #[case::json_true("true", "true")]
    #[case::json_number("42", "42")]
    #[case::json_string(r#""hello""#, r#""hello""#)]
    fn route_check_non_object_json_treated_as_plaintext(
        #[case] input: &str,
        #[case] expected_command: &str,
    ) {
        let args = check_args(None, None);
        let route = route_check(&args, input.as_bytes());
        let endpoint = unwrap_single(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            Some(expected_command.to_string())
        );
    }

    // === route_check: plaintext stdin ===

    #[rstest]
    fn route_check_plaintext_single_line() {
        let args = check_args(None, None);
        let route = route_check(&args, "git status\n".as_bytes());
        let endpoint = unwrap_single(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            Some("git status".to_string())
        );
    }

    #[rstest]
    fn route_check_plaintext_multi_line() {
        let args = check_args(None, None);
        let input = indoc! {"
            git status
            ls -la
            echo hello
        "};
        let route = route_check(&args, input.as_bytes());
        let adapters = unwrap_multi(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        let commands: Vec<String> = adapters
            .iter()
            .filter_map(|a| {
                a.extract_command()
                    .unwrap_or_else(|e| panic!("unexpected error: {e}"))
            })
            .collect();
        assert_eq!(commands, vec!["git status", "ls -la", "echo hello"]);
    }

    #[rstest]
    fn route_check_plaintext_skips_empty_lines() {
        let args = check_args(None, None);
        let input = indoc! {"
            git status

            ls -la

        "};
        let route = route_check(&args, input.as_bytes());
        let adapters = unwrap_multi(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        let commands: Vec<String> = adapters
            .iter()
            .filter_map(|a| {
                a.extract_command()
                    .unwrap_or_else(|e| panic!("unexpected error: {e}"))
            })
            .collect();
        assert_eq!(commands, vec!["git status", "ls -la"]);
    }

    #[rstest]
    fn route_check_plaintext_trims_whitespace() {
        let args = check_args(None, None);
        let route = route_check(&args, "  git status  \n".as_bytes());
        let endpoint = unwrap_single(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            Some("git status".to_string())
        );
    }

    #[rstest]
    fn route_check_empty_stdin_returns_error() {
        let args = check_args(None, None);
        let result = route_check(&args, "".as_bytes());
        match result {
            Err(e) => assert!(
                e.to_string().contains("no commands provided"),
                "error was: {e}"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[rstest]
    fn route_check_only_empty_lines_returns_error() {
        let args = check_args(None, None);
        let result = route_check(&args, "\n\n  \n".as_bytes());
        match result {
            Err(e) => assert!(
                e.to_string().contains("no commands provided"),
                "error was: {e}"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    // === route_check: --command flag takes precedence ===

    #[rstest]
    fn route_check_command_flag_takes_precedence_over_stdin() {
        let args = check_args(Some("echo hello"), Some("claude-code-hook"));
        let route = route_check(&args, std::io::empty());
        let endpoint = unwrap_single(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
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
        let route = route_check(&args, stdin_json.as_bytes());
        let endpoint = unwrap_single(route.unwrap_or_else(|e| panic!("unexpected error: {e}")));
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            Some("ls".to_string())
        );
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
