use std::io::Read;

use crate::adapter::Endpoint;
use crate::adapter::hook_adapter::{ClaudeCodeHookAdapter, HookEventKind, HookInput};

use super::HookArgs;

/// Result of routing `runok hook` stdin input.
pub enum HookRoute {
    /// PreToolUse (including inputs with no `hook_event_name`, for
    /// hand-crafted/minimal JSON): rule evaluation + permissionDecision.
    Single(Box<dyn Endpoint>),
    /// PostToolUse: ask-resolution recording only.
    PostToolUseHook(ClaudeCodeHookAdapter),
    /// Any other (e.g. future) Claude Code hook event: nothing to do. This
    /// lets settings.json register `runok hook` once and keep working as
    /// Claude Code adds new hook events, without requiring a runok upgrade
    /// first.
    NoOp,
}

/// Route `runok hook` stdin input by its `hook_event_name`.
pub fn route_hook(args: &HookArgs, mut stdin: impl Read) -> Result<HookRoute, anyhow::Error> {
    match args.agent.as_deref() {
        Some("claude-code") => {}
        Some(agent) => {
            return Err(anyhow::anyhow!(
                "Unknown agent: '{agent}'. Valid agents: claude-code"
            ));
        }
        None => {
            return Err(anyhow::anyhow!(
                "Missing required --agent flag. Valid agents: claude-code"
            ));
        }
    }

    let mut stdin_input = String::new();
    stdin.read_to_string(&mut stdin_input)?;

    let hook_input: HookInput =
        serde_json::from_str(&stdin_input).map_err(|e| anyhow::anyhow!("JSON parse error: {e}"))?;

    let adapter = ClaudeCodeHookAdapter::new(hook_input);
    Ok(match adapter.event_kind() {
        HookEventKind::PreToolUse => HookRoute::Single(Box::new(adapter)),
        HookEventKind::PostToolUse => HookRoute::PostToolUseHook(adapter),
        HookEventKind::Unknown => HookRoute::NoOp,
    })
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::*;

    fn hook_args(agent: Option<&str>) -> HookArgs {
        HookArgs {
            agent: agent.map(String::from),
            verbose: false,
        }
    }

    fn hook_json(hook_event_name: &str, command: &str) -> String {
        serde_json::json!({
            "session_id": "s",
            "transcript_path": "/tmp",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": hook_event_name,
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "123"
        })
        .to_string()
    }

    #[rstest]
    fn route_hook_pre_tool_use_routes_to_single() {
        let args = hook_args(Some("claude-code"));
        let stdin = hook_json("PreToolUse", "git status");
        let route =
            route_hook(&args, stdin.as_bytes()).unwrap_or_else(|e| panic!("unexpected error: {e}"));
        let endpoint = match route {
            HookRoute::Single(ep) => ep,
            _ => panic!("expected Single"),
        };
        assert_eq!(
            endpoint
                .extract_command()
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            Some("git status".to_string())
        );
    }

    #[rstest]
    fn route_hook_absent_event_name_routes_to_single() {
        let args = hook_args(Some("claude-code"));
        let stdin = indoc! {r#"
            {
                "session_id": "s",
                "transcript_path": "/tmp",
                "cwd": "/tmp",
                "permission_mode": "default",
                "tool_name": "Bash",
                "tool_input": {"command": "ls"}
            }
        "#};
        let route =
            route_hook(&args, stdin.as_bytes()).unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert!(matches!(route, HookRoute::Single(_)));
    }

    #[rstest]
    fn route_hook_post_tool_use_routes_to_post_hook() {
        let args = hook_args(Some("claude-code"));
        let stdin = hook_json("PostToolUse", "git push");
        let route =
            route_hook(&args, stdin.as_bytes()).unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert!(matches!(route, HookRoute::PostToolUseHook(_)));
    }

    #[rstest]
    #[case::session_start("SessionStart")]
    #[case::stop("Stop")]
    fn route_hook_unknown_event_routes_to_noop(#[case] hook_event_name: &str) {
        let args = hook_args(Some("claude-code"));
        let stdin = hook_json(hook_event_name, "git status");
        let route =
            route_hook(&args, stdin.as_bytes()).unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert!(matches!(route, HookRoute::NoOp));
    }

    #[rstest]
    fn route_hook_rejects_missing_agent() {
        let args = hook_args(None);
        let stdin = hook_json("PreToolUse", "git status");
        let result = route_hook(&args, stdin.as_bytes());
        match result {
            Err(e) => assert_eq!(
                e.to_string(),
                "Missing required --agent flag. Valid agents: claude-code"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[rstest]
    fn route_hook_rejects_unknown_agent() {
        let args = hook_args(Some("other-agent"));
        let stdin = hook_json("PreToolUse", "git status");
        let result = route_hook(&args, stdin.as_bytes());
        match result {
            Err(e) => assert_eq!(
                e.to_string(),
                "Unknown agent: 'other-agent'. Valid agents: claude-code"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[rstest]
    fn route_hook_rejects_non_json_input() {
        let args = hook_args(Some("claude-code"));
        let result = route_hook(&args, "not valid json".as_bytes());
        match result {
            Err(e) => assert_eq!(
                e.to_string(),
                "JSON parse error: expected ident at line 1 column 2"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }
}
