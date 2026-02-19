use serde::{Deserialize, Serialize};

use crate::adapter::{ActionResult, Endpoint, SandboxInfo};
use crate::config::{ActionKind, Defaults};
use crate::rules::rule_engine::Action;

/// Claude Code PreToolUse Hook input (stdin JSON).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub permission_mode: String,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_use_id: String,
}

/// Bash tool's tool_input structure.
#[derive(Debug, Deserialize)]
pub struct BashToolInput {
    pub command: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// Claude Code PreToolUse Hook response (stdout JSON).
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Deserialize))]
pub struct HookOutput {
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Deserialize))]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    pub permission_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<UpdatedInput>,
}

#[derive(Debug, Serialize, PartialEq)]
#[cfg_attr(test, derive(Deserialize))]
pub struct UpdatedInput {
    pub command: String,
}

pub struct ClaudeCodeHookAdapter {
    input: HookInput,
}

impl ClaudeCodeHookAdapter {
    pub fn new(input: HookInput) -> Self {
        Self { input }
    }

    fn parse_bash_input(&self) -> Result<BashToolInput, anyhow::Error> {
        Ok(serde_json::from_value(self.input.tool_input.clone())?)
    }

    /// Build a HookOutput for a given action result.
    /// Separated from I/O for testability.
    fn build_action_output(&self, result: &ActionResult) -> Result<HookOutput, anyhow::Error> {
        let bash_input = self.parse_bash_input()?;

        let (decision, reason, updated_input) = match &result.action {
            Action::Allow => {
                let updated = Self::sandbox_updated_input(&result.sandbox, &bash_input.command);
                ("allow", None, updated)
            }
            Action::Deny(deny_response) => ("deny", deny_response.message.clone(), None),
            Action::Ask(message) => ("ask", message.clone(), None),
            Action::Default => {
                // run() dispatches Default to handle_no_match, but handle safely.
                ("allow", None, None)
            }
        };

        Ok(Self::build_output(decision, reason, updated_input))
    }

    /// Build a HookOutput for the no-match case (Bash tool, rule didn't match).
    /// Returns `None` when tool_name is not "Bash" (nothing to output).
    fn build_no_match_output(
        &self,
        defaults: &Defaults,
    ) -> Result<Option<HookOutput>, anyhow::Error> {
        if self.input.tool_name != "Bash" {
            return Ok(None);
        }

        let decision = match defaults.action {
            Some(ActionKind::Allow) => "allow",
            Some(ActionKind::Deny) => "deny",
            Some(ActionKind::Ask) | None => "ask",
        };

        let updated_input = if decision == "allow" {
            if let Some(ref sandbox_name) = defaults.sandbox {
                let bash_input = self.parse_bash_input()?;
                Some(UpdatedInput {
                    command: Self::wrap_with_sandbox(sandbox_name, &bash_input.command),
                })
            } else {
                None
            }
        } else {
            None
        };

        Ok(Some(Self::build_output(decision, None, updated_input)))
    }

    fn build_output(
        decision: &str,
        reason: Option<String>,
        updated_input: Option<UpdatedInput>,
    ) -> HookOutput {
        HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision.to_string(),
                permission_decision_reason: reason,
                updated_input,
            },
        }
    }

    fn write_json(
        writer: &mut dyn std::io::Write,
        output: &HookOutput,
    ) -> Result<(), anyhow::Error> {
        serde_json::to_writer(writer, output)?;
        Ok(())
    }

    fn sandbox_updated_input(
        sandbox: &SandboxInfo,
        original_command: &str,
    ) -> Option<UpdatedInput> {
        match sandbox {
            SandboxInfo::Preset(Some(preset)) => Some(UpdatedInput {
                command: Self::wrap_with_sandbox(preset, original_command),
            }),
            _ => None,
        }
    }

    /// Wrap a command with `runok exec --sandbox <preset> -- <quoted_command>`.
    /// The command is shell-quoted to prevent shell metacharacters (e.g. `&&`,
    /// `||`, `;`, `|`) from being interpreted outside the sandbox.
    fn wrap_with_sandbox(preset: &str, command: &str) -> String {
        let quoted = shlex::try_quote(command).unwrap_or_else(|_| command.into());
        format!("runok exec --sandbox {preset} -- {quoted}")
    }
}

impl Endpoint for ClaudeCodeHookAdapter {
    fn extract_command(&self) -> Result<Option<String>, anyhow::Error> {
        if self.input.tool_name != "Bash" {
            return Ok(None);
        }

        let bash_input = self.parse_bash_input()?;
        Ok(Some(bash_input.command))
    }

    fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
        let output = self.build_action_output(&result)?;
        Self::write_json(&mut std::io::stdout(), &output)?;
        Ok(0)
    }

    fn handle_no_match(&self, defaults: &Defaults) -> Result<i32, anyhow::Error> {
        if let Some(output) = self.build_no_match_output(defaults)? {
            Self::write_json(&mut std::io::stdout(), &output)?;
        }
        Ok(0)
    }

    fn handle_error(&self, error: anyhow::Error) -> i32 {
        eprintln!("{error:#}");
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::SandboxInfo;
    use crate::rules::rule_engine::DenyResponse;
    use indoc::indoc;
    use rstest::rstest;
    use serde_json::json;

    fn make_hook_input(tool_name: &str, tool_input: serde_json::Value) -> HookInput {
        HookInput {
            session_id: "test-session".to_string(),
            transcript_path: "/tmp/transcript".to_string(),
            cwd: "/tmp".to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: tool_name.to_string(),
            tool_input,
            tool_use_id: "test-tool-use-id".to_string(),
        }
    }

    fn bash_tool_input(command: &str) -> serde_json::Value {
        json!({ "command": command })
    }

    fn make_output(
        decision: &str,
        reason: Option<&str>,
        updated_command: Option<&str>,
    ) -> HookOutput {
        HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: decision.to_string(),
                permission_decision_reason: reason.map(|s| s.to_string()),
                updated_input: updated_command.map(|c| UpdatedInput {
                    command: c.to_string(),
                }),
            },
        }
    }

    // --- extract_command ---

    #[rstest]
    #[case::bash_tool("Bash", bash_tool_input("git status"), Some("git status".to_string()))]
    #[case::non_bash_tool("Read", json!({"path": "/tmp/file"}), None)]
    #[case::write_tool("Write", json!({"path": "/tmp/file", "content": "hello"}), None)]
    fn extract_command_filters_by_tool_name(
        #[case] tool_name: &str,
        #[case] tool_input: serde_json::Value,
        #[case] expected: Option<String>,
    ) {
        let adapter = ClaudeCodeHookAdapter::new(make_hook_input(tool_name, tool_input));
        let result = adapter
            .extract_command()
            .unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(result, expected);
    }

    #[rstest]
    fn extract_command_invalid_bash_input_returns_error() {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", json!({"not_command": "value"})));
        assert!(adapter.extract_command().is_err());
    }

    // --- build_action_output ---

    #[rstest]
    #[case::allow(
        Action::Allow,
        SandboxInfo::Preset(None),
        make_output("allow", None, None)
    )]
    #[case::allow_with_sandbox(
        Action::Allow,
        SandboxInfo::Preset(Some("restricted".to_string())),
        make_output("allow", None, Some("runok exec --sandbox restricted -- 'git status'")),
    )]
    #[case::deny_with_message(
        Action::Deny(DenyResponse {
            message: Some("not allowed".to_string()),
            fix_suggestion: None,
            matched_rule: "rm -rf /".to_string(),
        }),
        SandboxInfo::Preset(None),
        make_output("deny", Some("not allowed"), None),
    )]
    #[case::deny_without_message(
        Action::Deny(DenyResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: "rm *".to_string(),
        }),
        SandboxInfo::Preset(None),
        make_output("deny", None, None),
    )]
    #[case::ask_with_message(
        Action::Ask(Some("please confirm".to_string())),
        SandboxInfo::Preset(None),
        make_output("ask", Some("please confirm"), None),
    )]
    #[case::ask_without_message(
        Action::Ask(None),
        SandboxInfo::Preset(None),
        make_output("ask", None, None)
    )]
    fn build_action_output_maps_action_to_hook_output(
        #[case] action: Action,
        #[case] sandbox: SandboxInfo,
        #[case] expected: HookOutput,
    ) {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("git status")));
        let result = ActionResult { action, sandbox };
        let output = adapter
            .build_action_output(&result)
            .unwrap_or_else(|e| panic!("build_action_output failed: {e}"));
        assert_eq!(output, expected);
    }

    // --- build_no_match_output ---

    #[rstest]
    fn build_no_match_output_non_bash_returns_none() {
        let adapter = ClaudeCodeHookAdapter::new(make_hook_input("Read", json!({"path": "/tmp"})));
        let output = adapter
            .build_no_match_output(&Defaults::default())
            .unwrap_or_else(|e| panic!("build_no_match_output failed: {e}"));
        assert!(output.is_none());
    }

    #[rstest]
    #[case::default_ask(None, "ask")]
    #[case::explicit_ask(Some(ActionKind::Ask), "ask")]
    #[case::explicit_allow(Some(ActionKind::Allow), "allow")]
    #[case::explicit_deny(Some(ActionKind::Deny), "deny")]
    fn build_no_match_output_bash_applies_defaults(
        #[case] default_action: Option<ActionKind>,
        #[case] expected_decision: &str,
    ) {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("some-command")));
        let defaults = Defaults {
            action: default_action,
            sandbox: None,
        };
        let output = adapter
            .build_no_match_output(&defaults)
            .unwrap_or_else(|e| panic!("build_no_match_output failed: {e}"));
        let output = output.unwrap_or_else(|| panic!("expected Some(HookOutput)"));
        assert_eq!(output, make_output(expected_decision, None, None),);
    }

    #[rstest]
    fn build_no_match_output_allow_with_default_sandbox() {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("npm install")));
        let defaults = Defaults {
            action: Some(ActionKind::Allow),
            sandbox: Some("restricted".to_string()),
        };
        let output = adapter
            .build_no_match_output(&defaults)
            .unwrap_or_else(|e| panic!("build_no_match_output failed: {e}"))
            .unwrap_or_else(|| panic!("expected Some(HookOutput)"));
        assert_eq!(
            output,
            make_output(
                "allow",
                None,
                Some("runok exec --sandbox restricted -- 'npm install'"),
            ),
        );
    }

    // --- handle_error ---

    #[rstest]
    fn handle_error_returns_exit_2() {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("git status")));
        let exit_code = adapter.handle_error(anyhow::anyhow!("test error"));
        assert_eq!(exit_code, 2);
    }

    // --- handle_action / handle_no_match exit codes ---

    #[rstest]
    fn handle_action_returns_exit_0() {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("git status")));
        let exit_code = adapter
            .handle_action(ActionResult {
                action: Action::Allow,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap_or_else(|e| panic!("handle_action failed: {e}"));
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn handle_no_match_returns_exit_0() {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("some-command")));
        let exit_code = adapter
            .handle_no_match(&Defaults::default())
            .unwrap_or_else(|e| panic!("handle_no_match failed: {e}"));
        assert_eq!(exit_code, 0);
    }

    // --- HookInput deserialization ---

    #[rstest]
    fn hook_input_deserializes_from_camel_case_json() {
        let json_str = indoc! {r#"
            {
                "sessionId": "sess-123",
                "transcriptPath": "/tmp/transcript.json",
                "cwd": "/home/user",
                "permissionMode": "default",
                "hookEventName": "PreToolUse",
                "toolName": "Bash",
                "toolInput": {"command": "git status"},
                "toolUseId": "use-456"
            }
        "#};

        let input: HookInput = serde_json::from_str(json_str)
            .unwrap_or_else(|e| panic!("deserialization failed: {e}"));
        assert_eq!(input.session_id, "sess-123");
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input["command"], "git status");
    }

    // --- HookOutput serialization ---

    #[rstest]
    fn hook_output_serializes_to_camel_case_json() {
        let output = make_output("allow", None, None);
        let json_val: serde_json::Value =
            serde_json::to_value(&output).unwrap_or_else(|e| panic!("serialization failed: {e}"));

        let expected = json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow"
            }
        });
        assert_eq!(json_val, expected);
    }

    #[rstest]
    fn hook_output_includes_optional_fields_when_present() {
        let output = make_output("deny", Some("dangerous command"), Some("safe-command"));
        let json_val: serde_json::Value =
            serde_json::to_value(&output).unwrap_or_else(|e| panic!("serialization failed: {e}"));

        let expected = json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "dangerous command",
                "updatedInput": {
                    "command": "safe-command"
                }
            }
        });
        assert_eq!(json_val, expected);
    }

    // --- sandbox_updated_input ---

    #[rstest]
    #[case::preset_some(
        SandboxInfo::Preset(Some("restricted".to_string())),
        "echo hello",
        Some("runok exec --sandbox restricted -- 'echo hello'"),
    )]
    #[case::preset_none(SandboxInfo::Preset(None), "echo hello", None)]
    #[case::merged_policy(SandboxInfo::MergedPolicy(None), "echo hello", None)]
    fn sandbox_updated_input_resolves_preset(
        #[case] sandbox: SandboxInfo,
        #[case] command: &str,
        #[case] expected_command: Option<&str>,
    ) {
        let result = ClaudeCodeHookAdapter::sandbox_updated_input(&sandbox, command);
        match expected_command {
            Some(expected) => {
                let updated = result.unwrap_or_else(|| panic!("expected Some(UpdatedInput)"));
                assert_eq!(updated.command, expected);
            }
            None => assert!(result.is_none()),
        }
    }

    // --- wrap_with_sandbox quotes shell metacharacters ---

    #[rstest]
    #[case::simple_command("ls", "runok exec --sandbox restricted -- ls")]
    #[case::command_with_spaces("git status", "runok exec --sandbox restricted -- 'git status'")]
    #[case::compound_and(
        "safe-cmd && dangerous-cmd",
        "runok exec --sandbox restricted -- 'safe-cmd && dangerous-cmd'"
    )]
    #[case::compound_pipe(
        "cat file | grep secret",
        "runok exec --sandbox restricted -- 'cat file | grep secret'"
    )]
    #[case::compound_semicolon("cmd1; cmd2", "runok exec --sandbox restricted -- 'cmd1; cmd2'")]
    fn wrap_with_sandbox_quotes_command(#[case] command: &str, #[case] expected: &str) {
        assert_eq!(
            ClaudeCodeHookAdapter::wrap_with_sandbox("restricted", command),
            expected,
        );
    }
}
