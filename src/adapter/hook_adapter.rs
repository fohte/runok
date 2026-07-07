use serde::{Deserialize, Serialize};

use crate::adapter::{ActionResult, Endpoint, SandboxInfo};
use crate::audit::{ApprovedToolUse, AuditMetadata, record_approval};
use crate::config::{ActionKind, Config, Defaults};
use crate::rules::rule_engine::{Action, DenyResponse};

/// Claude Code hook input (stdin JSON), for both PreToolUse and PostToolUse
/// events. PostToolUse carries extra fields (`tool_response`, `duration_ms`,
/// etc.) that are ignored here.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(PartialEq))]
pub struct HookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub permission_mode: String,
    /// Absent inputs are treated as PreToolUse.
    pub hook_event_name: Option<String>,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_use_id: Option<String>,
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

/// Build a combined reason string from a `DenyResponse`, including
/// the matched rule, optional message, and optional fix suggestion.
fn build_deny_reason(deny: &DenyResponse) -> String {
    let mut reason = if deny.matched_rule.is_empty() {
        "command denied by default policy".to_string()
    } else {
        format!("denied: {}", deny.matched_rule)
    };
    if let Some(ref message) = deny.message {
        reason.push_str(&format!(" ({})", message));
    }
    if let Some(ref suggestion) = deny.fix_suggestion {
        reason.push_str(&format!(" [suggestion: {}]", suggestion));
    }
    reason
}

impl ClaudeCodeHookAdapter {
    pub fn new(input: HookInput) -> Self {
        Self { input }
    }

    /// Whether the input is a PostToolUse event, which is handled by
    /// [`Self::handle_post_tool_use`] instead of the rule-evaluation flow.
    pub fn is_post_tool_use(&self) -> bool {
        self.input.hook_event_name.as_deref() == Some("PostToolUse")
    }

    /// Handle a PostToolUse hook invocation: when this tool call corresponds
    /// to an ask decision runok made at PreToolUse time, record that the
    /// user approved it.
    ///
    /// Never writes to stdout and always exits 0. PostToolUse fires after
    /// the command already ran, so nothing runok reports can change the
    /// session; failures only go to stderr (fail-open, the same policy as
    /// audit log writes).
    pub fn handle_post_tool_use(&self, config: &Config) -> i32 {
        if let Err(e) = self.record_ask_resolution(config) {
            eprintln!("runok: warning: ask resolution record failed: {e:#}");
        }
        0
    }

    fn record_ask_resolution(&self, config: &Config) -> Result<(), anyhow::Error> {
        if self.input.tool_name != "Bash" {
            return Ok(());
        }
        let audit_config = config.audit.clone().unwrap_or_default();
        if !audit_config.is_enabled() {
            return Ok(());
        }
        let bash_input = self.parse_bash_input()?;
        record_approval(
            &audit_config,
            &ApprovedToolUse {
                tool_use_id: self.input.tool_use_id.clone(),
                session_id: self.input.session_id.clone(),
                cwd: self.input.cwd.clone(),
                executed_command: bash_input.command,
            },
        )?;
        Ok(())
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
                let updated = Self::sandbox_updated_input(&result.sandbox, &bash_input.command)?;
                ("allow", None, updated)
            }
            Action::Deny(deny_response) => {
                let reason = build_deny_reason(deny_response);
                ("deny", Some(reason), None)
            }
            Action::Ask(message) => {
                // When the user approves an ask, Claude Code executes the updatedInput
                // command, so we need to wrap it with the sandbox just like allow.
                let updated = Self::sandbox_updated_input(&result.sandbox, &bash_input.command)?;
                ("ask", message.clone(), updated)
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

        let updated_input = if decision == "allow" || decision == "ask" {
            if let Some(ref sandbox_name) = defaults.sandbox {
                let bash_input = self.parse_bash_input()?;
                Some(UpdatedInput {
                    command: Self::wrap_with_sandbox(sandbox_name, &bash_input.command)?,
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
    ) -> Result<Option<UpdatedInput>, anyhow::Error> {
        match sandbox {
            SandboxInfo::Preset(Some(preset)) => Ok(Some(UpdatedInput {
                command: Self::wrap_with_sandbox(preset, original_command)?,
            })),
            _ => Ok(None),
        }
    }

    /// Wrap a command with `runok exec --sandbox <preset> -- <quoted_command>`.
    /// The command is shell-quoted to prevent shell metacharacters (e.g. `&&`,
    /// `||`, `;`, `|`) from being interpreted outside the sandbox.
    fn wrap_with_sandbox(preset: &str, command: &str) -> Result<String, anyhow::Error> {
        let quoted_preset = shlex::try_quote(preset)
            .map_err(|_| anyhow::anyhow!("sandbox preset name contains invalid characters"))?;
        let quoted_command = shlex::try_quote(command)
            .map_err(|_| anyhow::anyhow!("command contains invalid characters (NUL byte)"))?;
        Ok(format!(
            "runok exec --sandbox {quoted_preset} -- {quoted_command}"
        ))
    }
}

impl Endpoint for ClaudeCodeHookAdapter {
    fn audit_metadata(&self) -> AuditMetadata {
        AuditMetadata {
            endpoint_type: "hook".to_owned(),
            session_id: Some(self.input.session_id.clone()),
            cwd: Some(self.input.cwd.clone()),
            tool_name: Some(self.input.tool_name.clone()),
            hook_event_name: self.input.hook_event_name.clone(),
            tool_use_id: self.input.tool_use_id.clone(),
        }
    }

    fn is_auditable(&self) -> bool {
        true
    }

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
        // Exit 1 (non-blocking) so Claude Code falls back to its normal
        // permission flow instead of blocking the tool call. Exit 2 would be
        // interpreted as a blocking hook error.
        eprintln!("{error:#}");
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::SandboxInfo;
    use crate::rules::rule_engine::DenyResponse;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use serde_json::json;

    fn make_hook_input(tool_name: &str, tool_input: serde_json::Value) -> HookInput {
        make_hook_input_for_event(tool_name, tool_input, "PreToolUse")
    }

    fn make_hook_input_for_event(
        tool_name: &str,
        tool_input: serde_json::Value,
        hook_event_name: &str,
    ) -> HookInput {
        HookInput {
            session_id: "test-session".to_string(),
            transcript_path: "/tmp/transcript".to_string(),
            cwd: "/tmp".to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: Some(hook_event_name.to_string()),
            tool_name: tool_name.to_string(),
            tool_input,
            tool_use_id: Some("test-tool-use-id".to_string()),
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
        make_output("deny", Some("denied: rm -rf / (not allowed)"), None),
    )]
    #[case::deny_without_message(
        Action::Deny(DenyResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: "rm *".to_string(),
        }),
        SandboxInfo::Preset(None),
        make_output("deny", Some("denied: rm *"), None),
    )]
    #[case::deny_with_message_and_suggestion(
        Action::Deny(DenyResponse {
            message: Some("force push is not allowed".to_string()),
            fix_suggestion: Some("git push --force-with-lease".to_string()),
            matched_rule: "git push -f *".to_string(),
        }),
        SandboxInfo::Preset(None),
        make_output("deny", Some("denied: git push -f * (force push is not allowed) [suggestion: git push --force-with-lease]"), None),
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
    #[case::ask_with_sandbox(
        Action::Ask(Some("please confirm".to_string())),
        SandboxInfo::Preset(Some("restricted".to_string())),
        make_output("ask", Some("please confirm"), Some("runok exec --sandbox restricted -- 'git status'")),
    )]
    fn build_action_output_maps_action_to_hook_output(
        #[case] action: Action,
        #[case] sandbox: SandboxInfo,
        #[case] expected: HookOutput,
    ) {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("git status")));
        let result = ActionResult {
            action,
            sandbox,
            evaluations: vec![],
        };
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
    #[case::ask(ActionKind::Ask, "ask")]
    #[case::allow(ActionKind::Allow, "allow")]
    fn build_no_match_output_with_default_sandbox(
        #[case] action_kind: ActionKind,
        #[case] expected_decision: &str,
    ) {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("npm install")));
        let defaults = Defaults {
            action: Some(action_kind),
            sandbox: Some("restricted".to_string()),
        };
        let output = adapter
            .build_no_match_output(&defaults)
            .unwrap_or_else(|e| panic!("build_no_match_output failed: {e}"))
            .unwrap_or_else(|| panic!("expected Some(HookOutput)"));
        assert_eq!(
            output,
            make_output(
                expected_decision,
                None,
                Some("runok exec --sandbox restricted -- 'npm install'"),
            ),
        );
    }

    // --- handle_error ---

    #[rstest]
    fn handle_error_returns_exit_1() {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("git status")));
        let exit_code = adapter.handle_error(anyhow::anyhow!("test error"));
        assert_eq!(exit_code, 1);
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
                evaluations: vec![],
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
    fn hook_input_deserializes_from_snake_case_json() {
        let json_str = indoc! {r#"
            {
                "session_id": "sess-123",
                "transcript_path": "/tmp/transcript.json",
                "cwd": "/home/user",
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "tool_use_id": "use-456"
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
        let result = ClaudeCodeHookAdapter::sandbox_updated_input(&sandbox, command)
            .unwrap_or_else(|e| panic!("unexpected error: {e}"));
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
            ClaudeCodeHookAdapter::wrap_with_sandbox("restricted", command)
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            expected,
        );
    }

    #[rstest]
    #[case::preset_with_spaces(
        "my preset",
        "echo hello",
        "runok exec --sandbox 'my preset' -- 'echo hello'"
    )]
    #[case::preset_with_special_chars("pre$et", "ls", "runok exec --sandbox 'pre$et' -- ls")]
    fn wrap_with_sandbox_quotes_preset(
        #[case] preset: &str,
        #[case] command: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            ClaudeCodeHookAdapter::wrap_with_sandbox(preset, command)
                .unwrap_or_else(|e| panic!("unexpected error: {e}")),
            expected,
        );
    }

    #[rstest]
    fn wrap_with_sandbox_rejects_nul_byte() {
        let command = "echo \0hello";
        assert!(ClaudeCodeHookAdapter::wrap_with_sandbox("restricted", command).is_err());
    }

    // --- audit metadata ---

    #[rstest]
    fn audit_metadata_returns_hook_endpoint_type() {
        let adapter =
            ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("git status")));
        assert_eq!(
            adapter.audit_metadata(),
            AuditMetadata {
                endpoint_type: "hook".to_string(),
                session_id: Some("test-session".to_string()),
                cwd: Some("/tmp".to_string()),
                tool_name: Some("Bash".to_string()),
                hook_event_name: Some("PreToolUse".to_string()),
                tool_use_id: Some("test-tool-use-id".to_string()),
            },
        );
    }

    #[rstest]
    fn is_auditable_returns_true() {
        let adapter = ClaudeCodeHookAdapter::new(make_hook_input("Bash", bash_tool_input("ls")));
        assert!(adapter.is_auditable());
    }

    // --- PostToolUse ---

    use tempfile::TempDir;

    #[rstest]
    #[case::post_tool_use(Some("PostToolUse"), true)]
    #[case::pre_tool_use(Some("PreToolUse"), false)]
    #[case::absent(None, false)]
    fn is_post_tool_use_checks_event_name(
        #[case] hook_event_name: Option<&str>,
        #[case] expected: bool,
    ) {
        let mut input = make_hook_input("Bash", bash_tool_input("git status"));
        input.hook_event_name = hook_event_name.map(str::to_string);
        let adapter = ClaudeCodeHookAdapter::new(input);
        assert_eq!(adapter.is_post_tool_use(), expected);
    }

    #[rstest]
    fn hook_input_deserializes_without_event_name_and_tool_use_id() {
        // Minimal inputs (older Claude Code versions, hand-crafted JSON)
        // must still parse.
        let json_str = indoc! {r#"
            {
                "session_id": "sess-123",
                "transcript_path": "/tmp/transcript.json",
                "cwd": "/home/user",
                "permission_mode": "default",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"}
            }
        "#};

        let input: HookInput = serde_json::from_str(json_str)
            .unwrap_or_else(|e| panic!("deserialization failed: {e}"));
        assert_eq!(
            input,
            HookInput {
                session_id: "sess-123".to_string(),
                transcript_path: "/tmp/transcript.json".to_string(),
                cwd: "/home/user".to_string(),
                permission_mode: "default".to_string(),
                hook_event_name: None,
                tool_name: "Bash".to_string(),
                tool_input: json!({"command": "git status"}),
                tool_use_id: None,
            },
        );
    }

    #[fixture]
    fn audit_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn config_with_audit(dir: &TempDir) -> Config {
        Config {
            audit: Some(crate::config::AuditConfig {
                enabled: Some(true),
                path: Some(dir.path().to_string_lossy().to_string()),
                rotation: None,
            }),
            ..Default::default()
        }
    }

    fn audit_lines(dir: &TempDir) -> Vec<String> {
        let today = chrono::Utc::now().format("%Y-%m-%d");
        let path = dir.path().join(format!("audit-{today}.jsonl"));
        if !path.exists() {
            return vec![];
        }
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read audit file: {e}"))
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_ask_entry(dir: &TempDir, command: &str, tool_use_id: &str) {
        let entry = crate::audit::AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            command: command.to_owned(),
            action: crate::audit::SerializableAction::Ask { message: None },
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata {
                endpoint_type: "hook".to_owned(),
                session_id: Some("test-session".to_owned()),
                cwd: Some("/tmp".to_owned()),
                tool_name: Some("Bash".to_owned()),
                hook_event_name: Some("PreToolUse".to_owned()),
                tool_use_id: Some(tool_use_id.to_owned()),
            },
            command_evaluations: vec![],
        };
        let today = chrono::Utc::now().format("%Y-%m-%d");
        let path = dir.path().join(format!("audit-{today}.jsonl"));
        let line = serde_json::to_string(&entry).unwrap();
        std::fs::write(path, format!("{line}\n")).unwrap();
    }

    /// Normalize the dynamic timestamp so the whole record can be asserted
    /// with a single equality check.
    fn normalize_timestamp(
        mut resolution: crate::audit::AskResolution,
    ) -> crate::audit::AskResolution {
        resolution.timestamp = "TIMESTAMP".to_owned();
        resolution
    }

    #[rstest]
    fn handle_post_tool_use_records_resolution_for_matching_ask(audit_dir: TempDir) {
        write_ask_entry(&audit_dir, "terraform apply", "test-tool-use-id");
        let adapter = ClaudeCodeHookAdapter::new(make_hook_input_for_event(
            "Bash",
            bash_tool_input("terraform apply"),
            "PostToolUse",
        ));

        let exit_code = adapter.handle_post_tool_use(&config_with_audit(&audit_dir));

        assert_eq!(exit_code, 0);
        let lines = audit_lines(&audit_dir);
        assert_eq!(lines.len(), 2);
        let resolution: crate::audit::AskResolution = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(
            normalize_timestamp(resolution),
            crate::audit::AskResolution {
                timestamp: "TIMESTAMP".to_owned(),
                outcome: crate::audit::AskResolutionOutcome::Approved,
                tool_use_id: Some("test-tool-use-id".to_owned()),
                session_id: Some("test-session".to_owned()),
                cwd: Some("/tmp".to_owned()),
                command: "terraform apply".to_owned(),
                executed_command: "terraform apply".to_owned(),
            },
        );
    }

    #[rstest]
    #[case::non_bash_tool("Read", json!({"path": "/tmp"}))]
    #[case::invalid_bash_input("Bash", json!({"not_command": "x"}))]
    fn handle_post_tool_use_never_fails(
        audit_dir: TempDir,
        #[case] tool_name: &str,
        #[case] tool_input: serde_json::Value,
    ) {
        let adapter = ClaudeCodeHookAdapter::new(make_hook_input_for_event(
            tool_name,
            tool_input,
            "PostToolUse",
        ));

        let exit_code = adapter.handle_post_tool_use(&config_with_audit(&audit_dir));

        assert_eq!(exit_code, 0);
        assert_eq!(audit_lines(&audit_dir), Vec::<String>::new());
    }

    #[rstest]
    fn handle_post_tool_use_skips_when_audit_disabled(audit_dir: TempDir) {
        write_ask_entry(&audit_dir, "terraform apply", "test-tool-use-id");
        let config = Config {
            audit: Some(crate::config::AuditConfig {
                enabled: Some(false),
                path: Some(audit_dir.path().to_string_lossy().to_string()),
                rotation: None,
            }),
            ..Default::default()
        };
        let adapter = ClaudeCodeHookAdapter::new(make_hook_input_for_event(
            "Bash",
            bash_tool_input("terraform apply"),
            "PostToolUse",
        ));

        let exit_code = adapter.handle_post_tool_use(&config);

        assert_eq!(exit_code, 0);
        assert_eq!(
            audit_lines(&audit_dir).len(),
            1,
            "only the pre-existing ask entry"
        );
    }
}
