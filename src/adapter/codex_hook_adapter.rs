use serde::{Deserialize, Serialize};

use crate::adapter::hook_common::{
    BashToolInput, HookOutput, build_ask_reason, build_deny_reason, build_output,
    sandbox_updated_input,
};
use crate::adapter::{ActionResult, Endpoint};
use crate::audit::AuditMetadata;
use crate::config::Defaults;
use crate::rules::rule_engine::{Action, AskResponse};

/// Codex `PreToolUse`/`PermissionRequest` hook input (stdin JSON). Both events
/// share this shape; PreToolUse additionally carries `tool_use_id`, which
/// PermissionRequest omits.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(PartialEq))]
pub struct CodexHookInput {
    pub session_id: String,
    pub cwd: String,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub tool_use_id: Option<String>,
}

/// Which Codex hook event this input represents.
#[derive(Debug, PartialEq)]
pub enum CodexHookEventKind {
    PreToolUse,
    PermissionRequest,
    /// Any other (e.g. future) Codex hook event: nothing to do.
    Unknown,
}

pub struct CodexHookAdapter {
    input: CodexHookInput,
}

impl CodexHookAdapter {
    pub fn new(input: CodexHookInput) -> Self {
        Self { input }
    }

    /// Which flow this input should be routed through.
    pub fn event_kind(&self) -> CodexHookEventKind {
        match self.input.hook_event_name.as_str() {
            "PreToolUse" => CodexHookEventKind::PreToolUse,
            "PermissionRequest" => CodexHookEventKind::PermissionRequest,
            _ => CodexHookEventKind::Unknown,
        }
    }

    fn parse_bash_input(&self) -> Result<BashToolInput, anyhow::Error> {
        Ok(serde_json::from_value(self.input.tool_input.clone())?)
    }

    /// Codex requires `updatedInput` to be paired with an explicit
    /// `permissionDecision: allow` -- so Pass and a sandbox-less allow both
    /// write nothing here, deferring to Codex's own approval flow.
    ///
    /// Ask always maps to `deny` instead of deferring: Codex's `PreToolUse`
    /// hook has no way to open an approval prompt mid-call (unlike
    /// `PermissionRequest`, see `build_permission_request_output`), and
    /// `permissionDecision` is the only value that actually stops the tool
    /// from running -- silence or an annotation lets it execute regardless
    /// of `permission_mode`. The reason text carries the "ask" semantics
    /// (why human judgment is needed) and tells the model to stop and report
    /// back instead of retrying, since this session has no way to re-run the
    /// call with elevated permission.
    fn build_pre_tool_use_output(
        &self,
        result: &ActionResult,
    ) -> Result<Option<HookOutput>, anyhow::Error> {
        let bash_input = self.parse_bash_input()?;
        match &result.action {
            Action::Deny(deny_response) => Ok(Some(build_output(
                Some("deny"),
                Some(build_deny_reason(deny_response)),
                None,
            ))),
            Action::Allow => {
                let updated = sandbox_updated_input(
                    &result.sandbox,
                    &result.sandbox_wraps,
                    &bash_input.command,
                )?;
                Ok(updated.map(|u| build_output(Some("allow"), None, Some(u))))
            }
            Action::Ask(ask_response) => Ok(Some(build_output(
                Some("deny"),
                Some(build_ask_deny_reason(ask_response)),
                None,
            ))),
            Action::Pass => Ok(None),
        }
    }

    /// PermissionRequest: allow/deny only -- this hook has no `updatedInput`
    /// support at all, so sandbox presets are irrelevant here.
    fn build_permission_request_output(
        &self,
        result: &ActionResult,
    ) -> Result<Option<PermissionRequestOutput>, anyhow::Error> {
        let decision = match &result.action {
            Action::Deny(deny_response) => Some(PermissionRequestDecision {
                behavior: "deny".to_string(),
                message: Some(build_deny_reason(deny_response)),
            }),
            Action::Allow => Some(PermissionRequestDecision {
                behavior: "allow".to_string(),
                message: None,
            }),
            Action::Ask(_) | Action::Pass => None,
        };
        Ok(decision.map(|decision| PermissionRequestOutput {
            hook_specific_output: PermissionRequestHookSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision,
            },
        }))
    }
}

/// Build the `permissionDecisionReason` for an Ask action reported through
/// `PreToolUse`'s `deny`. Codex treats an empty (post-trim) reason as an
/// invalid `deny` and silently continues instead of blocking (see
/// `codex-rs/core/src/hook_runtime.rs`'s `block_reason` handling), so the
/// fixed trailing instruction is unconditional -- it's the only part
/// guaranteed to be there when `ask_response` carries neither a message nor
/// a fix suggestion. The instruction tells the model to stop rather than
/// retry: this session has no mechanism to re-run a call with elevated
/// permission, so retrying just repeats the same deny.
fn build_ask_deny_reason(ask_response: &AskResponse) -> String {
    let mut reason = build_ask_reason(ask_response);
    reason.push_str(
        ". This rule requires a human decision and this session has no approval prompt. Stop, \
         report which command needs approval and why, and let the delegator or the user decide. \
         Do not retry this command and do not work around the rule.",
    );
    reason
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Deserialize))]
struct PermissionRequestOutput {
    hook_specific_output: PermissionRequestHookSpecificOutput,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Deserialize))]
struct PermissionRequestHookSpecificOutput {
    hook_event_name: String,
    decision: PermissionRequestDecision,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(Deserialize))]
struct PermissionRequestDecision {
    behavior: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl Endpoint for CodexHookAdapter {
    fn extract_command(&self) -> Result<Option<String>, anyhow::Error> {
        if self.input.tool_name != "Bash" {
            return Ok(None);
        }
        Ok(Some(self.parse_bash_input()?.command))
    }

    fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
        match self.event_kind() {
            CodexHookEventKind::PreToolUse => {
                if let Some(output) = self.build_pre_tool_use_output(&result)? {
                    serde_json::to_writer(std::io::stdout(), &output)?;
                }
            }
            CodexHookEventKind::PermissionRequest => {
                if let Some(output) = self.build_permission_request_output(&result)? {
                    serde_json::to_writer(std::io::stdout(), &output)?;
                }
            }
            CodexHookEventKind::Unknown => {}
        }
        Ok(0)
    }

    // Only called for non-Bash tools (the extract_command == None path).
    // Codex has no tool-type-specific default behavior in scope for this
    // adapter, so nothing is written and the exit code stays 0.
    fn handle_no_match(&self, _defaults: &Defaults) -> Result<i32, anyhow::Error> {
        Ok(0)
    }

    fn handle_error(&self, error: anyhow::Error) -> i32 {
        eprintln!("{error:#}");
        1
    }

    fn audit_metadata(&self) -> AuditMetadata {
        AuditMetadata {
            endpoint_type: "hook".to_owned(),
            session_id: Some(self.input.session_id.clone()),
            cwd: Some(self.input.cwd.clone()),
            tool_name: Some(self.input.tool_name.clone()),
            hook_event_name: Some(self.input.hook_event_name.clone()),
            tool_use_id: self.input.tool_use_id.clone(),
        }
    }

    fn is_auditable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::SandboxInfo;
    use crate::adapter::hook_common::normalize_hook_origin_token;
    use crate::rules::rule_engine::{AskResponse, DenyResponse};
    use indoc::indoc;
    use rstest::rstest;
    use serde_json::json;

    fn make_hook_input(
        hook_event_name: &str,
        tool_name: &str,
        tool_input: serde_json::Value,
        tool_use_id: Option<&str>,
    ) -> CodexHookInput {
        CodexHookInput {
            session_id: "test-session".to_string(),
            cwd: "/tmp".to_string(),
            hook_event_name: hook_event_name.to_string(),
            tool_name: tool_name.to_string(),
            tool_input,
            tool_use_id: tool_use_id.map(str::to_string),
        }
    }

    fn pre_tool_use_input(tool_name: &str, tool_input: serde_json::Value) -> CodexHookInput {
        make_hook_input(
            "PreToolUse",
            tool_name,
            tool_input,
            Some("test-tool-use-id"),
        )
    }

    fn permission_request_input(tool_name: &str, tool_input: serde_json::Value) -> CodexHookInput {
        make_hook_input("PermissionRequest", tool_name, tool_input, None)
    }

    fn bash_tool_input(command: &str) -> serde_json::Value {
        json!({ "command": command })
    }

    fn action_result(action: Action, sandbox: SandboxInfo) -> ActionResult {
        ActionResult {
            action,
            sandbox,
            sandbox_wraps: vec![],
            evaluations: vec![],
        }
    }

    fn normalize_hook_origin_output(output: HookOutput) -> HookOutput {
        build_output(
            output.hook_specific_output.permission_decision.as_deref(),
            output.hook_specific_output.permission_decision_reason,
            output.hook_specific_output.updated_input.map(|u| {
                crate::adapter::hook_common::UpdatedInput {
                    command: normalize_hook_origin_token(&u.command),
                }
            }),
        )
    }

    // --- extract_command ---

    #[rstest]
    #[case::bash_tool("Bash", bash_tool_input("git status"), Some("git status".to_string()))]
    #[case::non_bash_tool("Read", json!({"path": "/tmp/file"}), None)]
    fn extract_command_filters_by_tool_name(
        #[case] tool_name: &str,
        #[case] tool_input: serde_json::Value,
        #[case] expected: Option<String>,
    ) {
        let adapter = CodexHookAdapter::new(pre_tool_use_input(tool_name, tool_input));
        let result = adapter
            .extract_command()
            .unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(result, expected);
    }

    // --- event_kind ---

    #[rstest]
    #[case::pre_tool_use("PreToolUse", CodexHookEventKind::PreToolUse)]
    #[case::permission_request("PermissionRequest", CodexHookEventKind::PermissionRequest)]
    #[case::session_start("SessionStart", CodexHookEventKind::Unknown)]
    fn event_kind_maps_event_name(
        #[case] hook_event_name: &str,
        #[case] expected: CodexHookEventKind,
    ) {
        let mut input = pre_tool_use_input("Bash", bash_tool_input("git status"));
        input.hook_event_name = hook_event_name.to_string();
        let adapter = CodexHookAdapter::new(input);
        assert_eq!(adapter.event_kind(), expected);
    }

    // --- build_pre_tool_use_output ---

    #[rstest]
    #[case::deny_with_message(
        Action::Deny(DenyResponse {
            message: Some("not allowed".to_string()),
            fix_suggestion: None,
            matched_rule: "rm -rf /".to_string(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(Some("deny"), Some("denied: rm -rf / (not allowed)".to_string()), None)),
    )]
    #[case::deny_without_message(
        Action::Deny(DenyResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: "rm *".to_string(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(Some("deny"), Some("denied: rm *".to_string()), None)),
    )]
    #[case::deny_with_message_and_suggestion(
        Action::Deny(DenyResponse {
            message: Some("force push is not allowed".to_string()),
            fix_suggestion: Some("git push --force-with-lease".to_string()),
            matched_rule: "git push -f *".to_string(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(
            Some("deny"),
            Some("denied: git push -f * (force push is not allowed) [suggestion: git push --force-with-lease]".to_string()),
            None,
        )),
    )]
    #[case::allow_with_sandbox(
        Action::Allow,
        SandboxInfo::Preset(Some("restricted".to_string())),
        Some(build_output(
            Some("allow"),
            None,
            Some(crate::adapter::hook_common::UpdatedInput {
                command: "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- 'git status'".to_string(),
            }),
        )),
    )]
    #[case::allow_without_sandbox(Action::Allow, SandboxInfo::Preset(None), None)]
    #[case::ask_with_message_and_fix_suggestion(
        Action::Ask(AskResponse {
            message: Some("please confirm".to_string()),
            fix_suggestion: Some("git push --force-with-lease".to_string()),
            matched_rule: "git push -f *".to_string(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(
            Some("deny"),
            Some(
                "approval required: git push -f * (please confirm) [suggestion: git push \
                 --force-with-lease]. This rule requires a human decision and this session has \
                 no approval prompt. Stop, report which command needs approval and why, and let \
                 the delegator or the user decide. Do not retry this command and do not work \
                 around the rule."
                    .to_string(),
            ),
            None,
        )),
    )]
    #[case::ask_with_message_only(
        Action::Ask(AskResponse {
            message: Some("please confirm".to_string()),
            fix_suggestion: None,
            matched_rule: "git push -f *".to_string(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(
            Some("deny"),
            Some(
                "approval required: git push -f * (please confirm). This rule requires a human \
                 decision and this session has no approval prompt. Stop, report which command \
                 needs approval and why, and let the delegator or the user decide. Do not retry \
                 this command and do not work around the rule."
                    .to_string(),
            ),
            None,
        )),
    )]
    #[case::ask_with_fix_suggestion_only(
        Action::Ask(AskResponse {
            message: None,
            fix_suggestion: Some("git push --force-with-lease".to_string()),
            matched_rule: "git push -f *".to_string(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(
            Some("deny"),
            Some(
                "approval required: git push -f * [suggestion: git push --force-with-lease]. \
                 This rule requires a human decision and this session has no approval prompt. \
                 Stop, report which command needs approval and why, and let the delegator or \
                 the user decide. Do not retry this command and do not work around the rule."
                    .to_string(),
            ),
            None,
        )),
    )]
    #[case::ask_with_neither(
        Action::Ask(AskResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: String::new(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(
            Some("deny"),
            Some(
                "approval required by default policy. This rule requires a human decision and \
                 this session has no approval prompt. Stop, report which command needs approval \
                 and why, and let the delegator or the user decide. Do not retry this command \
                 and do not work around the rule."
                    .to_string(),
            ),
            None,
        )),
    )]
    // Exercises the synthetic-ask code path (`default_action`/`escalate_to_ask`)
    // where no specific rule pattern matched -- `matched_rule` is empty, unlike
    // the pattern-derived cases above.
    #[case::ask_with_empty_matched_rule(
        Action::Ask(AskResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: String::new(),
        }),
        SandboxInfo::Preset(None),
        Some(build_output(
            Some("deny"),
            Some(
                "approval required by default policy. This rule requires a human decision and \
                 this session has no approval prompt. Stop, report which command needs approval \
                 and why, and let the delegator or the user decide. Do not retry this command \
                 and do not work around the rule."
                    .to_string(),
            ),
            None,
        )),
    )]
    #[case::pass(Action::Pass, SandboxInfo::Preset(None), None)]
    #[case::pass_with_sandbox(Action::Pass, SandboxInfo::Preset(Some("restricted".to_string())), None)]
    fn build_pre_tool_use_output_maps_action(
        #[case] action: Action,
        #[case] sandbox: SandboxInfo,
        #[case] expected: Option<HookOutput>,
    ) {
        let adapter =
            CodexHookAdapter::new(pre_tool_use_input("Bash", bash_tool_input("git status")));
        let result = action_result(action, sandbox);
        let output = adapter
            .build_pre_tool_use_output(&result)
            .unwrap_or_else(|e| panic!("build_pre_tool_use_output failed: {e}"))
            .map(normalize_hook_origin_output);
        assert_eq!(output, expected);
    }

    // --- build_permission_request_output ---

    #[rstest]
    #[case::deny(
        Action::Deny(DenyResponse {
            message: Some("not allowed".to_string()),
            fix_suggestion: None,
            matched_rule: "rm -rf /".to_string(),
        }),
        SandboxInfo::Preset(None),
        Some(PermissionRequestDecision { behavior: "deny".to_string(), message: Some("denied: rm -rf / (not allowed)".to_string()) }),
    )]
    #[case::allow_without_sandbox(
        Action::Allow,
        SandboxInfo::Preset(None),
        Some(PermissionRequestDecision { behavior: "allow".to_string(), message: None }),
    )]
    #[case::allow_with_sandbox_is_still_plain_allow(
        Action::Allow,
        SandboxInfo::Preset(Some("restricted".to_string())),
        Some(PermissionRequestDecision { behavior: "allow".to_string(), message: None }),
    )]
    #[case::ask(
        Action::Ask(AskResponse {
            message: Some("please confirm".to_string()),
            fix_suggestion: None,
            matched_rule: String::new(),
        }),
        SandboxInfo::Preset(None),
        None
    )]
    #[case::pass(Action::Pass, SandboxInfo::Preset(None), None)]
    fn build_permission_request_output_maps_action(
        #[case] action: Action,
        #[case] sandbox: SandboxInfo,
        #[case] expected_decision: Option<PermissionRequestDecision>,
    ) {
        let adapter = CodexHookAdapter::new(permission_request_input(
            "Bash",
            bash_tool_input("git status"),
        ));
        let result = action_result(action, sandbox);
        let output = adapter
            .build_permission_request_output(&result)
            .unwrap_or_else(|e| panic!("build_permission_request_output failed: {e}"));
        let expected = expected_decision.map(|decision| PermissionRequestOutput {
            hook_specific_output: PermissionRequestHookSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision,
            },
        });
        assert_eq!(output, expected);
    }

    // --- handle_action exit code ---

    #[rstest]
    #[case::pre_tool_use_allow("PreToolUse", Action::Allow, SandboxInfo::Preset(None))]
    #[case::pre_tool_use_deny(
        "PreToolUse",
        Action::Deny(DenyResponse { message: None, fix_suggestion: None, matched_rule: "rm *".to_string() }),
        SandboxInfo::Preset(None)
    )]
    #[case::permission_request_allow("PermissionRequest", Action::Allow, SandboxInfo::Preset(None))]
    #[case::unknown_event("SessionStart", Action::Allow, SandboxInfo::Preset(None))]
    fn handle_action_returns_exit_0(
        #[case] hook_event_name: &str,
        #[case] action: Action,
        #[case] sandbox: SandboxInfo,
    ) {
        let input = make_hook_input(
            hook_event_name,
            "Bash",
            bash_tool_input("git status"),
            Some("test-tool-use-id"),
        );
        let adapter = CodexHookAdapter::new(input);
        let exit_code = adapter
            .handle_action(action_result(action, sandbox))
            .unwrap_or_else(|e| panic!("handle_action failed: {e}"));
        assert_eq!(exit_code, 0);
    }

    // --- handle_no_match ---

    #[rstest]
    fn handle_no_match_returns_exit_0() {
        let adapter =
            CodexHookAdapter::new(pre_tool_use_input("Read", json!({"path": "/tmp/file"})));
        let exit_code = adapter
            .handle_no_match(&Defaults::default())
            .unwrap_or_else(|e| panic!("handle_no_match failed: {e}"));
        assert_eq!(exit_code, 0);
    }

    // --- handle_error ---

    #[rstest]
    fn handle_error_returns_exit_1() {
        let adapter =
            CodexHookAdapter::new(pre_tool_use_input("Bash", bash_tool_input("git status")));
        let exit_code = adapter.handle_error(anyhow::anyhow!("test error"));
        assert_eq!(exit_code, 1);
    }

    // --- audit_metadata ---

    #[rstest]
    fn audit_metadata_pre_tool_use_includes_tool_use_id() {
        let adapter =
            CodexHookAdapter::new(pre_tool_use_input("Bash", bash_tool_input("git status")));
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
    fn audit_metadata_permission_request_has_no_tool_use_id() {
        let adapter = CodexHookAdapter::new(permission_request_input(
            "Bash",
            bash_tool_input("git status"),
        ));
        assert_eq!(
            adapter.audit_metadata(),
            AuditMetadata {
                endpoint_type: "hook".to_string(),
                session_id: Some("test-session".to_string()),
                cwd: Some("/tmp".to_string()),
                tool_name: Some("Bash".to_string()),
                hook_event_name: Some("PermissionRequest".to_string()),
                tool_use_id: None,
            },
        );
    }

    #[rstest]
    fn is_auditable_returns_true() {
        let adapter =
            CodexHookAdapter::new(pre_tool_use_input("Bash", bash_tool_input("git status")));
        assert!(adapter.is_auditable());
    }

    // --- CodexHookInput deserialization ---

    #[rstest]
    fn codex_hook_input_deserializes_from_snake_case_json() {
        let json_str = indoc! {r#"
            {
                "session_id": "sess-123",
                "turn_id": "turn-1",
                "cwd": "/home/user",
                "hook_event_name": "PreToolUse",
                "model": "gpt-5-codex",
                "permission_mode": "default",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "tool_use_id": "use-456"
            }
        "#};

        let input: CodexHookInput = serde_json::from_str(json_str)
            .unwrap_or_else(|e| panic!("deserialization failed: {e}"));
        assert_eq!(
            input,
            CodexHookInput {
                session_id: "sess-123".to_string(),
                cwd: "/home/user".to_string(),
                hook_event_name: "PreToolUse".to_string(),
                tool_name: "Bash".to_string(),
                tool_input: json!({"command": "git status"}),
                tool_use_id: Some("use-456".to_string()),
            },
        );
    }

    #[rstest]
    fn codex_hook_input_permission_request_has_no_tool_use_id_field() {
        let json_str = indoc! {r#"
            {
                "session_id": "sess-123",
                "cwd": "/home/user",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": "git status"}
            }
        "#};

        let input: CodexHookInput = serde_json::from_str(json_str)
            .unwrap_or_else(|e| panic!("deserialization failed: {e}"));
        assert_eq!(input.tool_use_id, None);
    }

    // --- output JSON shape (camelCase keys) ---

    #[rstest]
    fn permission_request_output_serializes_to_camel_case_json() {
        let output = PermissionRequestOutput {
            hook_specific_output: PermissionRequestHookSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision {
                    behavior: "deny".to_string(),
                    message: Some("dangerous command".to_string()),
                },
            },
        };
        let json_val: serde_json::Value =
            serde_json::to_value(&output).unwrap_or_else(|e| panic!("serialization failed: {e}"));

        let expected = json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": "dangerous command"
                }
            }
        });
        assert_eq!(json_val, expected);
    }

    #[rstest]
    fn permission_request_output_omits_message_when_none() {
        let output = PermissionRequestOutput {
            hook_specific_output: PermissionRequestHookSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision {
                    behavior: "allow".to_string(),
                    message: None,
                },
            },
        };
        let json_val: serde_json::Value =
            serde_json::to_value(&output).unwrap_or_else(|e| panic!("serialization failed: {e}"));

        let expected = json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "allow"
                }
            }
        });
        assert_eq!(json_val, expected);
    }
}
