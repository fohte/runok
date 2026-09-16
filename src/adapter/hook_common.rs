//! Types and helpers shared by all `PreToolUse`-shaped hook adapters
//! (Claude Code, Codex). The `PreToolUse` stdout shape is identical across
//! agents, so it lives here once rather than being duplicated per adapter.

use serde::{Deserialize, Serialize};

use crate::adapter::SandboxInfo;
use crate::rules::rule_engine::DenyResponse;

/// Bash tool's tool_input structure.
#[derive(Debug, Deserialize)]
pub struct BashToolInput {
    pub command: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// `PreToolUse` Hook response (stdout JSON).
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
    /// Omitted for a `pass` decision, so the agent's own permission flow
    /// decides instead of runok.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
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

/// Build a combined reason string from a `DenyResponse`, including
/// the matched rule, optional message, and optional fix suggestion.
pub fn build_deny_reason(deny: &DenyResponse) -> String {
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

/// Build a `HookOutput` with a fixed `hookEventName: "PreToolUse"`.
pub fn build_output(
    decision: Option<&str>,
    reason: Option<String>,
    updated_input: Option<UpdatedInput>,
) -> HookOutput {
    HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: decision.map(str::to_string),
            permission_decision_reason: reason,
            updated_input,
        },
    }
}

pub fn sandbox_updated_input(
    sandbox: &SandboxInfo,
    original_command: &str,
) -> Result<Option<UpdatedInput>, anyhow::Error> {
    match sandbox {
        SandboxInfo::Preset(Some(preset)) => Ok(Some(UpdatedInput {
            command: wrap_with_sandbox(preset, original_command)?,
        })),
        _ => Ok(None),
    }
}

/// Wrap a command with `RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox
/// <preset> -- <quoted_command>`. The command is shell-quoted to prevent
/// shell metacharacters (e.g. `&&`, `||`, `;`, `|`) from being
/// interpreted outside the sandbox. The `RUNOK_HOOK_ORIGIN` env var
/// (scoped to this one invocation via the shell's assignment-prefix
/// syntax) tells `exec` that this invocation came from the hook (not
/// typed directly by a user), so that `defaults.action: pass` runs under
/// the sandbox instead of being denied. The token changes on every call
/// so it can't just be copy-pasted from a doc or a previous run -- `exec`
/// never verifies the token's value, only that the env var was set (see
/// the doc comment on `ExecAdapter::hook_origin` for why that's still an
/// accepted trade-off).
pub fn wrap_with_sandbox(preset: &str, command: &str) -> Result<String, anyhow::Error> {
    let quoted_preset = shlex::try_quote(preset)
        .map_err(|_| anyhow::anyhow!("sandbox preset name contains invalid characters"))?;
    let quoted_command = shlex::try_quote(command)
        .map_err(|_| anyhow::anyhow!("command contains invalid characters (NUL byte)"))?;
    let token = hook_origin_token();
    let env_var = crate::adapter::HOOK_ORIGIN_ENV_VAR;
    Ok(format!(
        "{env_var}={token} runok exec --sandbox {quoted_preset} -- {quoted_command}"
    ))
}

/// A per-call, non-cryptographic token (process id + current time) --
/// just enough entropy that the env var's value differs on every
/// invocation instead of being a single string anyone can hardcode.
fn hook_origin_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{:x}", std::process::id(), nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// `wrap_with_sandbox` embeds a fresh token on every call (see its doc
    /// comment). Replace it with a fixed placeholder so tests can still
    /// assert the wrapped command with a single equality check.
    fn normalize_hook_origin_token(command: &str) -> String {
        let re = regex::Regex::new(r"RUNOK_HOOK_ORIGIN=\S+").expect("valid regex");
        re.replace(command, "RUNOK_HOOK_ORIGIN=<token>")
            .into_owned()
    }

    // --- sandbox_updated_input ---

    #[rstest]
    #[case::preset_some(
        SandboxInfo::Preset(Some("restricted".to_string())),
        "echo hello",
        Some("RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- 'echo hello'"),
    )]
    #[case::preset_none(SandboxInfo::Preset(None), "echo hello", None)]
    #[case::merged_policy(SandboxInfo::MergedPolicy(None), "echo hello", None)]
    fn sandbox_updated_input_resolves_preset(
        #[case] sandbox: SandboxInfo,
        #[case] command: &str,
        #[case] expected_command: Option<&str>,
    ) {
        let result = sandbox_updated_input(&sandbox, command)
            .unwrap_or_else(|e| panic!("unexpected error: {e}"));
        match expected_command {
            Some(expected) => {
                let updated = result.unwrap_or_else(|| panic!("expected Some(UpdatedInput)"));
                assert_eq!(normalize_hook_origin_token(&updated.command), expected);
            }
            None => assert!(result.is_none()),
        }
    }

    // --- wrap_with_sandbox quotes shell metacharacters ---

    #[rstest]
    #[case::simple_command(
        "ls",
        "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- ls"
    )]
    #[case::command_with_spaces(
        "git status",
        "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- 'git status'"
    )]
    #[case::compound_and(
        "safe-cmd && dangerous-cmd",
        "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- 'safe-cmd && dangerous-cmd'"
    )]
    #[case::compound_pipe(
        "cat file | grep secret",
        "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- 'cat file | grep secret'"
    )]
    #[case::compound_semicolon(
        "cmd1; cmd2",
        "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- 'cmd1; cmd2'"
    )]
    fn wrap_with_sandbox_quotes_command(#[case] command: &str, #[case] expected: &str) {
        let actual = wrap_with_sandbox("restricted", command)
            .unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(normalize_hook_origin_token(&actual), expected);
    }

    #[rstest]
    #[case::preset_with_spaces(
        "my preset",
        "echo hello",
        "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox 'my preset' -- 'echo hello'"
    )]
    #[case::preset_with_special_chars(
        "pre$et",
        "ls",
        "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox 'pre$et' -- ls"
    )]
    fn wrap_with_sandbox_quotes_preset(
        #[case] preset: &str,
        #[case] command: &str,
        #[case] expected: &str,
    ) {
        let actual =
            wrap_with_sandbox(preset, command).unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(normalize_hook_origin_token(&actual), expected);
    }

    #[rstest]
    fn wrap_with_sandbox_rejects_nul_byte() {
        let command = "echo \0hello";
        assert!(wrap_with_sandbox("restricted", command).is_err());
    }
}
