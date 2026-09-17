//! Types and helpers shared by all `PreToolUse`-shaped hook adapters
//! (Claude Code, Codex). The `PreToolUse` stdout shape is identical across
//! agents, so it lives here once rather than being duplicated per adapter.

use serde::{Deserialize, Serialize};

use crate::adapter::SandboxInfo;
use crate::rules::rule_engine::{DenyResponse, SandboxWrap};

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
    wraps: &[SandboxWrap],
    original_command: &str,
) -> Result<Option<UpdatedInput>, anyhow::Error> {
    if !wraps.is_empty() {
        return Ok(Some(UpdatedInput {
            command: wrap_sub_commands(wraps, original_command)?,
        }));
    }
    match sandbox {
        SandboxInfo::Preset(Some(preset)) => Ok(Some(UpdatedInput {
            command: wrap_with_sandbox(preset, original_command)?,
        })),
        _ => Ok(None),
    }
}

/// Replace each sub-command that needs a sandbox with a `runok exec`
/// invocation carrying that sub-command as one quoted argument, leaving
/// every byte between them untouched: the operators that join the
/// sub-commands (`|`, `&&`, `;`) stay with the outer shell, while each
/// sub-command's own redirects go inside its sandbox along with it.
/// Replacements are applied back-to-front so the ranges still to come
/// stay valid.
fn wrap_sub_commands(
    wraps: &[SandboxWrap],
    original_command: &str,
) -> Result<String, anyhow::Error> {
    let mut command = original_command.to_string();
    let mut ordered: Vec<&SandboxWrap> = wraps.iter().collect();
    ordered.sort_by_key(|wrap| std::cmp::Reverse(wrap.range.start));

    for wrap in ordered {
        let sub_command = command.get(wrap.range.clone()).ok_or_else(|| {
            anyhow::anyhow!(
                "sandbox range {}..{} is not a valid slice of the command",
                wrap.range.start,
                wrap.range.end
            )
        })?;
        let wrapped = wrap_with_sandbox(&wrap.preset, sub_command)?;
        command.replace_range(wrap.range.clone(), &wrapped);
    }

    Ok(command)
}

/// Shell-quotes `command` and `preset` so the wrapped command's own shell
/// syntax is interpreted inside the sandbox, not by the outer shell. Sets
/// `RUNOK_HOOK_ORIGIN` so `exec` treats this as a hook-originated call and
/// runs `defaults.action: pass` under the sandbox instead of denying it.
pub fn wrap_with_sandbox(preset: &str, command: &str) -> Result<String, anyhow::Error> {
    let quoted_command = shlex::try_quote(command)
        .map_err(|_| anyhow::anyhow!("command contains invalid characters (NUL byte)"))?;
    let quoted_preset = shlex::try_quote(preset)
        .map_err(|_| anyhow::anyhow!("sandbox preset name contains invalid characters"))?;
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

/// `wrap_with_sandbox` embeds a fresh token on every call (see its doc
/// comment). Replace it with a fixed placeholder so tests -- here and in
/// the other hook adapters -- can still assert the wrapped command with a
/// single equality check.
#[cfg(test)]
pub(crate) fn normalize_hook_origin_token(command: &str) -> String {
    let re = regex::Regex::new(r"RUNOK_HOOK_ORIGIN=\S+").expect("valid regex");
    re.replace_all(command, "RUNOK_HOOK_ORIGIN=<token>")
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // --- sandbox_updated_input ---

    fn wrap(range: std::ops::Range<usize>, preset: &str) -> SandboxWrap {
        SandboxWrap {
            range,
            preset: preset.to_string(),
        }
    }

    #[rstest]
    #[case::preset_some(
        SandboxInfo::Preset(Some("restricted".to_string())),
        vec![],
        "echo hello",
        Some("RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox restricted -- 'echo hello'"),
    )]
    #[case::preset_none(SandboxInfo::Preset(None), vec![], "echo hello", None)]
    #[case::merged_policy(SandboxInfo::MergedPolicy(None), vec![], "echo hello", None)]
    // Only `node` needs the sandbox, and its redirect is inside the wrapped
    // range, so `out.json` is opened by the shell inside the sandbox while
    // the pipe and `cat ...` stay outside it.
    #[case::wraps(
        SandboxInfo::Preset(None),
        vec![wrap(0..23, "readonly")],
        "node fix.mjs > out.json | cat notes.txt",
        Some(
            "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox readonly -- \
             'node fix.mjs > out.json' | cat notes.txt",
        ),
    )]
    // Applied back-to-front, so the earlier range is still valid once the
    // later one has been replaced by a longer string.
    #[case::multiple_wraps(
        SandboxInfo::Preset(None),
        vec![wrap(0..13, "readonly"), wrap(16..28, "writable")],
        "awk '{print}' | node fix.mjs",
        Some(
            "RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox readonly -- \"awk '{print}'\" | \
             RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox writable -- 'node fix.mjs'",
        ),
    )]
    // Wraps win over the whole-input preset: they express the same sandbox
    // per sub-command instead of one sandbox over everything.
    #[case::wraps_take_precedence_over_preset(
        SandboxInfo::Preset(Some("restricted".to_string())),
        vec![wrap(0..2, "readonly")],
        "ls | wc -l",
        Some("RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox readonly -- ls | wc -l"),
    )]
    fn sandbox_updated_input_resolves_preset(
        #[case] sandbox: SandboxInfo,
        #[case] wraps: Vec<SandboxWrap>,
        #[case] command: &str,
        #[case] expected_command: Option<&str>,
    ) {
        let result = sandbox_updated_input(&sandbox, &wraps, command)
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
