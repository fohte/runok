use serde::{Deserialize, Serialize};

use crate::config::{ActionKind, Defaults, MergedSandboxPolicy};
use crate::rules::rule_engine::Action;

use super::{ActionResult, Endpoint, SandboxInfo};

/// stdin JSON input for `runok check`.
#[derive(Debug, Deserialize)]
pub struct CheckInput {
    pub command: String,
}

/// JSON response written to stdout by `runok check`.
#[derive(Debug, Serialize, PartialEq)]
pub struct CheckOutput {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<CheckSandboxInfo>,
}

/// Informational sandbox policy included in the check response.
#[derive(Debug, Serialize, PartialEq)]
pub struct CheckSandboxInfo {
    pub preset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writable_roots: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_allowed: Option<bool>,
}

/// Generic check endpoint implementing `Endpoint`.
pub struct CheckAdapter {
    command: String,
}

impl CheckAdapter {
    /// Build from the `--command` CLI argument.
    pub fn from_command(command: String) -> Self {
        Self { command }
    }

    /// Build from stdin JSON input.
    pub fn from_stdin(input: CheckInput) -> Self {
        Self {
            command: input.command,
        }
    }
}

/// Build a `CheckOutput` from an `ActionResult`.
fn build_check_output(result: &ActionResult) -> CheckOutput {
    let (decision, reason, fix_suggestion) = match &result.action {
        Action::Allow => ("allow".to_string(), None, None),
        Action::Deny(deny) => (
            "deny".to_string(),
            deny.message.clone(),
            deny.fix_suggestion.clone(),
        ),
        Action::Ask(message) => ("ask".to_string(), message.clone(), None),
        Action::Default => ("ask".to_string(), None, None),
    };

    let sandbox = build_sandbox_info(&result.sandbox);

    CheckOutput {
        decision,
        reason,
        fix_suggestion,
        sandbox,
    }
}

/// Build a `CheckOutput` for the no-match case based on defaults.
fn build_no_match_output(defaults: &Defaults) -> CheckOutput {
    let decision = match defaults.action {
        Some(ActionKind::Allow) => "allow",
        Some(ActionKind::Deny) => "deny",
        Some(ActionKind::Ask) | None => "ask",
    };

    CheckOutput {
        decision: decision.to_string(),
        reason: None,
        fix_suggestion: None,
        sandbox: None,
    }
}

impl Endpoint for CheckAdapter {
    fn extract_command(&self) -> Result<Option<String>, anyhow::Error> {
        Ok(Some(self.command.clone()))
    }

    fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
        let output = build_check_output(&result);
        let json = serde_json::to_string(&output)?;
        println!("{json}");
        Ok(0)
    }

    fn handle_no_match(&self, defaults: &Defaults) -> Result<i32, anyhow::Error> {
        let output = build_no_match_output(defaults);
        let json = serde_json::to_string(&output)?;
        println!("{json}");
        Ok(0)
    }

    fn handle_error(&self, error: anyhow::Error) -> i32 {
        eprintln!("{error}");
        2
    }
}

/// Convert `SandboxInfo` into the informational `CheckSandboxInfo` for the response.
fn build_sandbox_info(info: &SandboxInfo) -> Option<CheckSandboxInfo> {
    match info {
        SandboxInfo::Preset(Some(preset)) => Some(CheckSandboxInfo {
            preset: preset.clone(),
            writable_roots: None,
            network_allowed: None,
        }),
        SandboxInfo::MergedPolicy(Some(policy)) => Some(merged_policy_to_sandbox_info(policy)),
        SandboxInfo::Preset(None) | SandboxInfo::MergedPolicy(None) => None,
    }
}

fn merged_policy_to_sandbox_info(policy: &MergedSandboxPolicy) -> CheckSandboxInfo {
    let writable_roots = if policy.writable.is_empty() {
        None
    } else {
        Some(policy.writable.clone())
    };

    let network_allowed = policy
        .network_allow
        .as_ref()
        .map(|allowed| !allowed.is_empty());

    CheckSandboxInfo {
        preset: "merged".to_string(),
        writable_roots,
        network_allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::rule_engine::DenyResponse;
    use rstest::rstest;

    // --- CheckAdapter construction ---

    #[rstest]
    fn from_command_extracts_command() {
        let adapter = CheckAdapter::from_command("ls -la".to_string());
        let result = adapter.extract_command();
        assert_eq!(result.ok(), Some(Some("ls -la".to_string())));
    }

    #[rstest]
    fn from_stdin_extracts_command() {
        let input = CheckInput {
            command: "docker run hello".to_string(),
        };
        let adapter = CheckAdapter::from_stdin(input);
        let result = adapter.extract_command();
        assert_eq!(result.ok(), Some(Some("docker run hello".to_string())));
    }

    // --- build_check_output: decision mapping ---

    #[rstest]
    #[case::allow(
        Action::Allow,
        SandboxInfo::Preset(None),
        CheckOutput { decision: "allow".to_string(), reason: None, fix_suggestion: None, sandbox: None },
    )]
    #[case::deny(
        Action::Deny(DenyResponse {
            message: Some("dangerous command".to_string()),
            fix_suggestion: Some("use rm with caution".to_string()),
            matched_rule: "rm -rf *".to_string(),
        }),
        SandboxInfo::Preset(None),
        CheckOutput {
            decision: "deny".to_string(),
            reason: Some("dangerous command".to_string()),
            fix_suggestion: Some("use rm with caution".to_string()),
            sandbox: None,
        },
    )]
    #[case::ask_with_message(
        Action::Ask(Some("please confirm".to_string())),
        SandboxInfo::Preset(None),
        CheckOutput { decision: "ask".to_string(), reason: Some("please confirm".to_string()), fix_suggestion: None, sandbox: None },
    )]
    #[case::ask_without_message(
        Action::Ask(None),
        SandboxInfo::Preset(None),
        CheckOutput { decision: "ask".to_string(), reason: None, fix_suggestion: None, sandbox: None },
    )]
    #[case::with_sandbox_preset(
        Action::Allow,
        SandboxInfo::Preset(Some("restricted".to_string())),
        CheckOutput {
            decision: "allow".to_string(),
            reason: None,
            fix_suggestion: None,
            sandbox: Some(CheckSandboxInfo { preset: "restricted".to_string(), writable_roots: None, network_allowed: None }),
        },
    )]
    fn build_check_output_maps_action_to_output(
        #[case] action: Action,
        #[case] sandbox: SandboxInfo,
        #[case] expected: CheckOutput,
    ) {
        let result = ActionResult { action, sandbox };
        assert_eq!(build_check_output(&result), expected);
    }

    // --- handle_action: exit code ---

    #[rstest]
    #[case::allow(Action::Allow)]
    #[case::deny(Action::Deny(DenyResponse {
        message: None,
        fix_suggestion: None,
        matched_rule: "test".to_string(),
    }))]
    #[case::ask(Action::Ask(None))]
    fn handle_action_always_returns_exit_0(#[case] action: Action) {
        let adapter = CheckAdapter::from_command("test".to_string());
        let result = ActionResult {
            action,
            sandbox: SandboxInfo::Preset(None),
        };
        assert_eq!(adapter.handle_action(result).ok(), Some(0));
    }

    // --- build_no_match_output: defaults mapping ---

    #[rstest]
    #[case::default_ask(None, "ask")]
    #[case::explicit_allow(Some(ActionKind::Allow), "allow")]
    #[case::explicit_deny(Some(ActionKind::Deny), "deny")]
    #[case::explicit_ask(Some(ActionKind::Ask), "ask")]
    fn build_no_match_output_maps_defaults(
        #[case] action_kind: Option<ActionKind>,
        #[case] expected_decision: &str,
    ) {
        let defaults = Defaults {
            action: action_kind,
            sandbox: None,
        };
        let output = build_no_match_output(&defaults);
        assert_eq!(output.decision, expected_decision);
        assert_eq!(output.reason, None);
        assert_eq!(output.fix_suggestion, None);
        assert_eq!(output.sandbox, None);
    }

    // --- handle_no_match: exit code ---

    #[rstest]
    fn handle_no_match_returns_exit_0() {
        let adapter = CheckAdapter::from_command("test".to_string());
        let defaults = Defaults::default();
        assert_eq!(adapter.handle_no_match(&defaults).ok(), Some(0));
    }

    // --- handle_error ---

    #[rstest]
    fn handle_error_returns_exit_2() {
        let adapter = CheckAdapter::from_command("test".to_string());
        let exit_code = adapter.handle_error(anyhow::anyhow!("something went wrong"));
        assert_eq!(exit_code, 2);
    }

    // --- build_sandbox_info ---

    #[rstest]
    #[case::no_preset(SandboxInfo::Preset(None), None)]
    #[case::no_merged_policy(SandboxInfo::MergedPolicy(None), None)]
    fn build_sandbox_info_returns_none_for_empty(
        #[case] info: SandboxInfo,
        #[case] expected: Option<CheckSandboxInfo>,
    ) {
        assert_eq!(build_sandbox_info(&info), expected);
    }

    #[rstest]
    fn build_sandbox_info_from_preset() {
        let info = SandboxInfo::Preset(Some("restricted".to_string()));
        let result = build_sandbox_info(&info);
        assert_eq!(
            result,
            Some(CheckSandboxInfo {
                preset: "restricted".to_string(),
                writable_roots: None,
                network_allowed: None,
            })
        );
    }

    #[rstest]
    fn build_sandbox_info_from_merged_policy() {
        let policy = MergedSandboxPolicy {
            writable: vec!["/tmp".to_string(), "/home".to_string()],
            deny: vec!["/etc".to_string()],
            network_allow: Some(vec!["example.com".to_string()]),
        };
        let info = SandboxInfo::MergedPolicy(Some(policy));
        let result = build_sandbox_info(&info);
        assert_eq!(
            result,
            Some(CheckSandboxInfo {
                preset: "merged".to_string(),
                writable_roots: Some(vec!["/tmp".to_string(), "/home".to_string()]),
                network_allowed: Some(true),
            })
        );
    }

    #[rstest]
    fn build_sandbox_info_merged_policy_empty_network() {
        let policy = MergedSandboxPolicy {
            writable: vec![],
            deny: vec![],
            network_allow: Some(vec![]),
        };
        let info = SandboxInfo::MergedPolicy(Some(policy));
        let result = build_sandbox_info(&info);
        assert_eq!(
            result,
            Some(CheckSandboxInfo {
                preset: "merged".to_string(),
                writable_roots: None,
                network_allowed: Some(false),
            })
        );
    }

    #[rstest]
    fn build_sandbox_info_merged_policy_no_network() {
        let policy = MergedSandboxPolicy {
            writable: vec!["/workspace".to_string()],
            deny: vec![],
            network_allow: None,
        };
        let info = SandboxInfo::MergedPolicy(Some(policy));
        let result = build_sandbox_info(&info);
        assert_eq!(
            result,
            Some(CheckSandboxInfo {
                preset: "merged".to_string(),
                writable_roots: Some(vec!["/workspace".to_string()]),
                network_allowed: None,
            })
        );
    }
}
