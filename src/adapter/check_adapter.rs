use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{ActionKind, Defaults, SandboxPreset};
use crate::rules::rule_engine::Action;

use super::{ActionResult, Endpoint, SandboxInfo};

/// Output format for `runok check` (generic mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    Json,
    #[default]
    Text,
}

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
    output_format: OutputFormat,
    sandbox_definitions: HashMap<String, SandboxPreset>,
}

impl CheckAdapter {
    /// Build from positional command arguments.
    pub fn from_command(command: String) -> Self {
        Self {
            command,
            output_format: OutputFormat::default(),
            sandbox_definitions: HashMap::new(),
        }
    }

    /// Build from stdin JSON input.
    pub fn from_stdin(input: CheckInput) -> Self {
        Self {
            command: input.command,
            output_format: OutputFormat::default(),
            sandbox_definitions: HashMap::new(),
        }
    }

    /// Set the output format.
    pub fn with_output_format(mut self, output_format: OutputFormat) -> Self {
        self.output_format = output_format;
        self
    }

    /// Set sandbox preset definitions for resolving preset names to policies.
    pub fn with_sandbox_definitions(mut self, definitions: HashMap<String, SandboxPreset>) -> Self {
        self.sandbox_definitions = definitions;
        self
    }
}

/// Build a `CheckOutput` from an `ActionResult`.
fn build_check_output(
    result: &ActionResult,
    sandbox_definitions: &HashMap<String, SandboxPreset>,
) -> CheckOutput {
    let (decision, reason, fix_suggestion) = match &result.action {
        Action::Allow => ("allow".to_string(), None, None),
        Action::Deny(deny) => (
            "deny".to_string(),
            deny.message.clone(),
            deny.fix_suggestion.clone(),
        ),
        Action::Ask(message) => ("ask".to_string(), message.clone(), None),
        Action::Pass => ("pass".to_string(), None, None),
    };

    let sandbox = build_sandbox_info(&result.sandbox, sandbox_definitions);

    CheckOutput {
        decision,
        reason,
        fix_suggestion,
        sandbox,
    }
}

/// Build a `CheckOutput` for the no-match case based on defaults.
fn build_no_match_output(defaults: &Defaults) -> CheckOutput {
    let decision = match defaults.resolved_action() {
        ActionKind::Allow => "allow",
        ActionKind::Deny => "deny",
        ActionKind::Ask => "ask",
        ActionKind::Pass => "pass",
    };

    CheckOutput {
        decision: decision.to_string(),
        reason: None,
        fix_suggestion: None,
        sandbox: None,
    }
}

/// Format a `CheckOutput` as human-readable text.
impl fmt::Display for CheckOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.decision)?;
        if let Some(ref reason) = self.reason {
            write!(f, ": {reason}")?;
        }
        if let Some(ref suggestion) = self.fix_suggestion {
            write!(f, " (suggestion: {suggestion})")?;
        }
        if let Some(ref sandbox) = self.sandbox {
            write!(f, " [sandbox: {}]", sandbox.preset)?;
        }
        Ok(())
    }
}

impl Endpoint for CheckAdapter {
    fn extract_command(&self) -> Result<Option<String>, anyhow::Error> {
        Ok(Some(self.command.clone()))
    }

    fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
        let output = build_check_output(&result, &self.sandbox_definitions);
        self.print_output(&output)?;
        Ok(0)
    }

    fn handle_no_match(&self, defaults: &Defaults) -> Result<i32, anyhow::Error> {
        let output = build_no_match_output(defaults);
        self.print_output(&output)?;
        Ok(0)
    }

    fn handle_error(&self, error: anyhow::Error) -> i32 {
        eprintln!("{error}");
        2
    }
}

impl CheckAdapter {
    fn print_output(&self, output: &CheckOutput) -> Result<(), anyhow::Error> {
        match self.output_format {
            OutputFormat::Json => {
                let json = serde_json::to_string(output)?;
                println!("{json}");
            }
            OutputFormat::Text => {
                println!("{output}");
            }
        }
        Ok(())
    }
}

/// Convert `SandboxInfo` into the informational `CheckSandboxInfo` for the response.
///
/// Resolves each preset name against `sandbox_definitions` and merges them via
/// `SandboxPreset::merge_strictest` ("Strictest Wins") to populate the actual
/// writable roots and network-allowed flag -- this works uniformly whether
/// `names` has one entry or several. Falls back to `writable_roots: None,
/// network_allowed: None` if any name is missing from `sandbox_definitions`
/// (e.g. the caller never called `with_sandbox_definitions`).
fn build_sandbox_info(
    info: &SandboxInfo,
    sandbox_definitions: &HashMap<String, SandboxPreset>,
) -> Option<CheckSandboxInfo> {
    let SandboxInfo::Preset(names) = info;
    if names.is_empty() {
        return None;
    }

    let preset = names.join(", ");

    let presets: Option<Vec<&SandboxPreset>> = names
        .iter()
        .map(|name| sandbox_definitions.get(name))
        .collect();
    let Some(presets) = presets else {
        return Some(CheckSandboxInfo {
            preset,
            writable_roots: None,
            network_allowed: None,
        });
    };

    // `merge_strictest` with a non-empty slice always returns `Some` (`names` is non-empty).
    let Some(merged) = SandboxPreset::merge_strictest(&presets) else {
        unreachable!("merge_strictest with a non-empty slice always returns Some");
    };

    Some(CheckSandboxInfo {
        preset,
        writable_roots: if merged.writable.is_empty() {
            None
        } else {
            Some(merged.writable)
        },
        network_allowed: Some(merged.network_allowed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FsAccessPolicy, FsPolicy, NetworkPolicy};
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
        SandboxInfo::Preset(vec![]),
        CheckOutput { decision: "allow".to_string(), reason: None, fix_suggestion: None, sandbox: None },
    )]
    #[case::deny(
        Action::Deny(DenyResponse {
            message: Some("dangerous command".to_string()),
            fix_suggestion: Some("use rm with caution".to_string()),
            matched_rule: "rm -rf *".to_string(),
        }),
        SandboxInfo::Preset(vec![]),
        CheckOutput {
            decision: "deny".to_string(),
            reason: Some("dangerous command".to_string()),
            fix_suggestion: Some("use rm with caution".to_string()),
            sandbox: None,
        },
    )]
    #[case::ask_with_message(
        Action::Ask(Some("please confirm".to_string())),
        SandboxInfo::Preset(vec![]),
        CheckOutput { decision: "ask".to_string(), reason: Some("please confirm".to_string()), fix_suggestion: None, sandbox: None },
    )]
    #[case::ask_without_message(
        Action::Ask(None),
        SandboxInfo::Preset(vec![]),
        CheckOutput { decision: "ask".to_string(), reason: None, fix_suggestion: None, sandbox: None },
    )]
    #[case::with_sandbox_preset(
        Action::Allow,
        SandboxInfo::Preset(vec!["restricted".to_string()]),
        CheckOutput {
            decision: "allow".to_string(),
            reason: None,
            fix_suggestion: None,
            sandbox: Some(CheckSandboxInfo { preset: "restricted".to_string(), writable_roots: None, network_allowed: None }),
        },
    )]
    #[case::with_multiple_sandbox_presets(
        Action::Allow,
        SandboxInfo::Preset(vec!["a".to_string(), "b".to_string()]),
        CheckOutput {
            decision: "allow".to_string(),
            reason: None,
            fix_suggestion: None,
            sandbox: Some(CheckSandboxInfo { preset: "a, b".to_string(), writable_roots: None, network_allowed: None }),
        },
    )]
    #[case::pass(
        Action::Pass,
        SandboxInfo::Preset(vec![]),
        CheckOutput { decision: "pass".to_string(), reason: None, fix_suggestion: None, sandbox: None },
    )]
    fn build_check_output_maps_action_to_output(
        #[case] action: Action,
        #[case] sandbox: SandboxInfo,
        #[case] expected: CheckOutput,
    ) {
        let result = ActionResult {
            action,
            sandbox,
            sandbox_wraps: vec![],
            evaluations: vec![],
        };
        assert_eq!(build_check_output(&result, &HashMap::new()), expected);
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
    #[case::pass(Action::Pass)]
    fn handle_action_always_returns_exit_0(#[case] action: Action) {
        let adapter = CheckAdapter::from_command("test".to_string());
        let result = ActionResult {
            action,
            sandbox: SandboxInfo::Preset(vec![]),
            sandbox_wraps: vec![],
            evaluations: vec![],
        };
        assert_eq!(adapter.handle_action(result).ok(), Some(0));
    }

    // --- build_no_match_output: defaults mapping ---

    #[rstest]
    #[case::default_pass(None, "pass")]
    #[case::explicit_allow(Some(ActionKind::Allow), "allow")]
    #[case::explicit_deny(Some(ActionKind::Deny), "deny")]
    #[case::explicit_ask(Some(ActionKind::Ask), "ask")]
    #[case::explicit_pass(Some(ActionKind::Pass), "pass")]
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
    #[case::no_preset(SandboxInfo::Preset(vec![]), None)]
    fn build_sandbox_info_returns_none_for_empty(
        #[case] info: SandboxInfo,
        #[case] expected: Option<CheckSandboxInfo>,
    ) {
        assert_eq!(build_sandbox_info(&info, &HashMap::new()), expected);
    }

    // No `sandbox_definitions` provided -- falls back to `writable_roots: None,
    // network_allowed: None` rather than resolving the preset.
    #[rstest]
    fn build_sandbox_info_from_preset_without_definitions() {
        let info = SandboxInfo::Preset(vec!["restricted".to_string()]);
        let result = build_sandbox_info(&info, &HashMap::new());
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
    fn build_sandbox_info_from_multiple_presets_joins_names_without_definitions() {
        let info = SandboxInfo::Preset(vec!["a".to_string(), "b".to_string()]);
        let result = build_sandbox_info(&info, &HashMap::new());
        assert_eq!(
            result,
            Some(CheckSandboxInfo {
                preset: "a, b".to_string(),
                writable_roots: None,
                network_allowed: None,
            })
        );
    }

    /// Build a `SandboxPreset` with the given write-allow roots and network policy,
    /// for exercising `SandboxPreset::merge_strictest` through `build_sandbox_info`.
    fn preset(writable: &[&str], network_allow: Option<bool>) -> SandboxPreset {
        SandboxPreset {
            fs: Some(FsPolicy {
                read: None,
                write: Some(FsAccessPolicy {
                    allow: Some(writable.iter().map(|s| s.to_string()).collect()),
                    deny: None,
                }),
            }),
            network: network_allow.map(|allow| NetworkPolicy { allow: Some(allow) }),
        }
    }

    #[rstest]
    #[case::single_preset(
        vec!["restricted"],
        vec![("restricted", preset(&["/tmp", "/home"], Some(true)))],
        CheckSandboxInfo {
            preset: "restricted".to_string(),
            writable_roots: Some(vec!["/home".to_string(), "/tmp".to_string()]),
            network_allowed: Some(true),
        },
    )]
    #[case::multiple_presets_merge_strictest(
        vec!["a", "b"],
        vec![
            ("a", preset(&["/tmp", "/home"], Some(true))),
            ("b", preset(&["/tmp", "/var"], Some(false))),
        ],
        CheckSandboxInfo {
            preset: "a, b".to_string(),
            // writable: intersection of {/tmp, /home} and {/tmp, /var} -> {/tmp}
            writable_roots: Some(vec!["/tmp".to_string()]),
            // network: AND -> denied because "b" denies it
            network_allowed: Some(false),
        },
    )]
    #[case::missing_definition_degrades_gracefully(
        vec!["a", "b"],
        vec![("a", preset(&["/tmp"], Some(true)))],
        CheckSandboxInfo {
            preset: "a, b".to_string(),
            writable_roots: None,
            network_allowed: None,
        },
    )]
    fn build_sandbox_info_resolves_with_definitions(
        #[case] names: Vec<&str>,
        #[case] definitions: Vec<(&str, SandboxPreset)>,
        #[case] expected: CheckSandboxInfo,
    ) {
        let sandbox_definitions: HashMap<String, SandboxPreset> = definitions
            .into_iter()
            .map(|(name, preset)| (name.to_string(), preset))
            .collect();
        let info = SandboxInfo::Preset(names.into_iter().map(String::from).collect());
        let result = build_sandbox_info(&info, &sandbox_definitions);
        assert_eq!(result, Some(expected));
    }

    // --- audit ---

    #[rstest]
    fn is_auditable_returns_false() {
        let adapter = CheckAdapter::from_command("test".to_string());
        assert!(!adapter.is_auditable());
    }
}
