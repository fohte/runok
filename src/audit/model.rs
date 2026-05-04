use serde::{Deserialize, Serialize};

use crate::config::ActionKind;
use crate::rules::command_parser::{EnvAssignment, ExtractedCommand, PipeInfo, RedirectInfo};
use crate::rules::rule_engine::{Action, DenyResponse, RuleMatchInfo};

/// A complete record of a single command evaluation.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    /// ISO 8601 timestamp (UTC).
    pub timestamp: String,
    /// Input command string.
    pub command: String,
    /// Final evaluation result.
    pub action: SerializableAction,
    /// List of rules that matched.
    pub matched_rules: Vec<SerializableRuleMatch>,
    /// Sandbox preset name (if applied).
    pub sandbox_preset: Option<String>,
    /// Default action setting value.
    pub default_action: Option<String>,
    /// Session and context information.
    pub metadata: AuditMetadata,
    /// Sub-evaluation results for compound/wrapper commands (if applicable).
    pub sub_evaluations: Option<Vec<SubEvaluation>>,
    /// Shell-level parse result for the top-level command. Set for
    /// non-compound inputs and absent (`None`) for compound (`a && b`,
    /// `a | b`, etc.) — use `sub_evaluations[].parsed` for those.
    /// Also absent when the input could not be parsed (e.g. unbalanced
    /// quotes), in which case audit consumers can still fall back to
    /// the raw `command` string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<SerializableParsedCommand>,
}

/// Context information about the evaluation.
#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct AuditMetadata {
    /// Endpoint subcommand type (exec, check, hook).
    pub endpoint_type: String,
    /// Session ID (if available from the environment).
    pub session_id: Option<String>,
    /// Working directory.
    pub cwd: Option<String>,
    /// Hook-specific: tool name (Bash, Read, etc.).
    pub tool_name: Option<String>,
    /// Hook-specific: hook event name.
    pub hook_event_name: Option<String>,
}

/// Serializable representation of an evaluation action.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "detail", rename_all = "lowercase")]
pub enum SerializableAction {
    Allow,
    Deny {
        message: Option<String>,
        fix_suggestion: Option<String>,
    },
    Ask {
        message: Option<String>,
    },
    Default,
}

/// Serializable representation of a matched rule.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SerializableRuleMatch {
    /// Action kind of the rule (allow, deny, ask).
    pub action_kind: String,
    /// Pattern string.
    pub pattern: String,
    /// Tokens captured by wildcards.
    pub matched_tokens: Vec<String>,
}

/// Sub-evaluation result for compound/wrapper commands.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SubEvaluation {
    /// Sub-command string.
    pub command: String,
    /// Evaluation result.
    pub action: SerializableAction,
    /// Matched rules.
    pub matched_rules: Vec<SerializableRuleMatch>,
    /// Evaluation type (compound split / wrapper recursive expansion).
    pub eval_type: String,
    /// Shell-level parse result for this sub-command. Absent when the
    /// extractor produced no env / argv / redirects / pipe data (e.g.
    /// AST leaf-text fallback), in which case `command` is the only
    /// available view of the sub-command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<SerializableParsedCommand>,
}

/// Shell-level parse result attached to an audit entry.
///
/// Captures everything `runok` already extracts from the command
/// string before rule evaluation: the inline environment prefix, the
/// command + argument tokens (with quotes resolved), redirects, and
/// pipeline position. Audit consumers can use this to filter on the
/// real binary (`parsed.argv[0]`) without re-implementing shell
/// tokenisation in `jq`.
///
/// Higher-level shaping (resolving `binary` vs `subcommand`,
/// normalising `mise` shims, classifying `-n` as boolean vs
/// value-taking) is intentionally not done here — those decisions are
/// CLI-specific and belong to the audit consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SerializableParsedCommand {
    /// Inline environment variable prefix (`FOO=bar BAZ=qux cmd ...`).
    /// Empty when the command had no such prefix.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<SerializableEnvVar>,
    /// The command name + argument tokens with shell quoting resolved.
    /// `argv[0]` is the binary as written. Empty when shell parsing
    /// could not produce an argv (e.g. an AST leaf-text fallback).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Redirect operators attached to the command (`> file`, `2>&1`,
    /// `<<EOF`, etc.). Empty when the command had no redirects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<SerializableRedirect>,
    /// Pipe position. `pipe.stdin` / `pipe.stdout` are `false` for a
    /// standalone command.
    #[serde(default, skip_serializing_if = "SerializablePipe::is_default")]
    pub pipe: SerializablePipe,
}

/// A `KEY=VALUE` environment variable assignment that prefixed the
/// command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SerializableEnvVar {
    /// Variable name.
    pub name: String,
    /// Variable value with shell quotes resolved. `None` for the bare
    /// `KEY= cmd` form (clear the variable).
    pub value: Option<String>,
}

/// A redirect operator attached to a command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SerializableRedirect {
    /// Redirect category: `"input"`, `"output"`, or `"dup"`.
    pub redirect_type: String,
    /// The redirect operator text (`>`, `>>`, `<`, `<<<`, `>&`, etc.).
    pub operator: String,
    /// Redirect target (filename, fd reference like `&1`, etc.).
    pub target: String,
    /// Explicit file descriptor (e.g. `2` in `2>file`).
    pub descriptor: Option<i64>,
}

/// Pipeline position of a command.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SerializablePipe {
    /// Stdin comes from a preceding pipe.
    pub stdin: bool,
    /// Stdout feeds a following pipe.
    pub stdout: bool,
}

impl SerializablePipe {
    fn is_default(&self) -> bool {
        !self.stdin && !self.stdout
    }
}

impl From<Action> for SerializableAction {
    fn from(action: Action) -> Self {
        match action {
            Action::Allow => SerializableAction::Allow,
            Action::Deny(DenyResponse {
                message,
                fix_suggestion,
                ..
            }) => SerializableAction::Deny {
                message,
                fix_suggestion,
            },
            Action::Ask(message) => SerializableAction::Ask { message },
        }
    }
}

impl From<RuleMatchInfo> for SerializableRuleMatch {
    fn from(info: RuleMatchInfo) -> Self {
        SerializableRuleMatch {
            action_kind: match info.action_kind {
                ActionKind::Allow => "allow".to_owned(),
                ActionKind::Ask => "ask".to_owned(),
                ActionKind::Deny => "deny".to_owned(),
            },
            pattern: info.pattern,
            matched_tokens: info.matched_tokens,
        }
    }
}

impl From<&EnvAssignment> for SerializableEnvVar {
    fn from(assignment: &EnvAssignment) -> Self {
        SerializableEnvVar {
            name: assignment.name.clone(),
            value: assignment.value.clone(),
        }
    }
}

impl From<&RedirectInfo> for SerializableRedirect {
    fn from(info: &RedirectInfo) -> Self {
        SerializableRedirect {
            redirect_type: info.redirect_type.clone(),
            operator: info.operator.clone(),
            target: info.target.clone(),
            descriptor: info.descriptor,
        }
    }
}

impl From<&PipeInfo> for SerializablePipe {
    fn from(info: &PipeInfo) -> Self {
        SerializablePipe {
            stdin: info.stdin,
            stdout: info.stdout,
        }
    }
}

impl From<&ExtractedCommand> for SerializableParsedCommand {
    fn from(extracted: &ExtractedCommand) -> Self {
        SerializableParsedCommand {
            env: extracted.env.iter().map(SerializableEnvVar::from).collect(),
            argv: extracted.argv.clone(),
            redirects: extracted
                .redirects
                .iter()
                .map(SerializableRedirect::from)
                .collect(),
            pipe: SerializablePipe::from(&extracted.pipe),
        }
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::allow_action(
        SerializableAction::Allow,
        indoc! {r#"{"type":"allow"}"#},
    )]
    #[case::deny_action_with_details(
        SerializableAction::Deny {
            message: Some("force push is forbidden".to_owned()),
            fix_suggestion: Some("git push origin main".to_owned()),
        },
        indoc! {r#"{"type":"deny","detail":{"message":"force push is forbidden","fix_suggestion":"git push origin main"}}"#},
    )]
    #[case::deny_action_without_details(
        SerializableAction::Deny {
            message: None,
            fix_suggestion: None,
        },
        indoc! {r#"{"type":"deny","detail":{"message":null,"fix_suggestion":null}}"#},
    )]
    #[case::ask_action_with_message(
        SerializableAction::Ask {
            message: Some("are you sure?".to_owned()),
        },
        indoc! {r#"{"type":"ask","detail":{"message":"are you sure?"}}"#},
    )]
    #[case::ask_action_without_message(
        SerializableAction::Ask { message: None },
        indoc! {r#"{"type":"ask","detail":{"message":null}}"#},
    )]
    #[case::default_action(
        SerializableAction::Default,
        indoc! {r#"{"type":"default"}"#},
    )]
    fn serializable_action_roundtrip(
        #[case] action: SerializableAction,
        #[case] expected_json: &str,
    ) {
        let serialized = serde_json::to_string(&action).unwrap();
        assert_eq!(serialized, expected_json);

        let deserialized: SerializableAction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, action);
    }

    #[rstest]
    #[case::single_rule(
        vec![SerializableRuleMatch {
            action_kind: "deny".to_owned(),
            pattern: "git push -f *".to_owned(),
            matched_tokens: vec!["origin".to_owned(), "main".to_owned()],
        }],
    )]
    #[case::empty_rules(vec![])]
    fn serializable_rule_match_roundtrip(#[case] rules: Vec<SerializableRuleMatch>) {
        let serialized = serde_json::to_string(&rules).unwrap();
        let deserialized: Vec<SerializableRuleMatch> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, rules);
    }

    #[rstest]
    #[case::sub_evaluation_compound(
        SubEvaluation {
            command: "echo hello".to_owned(),
            action: SerializableAction::Allow,
            matched_rules: vec![SerializableRuleMatch {
                action_kind: "allow".to_owned(),
                pattern: "echo *".to_owned(),
                matched_tokens: vec!["hello".to_owned()],
            }],
            eval_type: "compound".to_owned(),
            parsed: None,
        },
    )]
    fn sub_evaluation_roundtrip(#[case] sub_eval: SubEvaluation) {
        let serialized = serde_json::to_string(&sub_eval).unwrap();
        let deserialized: SubEvaluation = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, sub_eval);
    }

    #[rstest]
    #[case::without_sub_evaluations(AuditEntry {
        timestamp: "2026-02-25T10:30:00Z".to_owned(),
        command: "git push -f origin main".to_owned(),
        action: SerializableAction::Deny {
            message: Some("force push is forbidden".to_owned()),
            fix_suggestion: Some("git push origin main".to_owned()),
        },
        matched_rules: vec![SerializableRuleMatch {
            action_kind: "deny".to_owned(),
            pattern: "git push -f|--force *".to_owned(),
            matched_tokens: vec!["origin".to_owned(), "main".to_owned()],
        }],
        sandbox_preset: None,
        default_action: Some("ask".to_owned()),
        metadata: AuditMetadata {
            endpoint_type: "hook".to_owned(),
            session_id: Some("abc-123".to_owned()),
            cwd: Some("/home/user/project".to_owned()),
            tool_name: Some("Bash".to_owned()),
            hook_event_name: Some("PreToolUse".to_owned()),
        },
        sub_evaluations: None,
        parsed: None,
    })]
    #[case::with_sub_evaluations(AuditEntry {
        timestamp: "2026-02-25T11:00:00Z".to_owned(),
        command: "echo hello && rm -rf /".to_owned(),
        action: SerializableAction::Deny {
            message: None,
            fix_suggestion: None,
        },
        matched_rules: vec![],
        sandbox_preset: None,
        default_action: None,
        metadata: AuditMetadata {
            endpoint_type: "exec".to_owned(),
            ..AuditMetadata::default()
        },
        sub_evaluations: Some(vec![
            SubEvaluation {
                command: "echo hello".to_owned(),
                action: SerializableAction::Allow,
                matched_rules: vec![],
                eval_type: "compound".to_owned(),
                parsed: None,
            },
            SubEvaluation {
                command: "rm -rf /".to_owned(),
                action: SerializableAction::Deny {
                    message: None,
                    fix_suggestion: None,
                },
                matched_rules: vec![SerializableRuleMatch {
                    action_kind: "deny".to_owned(),
                    pattern: "rm -rf *".to_owned(),
                    matched_tokens: vec!["/".to_owned()],
                }],
                eval_type: "compound".to_owned(),
                parsed: None,
            },
        ]),
        parsed: None,
    })]
    fn audit_entry_roundtrip(#[case] entry: AuditEntry) {
        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, entry);
    }

    #[rstest]
    #[case::allow(Action::Allow, SerializableAction::Allow)]
    #[case::deny_with_details(
        Action::Deny(DenyResponse {
            message: Some("forbidden".to_owned()),
            fix_suggestion: Some("use safe command".to_owned()),
            matched_rule: "git push -f *".to_owned(),
        }),
        SerializableAction::Deny {
            message: Some("forbidden".to_owned()),
            fix_suggestion: Some("use safe command".to_owned()),
        },
    )]
    #[case::deny_without_details(
        Action::Deny(DenyResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: "rm -rf *".to_owned(),
        }),
        SerializableAction::Deny {
            message: None,
            fix_suggestion: None,
        },
    )]
    #[case::ask_with_message(
        Action::Ask(Some("are you sure?".to_owned())),
        SerializableAction::Ask {
            message: Some("are you sure?".to_owned()),
        },
    )]
    #[case::ask_without_message(
        Action::Ask(None),
        SerializableAction::Ask { message: None },
    )]
    fn action_to_serializable(#[case] action: Action, #[case] expected: SerializableAction) {
        let result: SerializableAction = action.into();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::allow_rule(
        RuleMatchInfo {
            action_kind: ActionKind::Allow,
            pattern: "echo *".to_owned(),
            matched_tokens: vec!["hello".to_owned()],
        },
        SerializableRuleMatch {
            action_kind: "allow".to_owned(),
            pattern: "echo *".to_owned(),
            matched_tokens: vec!["hello".to_owned()],
        },
    )]
    #[case::deny_rule(
        RuleMatchInfo {
            action_kind: ActionKind::Deny,
            pattern: "rm -rf *".to_owned(),
            matched_tokens: vec!["/".to_owned()],
        },
        SerializableRuleMatch {
            action_kind: "deny".to_owned(),
            pattern: "rm -rf *".to_owned(),
            matched_tokens: vec!["/".to_owned()],
        },
    )]
    #[case::ask_rule(
        RuleMatchInfo {
            action_kind: ActionKind::Ask,
            pattern: "git push *".to_owned(),
            matched_tokens: vec!["origin".to_owned(), "main".to_owned()],
        },
        SerializableRuleMatch {
            action_kind: "ask".to_owned(),
            pattern: "git push *".to_owned(),
            matched_tokens: vec!["origin".to_owned(), "main".to_owned()],
        },
    )]
    fn rule_match_info_to_serializable(
        #[case] info: RuleMatchInfo,
        #[case] expected: SerializableRuleMatch,
    ) {
        let result: SerializableRuleMatch = info.into();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::default_drops_all_fields(
        SerializableParsedCommand {
            env: vec![],
            argv: vec![],
            redirects: vec![],
            pipe: SerializablePipe::default(),
        },
        "{}",
    )]
    #[case::env_and_argv(
        SerializableParsedCommand {
            env: vec![SerializableEnvVar {
                name: "FOO".to_owned(),
                value: Some("x".to_owned()),
            }],
            argv: vec!["helmfile".to_owned(), "template".to_owned()],
            redirects: vec![],
            pipe: SerializablePipe::default(),
        },
        r#"{"env":[{"name":"FOO","value":"x"}],"argv":["helmfile","template"]}"#,
    )]
    #[case::redirects_and_pipe(
        SerializableParsedCommand {
            env: vec![],
            argv: vec!["echo".to_owned(), "hi".to_owned()],
            redirects: vec![SerializableRedirect {
                redirect_type: "output".to_owned(),
                operator: ">".to_owned(),
                target: "/tmp/log".to_owned(),
                descriptor: None,
            }],
            pipe: SerializablePipe { stdin: false, stdout: true },
        },
        r#"{"argv":["echo","hi"],"redirects":[{"redirect_type":"output","operator":">","target":"/tmp/log","descriptor":null}],"pipe":{"stdin":false,"stdout":true}}"#,
    )]
    fn parsed_command_serialises(
        #[case] parsed: SerializableParsedCommand,
        #[case] expected: &str,
    ) {
        let serialized = serde_json::to_string(&parsed).unwrap();
        assert_eq!(serialized, expected);
        let deserialized: SerializableParsedCommand = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, parsed);
    }

    #[rstest]
    fn audit_entry_with_parsed_roundtrips() {
        let entry = AuditEntry {
            timestamp: "2026-05-04T00:00:00Z".to_owned(),
            command: "FOO=x helmfile template".to_owned(),
            action: SerializableAction::Allow,
            matched_rules: vec![],
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata::default(),
            sub_evaluations: None,
            parsed: Some(SerializableParsedCommand {
                env: vec![SerializableEnvVar {
                    name: "FOO".to_owned(),
                    value: Some("x".to_owned()),
                }],
                argv: vec!["helmfile".to_owned(), "template".to_owned()],
                redirects: vec![],
                pipe: SerializablePipe::default(),
            }),
        };
        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, entry);
    }

    #[rstest]
    fn audit_entry_without_parsed_omits_field() {
        // Existing audit consumers must not see a `parsed` key when the
        // value is None, otherwise jq filters that grew up against the
        // pre-parsed-field schema would suddenly see a new noisy field.
        let entry = AuditEntry {
            timestamp: "2026-05-04T00:00:00Z".to_owned(),
            command: "git status".to_owned(),
            action: SerializableAction::Allow,
            matched_rules: vec![],
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata::default(),
            sub_evaluations: None,
            parsed: None,
        };
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(
            !serialized.contains("\"parsed\""),
            "parsed key should be skipped when None: {serialized}"
        );
    }
}
