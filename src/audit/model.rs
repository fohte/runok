use serde::{Deserialize, Serialize};

use crate::config::ActionKind;
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
            Action::Default => SerializableAction::Default,
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
            },
        ]),
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
    #[case::default(Action::Default, SerializableAction::Default)]
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
}
