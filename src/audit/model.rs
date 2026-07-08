use serde::{Deserialize, Serialize};

use crate::config::ActionKind;
use crate::rules::command_parser::{EnvAssignment, ExtractedCommand, PipeInfo, RedirectInfo};
use crate::rules::rule_engine::{Action, DenyResponse, RuleMatchInfo};

/// A complete record of a single command evaluation.
///
/// Deserialisation accepts both the current schema (with
/// `command_evaluations`) and the pre-#333 schema (with top-level
/// `matched_rules` / `sub_evaluations`). The old shape is rewritten
/// into `command_evaluations` on the fly so `runok audit` keeps
/// surfacing logs written by older runok versions. Serialisation
/// always emits the current schema.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(try_from = "RawAuditEntry")]
pub struct AuditEntry {
    /// ISO 8601 timestamp (UTC).
    pub timestamp: String,
    /// Input command string as runok received it.
    pub command: String,
    /// Final evaluation result for the input as a whole.
    pub action: SerializableAction,
    /// Sandbox preset name (if applied).
    pub sandbox_preset: Option<String>,
    /// Default action setting value.
    pub default_action: Option<String>,
    /// Session and context information.
    pub metadata: AuditMetadata,
    /// Per-command evaluation records, in source order.
    ///
    /// One entry per shell command extracted from `command`. A
    /// non-compound input (e.g. `git status`) produces one entry; a
    /// compound or pipelined input (e.g. `a && b`, `a | b`) produces
    /// one per branch. May be empty when the input contained no
    /// runnable command (comment-only, parse error).
    ///
    /// Audit consumers can read `argv[0]` from each entry without
    /// branching on a separate top-level vs. nested-list shape.
    pub command_evaluations: Vec<CommandEvaluation>,
}

/// On-the-wire shape used only for deserialisation.
///
/// `command_evaluations` is the current field. `matched_rules` and
/// `sub_evaluations` were emitted by runok versions before the
/// command_evaluations consolidation. When a log file mixes both
/// shapes (e.g. retention spans the upgrade), each entry is upgraded
/// independently.
#[derive(Debug, Deserialize)]
struct RawAuditEntry {
    timestamp: String,
    command: String,
    action: SerializableAction,
    #[serde(default)]
    sandbox_preset: Option<String>,
    #[serde(default)]
    default_action: Option<String>,
    #[serde(default)]
    metadata: AuditMetadata,
    #[serde(default)]
    command_evaluations: Option<Vec<CommandEvaluation>>,
    /// Legacy: top-level matched rules from the pre-consolidation schema.
    #[serde(default)]
    matched_rules: Option<Vec<SerializableRuleMatch>>,
    /// Legacy: per-branch results from the pre-consolidation schema.
    #[serde(default)]
    sub_evaluations: Option<Vec<LegacySubEvaluation>>,
}

/// Legacy sub-evaluation entry as emitted before the
/// command_evaluations consolidation. Kept here only so legacy logs
/// keep deserialising; never written.
#[derive(Debug, Deserialize)]
struct LegacySubEvaluation {
    command: String,
    action: SerializableAction,
    #[serde(default)]
    matched_rules: Vec<SerializableRuleMatch>,
    eval_type: String,
}

impl TryFrom<RawAuditEntry> for AuditEntry {
    type Error = String;

    fn try_from(raw: RawAuditEntry) -> Result<Self, Self::Error> {
        let command_evaluations = if let Some(evals) = raw.command_evaluations {
            evals
        } else if let Some(subs) = raw.sub_evaluations {
            // Legacy compound entry: each sub became one CommandEvaluation.
            // Old logs predate env / argv / redirects / pipe so those stay empty.
            subs.into_iter()
                .map(|s| CommandEvaluation {
                    command: s.command,
                    action: s.action,
                    matched_rules: s.matched_rules,
                    eval_type: parse_legacy_eval_type(&s.eval_type),
                    env: Vec::new(),
                    argv: Vec::new(),
                    redirects: Vec::new(),
                    pipe: SerializablePipe::default(),
                    alias_chain: Vec::new(),
                })
                .collect()
        } else {
            // Legacy non-compound entry: synthesise a single primary
            // record from the top-level command + matched_rules.
            vec![CommandEvaluation {
                command: raw.command.clone(),
                action: raw.action.clone(),
                matched_rules: raw.matched_rules.unwrap_or_default(),
                eval_type: EvalType::Primary,
                env: Vec::new(),
                argv: Vec::new(),
                redirects: Vec::new(),
                pipe: SerializablePipe::default(),
                alias_chain: Vec::new(),
            }]
        };

        Ok(AuditEntry {
            timestamp: raw.timestamp,
            command: raw.command,
            action: raw.action,
            sandbox_preset: raw.sandbox_preset,
            default_action: raw.default_action,
            metadata: raw.metadata,
            command_evaluations,
        })
    }
}

fn parse_legacy_eval_type(s: &str) -> EvalType {
    match s {
        "primary" => EvalType::Primary,
        // Anything else (including `"compound"`, `"wrapper"` from the
        // old wrapper expansion path, or unknown values from a
        // forward-compat log) maps to Compound. The audit consumer
        // can still read the per-branch `command` to disambiguate.
        _ => EvalType::Compound,
    }
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
    /// Hook-specific: tool use ID shared by the PreToolUse and PostToolUse
    /// inputs of the same tool call. Correlation key for `AskResolution`.
    pub tool_use_id: Option<String>,
}

/// Record of an `ask` decision being approved in the agent's permission
/// dialog.
///
/// Written as its own JSONL line in the same date-partitioned files as
/// decision entries. The `kind` tag discriminates the two record types:
/// decision entries have no `kind` field. Older runok versions skip these
/// lines as unparseable, so appending them does not break existing readers.
///
/// `command` is copied from the correlated ask decision entry so the record
/// is self-contained for consumers that aggregate approvals without
/// re-joining decision entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename = "ask_resolution")]
pub struct AskResolution {
    /// ISO 8601 timestamp (UTC) of the approval.
    pub timestamp: String,
    /// How the ask was resolved.
    pub outcome: AskResolutionOutcome,
    /// Tool use ID of the approved tool call. `None` when the hook input
    /// carried no `tool_use_id` (correlation fell back to session + command).
    pub tool_use_id: Option<String>,
    /// Session ID from the PostToolUse hook input.
    pub session_id: Option<String>,
    /// Working directory from the PostToolUse hook input.
    pub cwd: Option<String>,
    /// Original command from the correlated ask decision entry.
    pub command: String,
    /// Command the agent actually executed. Differs from `command` when the
    /// PreToolUse response rewrote it via `updatedInput` (sandbox wrapping).
    pub executed_command: String,
}

/// How an ask was resolved.
///
/// Only `approved` can be observed today: Claude Code fires no hook after
/// the user denies a permission dialog, so denials are unrecordable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AskResolutionOutcome {
    Approved,
}

/// Serializable representation of an evaluation action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SerializableRuleMatch {
    /// Action kind of the rule (allow, deny, ask).
    pub action_kind: String,
    /// Pattern string.
    pub pattern: String,
    /// Tokens captured by wildcards.
    pub matched_tokens: Vec<String>,
}

/// How a `CommandEvaluation` was extracted from the input.
///
/// `Primary` is used for non-compound inputs (one entry total).
/// `Compound` is used for each branch of `a && b` / `a || b` /
/// `a ; b` / `a | b` / etc.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EvalType {
    Primary,
    Compound,
}

/// Per-branch record of a single command extracted from the input.
///
/// Carries the rule-evaluation result and the shell-level parse
/// result side by side, so audit consumers can filter on the actual
/// binary (`argv[0]`) without re-implementing shell tokenisation.
/// Higher-level shaping (`binary` vs `subcommand`, `mise` shim
/// normalisation, treating `-n` as boolean vs value-taking) is
/// intentionally not done here — those rules differ per CLI and
/// belong to the consumer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommandEvaluation {
    /// The branch command string (redirects stripped, env prefix kept).
    pub command: String,
    /// Evaluation result for this branch.
    pub action: SerializableAction,
    /// Rules that matched for this branch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<SerializableRuleMatch>,
    /// How this branch was extracted from the input.
    pub eval_type: EvalType,
    /// Inline `KEY=VALUE` env prefix. Empty when the branch had none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<SerializableEnvVar>,
    /// Command name + arguments with shell quoting resolved. `argv[0]`
    /// is the binary as written. Empty when shell parsing could not
    /// produce an argv (AST leaf-text fallback).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Redirect operators attached to this branch. Empty when none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<SerializableRedirect>,
    /// Pipeline position. Both `stdin` / `stdout` are `false` for a
    /// standalone branch; the field is omitted from JSON in that case.
    #[serde(default, skip_serializing_if = "SerializablePipe::is_default")]
    pub pipe: SerializablePipe,
    /// Names of aliases applied to this branch before rule evaluation, in
    /// the order they fired. Empty when no alias expansion was triggered;
    /// omitted from JSON in that case to keep legacy audit shape unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alias_chain: Vec<String>,
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

/// Build the parse-related fields of a `CommandEvaluation` from an
/// `ExtractedCommand` produced by the rules layer. Used by the
/// adapter and by tests that synthesise audit entries.
pub fn parse_fields_from_extracted(
    extracted: &ExtractedCommand,
) -> (
    Vec<SerializableEnvVar>,
    Vec<String>,
    Vec<SerializableRedirect>,
    SerializablePipe,
) {
    let env = extracted.env.iter().map(SerializableEnvVar::from).collect();
    let argv = extracted.argv.clone();
    let redirects = extracted
        .redirects
        .iter()
        .map(SerializableRedirect::from)
        .collect();
    let pipe = SerializablePipe::from(&extracted.pipe);
    (env, argv, redirects, pipe)
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

    fn sample_primary_evaluation() -> CommandEvaluation {
        CommandEvaluation {
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
            eval_type: EvalType::Primary,
            env: vec![],
            argv: vec![
                "git".to_owned(),
                "push".to_owned(),
                "-f".to_owned(),
                "origin".to_owned(),
                "main".to_owned(),
            ],
            redirects: vec![],
            pipe: SerializablePipe::default(),
            alias_chain: vec![],
        }
    }

    #[rstest]
    #[case::single_command(AuditEntry {
        timestamp: "2026-02-25T10:30:00Z".to_owned(),
        command: "git push -f origin main".to_owned(),
        action: SerializableAction::Deny {
            message: Some("force push is forbidden".to_owned()),
            fix_suggestion: Some("git push origin main".to_owned()),
        },
        sandbox_preset: None,
        default_action: Some("ask".to_owned()),
        metadata: AuditMetadata {
            endpoint_type: "hook".to_owned(),
            session_id: Some("abc-123".to_owned()),
            cwd: Some("/home/user/project".to_owned()),
            tool_name: Some("Bash".to_owned()),
            hook_event_name: Some("PreToolUse".to_owned()),
            tool_use_id: Some("toolu_01".to_owned()),
        },
        command_evaluations: vec![sample_primary_evaluation()],
    })]
    #[case::compound(AuditEntry {
        timestamp: "2026-02-25T11:00:00Z".to_owned(),
        command: "echo hello && rm -rf /".to_owned(),
        action: SerializableAction::Deny {
            message: None,
            fix_suggestion: None,
        },
        sandbox_preset: None,
        default_action: None,
        metadata: AuditMetadata {
            endpoint_type: "exec".to_owned(),
            ..AuditMetadata::default()
        },
        command_evaluations: vec![
            CommandEvaluation {
                command: "echo hello".to_owned(),
                action: SerializableAction::Allow,
                matched_rules: vec![],
                eval_type: EvalType::Compound,
                env: vec![],
                argv: vec!["echo".to_owned(), "hello".to_owned()],
                redirects: vec![],
                pipe: SerializablePipe::default(),
                alias_chain: vec![],
            },
            CommandEvaluation {
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
                eval_type: EvalType::Compound,
                env: vec![],
                argv: vec!["rm".to_owned(), "-rf".to_owned(), "/".to_owned()],
                redirects: vec![],
                pipe: SerializablePipe::default(),
                alias_chain: vec![],
            },
        ],
    })]
    fn audit_entry_roundtrip(#[case] entry: AuditEntry) {
        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, entry);
    }

    #[rstest]
    fn legacy_compound_audit_entry_deserialises_into_command_evaluations() {
        // Real-shape sample of the pre-#333 schema. The reader has to
        // surface this as a current-shape AuditEntry so existing audit
        // log files keep working after the upgrade.
        let legacy_json = indoc! {r#"
            {
                "timestamp": "2026-04-27T10:00:00Z",
                "command": "echo hi && rm -rf /",
                "action": {"type": "deny", "detail": {"message": null, "fix_suggestion": null}},
                "matched_rules": [],
                "sandbox_preset": null,
                "default_action": "ask",
                "metadata": {"endpoint_type": "exec"},
                "sub_evaluations": [
                    {
                        "command": "echo hi",
                        "action": {"type": "allow"},
                        "matched_rules": [{"action_kind": "allow", "pattern": "echo *", "matched_tokens": ["hi"]}],
                        "eval_type": "compound"
                    },
                    {
                        "command": "rm -rf /",
                        "action": {"type": "deny", "detail": {"message": null, "fix_suggestion": null}},
                        "matched_rules": [{"action_kind": "deny", "pattern": "rm -rf *", "matched_tokens": ["/"]}],
                        "eval_type": "compound"
                    }
                ]
            }
        "#};

        let entry: AuditEntry = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(entry.command, "echo hi && rm -rf /");
        assert_eq!(entry.command_evaluations.len(), 2);

        let first = &entry.command_evaluations[0];
        assert_eq!(first.command, "echo hi");
        assert_eq!(first.eval_type, EvalType::Compound);
        assert_eq!(first.matched_rules[0].pattern, "echo *");
        // Legacy logs predate env / argv / redirects / pipe.
        assert!(first.argv.is_empty());
        assert!(first.env.is_empty());

        let second = &entry.command_evaluations[1];
        assert_eq!(second.command, "rm -rf /");
        assert_eq!(second.eval_type, EvalType::Compound);
        assert!(matches!(second.action, SerializableAction::Deny { .. }));
    }

    #[rstest]
    fn legacy_single_audit_entry_deserialises_into_one_primary_evaluation() {
        let legacy_json = indoc! {r#"
            {
                "timestamp": "2026-04-27T10:00:00Z",
                "command": "git status",
                "action": {"type": "allow"},
                "matched_rules": [{"action_kind": "allow", "pattern": "git status", "matched_tokens": []}],
                "sandbox_preset": null,
                "default_action": null,
                "metadata": {"endpoint_type": "hook"},
                "sub_evaluations": null
            }
        "#};

        let entry: AuditEntry = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(entry.command_evaluations.len(), 1);
        let primary = &entry.command_evaluations[0];
        assert_eq!(primary.eval_type, EvalType::Primary);
        assert_eq!(primary.command, "git status");
        assert_eq!(primary.matched_rules[0].pattern, "git status");
        assert!(primary.argv.is_empty());
    }

    #[rstest]
    fn audit_entry_omits_legacy_top_level_keys() {
        // Hard-fail if anyone reintroduces the dropped top-level
        // `matched_rules` / `parsed` / `sub_evaluations` keys, since
        // consumers now branch on `command_evaluations` and would
        // silently miss data if those keys came back.
        let entry = AuditEntry {
            timestamp: "2026-05-04T00:00:00Z".to_owned(),
            command: "echo hi".to_owned(),
            action: SerializableAction::Allow,
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata::default(),
            command_evaluations: vec![CommandEvaluation {
                command: "echo hi".to_owned(),
                action: SerializableAction::Allow,
                matched_rules: vec![],
                eval_type: EvalType::Primary,
                env: vec![],
                argv: vec!["echo".to_owned(), "hi".to_owned()],
                redirects: vec![],
                pipe: SerializablePipe::default(),
                alias_chain: vec![],
            }],
        };
        let json = serde_json::to_string(&entry).unwrap();
        for forbidden in ["\"matched_rules\":[", "\"sub_evaluations\"", "\"parsed\""] {
            assert!(
                !json.contains(forbidden),
                "{forbidden} must not appear at top level: {json}"
            );
        }
    }

    #[rstest]
    #[case::primary_minimal(
        CommandEvaluation {
            command: "echo hi".to_owned(),
            action: SerializableAction::Allow,
            matched_rules: vec![],
            eval_type: EvalType::Primary,
            env: vec![],
            argv: vec!["echo".to_owned(), "hi".to_owned()],
            redirects: vec![],
            pipe: SerializablePipe::default(),
            alias_chain: vec![],
        },
        r#"{"command":"echo hi","action":{"type":"allow"},"eval_type":"primary","argv":["echo","hi"]}"#,
    )]
    #[case::env_argv_redirects_pipe(
        CommandEvaluation {
            command: "FOO=x echo hi > /tmp/log".to_owned(),
            action: SerializableAction::Allow,
            matched_rules: vec![],
            eval_type: EvalType::Compound,
            env: vec![SerializableEnvVar {
                name: "FOO".to_owned(),
                value: Some("x".to_owned()),
            }],
            argv: vec!["echo".to_owned(), "hi".to_owned()],
            redirects: vec![SerializableRedirect {
                redirect_type: "output".to_owned(),
                operator: ">".to_owned(),
                target: "/tmp/log".to_owned(),
                descriptor: None,
            }],
            pipe: SerializablePipe { stdin: false, stdout: true },
            alias_chain: vec![],
        },
        r#"{"command":"FOO=x echo hi > /tmp/log","action":{"type":"allow"},"eval_type":"compound","env":[{"name":"FOO","value":"x"}],"argv":["echo","hi"],"redirects":[{"redirect_type":"output","operator":">","target":"/tmp/log","descriptor":null}],"pipe":{"stdin":false,"stdout":true}}"#,
    )]
    fn command_evaluation_serialises(#[case] eval: CommandEvaluation, #[case] expected: &str) {
        let serialized = serde_json::to_string(&eval).unwrap();
        assert_eq!(serialized, expected);
        let deserialized: CommandEvaluation = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, eval);
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
    #[case::with_tool_use_id(
        AskResolution {
            timestamp: "2026-07-08T10:30:00Z".to_owned(),
            outcome: AskResolutionOutcome::Approved,
            tool_use_id: Some("toolu_01".to_owned()),
            session_id: Some("sess-1".to_owned()),
            cwd: Some("/home/user/project".to_owned()),
            command: "terraform apply".to_owned(),
            executed_command: "runok exec --sandbox restricted -- 'terraform apply'".to_owned(),
        },
        indoc! {r#"{"kind":"ask_resolution","timestamp":"2026-07-08T10:30:00Z","outcome":"approved","tool_use_id":"toolu_01","session_id":"sess-1","cwd":"/home/user/project","command":"terraform apply","executed_command":"runok exec --sandbox restricted -- 'terraform apply'"}"#},
    )]
    #[case::without_tool_use_id(
        AskResolution {
            timestamp: "2026-07-08T10:30:00Z".to_owned(),
            outcome: AskResolutionOutcome::Approved,
            tool_use_id: None,
            session_id: Some("sess-1".to_owned()),
            cwd: Some("/tmp".to_owned()),
            command: "git push".to_owned(),
            executed_command: "git push".to_owned(),
        },
        indoc! {r#"{"kind":"ask_resolution","timestamp":"2026-07-08T10:30:00Z","outcome":"approved","tool_use_id":null,"session_id":"sess-1","cwd":"/tmp","command":"git push","executed_command":"git push"}"#},
    )]
    fn ask_resolution_roundtrip(#[case] resolution: AskResolution, #[case] expected_json: &str) {
        let serialized = serde_json::to_string(&resolution).unwrap();
        assert_eq!(serialized, expected_json);

        let deserialized: AskResolution = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, resolution);
    }

    #[rstest]
    fn ask_resolution_line_does_not_deserialize_as_audit_entry() {
        // Decision-entry readers must be able to reject resolution lines;
        // they lack the required `action` field.
        let line = indoc! {r#"{"kind":"ask_resolution","timestamp":"2026-07-08T10:30:00Z","outcome":"approved","tool_use_id":"toolu_01","session_id":"s","cwd":"/tmp","command":"git push","executed_command":"git push"}"#};
        assert!(serde_json::from_str::<AuditEntry>(line).is_err());
    }

    #[rstest]
    fn audit_metadata_without_tool_use_id_deserializes_to_none() {
        // Entries written before the field existed must keep parsing.
        let legacy_json = indoc! {r#"{"endpoint_type":"hook","session_id":"s","cwd":"/tmp","tool_name":"Bash","hook_event_name":"PreToolUse"}"#};
        let metadata: AuditMetadata = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(
            metadata,
            AuditMetadata {
                endpoint_type: "hook".to_owned(),
                session_id: Some("s".to_owned()),
                cwd: Some("/tmp".to_owned()),
                tool_name: Some("Bash".to_owned()),
                hook_event_name: Some("PreToolUse".to_owned()),
                tool_use_id: None,
            },
        );
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
