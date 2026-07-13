use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::model::{AuditEntry, SerializableAction, SerializableRuleMatch};
use crate::config::{Config, ConfigLoader, ConfigSource, DefaultConfigLoader};
use crate::rules::rule_engine::{EvalContext, evaluate_compound};

/// Re-evaluation of an audit entry's `command` against the config currently
/// in effect, as opposed to the `action` / `command_evaluations` recorded on
/// the entry, which are a snapshot from when the entry was decided.
///
/// Computed only for `runok audit --recheck`; never persisted to the audit
/// log. Serialises untagged so a successful recheck reads as
/// `{"action": ..., "command_evaluations": [...]}` and a failed one as
/// `{"error": "..."}`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Recheck {
    Ok {
        action: SerializableAction,
        command_evaluations: Vec<RecheckCommandEvaluation>,
    },
    /// The entry could not be re-evaluated: `metadata.cwd` was missing, the
    /// config at that cwd failed to load, or evaluation itself errored.
    /// Entries in this state are still emitted (fail-open) rather than
    /// dropped.
    Error { error: String },
}

/// Per-branch re-evaluation result, mirroring `CommandEvaluation`'s
/// `command` / `action` / `matched_rules` fields.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RecheckCommandEvaluation {
    pub command: String,
    pub action: SerializableAction,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<SerializableRuleMatch>,
}

impl Recheck {
    /// Whether the current action is `ask` with no branch matched by an
    /// explicit `ask` rule -- i.e. it is resolved purely via
    /// `defaults.action` fallback rather than a rule the user wrote on
    /// purpose.
    ///
    /// A merged `ask` can also arise from `evaluate_compound`'s
    /// sandbox-contradiction escalation, which turns a merged `allow` into
    /// `ask` without any branch itself resolving to `ask` (`merge_actions`
    /// never produces `ask` from all-`allow` branches on its own). That case
    /// is excluded by requiring at least one branch's own action to be
    /// `ask` too -- true for every `defaults.action`-fallback branch, but
    /// not for a sandbox-escalated one. An empty `command_evaluations` (the
    /// input had no runnable command) has no branches to check and can only
    /// reach `ask` via `defaults.action`, so it counts as a match.
    pub fn is_default_fallback_ask(&self) -> bool {
        match self {
            Recheck::Ok {
                action: SerializableAction::Ask { .. },
                command_evaluations,
            } => {
                let no_explicit_ask_rule = !command_evaluations
                    .iter()
                    .flat_map(|c| &c.matched_rules)
                    .any(|r| r.action_kind == "ask");
                let not_sandbox_escalation = command_evaluations.is_empty()
                    || command_evaluations
                        .iter()
                        .any(|c| matches!(c.action, SerializableAction::Ask { .. }));
                no_explicit_ask_rule && not_sandbox_escalation
            }
            _ => false,
        }
    }
}

/// Re-evaluate each entry's `command` against the config loaded from its own
/// `metadata.cwd`, using `evaluate_compound` -- the same entry point
/// `runok exec` / `check` use, so compound commands (`a && b`) re-evaluate
/// with the same sandbox-contradiction-triggered Ask escalation that
/// produced the original decision.
///
/// Config is cached per cwd since audit logs typically repeat a small
/// number of working directories. `loader` is injected so tests can use a
/// hermetic global config directory.
///
/// The `env` used for `when`-clause evaluation is the current process
/// environment, not a snapshot from when the entry was decided (the audit
/// log does not record one) -- rules that read `env.*` may re-evaluate
/// differently than they did at decision time.
pub fn recheck_entries(entries: &[AuditEntry], loader: &DefaultConfigLoader) -> Vec<Recheck> {
    let mut config_cache: HashMap<String, Result<Config, String>> = HashMap::new();
    let env: HashMap<String, String> = std::env::vars().collect();
    entries
        .iter()
        .map(|entry| recheck_one(entry, loader, &mut config_cache, &env))
        .collect()
}

fn recheck_one(
    entry: &AuditEntry,
    loader: &DefaultConfigLoader,
    config_cache: &mut HashMap<String, Result<Config, String>>,
    env: &HashMap<String, String>,
) -> Recheck {
    let Some(cwd) = &entry.metadata.cwd else {
        return Recheck::Error {
            error: "audit entry has no recorded cwd".to_owned(),
        };
    };

    let config = match get_cached_config(cwd, loader, config_cache) {
        Ok(config) => config,
        Err(error) => return Recheck::Error { error },
    };

    let context = EvalContext {
        env: env.clone(),
        cwd: PathBuf::from(cwd.as_str()),
    };

    match evaluate_compound(config, &entry.command, &context) {
        Ok(result) => Recheck::Ok {
            action: result.action.into(),
            command_evaluations: result
                .sub_command_details
                .into_iter()
                .map(|d| RecheckCommandEvaluation {
                    command: d.command,
                    action: d.action.into(),
                    matched_rules: d
                        .matched_rules
                        .into_iter()
                        .map(SerializableRuleMatch::from)
                        .collect(),
                })
                .collect(),
        },
        Err(e) => Recheck::Error {
            error: format!("failed to evaluate command: {e}"),
        },
    }
}

/// Look up `cwd` in `config_cache`, loading and caching it (including the
/// error message on failure) on a miss.
fn get_cached_config<'a>(
    cwd: &str,
    loader: &DefaultConfigLoader,
    config_cache: &'a mut HashMap<String, Result<Config, String>>,
) -> Result<&'a Config, String> {
    // `contains_key` before inserting avoids allocating `cwd.to_owned()` on
    // every cache hit, unlike `entry()`, which allocates the key eagerly
    // even when it turns out to already be present. An early `get`-based
    // return would drop the extra lookup on a hit too, but the borrow it
    // returns is tied to the same `'a` as the later `insert()`'s mutable
    // borrow, so the borrow checker rejects it even though the two
    // branches are mutually exclusive at runtime.
    if !config_cache.contains_key(cwd) {
        let source = ConfigSource::from_flag(None, Path::new(cwd));
        let result = loader
            .load(&source)
            .map_err(|e| format!("failed to load config: {e}"));
        config_cache.insert(cwd.to_owned(), result);
    }
    config_cache[cwd].as_ref().map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    use super::*;
    use crate::audit::AuditMetadata;

    #[fixture]
    fn project_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn write_config(dir: &TempDir, yaml: &str) {
        std::fs::write(dir.path().join("runok.yml"), yaml).unwrap();
    }

    /// A loader whose global config directory never exists, so tests are
    /// isolated from whatever global `runok.yml` happens to be present on
    /// the machine running them.
    fn hermetic_loader() -> DefaultConfigLoader {
        DefaultConfigLoader::with_global_dir(PathBuf::from(
            "/nonexistent/runok-recheck-test-global",
        ))
    }

    fn ask_entry(command: &str, cwd: Option<&str>) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-07-08T10:00:00Z".to_owned(),
            command: command.to_owned(),
            action: SerializableAction::Ask { message: None },
            sandbox_preset: None,
            default_action: Some("ask".to_owned()),
            metadata: AuditMetadata {
                cwd: cwd.map(str::to_owned),
                ..AuditMetadata::default()
            },
            command_evaluations: vec![],
        }
    }

    #[rstest]
    #[case::allow_rule_added(
        indoc! {"
            rules:
              - allow: 'terraform apply'
        "},
        Recheck::Ok {
            action: SerializableAction::Allow,
            command_evaluations: vec![RecheckCommandEvaluation {
                command: "terraform apply".to_owned(),
                action: SerializableAction::Allow,
                matched_rules: vec![SerializableRuleMatch {
                    action_kind: "allow".to_owned(),
                    pattern: "terraform apply".to_owned(),
                    matched_tokens: vec![],
                }],
            }],
        },
    )]
    #[case::still_ask_without_matching_rule(
        "",
        Recheck::Ok {
            action: SerializableAction::Ask { message: None },
            command_evaluations: vec![RecheckCommandEvaluation {
                command: "terraform apply".to_owned(),
                action: SerializableAction::Ask { message: None },
                matched_rules: vec![],
            }],
        },
    )]
    fn recheck_entries_reflects_config(
        project_dir: TempDir,
        #[case] yaml: &str,
        #[case] expected: Recheck,
    ) {
        write_config(&project_dir, yaml);
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entries = vec![ask_entry("terraform apply", Some(&cwd))];

        let results = recheck_entries(&entries, &hermetic_loader());

        assert_eq!(results, vec![expected]);
    }

    #[rstest]
    fn recheck_entries_reports_error_for_missing_cwd() {
        let entries = vec![ask_entry("terraform apply", None)];

        let results = recheck_entries(&entries, &hermetic_loader());

        assert_eq!(
            results,
            vec![Recheck::Error {
                error: "audit entry has no recorded cwd".to_owned(),
            }],
        );
    }

    #[rstest]
    fn recheck_entries_reports_error_for_unparseable_config(project_dir: TempDir) {
        write_config(&project_dir, "rules: [invalid yaml\n  broken:");
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entries = vec![ask_entry("terraform apply", Some(&cwd))];

        let results = recheck_entries(&entries, &hermetic_loader());

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], Recheck::Error { error } if error.starts_with("failed to load config: "))
        );
    }

    #[rstest]
    fn recheck_entries_caches_config_per_cwd(project_dir: TempDir) {
        write_config(
            &project_dir,
            indoc! {"
                rules:
                  - allow: 'echo hi'
            "},
        );
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entries = vec![
            ask_entry("echo hi", Some(&cwd)),
            ask_entry("echo hi", Some(&cwd)),
        ];

        let results = recheck_entries(&entries, &hermetic_loader());

        let expected = Recheck::Ok {
            action: SerializableAction::Allow,
            command_evaluations: vec![RecheckCommandEvaluation {
                command: "echo hi".to_owned(),
                action: SerializableAction::Allow,
                matched_rules: vec![SerializableRuleMatch {
                    action_kind: "allow".to_owned(),
                    pattern: "echo hi".to_owned(),
                    matched_tokens: vec![],
                }],
            }],
        };
        assert_eq!(results, vec![expected.clone(), expected]);
    }

    #[rstest]
    #[case::allow(SerializableAction::Allow, SerializableAction::Allow, vec![], false)]
    #[case::deny(
        SerializableAction::Deny { message: None, fix_suggestion: None },
        SerializableAction::Deny { message: None, fix_suggestion: None },
        vec![],
        false,
    )]
    #[case::default_fallback_ask(
        SerializableAction::Ask { message: None },
        SerializableAction::Ask { message: None },
        vec![],
        true,
    )]
    #[case::explicit_ask_rule(
        SerializableAction::Ask { message: None },
        SerializableAction::Ask { message: None },
        vec![SerializableRuleMatch {
            action_kind: "ask".to_owned(),
            pattern: "terraform apply".to_owned(),
            matched_tokens: vec![],
        }],
        false,
    )]
    #[case::sandbox_contradiction_escalation(
        // evaluate_compound's sandbox-contradiction escalation: the merged
        // action becomes `ask`, but the branch's own action (from an
        // `allow` rule) never did -- not a `defaults.action` fallback.
        SerializableAction::Ask { message: Some("sandbox policy conflict: writable roots are contradictory".to_owned()) },
        SerializableAction::Allow,
        vec![SerializableRuleMatch {
            action_kind: "allow".to_owned(),
            pattern: "terraform apply".to_owned(),
            matched_tokens: vec![],
        }],
        false,
    )]
    fn is_default_fallback_ask_distinguishes_rule_from_default(
        #[case] action: SerializableAction,
        #[case] branch_action: SerializableAction,
        #[case] matched_rules: Vec<SerializableRuleMatch>,
        #[case] expected: bool,
    ) {
        let recheck = Recheck::Ok {
            action,
            command_evaluations: vec![RecheckCommandEvaluation {
                command: "terraform apply".to_owned(),
                action: branch_action,
                matched_rules,
            }],
        };
        assert_eq!(recheck.is_default_fallback_ask(), expected);
    }

    #[rstest]
    fn is_default_fallback_ask_true_for_empty_command_evaluations() {
        // Comment-only / no-runnable-command input: `command_evaluations`
        // has no branches to inspect, so the merged `ask` can only have
        // come from `default_action(config)` directly.
        let recheck = Recheck::Ok {
            action: SerializableAction::Ask { message: None },
            command_evaluations: vec![],
        };
        assert!(recheck.is_default_fallback_ask());
    }

    #[rstest]
    fn is_default_fallback_ask_false_for_error() {
        let recheck = Recheck::Error {
            error: "boom".to_owned(),
        };
        assert!(!recheck.is_default_fallback_ask());
    }
}
