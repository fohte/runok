use std::collections::{HashMap, HashSet};

use crate::config::{Config, Definitions, MergedSandboxPolicy, SandboxPreset};
use crate::rules::RuleError;
use crate::rules::command_parser::{ExtractedCommand, PipeInfo, extract_commands_with_metadata};

use super::simple_eval::evaluate_command_inner;
use super::{Action, CompoundEvalResult, DenyResponse, EvalContext, EvalResult, SubCommandDetail};

/// Evaluate a potentially compound command (containing `|`, `&&`, `||`, `;`)
/// by splitting it into individual commands, evaluating each, and aggregating
/// the results.
///
/// - Action aggregation: Explicit Deny Wins (deny > ask > allow > default)
/// - Sandbox policy aggregation: Strictest Wins (writable roots intersected,
///   deny paths unioned, network access intersected)
/// - If sandbox aggregation produces empty writable roots (contradiction),
///   the action is escalated to `Ask`
///
/// For single (non-compound) commands, this delegates to `evaluate_command`.
pub fn evaluate_compound(
    config: &Config,
    command: &str,
    context: &EvalContext,
) -> Result<CompoundEvalResult, RuleError> {
    let extracted = extract_commands_with_metadata(command).unwrap_or_else(|_| {
        vec![ExtractedCommand {
            command: command.to_string(),
            env: vec![],
            argv: vec![],
            redirects: vec![],
            pipe: PipeInfo::default(),
            loop_kind: String::new(),
        }]
    });

    let default_definitions = Definitions::default();
    let definitions = config.definitions.as_ref().unwrap_or(&default_definitions);
    let sandbox_defs = definitions.sandbox.as_ref();

    let mut merged_action: Option<Action> = None;
    let mut preset_names: Vec<String> = Vec::new();
    let mut sub_results: Vec<EvalResult> = Vec::new();
    let mut sub_command_details: Vec<SubCommandDetail> = Vec::new();

    for ext_cmd in &extracted {
        let result = evaluate_command_inner(
            config,
            &ext_cmd.command,
            context,
            0,
            &ext_cmd.redirects,
            &ext_cmd.pipe,
            &ext_cmd.loop_kind,
        )?;

        if let Some(ref name) = result.sandbox_preset {
            preset_names.push(name.clone());
        }

        sub_command_details.push(SubCommandDetail {
            command: ext_cmd.command.clone(),
            action: result.action.clone(),
            matched_rules: result.matched_rules.clone(),
        });

        merged_action = Some(match merged_action {
            Some(prev) => merge_actions(prev, result.action.clone()),
            None => result.action.clone(),
        });

        sub_results.push(result);
    }

    let action = merged_action.unwrap_or_else(|| default_action(config));

    // Deduplicate preset names while preserving order
    let mut seen = HashSet::new();
    let unique_names: Vec<&String> = preset_names
        .iter()
        .filter(|n| seen.insert(n.as_str()))
        .collect();

    let sandbox_policy = if unique_names.is_empty() {
        None
    } else if let Some(sandbox_map) = sandbox_defs {
        let presets: Vec<&SandboxPreset> = unique_names
            .iter()
            .filter_map(|name| sandbox_map.get(name.as_str()))
            .collect();

        if presets.is_empty() {
            None
        } else {
            SandboxPreset::merge_strictest(&presets)
        }
    } else {
        None
    };

    // If sandbox policy has contradicting writable roots (empty after intersection
    // but presets did define writable roots), escalate action to Ask
    let (final_action, final_policy) = match (action, sandbox_policy) {
        (action, Some(policy))
            if has_writable_contradiction(&policy, &unique_names, sandbox_defs) =>
        {
            let escalated = escalate_to_ask(action);
            (escalated, Some(policy))
        }
        (action, policy) => (action, policy),
    };

    Ok(CompoundEvalResult {
        action: final_action,
        sandbox_policy: final_policy,
        sub_results,
        sub_command_details,
    })
}

/// Check if the merged policy has a writable roots contradiction:
/// at least one source preset defined writable roots, but the intersection
/// is empty.
fn has_writable_contradiction(
    policy: &MergedSandboxPolicy,
    preset_names: &[&String],
    sandbox_defs: Option<&HashMap<String, SandboxPreset>>,
) -> bool {
    if !policy.writable.is_empty() {
        return false;
    }

    let sandbox_map = match sandbox_defs {
        Some(m) => m,
        None => return false,
    };

    preset_names.iter().any(|name| {
        sandbox_map
            .get(name.as_str())
            .and_then(|p| p.fs.as_ref())
            .and_then(|fs| fs.write_allow())
            .is_some_and(|w: &Vec<String>| !w.is_empty())
    })
}

/// Escalate an action to Ask if it is currently Allow or Default.
fn escalate_to_ask(action: Action) -> Action {
    match action {
        Action::Allow => Action::Ask(Some(
            "sandbox policy conflict: writable roots are contradictory".to_string(),
        )),
        other => other,
    }
}

/// Normalize whitespace in a command string for comparison purposes.
/// Collapses runs of whitespace into a single space and trims leading/trailing whitespace.
/// This prevents false negatives in self-reference detection when tree-sitter
/// reconstructs command text with slightly different whitespace than the original input.
pub(super) fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Merge two evaluation results using Explicit Deny Wins priority.
pub(super) fn merge_results(a: EvalResult, b: EvalResult) -> EvalResult {
    let mut combined_rules = a.matched_rules;
    combined_rules.extend(b.matched_rules);

    // The alias chain belongs to the winning side's matched rule. When the
    // losing side's chain is non-empty, append it so audit logs still show
    // every alias that contributed to a match somewhere in the merged result.
    if action_priority(&b.action) > action_priority(&a.action) {
        let mut alias_chain = b.alias_chain;
        for name in a.alias_chain {
            if !alias_chain.contains(&name) {
                alias_chain.push(name);
            }
        }
        EvalResult {
            action: b.action,
            sandbox_preset: b.sandbox_preset,
            matched_rules: combined_rules,
            alias_chain,
        }
    } else {
        let mut alias_chain = a.alias_chain;
        for name in b.alias_chain {
            if !alias_chain.contains(&name) {
                alias_chain.push(name);
            }
        }
        EvalResult {
            action: a.action,
            sandbox_preset: a.sandbox_preset,
            matched_rules: combined_rules,
            alias_chain,
        }
    }
}

/// Merge two actions using Explicit Deny Wins priority, returning the more
/// restrictive one.
fn merge_actions(a: Action, b: Action) -> Action {
    if action_priority(&b) > action_priority(&a) {
        b
    } else {
        a
    }
}

/// Map an action to its priority for Explicit Deny Wins comparison.
/// Higher value = more restrictive.
pub(super) fn action_priority(action: &Action) -> u8 {
    match action {
        Action::Allow => 0,
        Action::Ask(_) => 1,
        Action::Deny(_) => 2,
    }
}

/// Return the action to use when no rule matched.
///
/// Uses `defaults.action` from the config, falling back to `Ask` when
/// not configured.
pub fn default_action(config: &Config) -> Action {
    use crate::config::ActionKind;
    match config.defaults.as_ref().and_then(|d| d.action) {
        Some(ActionKind::Allow) => Action::Allow,
        Some(ActionKind::Deny) => Action::Deny(DenyResponse {
            message: None,
            fix_suggestion: None,
            matched_rule: String::new(),
        }),
        Some(ActionKind::Ask) | None => Action::Ask(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rstest::rstest;

    use crate::config::{ActionKind, Config, Defaults, Definitions, RuleEntry};

    use super::super::test_support::{allow_rule, ask_rule, deny_rule, empty_context, make_config};
    use super::*;

    // ========================================
    // Compound command evaluation
    // ========================================

    #[rstest]
    #[case::pipeline("ls -la | grep foo")]
    #[case::and_chain("echo hello && ls -la")]
    #[case::or_chain("echo hello || ls -la")]
    fn compound_all_allow(#[case] command: &str, empty_context: EvalContext) {
        let config = make_config(vec![
            allow_rule("ls *"),
            allow_rule("grep *"),
            allow_rule("echo *"),
        ]);
        let result = evaluate_compound(&config, command, &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    #[case::pipeline("ls -la | rm -rf /")]
    #[case::and_chain("echo hello && rm -rf /")]
    #[case::or_chain("echo hello || rm -rf /")]
    fn compound_deny_wins(#[case] command: &str, empty_context: EvalContext) {
        let config = make_config(vec![
            allow_rule("ls *"),
            allow_rule("echo *"),
            deny_rule("rm -rf *"),
        ]);
        let result = evaluate_compound(&config, command, &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn compound_ask_wins_over_allow(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("echo *"), ask_rule("git push *")]);
        let result =
            evaluate_compound(&config, "echo done && git push origin", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn compound_deny_wins_over_ask_and_allow(empty_context: EvalContext) {
        let config = make_config(vec![
            allow_rule("echo *"),
            ask_rule("git push *"),
            deny_rule("rm -rf *"),
        ]);
        let result = evaluate_compound(
            &config,
            "echo done && git push origin && rm -rf /",
            &empty_context,
        )
        .unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn compound_single_command_delegates(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git status")]);
        let result = evaluate_compound(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.sandbox_policy, None);
    }

    #[rstest]
    fn compound_no_matching_rules_returns_default(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git status")]);
        let result = evaluate_compound(&config, "hg status | wc -l", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    // ========================================
    // Compound: Default resolved via defaults.action
    // ========================================

    #[rstest]
    fn compound_default_resolved_to_ask_wins_over_allow(empty_context: EvalContext) {
        // When one sub-command is allowed and another is unmatched,
        // the unmatched sub-command should be resolved via defaults.action.
        // With defaults.action = ask, the overall result should be Ask (not Allow).
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Ask),
                sandbox: None,
            }),
            rules: Some(vec![allow_rule("echo *")]),
            ..Default::default()
        };
        let result =
            evaluate_compound(&config, "echo hello; eval \"rm -rf /\"", &empty_context).unwrap();
        assert!(
            matches!(result.action, Action::Ask(_)),
            "expected Ask, got {:?}",
            result.action
        );
    }

    #[rstest]
    fn compound_default_resolved_to_deny_wins_over_allow(empty_context: EvalContext) {
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Deny),
                sandbox: None,
            }),
            rules: Some(vec![allow_rule("echo *")]),
            ..Default::default()
        };
        let result = evaluate_compound(&config, "echo hello; unknown_cmd", &empty_context).unwrap();
        assert!(
            matches!(result.action, Action::Deny(_)),
            "expected Deny, got {:?}",
            result.action
        );
    }

    #[rstest]
    fn compound_default_resolved_to_allow_stays_allow(empty_context: EvalContext) {
        // When defaults.action = allow, unmatched commands resolve to Allow,
        // and the overall result remains Allow.
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Allow),
                sandbox: None,
            }),
            rules: Some(vec![allow_rule("echo *")]),
            ..Default::default()
        };
        let result = evaluate_compound(&config, "echo hello; unknown_cmd", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    fn compound_no_defaults_unmatched_wins_over_allow(empty_context: EvalContext) {
        // Without defaults.action configured, unmatched sub-commands
        // resolve to Ask (the safe default).  Ask wins over Allow,
        // preventing a security bypass.
        let config = make_config(vec![allow_rule("echo *")]);
        let result = evaluate_compound(&config, "echo hello; unknown_cmd", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    #[rstest]
    fn compound_all_unmatched_with_defaults_ask(empty_context: EvalContext) {
        // All sub-commands unmatched with defaults.action = ask
        // should result in Ask.
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Ask),
                sandbox: None,
            }),
            rules: Some(vec![allow_rule("git status")]),
            ..Default::default()
        };
        let result = evaluate_compound(&config, "unknown_a && unknown_b", &empty_context).unwrap();
        assert!(
            matches!(result.action, Action::Ask(_)),
            "expected Ask, got {:?}",
            result.action
        );
    }

    #[rstest]
    fn compound_deny_rule_still_wins_over_resolved_default(empty_context: EvalContext) {
        // Even when defaults.action = ask, an explicit deny rule should still win.
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Ask),
                sandbox: None,
            }),
            rules: Some(vec![allow_rule("echo *"), deny_rule("rm -rf *")]),
            ..Default::default()
        };
        let result = evaluate_compound(&config, "echo hello && rm -rf /", &empty_context).unwrap();
        assert!(
            matches!(result.action, Action::Deny(_)),
            "expected Deny, got {:?}",
            result.action
        );
    }

    // ========================================
    // Compound: sandbox policy aggregation
    // ========================================

    use crate::config::{FsAccessPolicy, FsPolicy, NetworkPolicy, SandboxPreset};

    fn make_sandbox_config(
        rules: Vec<RuleEntry>,
        sandbox: HashMap<String, SandboxPreset>,
    ) -> Config {
        Config {
            rules: Some(rules),
            definitions: Some(Definitions {
                sandbox: Some(sandbox),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn allow_rule_with_sandbox(pattern: &str, sandbox: &str) -> RuleEntry {
        let mut rule = allow_rule(pattern);
        rule.sandbox = Some(sandbox.to_string());
        rule
    }

    #[rstest]
    fn compound_sandbox_writable_roots_intersection(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("ls *", "preset_a"),
                allow_rule_with_sandbox("cat *", "preset_b"),
            ],
            HashMap::from([
                (
                    "preset_a".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec![
                                    "/tmp".to_string(),
                                    "/home".to_string(),
                                    "/var".to_string(),
                                ]),
                                deny: None,
                            }),
                        }),
                        network: None,
                    },
                ),
                (
                    "preset_b".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string(), "/var".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: None,
                    },
                ),
            ]),
        );

        let result = evaluate_compound(&config, "ls -la | cat -", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
        let policy = result.sandbox_policy.unwrap();
        assert_eq!(policy.writable, vec!["/tmp", "/var"]);
    }

    #[rstest]
    fn compound_sandbox_deny_paths_union(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("ls *", "preset_a"),
                allow_rule_with_sandbox("cat *", "preset_b"),
            ],
            HashMap::from([
                (
                    "preset_a".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: Some(vec!["/etc/passwd".to_string()]),
                            }),
                        }),
                        network: None,
                    },
                ),
                (
                    "preset_b".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: Some(vec!["/etc/shadow".to_string()]),
                            }),
                        }),
                        network: None,
                    },
                ),
            ]),
        );

        let result = evaluate_compound(&config, "ls -la | cat -", &empty_context).unwrap();
        let policy = result.sandbox_policy.unwrap();
        assert_eq!(policy.deny, vec!["/etc/passwd", "/etc/shadow"]);
    }

    #[rstest]
    fn compound_sandbox_network_intersection(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("curl *", "preset_a"),
                allow_rule_with_sandbox("wget *", "preset_b"),
            ],
            HashMap::from([
                (
                    "preset_a".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: Some(NetworkPolicy { allow: Some(true) }),
                    },
                ),
                (
                    "preset_b".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: Some(NetworkPolicy { allow: Some(true) }),
                    },
                ),
            ]),
        );

        let result = evaluate_compound(
            &config,
            "curl https://github.com && wget https://npmjs.org",
            &empty_context,
        )
        .unwrap();
        let policy = result.sandbox_policy.unwrap();
        assert!(policy.network_allowed);
    }

    #[rstest]
    fn compound_sandbox_network_restricted_by_any(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("curl *", "net_ok"),
                allow_rule_with_sandbox("ls *", "no_net"),
            ],
            HashMap::from([
                (
                    "net_ok".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: Some(NetworkPolicy { allow: Some(true) }),
                    },
                ),
                (
                    "no_net".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: Some(NetworkPolicy { allow: Some(false) }),
                    },
                ),
            ]),
        );

        let result = evaluate_compound(
            &config,
            "curl https://github.com && ls /tmp",
            &empty_context,
        )
        .unwrap();
        let policy = result.sandbox_policy.unwrap();
        // One preset denies network -> result is denied
        assert!(!policy.network_allowed);
    }

    // ========================================
    // Compound: writable roots contradiction -> ask escalation
    // ========================================

    #[rstest]
    fn compound_writable_contradiction_escalates_to_ask(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("ls *", "only_tmp"),
                allow_rule_with_sandbox("cat *", "only_home"),
            ],
            HashMap::from([
                (
                    "only_tmp".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: None,
                    },
                ),
                (
                    "only_home".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/home".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: None,
                    },
                ),
            ]),
        );

        let result = evaluate_compound(&config, "ls -la | cat -", &empty_context).unwrap();
        // Writable roots intersection is empty -> contradiction -> escalate to Ask
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn compound_writable_contradiction_does_not_downgrade_deny(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("ls *", "only_tmp"),
                deny_rule("cat *"),
            ],
            HashMap::from([(
                "only_tmp".to_string(),
                SandboxPreset {
                    fs: Some(FsPolicy {
                        read: None,
                        write: Some(FsAccessPolicy {
                            allow: Some(vec!["/tmp".to_string()]),
                            deny: None,
                        }),
                    }),
                    network: None,
                },
            )]),
        );

        let result = evaluate_compound(&config, "ls -la | cat -", &empty_context).unwrap();
        // deny should not be downgraded to ask
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn compound_same_sandbox_preset_deduplicates(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("ls *", "preset_a"),
                allow_rule_with_sandbox("cat *", "preset_a"),
            ],
            HashMap::from([(
                "preset_a".to_string(),
                SandboxPreset {
                    fs: Some(FsPolicy {
                        read: None,
                        write: Some(FsAccessPolicy {
                            allow: Some(vec!["/tmp".to_string()]),
                            deny: Some(vec!["/etc".to_string()]),
                        }),
                    }),
                    network: None,
                },
            )]),
        );

        let result = evaluate_compound(&config, "ls -la | cat -", &empty_context).unwrap();
        let policy = result.sandbox_policy.unwrap();
        // Same preset intersected with itself should preserve the values
        assert_eq!(policy.writable, vec!["/tmp"]);
        assert_eq!(policy.deny, vec!["/etc"]);
    }

    #[rstest]
    fn compound_no_sandbox_presets_returns_none(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("ls *"), allow_rule("cat *")]);
        let result = evaluate_compound(&config, "ls -la | cat -", &empty_context).unwrap();
        assert_eq!(result.sandbox_policy, None);
    }

    #[rstest]
    fn compound_semicolon_separator(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("echo *"), deny_rule("rm -rf *")]);
        let result = evaluate_compound(&config, "echo hello; rm -rf /", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn compound_mixed_operators(empty_context: EvalContext) {
        let config = make_config(vec![
            allow_rule("echo *"),
            allow_rule("ls *"),
            ask_rule("grep *"),
        ]);
        let result =
            evaluate_compound(&config, "echo hello | grep world && ls -la", &empty_context)
                .unwrap();
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn compound_partial_sandbox_only_some_commands(empty_context: EvalContext) {
        // Only python3 has a sandbox preset; ls does not.
        // The merged policy should reflect only the single preset.
        let config = make_sandbox_config(
            vec![
                allow_rule("ls *"),
                allow_rule_with_sandbox("python3 *", "restricted"),
            ],
            HashMap::from([(
                "restricted".to_string(),
                SandboxPreset {
                    fs: Some(FsPolicy {
                        read: None,
                        write: Some(FsAccessPolicy {
                            allow: Some(vec!["/tmp".to_string()]),
                            deny: Some(vec!["/etc".to_string()]),
                        }),
                    }),
                    network: None,
                },
            )]),
        );

        let result =
            evaluate_compound(&config, "ls -la | python3 script.py", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
        let policy = result.sandbox_policy.unwrap();
        assert_eq!(policy.writable, vec!["/tmp"]);
        assert_eq!(policy.deny, vec!["/etc"]);
    }

    #[rstest]
    fn compound_single_command_with_sandbox(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![allow_rule_with_sandbox("python3 *", "restricted")],
            HashMap::from([(
                "restricted".to_string(),
                SandboxPreset {
                    fs: Some(FsPolicy {
                        read: None,
                        write: Some(FsAccessPolicy {
                            allow: Some(vec!["/tmp".to_string()]),
                            deny: None,
                        }),
                    }),
                    network: Some(NetworkPolicy { allow: Some(true) }),
                },
            )]),
        );

        let result = evaluate_compound(&config, "python3 script.py", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
        let policy = result.sandbox_policy.unwrap();
        assert_eq!(policy.writable, vec!["/tmp"]);
        assert!(policy.network_allowed);
    }

    #[rstest]
    fn compound_three_presets_progressive_intersection(empty_context: EvalContext) {
        let config = make_sandbox_config(
            vec![
                allow_rule_with_sandbox("cmd1 *", "p1"),
                allow_rule_with_sandbox("cmd2 *", "p2"),
                allow_rule_with_sandbox("cmd3 *", "p3"),
            ],
            HashMap::from([
                (
                    "p1".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec![
                                    "/a".to_string(),
                                    "/b".to_string(),
                                    "/c".to_string(),
                                ]),
                                deny: Some(vec!["/x".to_string()]),
                            }),
                        }),
                        network: None,
                    },
                ),
                (
                    "p2".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/b".to_string(), "/c".to_string()]),
                                deny: Some(vec!["/y".to_string()]),
                            }),
                        }),
                        network: None,
                    },
                ),
                (
                    "p3".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/c".to_string(), "/d".to_string()]),
                                deny: Some(vec!["/z".to_string()]),
                            }),
                        }),
                        network: None,
                    },
                ),
            ]),
        );

        let result = evaluate_compound(
            &config,
            "cmd1 arg1 && cmd2 arg2 && cmd3 arg3",
            &empty_context,
        )
        .unwrap();
        let policy = result.sandbox_policy.unwrap();
        // Writable: {a,b,c} ∩ {b,c} ∩ {c,d} = {c}
        assert_eq!(policy.writable, vec!["/c"]);
        // Deny: {x} ∪ {y} ∪ {z}
        assert_eq!(policy.deny, vec!["/x", "/y", "/z"]);
    }

    #[rstest]
    fn compound_ask_not_overwritten_by_escalation(empty_context: EvalContext) {
        // If action is already Ask (from rule evaluation), writable contradiction
        // should not overwrite the existing Ask message.
        let config = make_sandbox_config(
            vec![
                {
                    let mut rule = ask_rule("ls *");
                    rule.sandbox = Some("only_tmp".to_string());
                    rule.message = Some("confirm ls".to_string());
                    rule
                },
                allow_rule_with_sandbox("cat *", "only_home"),
            ],
            HashMap::from([
                (
                    "only_tmp".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/tmp".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: None,
                    },
                ),
                (
                    "only_home".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["/home".to_string()]),
                                deny: None,
                            }),
                        }),
                        network: None,
                    },
                ),
            ]),
        );

        let result = evaluate_compound(&config, "ls -la | cat -", &empty_context).unwrap();
        // Action is Ask from the rule itself; escalation should not change it
        match &result.action {
            Action::Ask(msg) => {
                assert_eq!(msg.as_deref(), Some("confirm ls"));
            }
            other => panic!("expected Ask, got {:?}", other),
        }
    }
}
