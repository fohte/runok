use crate::config::{ActionKind, Config, Definitions, RuleEntry};
use crate::rules::RuleError;
use crate::rules::alias_expander::expand_rule_pattern;
use crate::rules::command_parser::{
    ExtractedCommand, PipeInfo, RedirectInfo, extract_commands, extract_commands_with_metadata,
    parse_command, shell_quote_join,
};
use crate::rules::expr_evaluator::evaluate;
use crate::rules::pattern_matcher::{extract_placeholder, matches_with_captures};
use crate::rules::pattern_parser::parse_multi;

use super::compound::{action_priority, default_action, merge_results, normalize_whitespace};
use super::flag_schema::{build_expr_context, build_flag_schema};
use super::{Action, DenyResponse, EvalContext, EvalResult, RuleMatchInfo};

/// Maximum recursion depth for wrapper command evaluation.
const MAX_WRAPPER_DEPTH: usize = 10;

pub(super) fn evaluate_command_inner(
    config: &Config,
    command: &str,
    context: &EvalContext,
    depth: usize,
    redirects: &[RedirectInfo],
    pipe: &PipeInfo,
    loop_kind: &str,
) -> Result<EvalResult, RuleError> {
    if depth > MAX_WRAPPER_DEPTH {
        return Err(RuleError::RecursionDepthExceeded(MAX_WRAPPER_DEPTH));
    }

    // Guard: if the command is compound (contains &&, ||, ;, |), split it and
    // evaluate each sub-command individually. This prevents wildcard patterns
    // from greedily matching across shell operators (e.g. `cd *` matching
    // `cd /path && rm -rf dist`).
    //
    // Filter out sub-commands identical to the original command to avoid
    // infinite recursion. This happens when extract_commands returns the
    // parent command alongside embedded sub-commands (e.g. command
    // substitutions: `echo $(rm -rf /)` extracts both `echo $(rm -rf /)`
    // and `rm -rf /`).
    //
    // When self-referencing sub-commands are filtered out, the remaining
    // nested sub-commands are still evaluated recursively, and the original
    // command falls through to simple-command rule evaluation below. Both
    // results are merged so that rules matching the outer command (e.g.
    // `rm *` for `rm $(echo hello)`) are not skipped.
    if let Ok(sub_commands) = extract_commands_with_metadata(command)
        && sub_commands.len() > 1
    {
        let normalized_command = normalize_whitespace(command);
        let nested_subs: Vec<&ExtractedCommand> = sub_commands
            .iter()
            .filter(|sub| normalize_whitespace(&sub.command) != normalized_command)
            .collect();
        let had_self_reference = nested_subs.len() < sub_commands.len();

        if !had_self_reference {
            // Pure compound (no self-reference): evaluate all sub-commands and return.
            let mut merged: Option<EvalResult> = None;
            for sub in &nested_subs {
                let result = evaluate_command_inner(
                    config,
                    &sub.command,
                    context,
                    depth + 1,
                    &sub.redirects,
                    &sub.pipe,
                    &sub.loop_kind,
                )?;
                merged = Some(match merged {
                    Some(prev) => merge_results(prev, result),
                    None => result,
                });
            }
            return Ok(merged.unwrap_or(EvalResult {
                action: default_action(config),
                sandbox_preset: None,
                matched_rules: Vec::new(),
                alias_chain: Vec::new(),
            }));
        }
        // Self-reference detected (e.g. command substitution): evaluate only
        // the nested sub-commands here, then fall through to evaluate the
        // original command as a simple command. The results are merged at the end.
        if !nested_subs.is_empty() {
            let mut nested_merged: Option<EvalResult> = None;
            for sub in &nested_subs {
                let result = evaluate_command_inner(
                    config,
                    &sub.command,
                    context,
                    depth + 1,
                    &sub.redirects,
                    &sub.pipe,
                    &sub.loop_kind,
                )?;
                nested_merged = Some(match nested_merged {
                    Some(prev) => merge_results(prev, result),
                    None => result,
                });
            }
            // Fall through to simple-command evaluation below, then merge.
            // Store the nested result to merge after simple-command evaluation.
            // We use a closure-like approach: evaluate the rest of this function
            // and merge before returning.
            if let Some(nested_result) = nested_merged {
                // Evaluate the original command as a simple command (skip the
                // compound guard by calling the remaining logic directly).
                let simple_result = evaluate_simple_command(
                    config, command, context, depth, redirects, pipe, loop_kind,
                )?;
                return Ok(merge_results(nested_result, simple_result));
            }
        }
        // nested_subs was empty and had self-reference: fall through to
        // simple-command evaluation.
    }

    evaluate_simple_command(config, command, context, depth, redirects, pipe, loop_kind)
}

/// Evaluate a single (non-compound) command against rules and wrappers.
///
/// This contains the core rule-matching and wrapper-unwrapping logic,
/// separated from `evaluate_command_inner` so the compound guard can
/// call it directly when it needs to evaluate the original command as
/// a simple command (e.g. after filtering out self-referencing sub-commands
/// from command substitutions).
fn evaluate_simple_command(
    config: &Config,
    command: &str,
    context: &EvalContext,
    depth: usize,
    redirects: &[RedirectInfo],
    pipe: &PipeInfo,
    loop_kind: &str,
) -> Result<EvalResult, RuleError> {
    let rules = match &config.rules {
        Some(rules) => rules,
        None => {
            return Ok(EvalResult {
                action: default_action(config),
                sandbox_preset: None,
                matched_rules: Vec::new(),
                alias_chain: Vec::new(),
            });
        }
    };

    let default_definitions = Definitions::default();
    let definitions = config.definitions.as_ref().unwrap_or(&default_definitions);

    // Collect all matched rules with their parsed patterns
    let mut matched: Vec<MatchedRule> = Vec::new();
    let mut match_infos: Vec<RuleMatchInfo> = Vec::new();

    for rule in rules {
        let (action_kind, pattern_str) = match rule.action_and_pattern() {
            Some(pair) => pair,
            None => continue,
        };

        let expansions = expand_rule_pattern(
            pattern_str,
            config.definitions.as_ref().and_then(|d| d.aliases.as_ref()),
        )?;

        'rule: for expansion in &expansions {
            for pattern in &parse_multi(&expansion.pattern)? {
                let schema = build_flag_schema(pattern, definitions);
                let parsed_command = parse_command(command, &schema)?;

                let Some(match_captures) =
                    matches_with_captures(pattern, &parsed_command, definitions)
                else {
                    continue;
                };

                if let Some(when_expr) = &rule.when {
                    let expr_context = build_expr_context(
                        &parsed_command,
                        context,
                        definitions,
                        redirects,
                        pipe,
                        &match_captures,
                        loop_kind,
                    );
                    match evaluate(when_expr, &expr_context) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(e) => return Err(e.into()),
                    }
                }

                match_infos.push(RuleMatchInfo {
                    action_kind,
                    pattern: pattern_str.to_string(),
                    matched_tokens: match_captures.wildcards,
                });

                matched.push(MatchedRule {
                    action_kind,
                    rule,
                    pattern_str: pattern_str.to_string(),
                    alias_chain: expansion.chain.clone(),
                });

                break 'rule;
            }
        }
    }

    // Try wrapper pattern matching for recursive evaluation
    let wrapper_result =
        try_unwrap_wrapper(config, command, context, definitions, depth, loop_kind)?;

    if matched.is_empty() && wrapper_result.is_none() {
        return Ok(EvalResult {
            action: default_action(config),
            sandbox_preset: None,
            matched_rules: match_infos,
            alias_chain: Vec::new(),
        });
    }

    // Determine the direct rule result
    let direct_result = if matched.is_empty() {
        None
    } else {
        // Explicit Deny Wins: pick the most restrictive action.
        // ActionKind ordering: Allow < Ask < Deny
        let Some(most_restrictive) = matched.iter().max_by_key(|m| m.action_kind) else {
            unreachable!("matched is non-empty");
        };

        let action = match most_restrictive.action_kind {
            ActionKind::Deny => Action::Deny(DenyResponse {
                message: most_restrictive.rule.message.clone(),
                fix_suggestion: most_restrictive.rule.fix_suggestion.clone(),
                matched_rule: most_restrictive.pattern_str.clone(),
            }),
            ActionKind::Ask => Action::Ask(most_restrictive.rule.message.clone()),
            ActionKind::Allow => Action::Allow,
        };

        let sandbox_preset = most_restrictive.rule.sandbox.clone();
        let alias_chain = most_restrictive.alias_chain.clone();

        Some(EvalResult {
            action,
            sandbox_preset,
            matched_rules: match_infos,
            alias_chain,
        })
    };

    // Merge direct result with wrapper result using Explicit Deny Wins
    let merged = match (direct_result, wrapper_result) {
        (Some(direct), Some(wrapper)) => merge_results(direct, wrapper),
        (Some(direct), None) => direct,
        (None, Some(wrapper)) => wrapper,
        (None, None) => unreachable!("at least one result exists"),
    };
    Ok(merged)
}

/// Try to match the command against wrapper patterns and recursively
/// evaluate the inner command.
///
/// If the extracted inner command is a compound command (containing
/// pipelines, `&&`, `||`, or `;`), it is split into individual commands
/// and each is evaluated separately. The results are merged using
/// Explicit Deny Wins.
fn try_unwrap_wrapper(
    config: &Config,
    command: &str,
    context: &EvalContext,
    definitions: &Definitions,
    depth: usize,
    loop_kind: &str,
) -> Result<Option<EvalResult>, RuleError> {
    let wrappers = match definitions.wrappers.as_ref() {
        Some(w) if !w.is_empty() => w,
        _ => return Ok(None),
    };

    for wrapper_pattern_str in wrappers {
        let patterns = parse_multi(wrapper_pattern_str)?;

        // Try each expanded pattern for this wrapper definition
        let mut all_candidates: Vec<Vec<String>> = Vec::new();
        for pattern in &patterns {
            let schema = build_flag_schema(pattern, definitions);
            let parsed_command = parse_command(command, &schema)?;

            let candidates = extract_placeholder(pattern, &parsed_command, definitions)?;
            if !candidates.is_empty() {
                all_candidates = candidates;
                break;
            }
        }

        if all_candidates.is_empty() {
            continue;
        }

        // Try each candidate capture and pick the one with the highest
        // action priority. This handles ambiguous patterns like `xargs * <cmd>`
        // where the wildcard can consume varying numbers of tokens.
        let mut best: Option<EvalResult> = None;
        for tokens in all_candidates {
            // Single token: a shell script string (e.g., from `bash -c <cmd>`)
            // that should be passed as-is for tree-sitter to parse.
            // Multiple tokens: a structured command + args (e.g., from `sudo <cmd>`)
            // that must be re-quoted to preserve tokens containing spaces.
            let inner_command = if tokens.len() == 1 {
                let Some(single) = tokens.into_iter().next() else {
                    unreachable!("tokens.len() == 1 guarantees at least one element");
                };
                single
            } else {
                shell_quote_join(&tokens)?
            };
            // Split compound commands (e.g., "ls; rm -rf /") into individual ones
            let sub_commands =
                extract_commands(&inner_command).unwrap_or_else(|_| vec![inner_command]);

            let mut result: Option<EvalResult> = None;
            for cmd in &sub_commands {
                let sub_result = evaluate_command_inner(
                    config,
                    cmd,
                    context,
                    depth + 1,
                    &[],
                    &PipeInfo::default(),
                    loop_kind,
                )?;
                result = Some(match result {
                    Some(prev) => merge_results(prev, sub_result),
                    None => sub_result,
                });
            }

            if let Some(candidate_result) = result {
                // When the wildcard in a wrapper pattern (e.g. `xargs * <cmd>`)
                // can consume different numbers of tokens, some splits produce
                // inner commands that match rules while others don't.  Prefer
                // candidates that actually matched a rule (non-empty matched_rules)
                // over unmatched ones, and among matched candidates pick the most
                // restrictive (Explicit Deny Wins).
                best = Some(match best {
                    Some(prev) => {
                        let prev_matched = !prev.matched_rules.is_empty();
                        let cand_matched = !candidate_result.matched_rules.is_empty();
                        let prev_prio = action_priority(&prev.action);
                        let cand_prio = action_priority(&candidate_result.action);
                        if (cand_matched, cand_prio) > (prev_matched, prev_prio) {
                            candidate_result
                        } else {
                            prev
                        }
                    }
                    None => candidate_result,
                });
            }
        }
        if best.is_some() {
            return Ok(best);
        }
    }

    Ok(None)
}

struct MatchedRule<'a> {
    action_kind: ActionKind,
    rule: &'a RuleEntry,
    pattern_str: String,
    alias_chain: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use rstest::{fixture, rstest};

    use crate::config::{Config, Defaults, Definitions, RuleEntry};
    use crate::rules::rule_engine::evaluate_command;

    use super::*;

    #[fixture]
    fn empty_context() -> EvalContext {
        EvalContext {
            env: HashMap::new(),
            cwd: PathBuf::from("/tmp"),
        }
    }

    fn make_config(rules: Vec<RuleEntry>) -> Config {
        Config {
            rules: Some(rules),
            ..Default::default()
        }
    }

    fn allow_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            allow: Some(pattern.to_string()),
            deny: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
            tests: None,
        }
    }

    fn deny_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            deny: Some(pattern.to_string()),
            allow: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
            tests: None,
        }
    }

    fn ask_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            ask: Some(pattern.to_string()),
            allow: None,
            deny: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
            tests: None,
        }
    }

    // ========================================
    // No rules -> Default
    // ========================================

    #[rstest]
    fn no_rules_returns_default(empty_context: EvalContext) {
        let config = Config::default();
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
        assert_eq!(result.sandbox_preset, None);
    }

    #[rstest]
    fn empty_rules_returns_default(empty_context: EvalContext) {
        let config = make_config(vec![]);
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    // ========================================
    // Single rule matching
    // ========================================

    #[rstest]
    fn single_allow_rule(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git status")]);
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    fn single_deny_rule(empty_context: EvalContext) {
        let config = make_config(vec![deny_rule("rm -rf /")]);
        let result = evaluate_command(&config, "rm -rf /", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn single_ask_rule(empty_context: EvalContext) {
        let config = make_config(vec![ask_rule("git push *")]);
        let result = evaluate_command(&config, "git push origin main", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn no_matching_rule_returns_default(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git status")]);
        let result = evaluate_command(&config, "hg status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    // ========================================
    // Explicit Deny Wins: priority ordering
    // ========================================

    #[rstest]
    fn deny_wins_over_allow(empty_context: EvalContext) {
        let config = make_config(vec![
            allow_rule("git *"),
            deny_rule("git push -f|--force *"),
        ]);
        let result = evaluate_command(&config, "git push --force origin", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn deny_wins_over_ask(empty_context: EvalContext) {
        let config = make_config(vec![
            ask_rule("git push *"),
            deny_rule("git push -f|--force *"),
        ]);
        let result = evaluate_command(&config, "git push --force origin", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn ask_wins_over_allow(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git *"), ask_rule("git push *")]);
        let result = evaluate_command(&config, "git push origin", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Ask(_)));
    }

    #[rstest]
    fn deny_wins_over_allow_and_ask(empty_context: EvalContext) {
        let config = make_config(vec![
            allow_rule("git *"),
            ask_rule("git push *"),
            deny_rule("git push -f|--force *"),
        ]);
        let result = evaluate_command(&config, "git push --force origin", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    // ========================================
    // Rule order independence
    // ========================================

    #[rstest]
    fn deny_wins_regardless_of_order(empty_context: EvalContext) {
        // deny first, then allow
        let config1 = make_config(vec![
            deny_rule("git push -f|--force *"),
            allow_rule("git *"),
        ]);
        let result1 =
            evaluate_command(&config1, "git push --force origin", &empty_context).unwrap();
        assert!(matches!(result1.action, Action::Deny(_)));

        // allow first, then deny
        let config2 = make_config(vec![
            allow_rule("git *"),
            deny_rule("git push -f|--force *"),
        ]);
        let result2 =
            evaluate_command(&config2, "git push --force origin", &empty_context).unwrap();
        assert!(matches!(result2.action, Action::Deny(_)));
    }

    // ========================================
    // DenyResponse details
    // ========================================

    #[rstest]
    fn deny_response_includes_details(empty_context: EvalContext) {
        let mut rule = deny_rule("git push -f|--force *");
        rule.message = Some("Force push is not allowed".to_string());
        rule.fix_suggestion = Some("git push --force-with-lease".to_string());

        let config = make_config(vec![rule]);
        let result = evaluate_command(&config, "git push --force origin", &empty_context).unwrap();

        match result.action {
            Action::Deny(resp) => {
                assert_eq!(resp.message.as_deref(), Some("Force push is not allowed"));
                assert_eq!(
                    resp.fix_suggestion.as_deref(),
                    Some("git push --force-with-lease")
                );
                assert_eq!(resp.matched_rule, "git push -f|--force *");
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    // ========================================
    // Wildcard command name in rules
    // ========================================

    #[rstest]
    #[case::help_matches("* --help", "git --help", Action::Allow)]
    #[case::version_matches("* --version", "node --version", Action::Allow)]
    #[case::no_match_without_flag("* --help", "git status", Action::Ask(None))]
    fn wildcard_command_matching(
        #[case] pattern: &str,
        #[case] command: &str,
        #[case] expected: Action,
        empty_context: EvalContext,
    ) {
        let config = make_config(vec![allow_rule(pattern)]);
        let result = evaluate_command(&config, command, &empty_context).unwrap();
        assert_eq!(result.action, expected);
    }

    #[rstest]
    fn wildcard_command_deny_wins_over_wildcard_allow(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("* --help"), deny_rule("rm *")]);
        let result = evaluate_command(&config, "rm --help", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    // ========================================
    // When clause filtering
    // ========================================

    #[test]
    fn when_clause_satisfied_matches() {
        let mut rule = deny_rule("aws *");
        rule.when = Some("env.AWS_PROFILE == 'prod'".to_string());

        let context = EvalContext {
            env: HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
            cwd: PathBuf::from("/tmp"),
        };

        let config = make_config(vec![rule]);
        let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[test]
    fn when_clause_not_satisfied_skips_rule() {
        let mut rule = deny_rule("aws *");
        rule.when = Some("env.AWS_PROFILE == 'prod'".to_string());

        let context = EvalContext {
            env: HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
            cwd: PathBuf::from("/tmp"),
        };

        let config = make_config(vec![rule]);
        let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    #[test]
    fn when_clause_skips_deny_falls_back_to_allow() {
        let mut deny = deny_rule("aws *");
        deny.when = Some("env.AWS_PROFILE == 'prod'".to_string());

        let context = EvalContext {
            env: HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
            cwd: PathBuf::from("/tmp"),
        };

        let config = make_config(vec![deny, allow_rule("aws *")]);
        let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    // ========================================
    // Sandbox preset propagation
    // ========================================

    #[rstest]
    fn sandbox_preset_from_matched_rule(empty_context: EvalContext) {
        let mut rule = allow_rule("python3 *");
        rule.sandbox = Some("restricted".to_string());

        let config = make_config(vec![rule]);
        let result = evaluate_command(&config, "python3 script.py", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
        assert_eq!(result.sandbox_preset.as_deref(), Some("restricted"));
    }

    #[rstest]
    fn no_sandbox_when_rule_has_no_sandbox(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git status")]);
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.sandbox_preset, None);
    }

    #[rstest]
    fn sandbox_from_most_restrictive_matched_rule(empty_context: EvalContext) {
        let allow = allow_rule("python3 *");
        let mut ask = ask_rule("python3 *");
        ask.sandbox = Some("sandboxed".to_string());

        let config = make_config(vec![allow, ask]);
        let result = evaluate_command(&config, "python3 script.py", &empty_context).unwrap();
        // ask wins over allow
        assert!(matches!(result.action, Action::Ask(_)));
        assert_eq!(result.sandbox_preset.as_deref(), Some("sandboxed"));
    }

    // ========================================
    // Multiple matches with same action level
    // ========================================

    #[rstest]
    fn multiple_deny_rules_picks_first_deny(empty_context: EvalContext) {
        let mut deny1 = deny_rule("rm *");
        deny1.message = Some("generic rm denied".to_string());

        let mut deny2 = deny_rule("rm -rf *");
        deny2.message = Some("rm -rf denied".to_string());

        let config = make_config(vec![deny1, deny2]);
        let result = evaluate_command(&config, "rm -rf /", &empty_context).unwrap();
        // Both match; the result should be Deny (either message is acceptable since
        // both are at the same action level; max_by_key picks the last one for equal keys)
        assert!(matches!(result.action, Action::Deny(_)));
    }

    // ========================================
    // Wildcard patterns
    // ========================================

    #[rstest]
    fn wildcard_deny_matches_all_subcommands(empty_context: EvalContext) {
        let config = make_config(vec![allow_rule("git status"), deny_rule("git *")]);
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        // Both match: deny wins
        assert!(matches!(result.action, Action::Deny(_)));
    }

    // ========================================
    // Ask message propagation
    // ========================================

    #[rstest]
    fn ask_response_includes_message(empty_context: EvalContext) {
        let mut rule = ask_rule("git push *");
        rule.message = Some("Are you sure?".to_string());

        let config = make_config(vec![rule]);
        let result = evaluate_command(&config, "git push origin", &empty_context).unwrap();
        assert_eq!(
            result.action,
            Action::Ask(Some("Are you sure?".to_string()))
        );
    }

    // ========================================
    // Path reference in rules
    // ========================================

    #[rstest]
    fn deny_with_path_ref(empty_context: EvalContext) {
        let config = Config {
            rules: Some(vec![deny_rule("cat <path:sensitive>")]),
            definitions: Some(Definitions {
                paths: Some(HashMap::from([(
                    "sensitive".to_string(),
                    vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()],
                )])),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = evaluate_command(&config, "cat /etc/passwd", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));

        let result = evaluate_command(&config, "cat /tmp/safe.txt", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    // ========================================
    // Invalid rule entries are skipped
    // ========================================

    #[rstest]
    fn rule_with_no_action_is_skipped(empty_context: EvalContext) {
        let invalid_rule = RuleEntry {
            deny: None,
            allow: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
            tests: None,
        };
        let config = make_config(vec![invalid_rule, allow_rule("git status")]);
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    // ========================================
    // Compound command guard in evaluate_command
    // ========================================

    #[rstest]
    #[case::cd_and_rm(
        "cd /path && rm -rf dist",
        vec![allow_rule("cd *"), deny_rule("rm *")],
        "Deny",
    )]
    #[case::cd_and_pnpm_build(
        "cd /path && pnpm build",
        vec![allow_rule("cd *"), allow_rule("pnpm *")],
        "Allow",
    )]
    #[case::cd_and_unmatched_escalates_to_ask(
        "cd /path && unknown-cmd",
        vec![allow_rule("cd *")],
        "Ask",
    )]
    #[case::triple_compound(
        "cd /path/to/dir && rm -rf dist .astro && pnpm build",
        vec![allow_rule("cd *"), deny_rule("rm *"), allow_rule("pnpm *")],
        "Deny",
    )]
    #[case::semicolon_separated(
        "cd /path ; rm -rf /",
        vec![allow_rule("cd *"), deny_rule("rm *")],
        "Deny",
    )]
    #[case::pipe_separated(
        "echo hello | grep world",
        vec![allow_rule("echo *"), allow_rule("grep *")],
        "Allow",
    )]
    #[case::or_separated(
        "false || rm -rf /",
        vec![allow_rule("false"), deny_rule("rm *")],
        "Deny",
    )]
    fn compound_command_guard_splits_and_evaluates_individually(
        empty_context: EvalContext,
        #[case] command: &str,
        #[case] rules: Vec<RuleEntry>,
        #[case] expected_variant: &str,
    ) {
        let config = make_config(rules);
        let result = evaluate_command(&config, command, &empty_context).unwrap();
        let variant = format!("{:?}", result.action);
        assert!(
            variant.starts_with(expected_variant),
            "expected action starting with '{expected_variant}', got '{variant}'"
        );
    }

    #[rstest]
    fn compound_guard_cd_wildcard_does_not_match_entire_compound(empty_context: EvalContext) {
        // This is the exact bug scenario: `cd *` must NOT match the entire
        // compound command `cd /path && rm -rf dist && pnpm build`.
        // Unmatched sub-commands escalate to Ask even without defaults.action,
        // so the overall result must be Ask, not Allow.
        let config = make_config(vec![allow_rule("cd *")]);
        let result = evaluate_command(
            &config,
            "cd /path/to/dir && rm -rf dist .astro && pnpm build 2>&1",
            &empty_context,
        )
        .unwrap();
        assert!(
            matches!(result.action, Action::Ask(_)),
            "expected Ask (from unmatched sub-commands), got {:?}",
            result.action
        );
    }

    // ========================================
    // Wrapper command recursive evaluation
    // ========================================

    fn make_config_with_wrappers(rules: Vec<RuleEntry>, wrappers: Vec<&str>) -> Config {
        Config {
            rules: Some(rules),
            definitions: Some(Definitions {
                wrappers: Some(wrappers.into_iter().map(String::from).collect()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[rstest]
    #[case::sudo("sudo <cmd>", "sudo rm -rf /")]
    #[case::bash_c("bash -c <cmd>", "bash -c 'rm -rf /'")]
    fn wrapper_evaluates_inner_deny(
        #[case] wrapper: &str,
        #[case] command: &str,
        empty_context: EvalContext,
    ) {
        let config = make_config_with_wrappers(vec![deny_rule("rm -rf *")], vec![wrapper]);
        let result = evaluate_command(&config, command, &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn wrapper_allows_safe_inner_command(empty_context: EvalContext) {
        let config = make_config_with_wrappers(
            vec![allow_rule("ls *"), deny_rule("rm -rf *")],
            vec!["sudo <cmd>"],
        );
        let result = evaluate_command(&config, "sudo ls -la", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    fn nested_wrappers_sudo_bash_c(empty_context: EvalContext) {
        let config = make_config_with_wrappers(
            vec![deny_rule("rm -rf *")],
            vec!["sudo <cmd>", "bash -c <cmd>"],
        );
        let result = evaluate_command(&config, "sudo bash -c 'rm -rf /'", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn wrapper_no_match_returns_default(empty_context: EvalContext) {
        let config = make_config_with_wrappers(vec![deny_rule("rm -rf *")], vec!["sudo <cmd>"]);
        let result = evaluate_command(&config, "ls -la", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    #[rstest]
    fn wrapper_deny_wins_over_allow_from_direct_rule(empty_context: EvalContext) {
        let config = make_config_with_wrappers(
            vec![allow_rule("sudo *"), deny_rule("rm -rf *")],
            vec!["sudo <cmd>"],
        );
        let result = evaluate_command(&config, "sudo rm -rf /", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[test]
    fn recursion_depth_exceeded() {
        let context = EvalContext {
            env: HashMap::new(),
            cwd: PathBuf::from("/tmp"),
        };
        let config = make_config_with_wrappers(vec![], vec!["a <cmd>"]);
        let result = evaluate_command(&config, "a a a a a a a a a a a a", &context);
        assert!(
            matches!(result, Err(RuleError::RecursionDepthExceeded(_))),
            "expected RecursionDepthExceeded, got {:?}",
            result,
        );
    }

    #[rstest]
    fn wrapper_without_placeholder_does_not_recurse(empty_context: EvalContext) {
        let config = make_config_with_wrappers(vec![allow_rule("sudo *")], vec!["time *"]);
        let result = evaluate_command(&config, "time ls -la", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    #[rstest]
    fn no_wrappers_defined_skips_unwrap(empty_context: EvalContext) {
        let config = make_config(vec![deny_rule("rm -rf *")]);
        let result = evaluate_command(&config, "sudo rm -rf /", &empty_context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    #[rstest]
    fn compound_command_in_wrapper_denies_dangerous_part(empty_context: EvalContext) {
        let config = make_config_with_wrappers(vec![deny_rule("rm -rf *")], vec!["bash -c <cmd>"]);
        let result = evaluate_command(&config, "bash -c 'ls; rm -rf /'", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn compound_command_in_wrapper_allows_safe_commands(empty_context: EvalContext) {
        let config = make_config_with_wrappers(
            vec![allow_rule("ls *"), allow_rule("echo *")],
            vec!["bash -c <cmd>"],
        );
        let result =
            evaluate_command(&config, "bash -c 'ls -la && echo done'", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
    }

    #[rstest]
    #[case::optional_present("sudo [-E] <cmd>", "sudo -E rm foo")]
    #[case::optional_absent("sudo [-E] <cmd>", "sudo rm foo")]
    #[case::optional_with_value_present("sudo [-u root] <cmd>", "sudo -u root rm foo")]
    #[case::optional_with_value_absent("sudo [-u root] <cmd>", "sudo rm foo")]
    fn wrapper_with_optional_evaluates_inner(
        #[case] wrapper: &str,
        #[case] command: &str,
        empty_context: EvalContext,
    ) {
        let config = make_config_with_wrappers(vec![deny_rule("rm *")], vec![wrapper]);
        let result = evaluate_command(&config, command, &empty_context).unwrap();
        assert!(
            matches!(result.action, Action::Deny(_)),
            "expected Deny for {command:?}, got {:?}",
            result.action,
        );
    }

    #[rstest]
    fn wrapper_preserves_quoting_in_inner_command(empty_context: EvalContext) {
        // "sudo echo 'hello world'" should evaluate "echo 'hello world'" as
        // 2 tokens [echo, hello world], not 3 tokens [echo, hello, world].
        // The deny rule matches echo with exactly 1 argument via "echo <arg>",
        // which only works if quoting is preserved.
        let config = make_config_with_wrappers(vec![deny_rule("echo *")], vec!["sudo <cmd>"]);
        let result = evaluate_command(&config, "sudo echo 'hello world'", &empty_context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn wrapper_compound_unmatched_resolved_via_defaults_action(empty_context: EvalContext) {
        // bash -c 'echo hello; unknown_cmd' with defaults.action = ask
        // should resolve the unmatched "unknown_cmd" to Ask, not silently allow.
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Ask),
                sandbox: None,
            }),
            rules: Some(vec![allow_rule("echo *")]),
            definitions: Some(Definitions {
                wrappers: Some(vec!["bash -c <cmd>".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let result =
            evaluate_command(&config, "bash -c 'echo hello; unknown_cmd'", &empty_context).unwrap();
        assert!(
            matches!(result.action, Action::Ask(_)),
            "expected Ask, got {:?}",
            result.action
        );
    }
}
