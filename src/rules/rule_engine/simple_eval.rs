use crate::config::{ActionKind, Config, Definitions, RuleEntry};
use crate::rules::RuleError;
use crate::rules::alias_expander::expand_rule_pattern;
use crate::rules::command_parser::{FunctionCallInfo, PipeInfo, RedirectInfo, parse_command};
use crate::rules::expr_evaluator::evaluate;
use crate::rules::pattern_matcher::matches_with_captures;
use crate::rules::pattern_parser::parse_multi;

use super::compound::merge_results;
use super::flag_schema::{build_expr_context, build_flag_schema};
use super::function::try_unwrap_function_call;
use super::require_command_in_path::resolve_unmatched;
use super::wrapper::try_unwrap_wrapper;
use super::{Action, DenyResponse, EvalContext, EvalResult, RuleMatchInfo};

/// Evaluate a single (non-compound) command against rules, function
/// calls, and wrappers.
///
/// This contains the core rule-matching and wrapper-unwrapping logic,
/// separated from `evaluate_command_inner` so the compound guard can
/// call it directly when it needs to evaluate the original command as
/// a simple command (e.g. after filtering out self-referencing sub-commands
/// from command substitutions).
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent recursive-evaluation context (redirect/pipe/loop position, the resolved function call for this command if any, the in-progress call stack for cycle detection, and whether the original input contains a source/./eval command); grouping them into a struct would obscure the per-call-site overrides this function relies on"
)]
pub(super) fn evaluate_simple_command(
    config: &Config,
    command: &str,
    context: &EvalContext,
    depth: usize,
    redirects: &[RedirectInfo],
    pipe: &PipeInfo,
    loop_kind: &str,
    function_call: Option<&FunctionCallInfo>,
    call_stack: &[String],
    source_like_present: bool,
) -> Result<EvalResult, RuleError> {
    // A resolved function call takes priority over rule matching against
    // the bare call name (e.g. `f`): the call is what actually runs, and
    // rules are almost never written to match a user-defined function
    // name. `Ok(None)` (unresolved -- a cycle, `MAX_WRAPPER_DEPTH`
    // exceeded, or a body that failed to parse) falls through to treat
    // `command` as an ordinary, unknown command instead.
    if let Some(call_info) = function_call
        && let Some(result) = try_unwrap_function_call(
            config,
            context,
            call_info,
            depth,
            redirects,
            pipe,
            loop_kind,
            call_stack,
            source_like_present,
        )?
    {
        return Ok(result);
    }

    let rules = match &config.rules {
        Some(rules) => rules,
        None => {
            let (action, require_command_in_path) =
                resolve_unmatched(config, command, context, function_call, source_like_present);
            return Ok(EvalResult {
                action,
                sandbox_preset: None,
                matched_rules: Vec::new(),
                alias_chain: Vec::new(),
                require_command_in_path,
            });
        }
    };

    let default_definitions = Definitions::default();
    let definitions = config.definitions.as_ref().unwrap_or(&default_definitions);

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

    let wrapper_result = try_unwrap_wrapper(
        config,
        command,
        context,
        definitions,
        depth,
        loop_kind,
        call_stack,
        source_like_present,
    )?;

    if matched.is_empty() && wrapper_result.is_none() {
        let (action, require_command_in_path) =
            resolve_unmatched(config, command, context, function_call, source_like_present);
        return Ok(EvalResult {
            action,
            sandbox_preset: None,
            matched_rules: match_infos,
            alias_chain: Vec::new(),
            require_command_in_path,
        });
    }

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
            require_command_in_path: None,
        })
    };

    let merged = match (direct_result, wrapper_result) {
        (Some(direct), Some(wrapper)) => merge_results(direct, wrapper),
        (Some(direct), None) => direct,
        (None, Some(wrapper)) => wrapper,
        (None, None) => unreachable!("at least one result exists"),
    };
    Ok(merged)
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

    use rstest::rstest;

    use crate::config::{Config, Definitions, RuleEntry};
    use crate::rules::rule_engine::evaluate_command;

    use super::super::test_support::{allow_rule, ask_rule, deny_rule, empty_context, make_config};
    use super::*;

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

    #[rstest]
    fn when_clause_satisfied_matches(empty_context: EvalContext) {
        let mut rule = deny_rule("aws *");
        rule.when = Some("env.AWS_PROFILE == 'prod'".to_string());

        let context = EvalContext {
            env: HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
            ..empty_context
        };

        let config = make_config(vec![rule]);
        let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
        assert!(matches!(result.action, Action::Deny(_)));
    }

    #[rstest]
    fn when_clause_not_satisfied_skips_rule(empty_context: EvalContext) {
        let mut rule = deny_rule("aws *");
        rule.when = Some("env.AWS_PROFILE == 'prod'".to_string());

        let context = EvalContext {
            env: HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
            ..empty_context
        };

        let config = make_config(vec![rule]);
        let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
        assert_eq!(result.action, Action::Ask(None));
    }

    #[rstest]
    fn when_clause_skips_deny_falls_back_to_allow(empty_context: EvalContext) {
        let mut deny = deny_rule("aws *");
        deny.when = Some("env.AWS_PROFILE == 'prod'".to_string());

        let context = EvalContext {
            env: HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
            ..empty_context
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
}
