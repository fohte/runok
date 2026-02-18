use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::config::{ActionKind, Config, Definitions, RuleEntry};
use crate::rules::RuleError;
use crate::rules::command_parser::{FlagSchema, ParsedCommand, extract_commands, parse_command};
use crate::rules::expr_evaluator::{ExprContext, evaluate};
use crate::rules::pattern_matcher::{extract_placeholder, matches};
use crate::rules::pattern_parser::{Pattern, PatternToken, parse as parse_pattern};

/// Context for rule evaluation, providing environment variables and
/// working directory for `when` clause evaluation.
pub struct EvalContext {
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
}

/// Result of rule evaluation: an action and an optional sandbox preset name.
#[derive(Debug, PartialEq)]
pub struct EvalResult {
    pub action: Action,
    /// Sandbox preset name from the matched rule, or `None` to fall back to `defaults.sandbox`.
    pub sandbox_preset: Option<String>,
}

/// The action determined by rule evaluation.
#[derive(Debug, PartialEq)]
pub enum Action {
    Allow,
    Deny(DenyResponse),
    Ask(Option<String>),
    Default,
}

/// Details included when a command is denied.
#[derive(Debug, PartialEq)]
pub struct DenyResponse {
    pub message: Option<String>,
    pub fix_suggestion: Option<String>,
    pub matched_rule: String,
}

/// Maximum recursion depth for wrapper command evaluation.
const MAX_WRAPPER_DEPTH: usize = 10;

/// Evaluate a command against all rules in the config, returning the most
/// restrictive matching action (Explicit Deny Wins).
///
/// If the command matches a wrapper pattern from `definitions.wrappers`,
/// the inner command is extracted and evaluated recursively.
pub fn evaluate_command(
    config: &Config,
    command: &str,
    context: &EvalContext,
) -> Result<EvalResult, RuleError> {
    evaluate_command_inner(config, command, context, 0)
}

fn evaluate_command_inner(
    config: &Config,
    command: &str,
    context: &EvalContext,
    depth: usize,
) -> Result<EvalResult, RuleError> {
    if depth > MAX_WRAPPER_DEPTH {
        return Err(RuleError::RecursionDepthExceeded(MAX_WRAPPER_DEPTH));
    }

    let rules = match &config.rules {
        Some(rules) => rules,
        None => {
            return Ok(EvalResult {
                action: Action::Default,
                sandbox_preset: None,
            });
        }
    };

    let default_definitions = Definitions::default();
    let definitions = config.definitions.as_ref().unwrap_or(&default_definitions);

    // Collect all matched rules with their parsed patterns
    let mut matched: Vec<MatchedRule> = Vec::new();

    for rule in rules {
        let (action_kind, pattern_str) = match rule.action_and_pattern() {
            Some(pair) => pair,
            None => continue,
        };

        let pattern = parse_pattern(pattern_str)?;
        let schema = build_flag_schema(&pattern);
        let parsed_command = parse_command(command, &schema)?;

        if !matches(&pattern, &parsed_command, definitions) {
            continue;
        }

        // Evaluate when clause if present
        if let Some(when_expr) = &rule.when {
            let expr_context = build_expr_context(&parsed_command, context, definitions);
            match evaluate(when_expr, &expr_context) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => return Err(e.into()),
            }
        }

        matched.push(MatchedRule {
            action_kind,
            rule,
            pattern_str: pattern_str.to_string(),
        });
    }

    // Try wrapper pattern matching for recursive evaluation
    let wrapper_result = try_unwrap_wrapper(config, command, context, definitions, depth)?;

    if matched.is_empty() && wrapper_result.is_none() {
        return Ok(EvalResult {
            action: Action::Default,
            sandbox_preset: None,
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

        Some(EvalResult {
            action,
            sandbox_preset,
        })
    };

    // Merge direct result with wrapper result using Explicit Deny Wins
    match (direct_result, wrapper_result) {
        (Some(direct), Some(wrapper)) => Ok(merge_results(direct, wrapper)),
        (Some(direct), None) => Ok(direct),
        (None, Some(wrapper)) => Ok(wrapper),
        (None, None) => unreachable!("at least one result exists"),
    }
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
) -> Result<Option<EvalResult>, RuleError> {
    let wrappers = match definitions.wrappers.as_ref() {
        Some(w) if !w.is_empty() => w,
        _ => return Ok(None),
    };

    for wrapper_pattern_str in wrappers {
        let pattern = parse_pattern(wrapper_pattern_str)?;
        let schema = build_flag_schema(&pattern);
        let parsed_command = parse_command(command, &schema)?;

        if let Some(inner_command) = extract_placeholder(&pattern, &parsed_command, definitions)? {
            // Split compound commands (e.g., "ls; rm -rf /") into individual ones
            let sub_commands =
                extract_commands(&inner_command).unwrap_or_else(|_| vec![inner_command]);

            let mut result: Option<EvalResult> = None;
            for cmd in &sub_commands {
                let sub_result = evaluate_command_inner(config, cmd, context, depth + 1)?;
                result = Some(match result {
                    Some(prev) => merge_results(prev, sub_result),
                    None => sub_result,
                });
            }
            return Ok(result);
        }
    }

    Ok(None)
}

/// Merge two evaluation results using Explicit Deny Wins priority.
fn merge_results(a: EvalResult, b: EvalResult) -> EvalResult {
    let a_priority = action_priority(&a.action);
    let b_priority = action_priority(&b.action);

    if b_priority > a_priority { b } else { a }
}

/// Map an action to its priority for Explicit Deny Wins comparison.
/// Higher value = more restrictive.
fn action_priority(action: &Action) -> u8 {
    match action {
        Action::Default => 0,
        Action::Allow => 1,
        Action::Ask(_) => 2,
        Action::Deny(_) => 3,
    }
}

struct MatchedRule<'a> {
    action_kind: ActionKind,
    rule: &'a RuleEntry,
    pattern_str: String,
}

/// Build a FlagSchema from a pattern's FlagWithValue tokens.
fn build_flag_schema(pattern: &Pattern) -> FlagSchema {
    let mut value_flags = HashSet::new();
    collect_value_flags(&pattern.tokens, &mut value_flags);
    FlagSchema { value_flags }
}

fn collect_value_flags(tokens: &[PatternToken], value_flags: &mut HashSet<String>) {
    for token in tokens {
        match token {
            PatternToken::FlagWithValue { aliases, .. } => {
                for alias in aliases {
                    value_flags.insert(alias.clone());
                }
            }
            PatternToken::Optional(inner) => collect_value_flags(inner, value_flags),
            _ => {}
        }
    }
}

/// Build an ExprContext for `when` clause evaluation from the parsed command
/// and evaluation context.
fn build_expr_context(
    parsed_command: &ParsedCommand,
    eval_context: &EvalContext,
    definitions: &Definitions,
) -> ExprContext {
    let flags: HashMap<String, Option<String>> = parsed_command
        .flags
        .iter()
        .map(|(k, v)| {
            // Strip leading dashes for when-clause access (e.g., --request -> request, -X -> X)
            let key = k.trim_start_matches('-').to_string();
            (key, v.clone())
        })
        .collect();

    let paths = definitions.paths.clone().unwrap_or_default();

    ExprContext {
        env: eval_context.env.clone(),
        flags,
        args: parsed_command.args.clone(),
        paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Definitions, RuleEntry};
    use rstest::{fixture, rstest};
    use std::collections::HashMap;

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
        }
    }

    // ========================================
    // No rules -> Default
    // ========================================

    #[rstest]
    fn no_rules_returns_default(empty_context: EvalContext) {
        let config = Config::default();
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Default);
        assert_eq!(result.sandbox_preset, None);
    }

    #[rstest]
    fn empty_rules_returns_default(empty_context: EvalContext) {
        let config = make_config(vec![]);
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Default);
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
        assert_eq!(result.action, Action::Default);
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
        assert_eq!(result.action, Action::Default);
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
        assert_eq!(result.action, Action::Default);
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
        };
        let config = make_config(vec![invalid_rule, allow_rule("git status")]);
        let result = evaluate_command(&config, "git status", &empty_context).unwrap();
        assert_eq!(result.action, Action::Allow);
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
        assert_eq!(result.action, Action::Default);
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
        assert_eq!(result.action, Action::Default);
    }

    #[rstest]
    fn no_wrappers_defined_skips_unwrap(empty_context: EvalContext) {
        let config = make_config(vec![deny_rule("rm -rf *")]);
        let result = evaluate_command(&config, "sudo rm -rf /", &empty_context).unwrap();
        assert_eq!(result.action, Action::Default);
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
    #[case::optional("sudo [-u root] <cmd>", "Optional ([...])")]
    #[case::path_ref("sudo <path:bin> <cmd>", "PathRef (<path:bin>)")]
    fn wrapper_with_unsupported_token_returns_error(
        #[case] wrapper: &str,
        #[case] expected_token: &str,
        empty_context: EvalContext,
    ) {
        let config = make_config_with_wrappers(vec![deny_rule("rm *")], vec![wrapper]);
        let result = evaluate_command(&config, "sudo rm foo", &empty_context);
        match result {
            Err(RuleError::UnsupportedWrapperToken(token)) => {
                assert_eq!(token, expected_token);
            }
            other => panic!("expected UnsupportedWrapperToken({expected_token:?}), got {other:?}",),
        }
    }
}
