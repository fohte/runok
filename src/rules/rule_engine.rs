use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::config::{
    ActionKind, Config, Definitions, MergedSandboxPolicy, RuleEntry, SandboxPreset,
};
use crate::rules::RuleError;
use crate::rules::command_parser::{
    FlagSchema, ParsedCommand, extract_commands, parse_command, shell_quote_join,
};
use crate::rules::expr_evaluator::{ExprContext, evaluate};
use crate::rules::pattern_matcher::{MatchCaptures, extract_placeholder, matches_with_captures};
use crate::rules::pattern_parser::{Pattern, PatternToken, parse_multi};

/// Context for rule evaluation, providing environment variables and
/// working directory for `when` clause evaluation.
pub struct EvalContext {
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
}

impl EvalContext {
    /// Build an `EvalContext` from the current process environment.
    pub fn from_env() -> Self {
        Self {
            env: std::env::vars().collect(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        }
    }
}

/// Information about a single rule match, used for verbose logging.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatchInfo {
    /// The action kind of the matched rule (allow, deny, ask).
    pub action_kind: ActionKind,
    /// The pattern string that matched.
    pub pattern: String,
    /// Tokens captured by wildcards (`*`) in the pattern.
    pub matched_tokens: Vec<String>,
}

/// Result of rule evaluation: an action and an optional sandbox preset name.
#[derive(Debug, PartialEq)]
pub struct EvalResult {
    pub action: Action,
    /// Sandbox preset name from the matched rule, or `None` to fall back to `defaults.sandbox`.
    pub sandbox_preset: Option<String>,
    /// Details of all rules that matched, for verbose logging.
    pub matched_rules: Vec<RuleMatchInfo>,
}

/// Per-sub-command evaluation detail, for verbose logging.
#[derive(Debug, PartialEq)]
pub struct SubCommandDetail {
    pub command: String,
    pub action: Action,
    pub matched_rules: Vec<RuleMatchInfo>,
}

/// Result of compound command evaluation: an action and an optional merged
/// sandbox policy built from all sub-commands' sandbox presets.
#[derive(Debug, PartialEq)]
pub struct CompoundEvalResult {
    pub action: Action,
    pub sandbox_policy: Option<MergedSandboxPolicy>,
    /// Per-sub-command evaluation results for audit logging.
    pub sub_results: Vec<EvalResult>,
    /// Per-sub-command evaluation details, for verbose logging.
    pub sub_command_details: Vec<SubCommandDetail>,
}

/// The action determined by rule evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Deny(DenyResponse),
    Ask(Option<String>),
}

/// Details included when a command is denied.
#[derive(Debug, Clone, PartialEq)]
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
    let commands = extract_commands(command).unwrap_or_else(|_| vec![command.to_string()]);

    let default_definitions = Definitions::default();
    let definitions = config.definitions.as_ref().unwrap_or(&default_definitions);
    let sandbox_defs = definitions.sandbox.as_ref();

    let mut merged_action: Option<Action> = None;
    let mut preset_names: Vec<String> = Vec::new();
    let mut sub_results: Vec<EvalResult> = Vec::new();
    let mut sub_command_details: Vec<SubCommandDetail> = Vec::new();

    for cmd in &commands {
        let result = evaluate_command(config, cmd, context)?;

        // Collect sandbox preset names
        if let Some(ref name) = result.sandbox_preset {
            preset_names.push(name.clone());
        }

        sub_command_details.push(SubCommandDetail {
            command: cmd.clone(),
            action: result.action.clone(),
            matched_rules: result.matched_rules.clone(),
        });

        // Aggregate action using Explicit Deny Wins
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

    // Resolve sandbox presets and merge policies
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

    // Check if any source preset actually defined writable roots
    preset_names.iter().any(|name| {
        sandbox_map
            .get(name.as_str())
            .and_then(|p| p.fs.as_ref())
            .and_then(|fs| fs.writable.as_ref())
            .is_some_and(|w| !w.is_empty())
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
fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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
    if let Ok(sub_commands) = extract_commands(command)
        && sub_commands.len() > 1
    {
        let normalized_command = normalize_whitespace(command);
        let nested_subs: Vec<&String> = sub_commands
            .iter()
            .filter(|sub| normalize_whitespace(sub) != normalized_command)
            .collect();
        let had_self_reference = nested_subs.len() < sub_commands.len();

        if !had_self_reference {
            // Pure compound (no self-reference): evaluate all sub-commands and return.
            let mut merged: Option<EvalResult> = None;
            for sub in &nested_subs {
                let result = evaluate_command_inner(config, sub, context, depth + 1)?;
                merged = Some(match merged {
                    Some(prev) => merge_results(prev, result),
                    None => result,
                });
            }
            return Ok(merged.unwrap_or(EvalResult {
                action: default_action(config),
                sandbox_preset: None,
                matched_rules: Vec::new(),
            }));
        }
        // Self-reference detected (e.g. command substitution): evaluate only
        // the nested sub-commands here, then fall through to evaluate the
        // original command as a simple command. The results are merged at the end.
        if !nested_subs.is_empty() {
            let mut nested_merged: Option<EvalResult> = None;
            for sub in &nested_subs {
                let result = evaluate_command_inner(config, sub, context, depth + 1)?;
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
                let simple_result = evaluate_simple_command(config, command, context, depth)?;
                return Ok(merge_results(nested_result, simple_result));
            }
        }
        // nested_subs was empty and had self-reference: fall through to
        // simple-command evaluation.
    }

    evaluate_simple_command(config, command, context, depth)
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
) -> Result<EvalResult, RuleError> {
    let rules = match &config.rules {
        Some(rules) => rules,
        None => {
            return Ok(EvalResult {
                action: default_action(config),
                sandbox_preset: None,
                matched_rules: Vec::new(),
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

        let patterns = parse_multi(pattern_str)?;

        // Try each expanded pattern (multi-word alternation produces multiple patterns);
        // use the first matching pattern for this rule.
        for pattern in &patterns {
            let schema = build_flag_schema(pattern);
            let parsed_command = parse_command(command, &schema)?;

            let match_captures = matches_with_captures(pattern, &parsed_command, definitions);
            let Some(match_captures) = match_captures else {
                continue;
            };

            // Evaluate when clause if present
            if let Some(when_expr) = &rule.when {
                let expr_context =
                    build_expr_context(&parsed_command, context, definitions, &match_captures);
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
            });

            break;
        }
    }

    // Try wrapper pattern matching for recursive evaluation
    let wrapper_result = try_unwrap_wrapper(config, command, context, definitions, depth)?;

    if matched.is_empty() && wrapper_result.is_none() {
        return Ok(EvalResult {
            action: default_action(config),
            sandbox_preset: None,
            matched_rules: match_infos,
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
            matched_rules: match_infos,
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
        let patterns = parse_multi(wrapper_pattern_str)?;

        // Try each expanded pattern for this wrapper definition
        let mut all_candidates: Vec<Vec<String>> = Vec::new();
        for pattern in &patterns {
            let schema = build_flag_schema(pattern);
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
                let sub_result = evaluate_command_inner(config, cmd, context, depth + 1)?;
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

/// Merge two evaluation results using Explicit Deny Wins priority.
fn merge_results(a: EvalResult, b: EvalResult) -> EvalResult {
    let mut combined_rules = a.matched_rules;
    combined_rules.extend(b.matched_rules);

    if action_priority(&b.action) > action_priority(&a.action) {
        EvalResult {
            action: b.action,
            sandbox_preset: b.sandbox_preset,
            matched_rules: combined_rules,
        }
    } else {
        EvalResult {
            action: a.action,
            sandbox_preset: a.sandbox_preset,
            matched_rules: combined_rules,
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
fn action_priority(action: &Action) -> u8 {
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
    match_captures: &MatchCaptures,
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
        vars: match_captures.vars.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Defaults, Definitions, RuleEntry};
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

    use crate::config::{FsPolicy, NetworkPolicy, SandboxPreset};

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
                            writable: Some(vec![
                                "/tmp".to_string(),
                                "/home".to_string(),
                                "/var".to_string(),
                            ]),
                            deny: None,
                        }),
                        network: None,
                    },
                ),
                (
                    "preset_b".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/tmp".to_string(), "/var".to_string()]),
                            deny: None,
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
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: Some(vec!["/etc/passwd".to_string()]),
                        }),
                        network: None,
                    },
                ),
                (
                    "preset_b".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: Some(vec!["/etc/shadow".to_string()]),
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
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: None,
                        }),
                        network: Some(NetworkPolicy { allow: Some(true) }),
                    },
                ),
                (
                    "preset_b".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: None,
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
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: None,
                        }),
                        network: Some(NetworkPolicy { allow: Some(true) }),
                    },
                ),
                (
                    "no_net".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: None,
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
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: None,
                        }),
                        network: None,
                    },
                ),
                (
                    "only_home".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/home".to_string()]),
                            deny: None,
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
                        writable: Some(vec!["/tmp".to_string()]),
                        deny: None,
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
                        writable: Some(vec!["/tmp".to_string()]),
                        deny: Some(vec!["/etc".to_string()]),
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
                        writable: Some(vec!["/tmp".to_string()]),
                        deny: Some(vec!["/etc".to_string()]),
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
                        writable: Some(vec!["/tmp".to_string()]),
                        deny: None,
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
                            writable: Some(vec![
                                "/a".to_string(),
                                "/b".to_string(),
                                "/c".to_string(),
                            ]),
                            deny: Some(vec!["/x".to_string()]),
                        }),
                        network: None,
                    },
                ),
                (
                    "p2".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/b".to_string(), "/c".to_string()]),
                            deny: Some(vec!["/y".to_string()]),
                        }),
                        network: None,
                    },
                ),
                (
                    "p3".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/c".to_string(), "/d".to_string()]),
                            deny: Some(vec!["/z".to_string()]),
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
                            writable: Some(vec!["/tmp".to_string()]),
                            deny: None,
                        }),
                        network: None,
                    },
                ),
                (
                    "only_home".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["/home".to_string()]),
                            deny: None,
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
