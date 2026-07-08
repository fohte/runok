use crate::config::{Config, Definitions};
use crate::rules::RuleError;
use crate::rules::command_parser::{PipeInfo, extract_commands, parse_command, shell_quote_join};
use crate::rules::pattern_matcher::extract_placeholder;
use crate::rules::pattern_parser::parse_multi;

use super::compound::{action_priority, merge_results};
use super::dispatch::evaluate_command_inner;
use super::flag_schema::build_flag_schema;
use super::{EvalContext, EvalResult};

/// Try to match the command against wrapper patterns and recursively
/// evaluate the inner command.
///
/// If the extracted inner command is a compound command (containing
/// pipelines, `&&`, `||`, or `;`), it is split into individual commands
/// and each is evaluated separately. The results are merged using
/// Explicit Deny Wins.
pub(super) fn try_unwrap_wrapper(
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use rstest::rstest;

    use crate::config::{ActionKind, Config, Defaults, Definitions, RuleEntry};
    use crate::rules::RuleError;
    use crate::rules::rule_engine::{Action, evaluate_command};

    use super::super::test_support::{allow_rule, deny_rule, empty_context, make_config};
    use super::*;

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
