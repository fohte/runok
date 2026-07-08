use crate::config::Config;
use crate::rules::RuleError;
use crate::rules::command_parser::{
    ExtractedCommand, PipeInfo, RedirectInfo, extract_commands_with_metadata,
};

use super::compound::{default_action, merge_results, normalize_whitespace};
use super::simple_eval::evaluate_simple_command;
use super::{EvalContext, EvalResult};

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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::config::RuleEntry;
    use crate::rules::rule_engine::{Action, evaluate_command};

    use super::super::test_support::{allow_rule, deny_rule, empty_context, make_config};
    use super::*;

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
}
