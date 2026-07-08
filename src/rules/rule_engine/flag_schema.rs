use std::collections::{HashMap, HashSet};

use crate::config::Definitions;
use crate::rules::command_parser::{FlagSchema, ParsedCommand, PipeInfo, RedirectInfo};
use crate::rules::expr_evaluator::ExprContext;
use crate::rules::pattern_matcher::MatchCaptures;
use crate::rules::pattern_parser::{Pattern, PatternToken};

use super::EvalContext;

/// Build a FlagSchema from a pattern's FlagWithValue and FlagGroupRef tokens.
///
/// FlagGroupRef aliases are resolved through `definitions.flag_groups` so the
/// command parser knows that the grouped flags consume the next token as
/// their value.
pub(super) fn build_flag_schema(pattern: &Pattern, definitions: &Definitions) -> FlagSchema {
    let mut value_flags = HashSet::new();
    collect_value_flags(&pattern.tokens, definitions, &mut value_flags);
    FlagSchema { value_flags }
}

fn collect_value_flags(
    tokens: &[PatternToken],
    definitions: &Definitions,
    value_flags: &mut HashSet<String>,
) {
    for token in tokens {
        match token {
            PatternToken::FlagWithValue { aliases, .. } => {
                for alias in aliases {
                    value_flags.insert(alias.clone());
                }
            }
            PatternToken::FlagGroupRef { name } => {
                if let Some(parsed) = definitions
                    .parsed_flag_groups
                    .as_ref()
                    .and_then(|g| g.get(name))
                    && parsed.value_pattern.is_some()
                {
                    // Only add aliases for value-taking flags (those with
                    // a value pattern). Bool flags do not consume the next
                    // token, so they must not be registered as value flags.
                    for alias in &parsed.aliases {
                        value_flags.insert(alias.clone());
                    }
                }
            }
            PatternToken::Optional(inner) => collect_value_flags(inner, definitions, value_flags),
            PatternToken::VarRef(name) => {
                // Pattern-typed vars expand inline into rule patterns, so
                // value-flag aliases nested inside the expansion (e.g.
                // `[--namespace *]`) must propagate up to the command parser.
                if let Some(sub_patterns) = definitions
                    .parsed_pattern_vars
                    .as_ref()
                    .and_then(|m| m.get(name))
                {
                    for sub in sub_patterns {
                        collect_value_flags(&sub.tokens, definitions, value_flags);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Build an ExprContext for `when` clause evaluation from the parsed command
/// and evaluation context.
pub(super) fn build_expr_context(
    parsed_command: &ParsedCommand,
    eval_context: &EvalContext,
    definitions: &Definitions,
    redirects: &[RedirectInfo],
    pipe: &PipeInfo,
    match_captures: &MatchCaptures,
    loop_kind: &str,
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

    // Seed flag_groups with every group declared in definitions so that
    // `flag_groups["name"]` always succeeds in CEL (returning an empty list
    // when no flag from the group was matched). Then overlay the values
    // captured during pattern matching.
    let mut flag_groups: HashMap<String, Vec<String>> = definitions
        .flag_groups
        .as_ref()
        .map(|g| g.keys().map(|k| (k.clone(), Vec::new())).collect())
        .unwrap_or_default();
    for (name, values) in &match_captures.flag_groups {
        flag_groups.insert(name.clone(), values.clone());
    }

    ExprContext {
        env: eval_context.env.clone(),
        flags,
        args: parsed_command.args.clone(),
        paths,
        redirects: redirects.to_vec(),
        pipe: pipe.clone(),
        vars: match_captures.vars.clone(),
        flag_groups,
        os: std::env::consts::OS.to_string(),
        loop_kind: loop_kind.to_string(),
        home: crate::config::dirs::home_dir().map(|p| p.to_string_lossy().into_owned()),
        cwd: eval_context.cwd.to_string_lossy().into_owned(),
    }
}
