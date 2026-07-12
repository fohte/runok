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
            // `?`-valued flags never consume a space-separated following
            // token as their value (see `match_flag_with_optional_value`),
            // so the command parser must treat them as boolean flags --
            // otherwise `git branch --abbrev 8` would wrongly assign `8` to
            // `--abbrev` instead of leaving it as a positional argument.
            PatternToken::FlagWithValue { value, .. }
                if matches!(value.as_ref(), PatternToken::OptionalValue) => {}
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
                    && parsed
                        .value_pattern
                        .as_ref()
                        .is_some_and(|v| !matches!(v, PatternToken::OptionalValue))
                {
                    // Only add aliases for value-taking flags (those with a
                    // space-separated value pattern). Bool flags and
                    // `?`-valued flags do not consume the next token, so
                    // they must not be registered as value flags.
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

    // Raw values for every `definitions.vars` entry, regardless of whether
    // the current rule's pattern captured them via `<var:name>`. Exposed to
    // CEL as `definitions.vars`. Drops each value's effective type
    // (`v.effective_type(def.var_type)`), so `glob_matches` against these
    // strings only agrees with `<var:name>` matching for `type: pattern`
    // values -- `literal` (exact match, no wildcard) and `path`
    // (canonicalized comparison) values are matched differently by
    // `<var:name>` than by `glob_matches`.
    let var_definitions: HashMap<String, Vec<String>> = definitions
        .vars
        .as_ref()
        .map(|vars| {
            vars.iter()
                .map(|(name, def)| {
                    let values = def.values.iter().map(|v| v.value().to_string()).collect();
                    (name.clone(), values)
                })
                .collect()
        })
        .unwrap_or_default();

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
        var_definitions,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::pattern_parser::parse as parse_pattern;
    use rstest::rstest;

    #[rstest]
    #[case::optional_value_flag_excluded("git branch --abbrev ?", &[])]
    #[case::wildcard_value_flag_included("git branch --sort committerdate", &["--sort"])]
    fn build_flag_schema_excludes_optional_value_flags(
        #[case] pattern_str: &str,
        #[case] expected: &[&str],
    ) {
        let pattern = parse_pattern(pattern_str).unwrap();
        let schema = build_flag_schema(&pattern, &Definitions::default());
        let expected: HashSet<String> = expected.iter().map(|s| s.to_string()).collect();
        assert_eq!(schema.value_flags, expected);
    }

    #[rstest]
    #[case::optional_value_group_excluded("-n|--number ?", &[])]
    #[case::wildcard_group_included("-f|--field *", &["-f", "--field"])]
    fn build_flag_schema_excludes_optional_value_flag_groups(
        #[case] group_definition: &str,
        #[case] expected: &[&str],
    ) {
        let pattern = parse_pattern("git tag <flag:count>").unwrap();
        let mut defs = Definitions {
            flag_groups: Some(HashMap::from([(
                "count".to_string(),
                group_definition.to_string(),
            )])),
            ..Definitions::default()
        };
        defs.resolve_flag_groups();

        let schema = build_flag_schema(&pattern, &defs);
        let expected: HashSet<String> = expected.iter().map(|s| s.to_string()).collect();
        assert_eq!(schema.value_flags, expected);
    }
}
