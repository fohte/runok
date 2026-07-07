//! Tests for the pattern-matching engine, split by the kind of `PatternToken`
//! each theme module exercises. Shared test helpers and fixtures used across
//! more than one theme module live here; helpers used by only one theme
//! module live in that module instead.

use super::*;
use crate::rules::command_parser::{FlagSchema, parse_command};
use crate::rules::pattern_parser::{PatternToken, parse as parse_pattern};
use rstest::fixture;
use std::collections::{HashMap, HashSet};

mod alternation_and_negation;
mod basic_tokens;
mod extract_and_opts;
mod flags;
mod optional_and_captures;

/// Helper: parse pattern and command, then check matching.
fn check_match(pattern_str: &str, command_str: &str, definitions: &Definitions) -> bool {
    let pattern = parse_pattern(pattern_str).unwrap();
    let schema = build_schema_from_pattern(&pattern, definitions);
    let command = parse_command(command_str, &schema).unwrap();
    matches(&pattern, &command, definitions)
}

/// Build a FlagSchema from a pattern's FlagWithValue and FlagGroupRef
/// tokens. Mirrors the production helper in `rule_engine::build_flag_schema`
/// so unit tests using `<flag:name>` see the same value-flag set the real
/// command parser does.
fn build_schema_from_pattern(pattern: &Pattern, definitions: &Definitions) -> FlagSchema {
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
            PatternToken::FlagGroupRef { name, .. } => {
                if let Some(parsed) = definitions
                    .parsed_flag_groups
                    .as_ref()
                    .and_then(|g| g.get(name))
                    && parsed.value_pattern.is_some()
                {
                    for alias in &parsed.aliases {
                        value_flags.insert(alias.clone());
                    }
                }
            }
            PatternToken::Optional(inner) => collect_value_flags(inner, definitions, value_flags),
            _ => {}
        }
    }
}

#[fixture]
fn empty_defs() -> Definitions {
    Definitions::default()
}
