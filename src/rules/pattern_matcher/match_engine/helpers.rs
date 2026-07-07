//! Shared helpers used by more than one match arm function in this module.

use std::collections::HashSet;

use crate::config::Definitions;
use crate::rules::pattern_parser::PatternToken;

/// Collect all flag aliases from `FlagWithValue` and `FlagGroupRef` tokens in
/// the pattern token list.  Used by the Literal matcher to identify value-flag
/// tokens whose values should also be skipped when searching for the first
/// positional argument in `cmd_tokens`.
///
/// Borrows aliases from `tokens` and `definitions` rather than cloning them,
/// since this runs on every recursive `match_engine` step (up to
/// `MAX_MATCH_STEPS`).
pub(super) fn collect_value_flag_aliases<'a>(
    tokens: &'a [PatternToken],
    definitions: &'a Definitions,
    aliases: &mut HashSet<&'a str>,
) {
    for token in tokens {
        match token {
            PatternToken::FlagWithValue {
                aliases: flag_aliases,
                ..
            } => {
                for a in flag_aliases {
                    aliases.insert(a.as_str());
                }
            }
            PatternToken::FlagGroupRef { name, .. } => {
                if let Some(parsed) = definitions
                    .parsed_flag_groups
                    .as_ref()
                    .and_then(|g| g.get(name))
                    && parsed.value_pattern.is_some()
                {
                    // Only register value-taking flags (those with a value
                    // pattern) so the positional-argument finder skips their
                    // values correctly.
                    for a in &parsed.aliases {
                        aliases.insert(a.as_str());
                    }
                }
            }
            PatternToken::Optional(inner) => {
                collect_value_flag_aliases(inner, definitions, aliases);
            }
            PatternToken::VarRef(name) => {
                // Pattern-typed vars expand into rule-pattern fragments. Walk
                // each parsed sub-pattern's tokens so any value-flags inside
                // the expansion (e.g. `[--namespace *]`) are registered too.
                if let Some(sub_patterns) = definitions
                    .parsed_pattern_vars
                    .as_ref()
                    .and_then(|m| m.get(name))
                {
                    for sub in sub_patterns {
                        collect_value_flag_aliases(&sub.tokens, definitions, aliases);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Find the index of the first positional (non-flag) token in `cmd_tokens`,
/// skipping over flag tokens and their associated values based on
/// `value_flag_aliases`.  Returns `None` if no positional token is found.
pub(super) fn find_first_positional(
    cmd_tokens: &[&str],
    value_flag_aliases: &HashSet<&str>,
) -> Option<usize> {
    let mut i = 0;
    while i < cmd_tokens.len() {
        let t = cmd_tokens[i];
        if t.starts_with('-') && t != "--" {
            if value_flag_aliases.contains(t) && i + 1 < cmd_tokens.len() {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            return Some(i);
        }
    }
    None
}

/// Count how many tokens `<vars>` should consume from the front of `tokens`.
///
/// Consumes consecutive tokens that contain `=` (i.e., `KEY=VALUE` style
/// environment variable assignments). Stops at the first token without `=`.
pub(super) fn consume_vars(tokens: &[&str]) -> usize {
    tokens.iter().take_while(|t| t.contains('=')).count()
}

/// Count how many tokens `<opts>` should consume from the front of `tokens`.
///
/// Consumes hyphen-prefixed tokens as flags. A short flag consisting of only
/// one ASCII letter after the hyphen (e.g., `-n`) may take the next token as
/// its argument if that token is not hyphen-prefixed. Flags with more
/// characters (e.g., `-I{}`, `-0`, `--verbose`) are treated as self-contained.
/// The POSIX `--` end-of-options marker terminates scanning.
pub(super) fn consume_opts(tokens: &[&str]) -> usize {
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if !token.starts_with('-') {
            break;
        }
        // `--` is the POSIX end-of-options marker; consume it and stop.
        if token == "--" {
            i += 1;
            break;
        }
        i += 1;

        // A short flag like `-n` (single hyphen + single letter) may have a
        // separate argument. Only flags whose second character is an ASCII
        // letter qualify; flags like `-0` are self-contained and do not
        // consume the next token.
        let is_short_alpha = token.len() == 2
            && !token.starts_with("--")
            && token.as_bytes()[1].is_ascii_alphabetic();
        if is_short_alpha && i < tokens.len() && !tokens[i].starts_with('-') {
            i += 1;
        }
    }
    i
}

/// Remove elements at the given indices from a slice, returning a new Vec.
pub(super) fn remove_indices<'a>(tokens: &[&'a str], indices: &[usize]) -> Vec<&'a str> {
    tokens
        .iter()
        .enumerate()
        .filter(|(i, _)| !indices.contains(i))
        .map(|(_, &t)| t)
        .collect()
}
