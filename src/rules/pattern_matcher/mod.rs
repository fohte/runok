//! Pattern-to-command matching engine.
//!
//! Matches a [`Pattern`] against the raw tokens of a [`ParsedCommand`],
//! supporting wildcards, alternations, negations, optional groups,
//! and path-variable expansion via [`Definitions`].

mod flag_utils;
mod token_matching;

use std::cell::Cell;
use std::collections::HashSet;

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::command_parser::ParsedCommand;
use crate::rules::pattern_parser::{CommandPattern, Pattern, PatternToken};

use flag_utils::{is_flag_only_negation, optional_flags_absent, split_flag_equals};
use token_matching::{
    literal_matches, match_flag_token_with_equals, match_single_token, normalize_path,
    resolve_paths,
};

/// Maximum number of recursive steps allowed during pattern matching.
/// Prevents exponential blowup from patterns with multiple consecutive wildcards.
const MAX_MATCH_STEPS: usize = 10_000;

/// Collect all flag aliases from `FlagWithValue` tokens in the pattern token
/// list.  Used by the Literal matcher to identify value-flag tokens whose
/// values should also be skipped when searching for the first positional
/// argument in `cmd_tokens`.
fn collect_value_flag_aliases<'a>(tokens: &'a [PatternToken], aliases: &mut HashSet<&'a str>) {
    for token in tokens {
        if let PatternToken::FlagWithValue {
            aliases: flag_aliases,
            ..
        } = token
        {
            for a in flag_aliases {
                aliases.insert(a.as_str());
            }
        }
        if let PatternToken::Optional(inner) = token {
            collect_value_flag_aliases(inner, aliases);
        }
    }
}

/// Find the index of the first positional (non-flag) token in `cmd_tokens`,
/// skipping over flag tokens and their associated values based on
/// `value_flag_aliases`.  Returns `None` if no positional token is found.
fn find_first_positional(cmd_tokens: &[&str], value_flag_aliases: &HashSet<&str>) -> Option<usize> {
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

/// Compute the range of command-name token counts to try when matching.
///
/// For a wildcard command pattern, the command name may span 1..=N tokens,
/// so we return `1..=raw_tokens.len()` and include all raw tokens.
/// For literal/alternation patterns, the command name is always 1 token
/// (already matched), so we return `1..=1` and skip it.
///
/// Returns `(cmd_tokens, skip_range)` where `cmd_tokens` are the tokens
/// to match against and `skip_range` is the range of command-name lengths
/// to try.
fn prepare_wildcard_iteration<'a>(
    pattern: &Pattern,
    command: &'a ParsedCommand,
) -> (Vec<&'a str>, std::ops::RangeInclusive<usize>) {
    if matches!(pattern.command, CommandPattern::Wildcard) {
        let tokens = command.raw_tokens.iter().map(|s| s.as_str()).collect();
        let len = command.raw_tokens.len();
        (tokens, 1..=len)
    } else {
        let tokens = command.raw_tokens[1..].iter().map(|s| s.as_str()).collect();
        (tokens, 0..=0)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether `pattern` matches `command`.
///
/// Path references (`<path:name>`) are expanded using `definitions.paths`.
/// Returns `true` if any valid alignment of pattern tokens against
/// `command.raw_tokens` succeeds.
pub fn matches(pattern: &Pattern, command: &ParsedCommand, definitions: &Definitions) -> bool {
    if !pattern.command.matches(&command.command) {
        return false;
    }

    let (cmd_tokens, skip_range) = prepare_wildcard_iteration(pattern, command);
    for skip in skip_range {
        let steps = Cell::new(0usize);
        let after_dd = Cell::new(false);
        if match_engine(
            &pattern.tokens,
            &cmd_tokens[skip..],
            definitions,
            &steps,
            None,
            None,
            &after_dd,
        )
        .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Like `matches`, but also returns the tokens captured by wildcards (`*`).
///
/// Returns `Some(captured_tokens)` if the pattern matches, `None` otherwise.
pub fn matches_with_captures(
    pattern: &Pattern,
    command: &ParsedCommand,
    definitions: &Definitions,
) -> Option<Vec<String>> {
    if !pattern.command.matches(&command.command) {
        return None;
    }

    let (cmd_tokens, skip_range) = prepare_wildcard_iteration(pattern, command);
    for skip in skip_range {
        let steps = Cell::new(0usize);
        let after_dd = Cell::new(false);
        let mut captures = Vec::new();
        if match_engine(
            &pattern.tokens,
            &cmd_tokens[skip..],
            definitions,
            &steps,
            Some(&mut captures),
            None,
            &after_dd,
        )
        .unwrap_or(false)
        {
            return Some(captures.into_iter().map(|s| s.to_string()).collect());
        }
    }
    None
}

/// Try to match a wrapper pattern against a command and extract all possible
/// token sequences captured by the `<cmd>` placeholder.
///
/// Returns `Ok(candidates)` where each candidate is a possible set of tokens
/// for the `<cmd>` placeholder, ordered from shortest to longest capture.
/// Returns an empty `Vec` if the pattern does not match or has no `<cmd>` placeholder.
/// Returns `Err` if the wrapper pattern contains unsupported tokens
/// (`Optional` or `PathRef`).
pub fn extract_placeholder(
    pattern: &Pattern,
    command: &ParsedCommand,
    definitions: &Definitions,
) -> Result<Vec<Vec<String>>, RuleError> {
    if !pattern.command.matches(&command.command) {
        return Ok(Vec::new());
    }

    let (cmd_tokens, skip_range) = prepare_wildcard_iteration(pattern, command);
    let mut all_candidates: Vec<Vec<&str>> = Vec::new();
    for skip in skip_range {
        let steps = Cell::new(0usize);
        let after_dd = Cell::new(false);
        let mut captured = Vec::new();
        match_engine(
            &pattern.tokens,
            &cmd_tokens[skip..],
            definitions,
            &steps,
            None,
            Some((&mut captured, &mut all_candidates)),
            &after_dd,
        )?;
    }
    Ok(all_candidates
        .into_iter()
        .map(|c| c.into_iter().map(|s| s.to_string()).collect())
        .collect())
}

// ---------------------------------------------------------------------------
// Unified match engine
// ---------------------------------------------------------------------------

/// Unified recursive matching engine.
///
/// Operates in one of two mutually exclusive modes determined by `captures`
/// and `extract`. Callers must not pass `Some` for both simultaneously:
///
/// - **Boolean matching** (`extract` is `None`): returns `Ok(true)` on the
///   first successful match. When `captures` is `Some`, wildcard-matched
///   tokens are recorded.
///
/// - **Placeholder extraction** (`extract` is `Some`): collects all possible
///   `<cmd>` captures. The first element is the current captured tokens, the
///   second is the collection of all candidates. Always returns `Ok(false)`
///   on success (candidates are collected into `all_candidates`). `captures`
///   is ignored in this mode.
///
/// Returns `Err` if the pattern contains unsupported tokens for the current mode.
fn match_engine<'a>(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    mut captures: Option<&mut Vec<&'a str>>,
    mut extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
) -> Result<bool, RuleError> {
    let count = steps.get() + 1;
    steps.set(count);
    if count > MAX_MATCH_STEPS {
        return Ok(false);
    }

    let is_extract = extract.is_some();

    // Base case: pattern exhausted
    let Some((first, rest)) = pattern_tokens.split_first() else {
        if let Some((captured, all_candidates)) = extract {
            if cmd_tokens.is_empty() && !captured.is_empty() {
                all_candidates.push(captured.clone());
            }
            return Ok(false);
        }
        return Ok(cmd_tokens.is_empty());
    };

    match first {
        PatternToken::Wildcard => {
            for skip in 0..=cmd_tokens.len() {
                let saved_dd = after_double_dash.get();
                if let Some((captured, all_candidates)) = &mut extract {
                    match_engine(
                        rest,
                        &cmd_tokens[skip..],
                        definitions,
                        steps,
                        None,
                        Some((captured, all_candidates)),
                        after_double_dash,
                    )?;
                } else if let Some(caps) = &mut captures {
                    let saved_len = caps.len();
                    caps.extend_from_slice(&cmd_tokens[..skip]);
                    if match_engine(
                        rest,
                        &cmd_tokens[skip..],
                        definitions,
                        steps,
                        Some(*caps),
                        None,
                        after_double_dash,
                    )? {
                        return Ok(true);
                    }
                    caps.truncate(saved_len);
                } else if match_engine(
                    rest,
                    &cmd_tokens[skip..],
                    definitions,
                    steps,
                    None,
                    None,
                    after_double_dash,
                )? {
                    return Ok(true);
                }
                after_double_dash.set(saved_dd);
            }
            Ok(false)
        }

        PatternToken::Literal(s) => {
            if cmd_tokens.is_empty() {
                return Ok(false);
            }
            // After `--`, all tokens are positional — no flag skipping.
            // Also, flag-like literals (e.g. `-m` from parse_multi) remain
            // positional to avoid mismatches with value-flag arguments.
            let is_flag_literal = s.starts_with('-') && s.as_str() != "--";
            if after_double_dash.get() || is_flag_literal {
                if literal_matches(s, cmd_tokens[0]) {
                    return match_engine(
                        rest,
                        &cmd_tokens[1..],
                        definitions,
                        steps,
                        captures,
                        extract,
                        after_double_dash,
                    );
                }
                return Ok(false);
            }
            // When matching `--`, set the after_double_dash flag so that
            // subsequent Literal matches do not skip flag-like tokens.
            if s.as_str() == "--" {
                if cmd_tokens[0] == "--" {
                    after_double_dash.set(true);
                    return match_engine(
                        rest,
                        &cmd_tokens[1..],
                        definitions,
                        steps,
                        captures,
                        extract,
                        after_double_dash,
                    );
                }
                return Ok(false);
            }
            // Order-independent matching: skip over leading flag tokens
            // (and their values for known value-flags) to find the first
            // positional argument.  Only the matched positional token is
            // removed; skipped flag tokens are kept for later FlagWithValue
            // or flag-only Alternation matching.
            let mut value_aliases = HashSet::new();
            collect_value_flag_aliases(rest, &mut value_aliases);
            let Some(pos) = find_first_positional(cmd_tokens, &value_aliases) else {
                return Ok(false);
            };
            if literal_matches(s, cmd_tokens[pos]) {
                let remaining = remove_indices(cmd_tokens, &[pos]);
                match_engine(
                    rest,
                    &remaining,
                    definitions,
                    steps,
                    captures,
                    extract,
                    after_double_dash,
                )
            } else {
                Ok(false)
            }
        }

        PatternToken::QuotedLiteral(s) => {
            if cmd_tokens.is_empty() || s != cmd_tokens[0] {
                return Ok(false);
            }
            match_engine(
                rest,
                &cmd_tokens[1..],
                definitions,
                steps,
                captures,
                extract,
                after_double_dash,
            )
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return Ok(false);
            }

            // Flag-only alternations use order-independent matching (BoolMatch only).
            let is_flag_only = alts.iter().all(|a| a.starts_with('-') && a != "--");
            if is_flag_only && !is_extract {
                for i in 0..cmd_tokens.len() {
                    if alts.iter().any(|a| literal_matches(a, cmd_tokens[i])) {
                        let remaining = remove_indices(cmd_tokens, &[i]);
                        let saved_dd = after_double_dash.get();
                        if let Some(caps) = &mut captures {
                            let saved_len = caps.len();
                            if match_engine(
                                rest,
                                &remaining,
                                definitions,
                                steps,
                                Some(*caps),
                                None,
                                after_double_dash,
                            )? {
                                return Ok(true);
                            }
                            caps.truncate(saved_len);
                        } else if match_engine(
                            rest,
                            &remaining,
                            definitions,
                            steps,
                            None,
                            None,
                            after_double_dash,
                        )? {
                            return Ok(true);
                        }
                        after_double_dash.set(saved_dd);
                    }
                }
                return Ok(false);
            }

            // After `--`, or flag-only alternations in extract mode,
            // match positionally (no flag skipping).  Flag-only
            // alternations in extract mode must use positional matching
            // because `find_first_positional` would skip past the flag
            // token that the alternation is meant to consume (e.g.
            // `bash -c <cmd>` where `-c` is `Alternation(["-c"])`).
            if after_double_dash.get() || (is_flag_only && is_extract) {
                if alts.iter().any(|a| literal_matches(a, cmd_tokens[0])) {
                    return match_engine(
                        rest,
                        &cmd_tokens[1..],
                        definitions,
                        steps,
                        captures,
                        extract,
                        after_double_dash,
                    );
                }
                return Ok(false);
            }

            // Order-independent matching: skip over leading flag tokens
            // to find the first positional argument, consistent with
            // Literal matching.
            let mut value_aliases = HashSet::new();
            collect_value_flag_aliases(rest, &mut value_aliases);
            let Some(pos) = find_first_positional(cmd_tokens, &value_aliases) else {
                return Ok(false);
            };
            if alts.iter().any(|a| literal_matches(a, cmd_tokens[pos])) {
                let remaining = remove_indices(cmd_tokens, &[pos]);
                match_engine(
                    rest,
                    &remaining,
                    definitions,
                    steps,
                    captures,
                    extract,
                    after_double_dash,
                )
            } else {
                Ok(false)
            }
        }

        PatternToken::FlagWithValue { aliases, value } => {
            for i in 0..cmd_tokens.len() {
                // Case 1: space-separated flag and value (e.g. `--sort value`)
                if aliases.iter().any(|a| a.as_str() == cmd_tokens[i])
                    && i + 1 < cmd_tokens.len()
                    && match_single_token(value, cmd_tokens[i + 1], definitions)
                {
                    let remaining = remove_indices(cmd_tokens, &[i, i + 1]);
                    let capture_val =
                        matches!(**value, PatternToken::Wildcard).then_some(cmd_tokens[i + 1]);
                    let saved_dd = after_double_dash.get();
                    if try_recurse_flag_value(
                        rest,
                        &remaining,
                        definitions,
                        steps,
                        &mut captures,
                        &mut extract,
                        capture_val,
                        after_double_dash,
                    )? {
                        return Ok(true);
                    }
                    after_double_dash.set(saved_dd);
                }

                // Case 2: `=`-joined flag and value (e.g. `--sort=value`)
                if let Some((flag_part, value_part)) = split_flag_equals(cmd_tokens[i])
                    && aliases.iter().any(|a| a.as_str() == flag_part)
                    && match_single_token(value, value_part, definitions)
                {
                    let remaining = remove_indices(cmd_tokens, &[i]);
                    let capture_val =
                        matches!(**value, PatternToken::Wildcard).then_some(value_part);
                    let saved_dd = after_double_dash.get();
                    if try_recurse_flag_value(
                        rest,
                        &remaining,
                        definitions,
                        steps,
                        &mut captures,
                        &mut extract,
                        capture_val,
                        after_double_dash,
                    )? {
                        return Ok(true);
                    }
                    after_double_dash.set(saved_dd);
                }
            }
            Ok(false)
        }

        PatternToken::Negation(inner) => {
            if is_flag_only_negation(inner) {
                // Flag-only negations: scan all tokens for the forbidden flag.
                let negation_passed = !cmd_tokens
                    .iter()
                    .any(|t| match_flag_token_with_equals(inner, t, definitions));
                if negation_passed {
                    match_engine(
                        rest,
                        cmd_tokens,
                        definitions,
                        steps,
                        captures,
                        extract,
                        after_double_dash,
                    )
                } else {
                    Ok(false)
                }
            } else if after_double_dash.get() {
                // After `--`, match positionally (no flag skipping)
                if cmd_tokens.is_empty() {
                    return Ok(false);
                }
                let negation_passed = !match_single_token(inner, cmd_tokens[0], definitions);
                if negation_passed {
                    match_engine(
                        rest,
                        &cmd_tokens[1..],
                        definitions,
                        steps,
                        captures,
                        extract,
                        after_double_dash,
                    )
                } else {
                    Ok(false)
                }
            } else {
                if cmd_tokens.is_empty() {
                    return Ok(false);
                }
                // Order-independent: skip flags to find the first positional,
                // then check negation against it.
                let mut value_aliases = HashSet::new();
                collect_value_flag_aliases(rest, &mut value_aliases);
                let Some(pos) = find_first_positional(cmd_tokens, &value_aliases) else {
                    return Ok(false);
                };
                let negation_passed = !match_single_token(inner, cmd_tokens[pos], definitions);
                if negation_passed {
                    let remaining = remove_indices(cmd_tokens, &[pos]);
                    match_engine(
                        rest,
                        &remaining,
                        definitions,
                        steps,
                        captures,
                        extract,
                        after_double_dash,
                    )
                } else {
                    Ok(false)
                }
            }
        }

        PatternToken::Optional(inner_tokens) => {
            if is_extract {
                return Err(RuleError::UnsupportedWrapperToken(
                    "Optional ([...])".into(),
                ));
            }
            // Try matching with the optional tokens present
            let combined: Vec<PatternToken> = inner_tokens
                .iter()
                .cloned()
                .chain(rest.iter().cloned())
                .collect();
            let saved_dd = after_double_dash.get();
            // extract is always None here (early return above for is_extract)
            if let Some(caps) = &mut captures {
                let saved_len = caps.len();
                if match_engine(
                    &combined,
                    cmd_tokens,
                    definitions,
                    steps,
                    Some(*caps),
                    None,
                    after_double_dash,
                )? {
                    return Ok(true);
                }
                caps.truncate(saved_len);
            } else if match_engine(
                &combined,
                cmd_tokens,
                definitions,
                steps,
                None,
                None,
                after_double_dash,
            )? {
                return Ok(true);
            }
            after_double_dash.set(saved_dd);
            // Try without the optional tokens
            if optional_flags_absent(inner_tokens, cmd_tokens) {
                return match_engine(
                    rest,
                    cmd_tokens,
                    definitions,
                    steps,
                    captures,
                    None,
                    after_double_dash,
                );
            }
            Ok(false)
        }

        PatternToken::PathRef(name) => {
            if is_extract {
                return Err(RuleError::UnsupportedWrapperToken(format!(
                    "PathRef (<path:{name}>)"
                )));
            }
            if cmd_tokens.is_empty() {
                return Ok(false);
            }
            let paths = resolve_paths(name, definitions);
            let normalized_cmd = normalize_path(cmd_tokens[0]);
            if paths.iter().any(|p| normalize_path(p) == normalized_cmd) {
                // extract is always None here (early return above for is_extract)
                match_engine(
                    rest,
                    &cmd_tokens[1..],
                    definitions,
                    steps,
                    captures,
                    None,
                    after_double_dash,
                )
            } else {
                Ok(false)
            }
        }

        PatternToken::Placeholder(name) => {
            if let Some((captured, all_candidates)) = &mut extract {
                // Wrapper placeholder extraction mode
                let is_cmd = name == "cmd";
                if rest.is_empty() {
                    if is_cmd {
                        if cmd_tokens.is_empty() {
                            return Ok(false);
                        }
                        let saved_len = captured.len();
                        captured.extend_from_slice(cmd_tokens);
                        all_candidates.push(captured.clone());
                        captured.truncate(saved_len);
                    } else if cmd_tokens.len() == 1 {
                        // Non-<cmd> placeholder at end consumes one token.
                        if !captured.is_empty() {
                            all_candidates.push(captured.clone());
                        }
                    }
                } else if !cmd_tokens.is_empty() {
                    for take in 1..=cmd_tokens.len() {
                        let saved_len = captured.len();
                        if is_cmd {
                            captured.extend_from_slice(&cmd_tokens[..take]);
                        }
                        match_engine(
                            rest,
                            &cmd_tokens[take..],
                            definitions,
                            steps,
                            None,
                            Some((captured, all_candidates)),
                            after_double_dash,
                        )?;
                        captured.truncate(saved_len);
                    }
                }
                Ok(false)
            } else {
                // Boolean matching: placeholder consumes one token
                if cmd_tokens.is_empty() {
                    return Ok(false);
                }
                match_engine(
                    rest,
                    &cmd_tokens[1..],
                    definitions,
                    steps,
                    captures,
                    None,
                    after_double_dash,
                )
            }
        }

        PatternToken::Opts => {
            let skip = consume_opts(cmd_tokens);
            match_engine(
                rest,
                &cmd_tokens[skip..],
                definitions,
                steps,
                captures,
                extract,
                after_double_dash,
            )
        }

        PatternToken::Vars => {
            let skip = consume_vars(cmd_tokens);
            match_engine(
                rest,
                &cmd_tokens[skip..],
                definitions,
                steps,
                captures,
                extract,
                after_double_dash,
            )
        }
    }
}

/// Helper for FlagWithValue: recurse with remaining tokens after removing
/// the matched flag+value, optionally capturing a wildcard value.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature plus capture_val"
)]
fn try_recurse_flag_value<'a>(
    rest: &[PatternToken],
    remaining: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    captures: &mut Option<&mut Vec<&'a str>>,
    extract: &mut Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    capture_val: Option<&'a str>,
    after_double_dash: &Cell<bool>,
) -> Result<bool, RuleError> {
    if let Some((captured, all_candidates)) = extract {
        match_engine(
            rest,
            remaining,
            definitions,
            steps,
            None,
            Some((captured, all_candidates)),
            after_double_dash,
        )?;
        // In extract mode, always continue scanning (don't return true)
        Ok(false)
    } else if let Some(caps) = captures {
        let saved_len = caps.len();
        if let Some(val) = capture_val {
            caps.push(val);
        }
        if match_engine(
            rest,
            remaining,
            definitions,
            steps,
            Some(*caps),
            None,
            after_double_dash,
        )? {
            return Ok(true);
        }
        caps.truncate(saved_len);
        Ok(false)
    } else {
        match_engine(
            rest,
            remaining,
            definitions,
            steps,
            None,
            None,
            after_double_dash,
        )
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Count how many tokens `<vars>` should consume from the front of `tokens`.
///
/// Consumes consecutive tokens that contain `=` (i.e., `KEY=VALUE` style
/// environment variable assignments). Stops at the first token without `=`.
fn consume_vars(tokens: &[&str]) -> usize {
    tokens.iter().take_while(|t| t.contains('=')).count()
}

/// Count how many tokens `<opts>` should consume from the front of `tokens`.
///
/// Consumes hyphen-prefixed tokens as flags. A short flag consisting of only
/// one ASCII letter after the hyphen (e.g., `-n`) may take the next token as
/// its argument if that token is not hyphen-prefixed. Flags with more
/// characters (e.g., `-I{}`, `-0`, `--verbose`) are treated as self-contained.
/// The POSIX `--` end-of-options marker terminates scanning.
fn consume_opts(tokens: &[&str]) -> usize {
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
fn remove_indices<'a>(tokens: &[&'a str], indices: &[usize]) -> Vec<&'a str> {
    tokens
        .iter()
        .enumerate()
        .filter(|(i, _)| !indices.contains(i))
        .map(|(_, &t)| t)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::command_parser::{FlagSchema, parse_command};
    use crate::rules::pattern_parser::parse as parse_pattern;
    use rstest::{fixture, rstest};
    use std::collections::{HashMap, HashSet};

    /// Helper: parse pattern and command, then check matching.
    fn check_match(pattern_str: &str, command_str: &str, definitions: &Definitions) -> bool {
        let pattern = parse_pattern(pattern_str).unwrap();
        let schema = build_schema_from_pattern(&pattern);
        let command = parse_command(command_str, &schema).unwrap();
        matches(&pattern, &command, definitions)
    }

    fn check_captures(
        pattern_str: &str,
        command_str: &str,
        definitions: &Definitions,
    ) -> Option<Vec<String>> {
        let pattern = parse_pattern(pattern_str).unwrap();
        let schema = build_schema_from_pattern(&pattern);
        let command = parse_command(command_str, &schema).unwrap();
        matches_with_captures(&pattern, &command, definitions)
    }

    /// Build a FlagSchema from a pattern's FlagWithValue tokens.
    fn build_schema_from_pattern(pattern: &Pattern) -> FlagSchema {
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

    #[fixture]
    fn empty_defs() -> Definitions {
        Definitions::default()
    }

    // ========================================
    // Simple literal matching
    // ========================================

    #[rstest]
    #[case::exact_match("git status", "git status", true)]
    #[case::exact_multi("git remote add origin", "git remote add origin", true)]
    #[case::command_mismatch("git status", "hg status", false)]
    #[case::too_few_args("git remote add", "git remote add origin", false)]
    #[case::too_many_args("git remote add origin", "git remote add", false)]
    #[case::command_only("git", "git", true)]
    #[case::command_only_mismatch("git", "git status", false)]
    fn simple_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // Order-independent literal matching
    // ========================================

    #[rstest]
    #[case::flag_before_literal("gh api -X GET *", "gh -X GET api /", true)]
    #[case::literal_at_normal_position("gh api -X GET *", "gh api -X GET /", true)]
    #[case::multiple_flags_before_literal("gh api -X GET *", "gh -X GET -v api /", true)]
    #[case::extra_flag_not_in_pattern_no_match(
        "git remote add origin",
        "git -v remote add origin",
        false
    )]
    #[case::double_dash_stays_positional("cmd foo -- bar", "cmd -- foo bar", false)]
    #[case::double_dash_at_correct_position("cmd foo -- bar", "cmd foo -- bar", true)]
    #[case::literal_mismatch_still_fails("gh api -X GET *", "gh -X GET issues /", false)]
    #[case::flag_literal_remains_positional("cmd -v status", "cmd status -v", false)]
    #[case::flag_after_double_dash_is_positional("cmd -- status *", "cmd -- -v status foo", false)]
    #[case::flag_not_consumed_means_no_match("rm /tmp/*", "rm -rf /tmp/foo", false)]
    #[case::flag_skip_leaves_flag_unconsumed("rm file", "rm -f file", false)]
    #[case::skipped_flag_consumed_by_wildcard("git [-C *] commit *", "git -v commit -m fix", true)]
    #[case::negation_bypass_with_flag("kubectl !describe *", "kubectl -v describe pods", false)]
    #[case::skipped_flag_unconsumed_without_wildcard("git [-C *] commit", "git -v commit", false)]
    fn order_independent_literal_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected,
            "pattern {pattern_str:?} vs command {command_str:?}",
        );
    }

    // ========================================
    // Alias / alternation matching
    // ========================================

    #[rstest]
    #[case::first_alt("git push main|master", "git push main", true)]
    #[case::second_alt("git push main|master", "git push master", true)]
    #[case::no_alt_match("git push main|master", "git push develop", false)]
    #[case::subcommand_alt("kubectl describe|get|list *", "kubectl get pods", true)]
    #[case::non_flag_alt_skips_flags("git push main|master *", "git push -v main origin", true)]
    #[case::non_flag_alt_skips_flags_second(
        "git push main|master *",
        "git push -v master origin",
        true
    )]
    #[case::non_flag_alt_after_double_dash_no_skip("cmd -- main|master", "cmd -- -v main", false)]
    fn alternation_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // Wildcard matching
    // ========================================

    #[rstest]
    #[case::trailing_wildcard("git push *", "git push origin main", true)]
    #[case::wildcard_zero("git push *", "git push", true)]
    #[case::wildcard_many("git *", "git remote add origin", true)]
    #[case::wildcard_with_flags("git push *", "git push --force origin", true)]
    #[case::middle_wildcard("git * status", "git -C /tmp status", true)]
    #[case::middle_wildcard_multi("git * status", "git -C /tmp --no-pager status", true)]
    fn wildcard_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // Negation matching
    // ========================================

    #[rstest]
    #[case::negation_matches("kubectl !describe *", "kubectl get pods", true)]
    #[case::negation_rejects("kubectl !describe *", "kubectl describe pods", false)]
    #[case::negation_alternation("kubectl !describe|get|list *", "kubectl delete pods", true)]
    #[case::negation_alternation_reject("kubectl !describe|get|list *", "kubectl get pods", false)]
    // Flag-only negation: order-independent matching
    #[case::flag_negation_rejects_at_end("find !-delete *", "find . -delete", false)]
    #[case::flag_negation_rejects_at_start("find !-delete *", "find -delete .", false)]
    #[case::flag_negation_allows_no_flag("find !-delete *", "find . -name foo", true)]
    #[case::flag_negation_alt_rejects(
        "find !-delete|-fprint|-fls *",
        "find . -type f -delete",
        false
    )]
    #[case::flag_negation_alt_allows(
        "find !-delete|-fprint|-fls *",
        "find . -type f -name foo",
        true
    )]
    // Flag-only negation with `=`-joined tokens
    #[case::flag_negation_rejects_equals_form("rg !--pre *", "rg --pre=pdftotext pattern", false)]
    #[case::flag_negation_allows_different_flag_equals(
        "rg !--pre *",
        "rg --color=always pattern",
        true
    )]
    #[case::flag_negation_alt_rejects_equals_form(
        "sort !-o|--output|--compress-program *",
        "sort --output=result.txt file.txt",
        false
    )]
    #[case::flag_negation_alt_allows_equals_different_flag(
        "sort !-o|--output|--compress-program *",
        "sort --reverse=true file.txt",
        true
    )]
    // Flag-only negation with empty command tokens (no arguments after command)
    #[case::flag_negation_empty_tokens_single("sort !-o *", "sort", true)]
    #[case::flag_negation_empty_tokens_alt("sort !-o|--output|--compress-program *", "sort", true)]
    #[case::flag_negation_empty_tokens_find("find !-delete *", "find", true)]
    // Positional negation with empty tokens should still be false
    #[case::positional_negation_empty_tokens("kubectl !describe *", "kubectl", false)]
    fn negation_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // FlagWithValue matching (order-independent)
    // ========================================

    #[rstest]
    #[case::flag_before_arg("curl -X|--request POST *", "curl -X POST https://example.com", true)]
    #[case::flag_after_arg("curl -X|--request POST *", "curl https://example.com -X POST", true)]
    #[case::long_alias(
        "curl -X|--request POST *",
        "curl --request POST https://example.com",
        true
    )]
    #[case::wrong_value("curl -X|--request POST *", "curl -X GET https://example.com", false)]
    #[case::missing_flag("curl -X|--request POST *", "curl https://example.com", false)]
    #[case::wildcard_value("curl -X|--request * *", "curl -X DELETE https://example.com", true)]
    #[case::bare_flag_before_arg("gh api -X GET *", "gh api -X GET repos/fohte/runok", true)]
    #[case::bare_flag_after_arg("gh api -X GET *", "gh api repos/fohte/runok -X GET", true)]
    #[case::bare_flag_wrong_value("gh api -X GET *", "gh api -X POST repos/fohte/runok", false)]
    #[case::bare_flag_missing("gh api -X GET *", "gh api repos/fohte/runok", false)]
    fn flag_with_value_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // Optional matching
    // ========================================

    #[rstest]
    #[case::with_optional_flag("rm [-f] *", "rm -f file.txt", true)]
    #[case::without_optional_flag("rm [-f] *", "rm file.txt", true)]
    #[case::optional_flag_with_value(
        "curl [-X|--request GET] *",
        "curl -X GET https://example.com",
        true
    )]
    #[case::optional_absent("curl [-X|--request GET] *", "curl https://example.com", true)]
    #[case::optional_wrong_value(
        "curl [-X|--request GET] *",
        "curl -X POST https://example.com",
        false
    )]
    #[case::optional_flag_with_value_after_arg(
        "curl [-X|--request GET] *",
        "curl https://example.com -X GET",
        true
    )]
    #[case::optional_dir("git [-C *] status", "git -C /tmp status", true)]
    #[case::optional_dir_absent("git [-C *] status", "git status", true)]
    // Multiple optional bare flags in any order
    #[case::optional_bare_flags_reversed(
        "curl [-s] [-X GET] *",
        "curl -X GET -s https://example.com",
        true
    )]
    #[case::optional_bare_flags_after_arg(
        "curl [-s] [-X GET] *",
        "curl https://example.com -X GET -s",
        true
    )]
    #[case::optional_bare_flags_interleaved(
        "curl [-s] [-X GET] *",
        "curl -X GET https://example.com -s",
        true
    )]
    #[case::optional_bare_flags_in_order(
        "curl [-s] [-X GET] *",
        "curl -s -X GET https://example.com",
        true
    )]
    #[case::optional_bare_flags_all_absent(
        "curl [-s] [-X GET] *",
        "curl https://example.com",
        true
    )]
    #[case::optional_bare_flags_only_s("curl [-s] [-X GET] *", "curl -s https://example.com", true)]
    #[case::optional_bare_flags_only_x(
        "curl [-s] [-X GET] *",
        "curl -X GET https://example.com",
        true
    )]
    // Wrong flag values must still be rejected
    #[case::optional_bare_flags_wrong_value_reversed(
        "curl [-s] [-X GET] *",
        "curl -X POST -s https://example.com",
        false
    )]
    #[case::optional_bare_flags_wrong_value_after_arg(
        "curl [-s] [-X GET] *",
        "curl https://example.com -X POST -s",
        false
    )]
    #[case::optional_bare_flags_wrong_value_interleaved(
        "curl [-s] [-X GET] *",
        "curl -X POST https://example.com -s",
        false
    )]
    // `=`-joined flag with value
    #[case::optional_flag_with_value_equals_joined(
        "git branch [--sort *]",
        "git branch --sort=-committerdate",
        true
    )]
    #[case::optional_flag_with_value_equals_joined_absent(
        "git branch [--sort *]",
        "git branch",
        true
    )]
    #[case::optional_flag_with_value_equals_joined_with_other_flags(
        "git branch [-a] [--sort *]",
        "git branch -a --sort=-committerdate",
        true
    )]
    #[case::optional_flag_with_value_equals_joined_specific_value(
        "curl [-X|--request GET] *",
        "curl -X=GET https://example.com",
        true
    )]
    #[case::optional_flag_with_value_equals_joined_wrong_value(
        "curl [-X|--request GET] *",
        "curl -X=POST https://example.com",
        false
    )]
    fn optional_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // PathRef expansion matching
    // ========================================

    #[test]
    fn path_ref_matches_listed_path() {
        let defs = Definitions {
            paths: Some(HashMap::from([(
                "sensitive".to_string(),
                vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()],
            )])),
            ..Default::default()
        };
        assert!(check_match(
            "cat <path:sensitive>",
            "cat /etc/passwd",
            &defs
        ));
        assert!(check_match(
            "cat <path:sensitive>",
            "cat /etc/shadow",
            &defs
        ));
    }

    #[test]
    fn path_ref_rejects_unlisted_path() {
        let defs = Definitions {
            paths: Some(HashMap::from([(
                "sensitive".to_string(),
                vec!["/etc/passwd".to_string()],
            )])),
            ..Default::default()
        };
        assert!(!check_match(
            "cat <path:sensitive>",
            "cat /tmp/file.txt",
            &defs
        ));
    }

    #[test]
    fn path_ref_undefined_name_never_matches() {
        let defs = empty_defs();
        assert!(!check_match(
            "cat <path:undefined>",
            "cat /etc/passwd",
            &defs
        ));
    }

    // ========================================
    // Wildcard command name matching
    // ========================================

    #[rstest]
    #[case::help_flag("* --help", "git --help", true)]
    #[case::version_flag("* --version", "node --version", true)]
    #[case::any_command_any_args("* *", "ls -la", true)]
    #[case::wildcard_only("*", "git", true)]
    #[case::wildcard_command_multi_word("*", "git status", true)]
    #[case::wildcard_command_flag_mismatch("* --help", "git --version", false)]
    #[case::wildcard_command_missing_flag("* --help", "git", false)]
    #[case::wildcard_help_multi_word("* --help", "git branch --help", true)]
    #[case::wildcard_help_three_words("* --help", "cargo test --help", true)]
    #[case::wildcard_help_deep_subcommand("* --help", "docker compose up --help", true)]
    #[case::wildcard_with_args_multi_word("* *", "git branch -a", true)]
    fn wildcard_command_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // Unmatched cases
    // ========================================

    #[rstest]
    #[case::different_command("git status", "hg status")]
    #[case::extra_args("git status", "git status --short")]
    #[case::missing_args("git push origin main", "git push origin")]
    fn no_match(#[case] pattern_str: &str, #[case] command_str: &str) {
        assert!(!check_match(pattern_str, command_str, &empty_defs()));
    }

    // ========================================
    // Negation as flag value
    // ========================================

    #[test]
    fn flag_with_negation_value() {
        // Pattern: deny curl with any method except GET
        assert!(check_match(
            "curl -X|--request !GET *",
            "curl -X POST https://example.com",
            &empty_defs()
        ));
        assert!(!check_match(
            "curl -X|--request !GET *",
            "curl -X GET https://example.com",
            &empty_defs()
        ));
    }

    // ========================================
    // Combined patterns
    // ========================================

    #[test]
    fn combined_optional_and_wildcard() {
        // git [-C *] [--no-pager] log *
        let pattern_str = "git [-C *] status";
        assert!(check_match(pattern_str, "git status", &empty_defs()));
        assert!(check_match(
            pattern_str,
            "git -C /tmp status",
            &empty_defs()
        ));
        assert!(check_match(
            pattern_str,
            "git -C /home/user/repo status",
            &empty_defs()
        ));
    }

    #[test]
    fn equals_joined_token() {
        assert!(check_match(
            "java -Denv=prod",
            "java -Denv=prod",
            &empty_defs()
        ));
        assert!(!check_match(
            "java -Denv=prod",
            "java -Denv=staging",
            &empty_defs()
        ));
    }

    // ========================================
    // Literal bracket command (`[`) matching
    // ========================================

    #[rstest]
    #[case::bracket_wildcard("[ *", "[ -f file ]", true)]
    #[case::bracket_exact_args("[ -f file ]", "[ -f file ]", true)]
    #[case::bracket_wildcard_no_args("[ *", "[ ]", true)]
    #[case::bracket_command_mismatch("[ *", "test -f file", false)]
    #[case::bracket_wrong_args("[ -f file ]", "[ -d dir ]", false)]
    fn bracket_command_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected
        );
    }

    // ========================================
    // Path normalization
    // ========================================

    #[rstest]
    #[case::dot_segment("cat /etc/./passwd", true)]
    #[case::dotdot_segment("cat /etc/../etc/passwd", true)]
    #[case::multiple_dots("cat /etc/./././passwd", true)]
    #[case::complex_traversal("cat /tmp/../etc/passwd", true)]
    #[case::unrelated_path("cat /tmp/file.txt", false)]
    fn path_ref_normalized(#[case] command_str: &str, #[case] expected: bool) {
        let defs = Definitions {
            paths: Some(HashMap::from([(
                "sensitive".to_string(),
                vec!["/etc/passwd".to_string()],
            )])),
            ..Default::default()
        };
        assert_eq!(
            check_match("cat <path:sensitive>", command_str, &defs),
            expected
        );
    }

    #[test]
    fn path_ref_definition_normalized() {
        // Definition itself contains non-canonical path
        let defs = Definitions {
            paths: Some(HashMap::from([(
                "sensitive".to_string(),
                vec!["/etc/./passwd".to_string()],
            )])),
            ..Default::default()
        };
        assert!(check_match(
            "cat <path:sensitive>",
            "cat /etc/passwd",
            &defs
        ));
    }

    // ========================================
    // Wildcard DoS prevention
    // ========================================

    #[test]
    fn wildcard_dos_terminates() {
        // Many consecutive wildcards against non-matching input would cause
        // exponential blowup without the step limit. This test verifies
        // that the matcher terminates quickly by returning false.
        let pattern_str = "cmd * * * * * * * * * * a";
        let command_str = "cmd b b b b b b b b b b b b b b b b b b b b";
        assert!(!check_match(pattern_str, command_str, &empty_defs()));
    }

    // ========================================
    // matches_with_captures tests
    // ========================================

    #[rstest]
    #[case::no_wildcard("git status", "git status", Some(vec![]))]
    #[case::single_wildcard("git *", "git status", Some(vec!["status".to_string()]))]
    #[case::wildcard_multiple_tokens(
        "git *",
        "git remote add origin",
        Some(vec!["remote".to_string(), "add".to_string(), "origin".to_string()])
    )]
    #[case::wildcard_in_optional(
        "git [-C *] status",
        "git -C /tmp status",
        Some(vec!["/tmp".to_string()])
    )]
    #[case::optional_absent_no_captures(
        "git [-C *] status",
        "git status",
        Some(vec![])
    )]
    #[case::no_match("git status", "ls -la", None)]
    #[case::different_command("git *", "ls -la", None)]
    #[case::wildcard_command_captures("* *", "git status", Some(vec!["status".to_string()]))]
    #[case::wildcard_command_no_args("*", "git", Some(vec![]))]
    fn matches_with_captures_returns_expected(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: Option<Vec<String>>,
        empty_defs: Definitions,
    ) {
        assert_eq!(
            check_captures(pattern_str, command_str, &empty_defs),
            expected
        );
    }

    // ========================================
    // <opts> matching in non-wrapper context
    // ========================================

    #[rstest]
    #[case::opts_consumes_flags("cmd <opts> arg", "cmd -v --debug arg", true)]
    #[case::opts_no_flags("cmd <opts> arg", "cmd arg", true)]
    #[case::opts_with_short_flag_value("cmd <opts> arg", "cmd -n 5 arg", true)]
    #[case::opts_mismatch_trailing("cmd <opts> arg", "cmd -v other", false)]
    #[case::opts_digit_flag_not_consuming("cmd <opts> arg", "cmd -0 arg", true)]
    #[case::opts_end_of_options_marker("cmd <opts> arg", "cmd -- arg", true)]
    #[case::opts_end_of_options_with_flags("cmd <opts> arg", "cmd -v -- arg", true)]
    fn opts_non_wrapper_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
        empty_defs: Definitions,
    ) {
        assert_eq!(check_match(pattern_str, command_str, &empty_defs), expected);
    }

    // ========================================
    // extract_placeholder tests
    // ========================================

    /// Helper: extract placeholder candidates from a wrapper pattern.
    fn check_extract(
        pattern_str: &str,
        command_str: &str,
        definitions: &Definitions,
    ) -> Vec<Vec<String>> {
        let pattern = parse_pattern(pattern_str).unwrap();
        let schema = build_schema_from_pattern(&pattern);
        let command = parse_command(command_str, &schema).unwrap();
        extract_placeholder(&pattern, &command, definitions).unwrap()
    }

    #[rstest]
    #[case::simple_placeholder(
        "sudo <cmd>",
        "sudo echo hello",
        vec![vec!["echo", "hello"]],
    )]
    #[case::literal_before_cmd(
        "run exec <cmd>",
        "run exec echo hello",
        vec![vec!["echo", "hello"]],
    )]
    #[case::wildcard_before_cmd(
        "xargs * <cmd>",
        "xargs -I{} echo hello",
        // Wildcard tries skip=0,1,2: all produce candidates
        vec![vec!["-I{}", "echo", "hello"], vec!["echo", "hello"], vec!["hello"]],
    )]
    #[case::no_match(
        "sudo <cmd>",
        "bash echo hello",
        Vec::<Vec<&str>>::new(),
    )]
    #[case::opts_before_cmd(
        "xargs <opts> <cmd>",
        "xargs -0 -I{} echo hello",
        vec![vec!["echo", "hello"]],
    )]
    #[case::negation_before_cmd(
        "run !--dry-run <cmd>",
        "run --verbose echo hello",
        vec![vec!["--verbose", "echo", "hello"]],
    )]
    #[case::positional_negation_before_cmd(
        "run !exec <cmd>",
        "run start echo hello",
        vec![vec!["echo", "hello"]],
    )]
    #[case::positional_negation_empty_tokens(
        "run !exec <cmd>",
        "run",
        Vec::<Vec<&str>>::new(),
    )]
    #[case::flag_negation_empty_tokens_before_cmd(
        "run !--dry-run <cmd>",
        "run",
        Vec::<Vec<&str>>::new(),
    )]
    #[case::flag_negation_rejected_before_cmd(
        "run !--dry-run <cmd>",
        "run --dry-run echo hello",
        Vec::<Vec<&str>>::new(),
    )]
    #[case::positional_negation_rejected_before_cmd(
        "run !exec <cmd>",
        "run exec echo hello",
        Vec::<Vec<&str>>::new(),
    )]
    fn extract_placeholder_cases(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: Vec<Vec<&str>>,
        empty_defs: Definitions,
    ) {
        let result = check_extract(pattern_str, command_str, &empty_defs);
        let expected: Vec<Vec<String>> = expected
            .into_iter()
            .map(|v| v.into_iter().map(|s| s.to_string()).collect())
            .collect();
        assert_eq!(result, expected);
    }

    #[rstest]
    fn extract_placeholder_bash_c(empty_defs: Definitions) {
        // First test: flag-like literal -c before <cmd>
        let result = check_extract("bash -c <cmd>", "bash -c 'rm -rf /'", &empty_defs);
        assert_eq!(result, vec![vec!["rm -rf /".to_string()]]);
    }

    #[rstest]
    fn extract_placeholder_flag_like_literal(empty_defs: Definitions) {
        // Simpler test: flag-like literal before non-cmd placeholder
        let result = check_extract("run -v <cmd>", "run -v echo hello", &empty_defs);
        assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
    }

    #[rstest]
    fn extract_placeholder_with_alternation(empty_defs: Definitions) {
        // Alternation token before <cmd>
        let result = check_extract("run fast|slow <cmd>", "run fast echo hello", &empty_defs);
        assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
    }

    #[rstest]
    #[case::space_separated("run -m debug echo hello")]
    #[case::equals_joined("run -m=debug echo hello")]
    fn extract_placeholder_with_flag_with_value(
        #[case] command_str: &str,
        empty_defs: Definitions,
    ) {
        let result = check_extract("run -m|--mode debug <cmd>", command_str, &empty_defs);
        assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
    }

    #[rstest]
    fn extract_placeholder_with_non_cmd_trailing(empty_defs: Definitions) {
        // Pattern with <cmd> followed by a non-<cmd> placeholder at the end.
        // The non-<cmd> placeholder consumes one token, <cmd> captures the rest.
        let result = check_extract("wrap <cmd> <suffix>", "wrap echo hello world", &empty_defs);
        // <cmd> tries take=1 ("echo"), take=2 ("echo hello") — for each,
        // <suffix> must consume exactly the remaining single token.
        // take=1: <cmd>=["echo"], <suffix> gets ["hello", "world"] -> 2 tokens, doesn't match
        // take=2: <cmd>=["echo", "hello"], <suffix> gets ["world"] -> 1 token, matches
        assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
    }

    #[rstest]
    fn extract_placeholder_cmd_followed_by_literal(empty_defs: Definitions) {
        // <cmd> in middle position followed by a literal sentinel.
        // Exercises the base case where captured is non-empty.
        let result = check_extract("wrap <cmd> done", "wrap echo hello done", &empty_defs);
        assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
    }

    // ========================================
    // Multi-word alternation matching
    // ========================================

    /// Helper: parse pattern with parse_multi, then check if any expanded pattern matches.
    fn check_multi_match(pattern_str: &str, command_str: &str, definitions: &Definitions) -> bool {
        use crate::rules::pattern_parser::parse_multi;

        let patterns = parse_multi(pattern_str).unwrap();
        for pattern in &patterns {
            let schema = build_schema_from_pattern(pattern);
            let command = parse_command(command_str, &schema).unwrap();
            if matches(pattern, &command, definitions) {
                return true;
            }
        }
        false
    }

    #[rstest]
    #[case::npx_variant(r#""npx prettier"|prettier *"#, "npx prettier --write .", true)]
    #[case::bare_variant(r#""npx prettier"|prettier *"#, "prettier --write .", true)]
    #[case::no_match_different_runner(
        r#""npx prettier"|prettier *"#,
        "yarn prettier --write .",
        false
    )]
    #[case::no_match_different_tool(r#""npx prettier"|prettier *"#, "npx eslint --fix .", false)]
    #[case::three_alternatives_first(
        r#""npx prettier"|"bunx prettier"|prettier *"#,
        "npx prettier --write .",
        true
    )]
    #[case::three_alternatives_second(
        r#""npx prettier"|"bunx prettier"|prettier *"#,
        "bunx prettier --write .",
        true
    )]
    #[case::three_alternatives_third(
        r#""npx prettier"|"bunx prettier"|prettier *"#,
        "prettier --write .",
        true
    )]
    #[case::python_pytest_module(r#""python -m pytest"|pytest *"#, "python -m pytest tests/", true)]
    #[case::python_pytest_bare(r#""python -m pytest"|pytest *"#, "pytest tests/", true)]
    #[case::python_pytest_no_match(r#""python -m pytest"|pytest *"#, "python -m mypy", false)]
    fn multi_word_alternation_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_multi_match(pattern_str, command_str, &empty_defs()),
            expected,
            "pattern {pattern_str:?} vs command {command_str:?}",
        );
    }

    #[rstest]
    #[case::backward_compat_first("ast-grep|sg scan *", "ast-grep scan foo", true)]
    #[case::backward_compat_second("ast-grep|sg scan *", "sg scan foo", true)]
    #[case::backward_compat_no_match("ast-grep|sg scan *", "rg scan foo", false)]
    fn multi_word_alternation_backward_compat(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_multi_match(pattern_str, command_str, &empty_defs()),
            expected,
        );
    }

    // === Alternation with glob wildcard matching ===

    #[rstest]
    #[case::glob_alt_match(
        "kubectl describe|get|list-* *",
        "kubectl list-buckets my-bucket",
        true
    )]
    #[case::glob_alt_exact_still_works(
        "kubectl describe|get|list-* *",
        "kubectl describe my-pod",
        true
    )]
    #[case::glob_alt_no_match("kubectl describe|get|list-* *", "kubectl delete my-pod", false)]
    #[case::glob_alt_list_instances(
        "aws * describe-*|get-*|list-* *",
        "aws ec2 list-instances --region us-east-1",
        true
    )]
    #[case::glob_alt_describe_prefix(
        "aws * describe-*|get-*|list-* *",
        "aws ec2 describe-instances --region us-east-1",
        true
    )]
    fn alternation_glob_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected,
            "pattern {pattern_str:?} vs command {command_str:?}",
        );
    }

    // === Negation alternation with glob wildcard ===

    #[rstest]
    #[case::negated_glob_blocks_match(
        "kubectl !describe|get|list-* *",
        "kubectl list-pods my-pod",
        false
    )]
    #[case::negated_glob_allows_non_match(
        "kubectl !describe|get|list-* *",
        "kubectl delete my-pod",
        true
    )]
    #[case::negated_glob_blocks_exact(
        "kubectl !describe|get|list-* *",
        "kubectl describe my-pod",
        false
    )]
    #[case::negated_glob_blocks_exact_get(
        "kubectl !describe|get|list-* *",
        "kubectl get pods",
        false
    )]
    fn negation_alternation_glob_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected,
            "pattern {pattern_str:?} vs command {command_str:?}",
        );
    }

    // === Literal token with glob wildcard ===

    #[rstest]
    #[case::literal_glob_prefix("aws ssm get-* *", "aws ssm get-parameter --name foo", true)]
    #[case::literal_glob_no_match("aws ssm get-* *", "aws ssm put-parameter --name foo", false)]
    #[case::literal_glob_exact_still_works(
        "aws ssm get-parameter *",
        "aws ssm get-parameter --name foo",
        true
    )]
    #[case::literal_glob_suffix("cmd *.txt", "cmd readme.txt", true)]
    #[case::literal_glob_suffix_no_match("cmd *.txt", "cmd readme.md", false)]
    #[case::literal_glob_middle("cmd foo*bar", "cmd fooXbar", true)]
    #[case::literal_glob_middle_no_match("cmd foo*bar", "cmd fooXbaz", false)]
    #[case::negated_literal_glob_blocks(
        "aws ssm !get-* *",
        "aws ssm get-parameter --name foo",
        false
    )]
    #[case::negated_literal_glob_allows(
        "aws ssm !get-* *",
        "aws ssm put-parameter --name foo",
        true
    )]
    fn literal_glob_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected,
            "pattern {pattern_str:?} vs command {command_str:?}",
        );
    }

    // === Double-dash (--) positional matching ===

    #[rstest]
    #[case::double_dash_exact("git checkout -- *", "git checkout -- README.md", true)]
    #[case::double_dash_multiple_files(
        "git checkout -- *",
        "git checkout -- README.md docs/index.md",
        true
    )]
    #[case::double_dash_with_optional_c(
        "git [-C *] checkout -- *",
        "git checkout -- README.md",
        true
    )]
    #[case::double_dash_with_optional_c_present(
        "git [-C *] checkout -- *",
        "git -C /tmp checkout -- README.md",
        true
    )]
    #[case::double_dash_rejects_args_before(
        "git [-C *] checkout -- *",
        "git checkout HEAD~1 -- README.md",
        false
    )]
    #[case::double_dash_rejects_no_separator("git checkout -- *", "git checkout HEAD~1", false)]
    fn double_dash_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected,
            "pattern {pattern_str:?} vs command {command_str:?}",
        );
    }

    // === Quoted literal with `*` (no glob) ===

    #[rstest]
    #[case::quoted_star_exact_match(r#"git commit -m "WIP*""#, "git commit -m WIP*", true)]
    #[case::quoted_star_no_glob(r#"git commit -m "WIP*""#, "git commit -m WIPfoo", false)]
    #[case::quoted_star_only(r#"cmd "*""#, "cmd *", true)]
    #[case::quoted_star_only_no_glob(r#"cmd "*""#, "cmd hello", false)]
    fn quoted_literal_matching(
        #[case] pattern_str: &str,
        #[case] command_str: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            check_match(pattern_str, command_str, &empty_defs()),
            expected,
            "pattern {pattern_str:?} vs command {command_str:?}",
        );
    }
}
