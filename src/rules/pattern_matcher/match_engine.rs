//! Unified recursive pattern-matching engine.
//!
//! Implements the core backtracking algorithm that walks a pattern's tokens
//! against a command's tokens, handling wildcards, alternations, negations,
//! optional groups, flag groups, and variable/path references.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::pattern_parser::{CommandPattern, PatternToken};

use super::flag_utils::{
    is_flag_only_negation, optional_flags_absent, split_flag_equals, split_short_flag_value,
};
use super::token_matching::{
    self, literal_matches, match_flag_token_with_equals, match_single_token, normalize_path,
    resolve_paths,
};

/// Maximum number of recursive steps allowed during pattern matching.
/// Prevents exponential blowup from patterns with multiple consecutive wildcards.
const MAX_MATCH_STEPS: usize = 10_000;

/// Collect all flag aliases from `FlagWithValue` and `FlagGroupRef` tokens in
/// the pattern token list.  Used by the Literal matcher to identify value-flag
/// tokens whose values should also be skipped when searching for the first
/// positional argument in `cmd_tokens`.
fn collect_value_flag_aliases(
    tokens: &[PatternToken],
    definitions: &Definitions,
    aliases: &mut HashSet<String>,
) {
    for token in tokens {
        match token {
            PatternToken::FlagWithValue {
                aliases: flag_aliases,
                ..
            } => {
                for a in flag_aliases {
                    aliases.insert(a.clone());
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
                        aliases.insert(a.clone());
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
fn find_first_positional(
    cmd_tokens: &[&str],
    value_flag_aliases: &HashSet<String>,
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

/// Run the match engine in boolean mode for the prefix-consumption test
/// used by pattern-typed `<var:name>` sub-patterns. Returns `true` when
/// `pattern_tokens` exactly consumes `cmd_tokens`.
///
/// Exposed to the `token_matching` submodule via `pub(super)` so that
/// `match_pattern_prefix` can probe consumption lengths without exposing
/// the full `match_engine` signature.
pub(super) fn match_engine_for_prefix_test(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
) -> Result<bool, RuleError> {
    match_engine(
        pattern_tokens,
        cmd_tokens,
        definitions,
        steps,
        None,
        None,
        after_double_dash,
        var_captures,
        flag_group_captures,
    )
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
#[expect(
    clippy::too_many_arguments,
    reason = "recursive engine needs all context threaded through"
)]
pub(super) fn match_engine<'a>(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    mut captures: Option<&mut Vec<&'a str>>,
    mut extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
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
                let saved_vc = var_captures.borrow().clone();
                if let Some((captured, all_candidates)) = &mut extract {
                    match_engine(
                        rest,
                        &cmd_tokens[skip..],
                        definitions,
                        steps,
                        None,
                        Some((captured, all_candidates)),
                        after_double_dash,
                        var_captures,
                        flag_group_captures,
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
                        var_captures,
                        flag_group_captures,
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
                    var_captures,
                    flag_group_captures,
                )? {
                    return Ok(true);
                }
                after_double_dash.set(saved_dd);
                *var_captures.borrow_mut() = saved_vc;
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
                        var_captures,
                        flag_group_captures,
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
                        var_captures,
                        flag_group_captures,
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
            collect_value_flag_aliases(rest, definitions, &mut value_aliases);
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
                    var_captures,
                    flag_group_captures,
                )
            } else {
                Ok(false)
            }
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return Ok(false);
            }

            let has_any_flag = alts.iter().any(|a| a.starts_with('-') && a != "--");

            // Alternations containing flag alternatives scan all tokens
            // (order-independent) so that flag-like tokens such as `-v`
            // can be matched regardless of position.  In extract mode
            // (wrapper placeholder extraction), positional matching is
            // used instead because the flag token must stay at position 0
            // for Placeholder capture to work correctly (e.g. `bash -c <cmd>`).
            if has_any_flag && !is_extract {
                for i in 0..cmd_tokens.len() {
                    // Direct match: e.g. `--output` matches `--output`
                    if alts.iter().any(|a| literal_matches(a, cmd_tokens[i])) {
                        let remaining = remove_indices(cmd_tokens, &[i]);
                        let saved_dd = after_double_dash.get();
                        let saved_vc = var_captures.borrow().clone();
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
                                var_captures,
                                flag_group_captures,
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
                            var_captures,
                            flag_group_captures,
                        )? {
                            return Ok(true);
                        }
                        after_double_dash.set(saved_dd);
                        *var_captures.borrow_mut() = saved_vc;
                    }

                    // `=`-joined match: e.g. `--output=/tmp/out` where
                    // `--output` matches an alternative. The value part
                    // is kept as a separate token for subsequent matching.
                    if let Some((flag_part, value_part)) = split_flag_equals(cmd_tokens[i])
                        && alts.iter().any(|a| literal_matches(a, flag_part))
                    {
                        let mut remaining = remove_indices(cmd_tokens, &[i]);
                        remaining.insert(i.min(remaining.len()), value_part);
                        let saved_dd = after_double_dash.get();
                        let saved_vc = var_captures.borrow().clone();
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
                                var_captures,
                                flag_group_captures,
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
                            var_captures,
                            flag_group_captures,
                        )? {
                            return Ok(true);
                        }
                        after_double_dash.set(saved_dd);
                        *var_captures.borrow_mut() = saved_vc;
                    }
                }
                return Ok(false);
            }

            // After `--`, or flag-containing alternations in extract
            // mode, match positionally (no flag skipping).
            if after_double_dash.get() || (has_any_flag && is_extract) {
                if alts.iter().any(|a| literal_matches(a, cmd_tokens[0])) {
                    return match_engine(
                        rest,
                        &cmd_tokens[1..],
                        definitions,
                        steps,
                        captures,
                        extract,
                        after_double_dash,
                        var_captures,
                        flag_group_captures,
                    );
                }
                return Ok(false);
            }

            // Non-flag alternations: skip over leading flag tokens to
            // find the first positional argument, consistent with
            // Literal matching.
            let mut value_aliases = HashSet::new();
            collect_value_flag_aliases(rest, definitions, &mut value_aliases);
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
                    var_captures,
                    flag_group_captures,
                )
            } else {
                Ok(false)
            }
        }

        PatternToken::FlagGroupRef { name } => {
            // Look up the pre-parsed flag group from the cache. If the group
            // is undefined (or was never resolved), the pattern matches
            // nothing — same policy as undefined `<path:name>` and
            // `<var:name>` references.
            let Some(parsed) = definitions
                .parsed_flag_groups
                .as_ref()
                .and_then(|g| g.get(name))
                .cloned()
            else {
                return Ok(false);
            };

            let aliases = &parsed.aliases;

            // Collect every command token that matches any alias, capturing
            // each occurrence's value into `flag_group_captures[name]`. We
            // greedily consume all matching occurrences (rather than only
            // the first) so that `when` clauses can inspect every value.
            let mut matched_indices: Vec<usize> = Vec::new();
            let mut captured_values: Vec<String> = Vec::new();

            match &parsed.value_pattern {
                Some(value) => {
                    // Value flag: capture flag + value pairs
                    for i in 0..cmd_tokens.len() {
                        let token = cmd_tokens[i];

                        // Case 1: space-separated flag and value (e.g. `-f value`)
                        if aliases.iter().any(|a| a.as_str() == token)
                            && i + 1 < cmd_tokens.len()
                            && match_single_token(value, cmd_tokens[i + 1], definitions)
                        {
                            if matched_indices.contains(&i) || matched_indices.contains(&(i + 1)) {
                                continue;
                            }
                            matched_indices.push(i);
                            matched_indices.push(i + 1);
                            captured_values.push(cmd_tokens[i + 1].to_string());
                            continue;
                        }

                        // Case 2: `=`-joined flag and value (e.g. `--field=value`)
                        if let Some((flag_part, value_part)) = split_flag_equals(token)
                            && aliases.iter().any(|a| a.as_str() == flag_part)
                            && match_single_token(value, value_part, definitions)
                        {
                            if matched_indices.contains(&i) {
                                continue;
                            }
                            matched_indices.push(i);
                            captured_values.push(value_part.to_string());
                            continue;
                        }

                        // Case 3: fused short flag and value (e.g. `-fvalue`)
                        if let Some((_flag_part, value_part)) =
                            split_short_flag_value(token, aliases)
                            && match_single_token(value, value_part, definitions)
                        {
                            if matched_indices.contains(&i) {
                                continue;
                            }
                            matched_indices.push(i);
                            captured_values.push(value_part.to_string());
                        }
                    }
                }
                None => {
                    // Bool flag: capture flag presence only
                    for (i, &token) in cmd_tokens.iter().enumerate() {
                        if aliases.iter().any(|a| a.as_str() == token)
                            && !matched_indices.contains(&i)
                        {
                            matched_indices.push(i);
                            captured_values.push(String::new());
                        }
                    }
                }
            }

            // The placeholder behaves like a flag alternation: at least one
            // occurrence must be present for the pattern to match.
            if captured_values.is_empty() {
                return Ok(false);
            }

            // Record captured values into the per-attempt flag-group map.
            let saved_fg = flag_group_captures.borrow().clone();
            flag_group_captures
                .borrow_mut()
                .entry(name.clone())
                .or_default()
                .extend(captured_values);

            matched_indices.sort_unstable();
            let remaining = remove_indices(cmd_tokens, &matched_indices);

            let saved_dd = after_double_dash.get();
            let saved_vc = var_captures.borrow().clone();
            let result = match_engine(
                rest,
                &remaining,
                definitions,
                steps,
                captures,
                extract,
                after_double_dash,
                var_captures,
                flag_group_captures,
            );
            if !matches!(result, Ok(true)) {
                // Restore on failure so that backtracking does not retain
                // partial captures from a non-matching alternative.
                after_double_dash.set(saved_dd);
                *var_captures.borrow_mut() = saved_vc;
                *flag_group_captures.borrow_mut() = saved_fg;
            }
            result
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
                    let saved_vc = var_captures.borrow().clone();
                    if try_recurse_flag_value(
                        rest,
                        &remaining,
                        definitions,
                        steps,
                        &mut captures,
                        &mut extract,
                        capture_val,
                        after_double_dash,
                        var_captures,
                        flag_group_captures,
                    )? {
                        return Ok(true);
                    }
                    after_double_dash.set(saved_dd);
                    *var_captures.borrow_mut() = saved_vc;
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
                    let saved_vc = var_captures.borrow().clone();
                    if try_recurse_flag_value(
                        rest,
                        &remaining,
                        definitions,
                        steps,
                        &mut captures,
                        &mut extract,
                        capture_val,
                        after_double_dash,
                        var_captures,
                        flag_group_captures,
                    )? {
                        return Ok(true);
                    }
                    after_double_dash.set(saved_dd);
                    *var_captures.borrow_mut() = saved_vc;
                }

                // Case 3: fused short flag and value (e.g. `-n3` for `-n *`)
                if let Some((_flag_part, value_part)) =
                    split_short_flag_value(cmd_tokens[i], aliases)
                    && match_single_token(value, value_part, definitions)
                {
                    let remaining = remove_indices(cmd_tokens, &[i]);
                    let capture_val =
                        matches!(**value, PatternToken::Wildcard).then_some(value_part);
                    let saved_dd = after_double_dash.get();
                    let saved_vc = var_captures.borrow().clone();
                    if try_recurse_flag_value(
                        rest,
                        &remaining,
                        definitions,
                        steps,
                        &mut captures,
                        &mut extract,
                        capture_val,
                        after_double_dash,
                        var_captures,
                        flag_group_captures,
                    )? {
                        return Ok(true);
                    }
                    after_double_dash.set(saved_dd);
                    *var_captures.borrow_mut() = saved_vc;
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
                        var_captures,
                        flag_group_captures,
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
                        var_captures,
                        flag_group_captures,
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
                collect_value_flag_aliases(rest, definitions, &mut value_aliases);
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
                        var_captures,
                        flag_group_captures,
                    )
                } else {
                    Ok(false)
                }
            }
        }

        PatternToken::Optional(inner_tokens) => {
            // Try matching with the optional tokens present
            let combined: Vec<PatternToken> = inner_tokens
                .iter()
                .cloned()
                .chain(rest.iter().cloned())
                .collect();
            let saved_dd = after_double_dash.get();
            let saved_vc = var_captures.borrow().clone();
            if let Some((captured, all_candidates)) = &mut extract {
                // Extract mode: enumerate both interpretations into
                // `all_candidates` without early return so that the wrapper
                // engine can compare candidates by action priority.
                match_engine(
                    &combined,
                    cmd_tokens,
                    definitions,
                    steps,
                    None,
                    Some((captured, all_candidates)),
                    after_double_dash,
                    var_captures,
                    flag_group_captures,
                )?;
                after_double_dash.set(saved_dd);
                *var_captures.borrow_mut() = saved_vc.clone();
                if optional_flags_absent(inner_tokens, cmd_tokens) {
                    match_engine(
                        rest,
                        cmd_tokens,
                        definitions,
                        steps,
                        None,
                        Some((captured, all_candidates)),
                        after_double_dash,
                        var_captures,
                        flag_group_captures,
                    )?;
                    after_double_dash.set(saved_dd);
                    *var_captures.borrow_mut() = saved_vc;
                }
                return Ok(false);
            }
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
                    var_captures,
                    flag_group_captures,
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
                var_captures,
                flag_group_captures,
            )? {
                return Ok(true);
            }
            after_double_dash.set(saved_dd);
            *var_captures.borrow_mut() = saved_vc;
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
                    var_captures,
                    flag_group_captures,
                );
            }
            Ok(false)
        }

        PatternToken::PathRef(name) => {
            if cmd_tokens.is_empty() {
                return Ok(false);
            }
            let paths = resolve_paths(name, definitions);
            let normalized_cmd = normalize_path(cmd_tokens[0]);
            if paths.iter().any(|p| normalize_path(p) == normalized_cmd) {
                match_engine(
                    rest,
                    &cmd_tokens[1..],
                    definitions,
                    steps,
                    captures,
                    extract,
                    after_double_dash,
                    var_captures,
                    flag_group_captures,
                )
            } else {
                Ok(false)
            }
        }

        PatternToken::VarRef(name) => {
            if cmd_tokens.is_empty() {
                return Ok(false);
            }
            // Pattern-typed var: inline-expand each parsed sub-pattern in
            // place of `<var:name>`. The sub-pattern's command name consumes
            // the next command token, and its tokens are spliced before the
            // outer pattern's remaining tokens before recursing.
            if let Some(sub_patterns) = definitions
                .parsed_pattern_vars
                .as_ref()
                .and_then(|m| m.get(name))
                && !sub_patterns.is_empty()
            {
                for sub in sub_patterns {
                    let head_consumed = match &sub.command {
                        CommandPattern::Literal(s) => {
                            if token_matching::literal_matches(s, cmd_tokens[0]) {
                                Some(1usize)
                            } else {
                                None
                            }
                        }
                        CommandPattern::Alternation(alts) => alts
                            .iter()
                            .any(|a| token_matching::literal_matches(a, cmd_tokens[0]))
                            .then_some(1),
                        CommandPattern::Wildcard => Some(1),
                        // Pattern-typed var values may not nest a `<var:>` at
                        // the command position; rejected by config validation.
                        CommandPattern::VarRef(_) => None,
                    };
                    let Some(head) = head_consumed else { continue };

                    let combined: Vec<PatternToken> = sub
                        .tokens
                        .iter()
                        .cloned()
                        .chain(rest.iter().cloned())
                        .collect();

                    let saved_dd = after_double_dash.get();
                    let saved_vc = var_captures.borrow().clone();
                    let saved_fg = flag_group_captures.borrow().clone();
                    var_captures
                        .borrow_mut()
                        .insert(name.clone(), cmd_tokens[0].to_string());

                    // `match_engine` itself truncates `caps` on failure (see
                    // the Wildcard / Optional arms), so wildcards captured
                    // during a failed sub-pattern attempt are restored
                    // automatically. We thread `captures` / `extract` through
                    // unchanged.
                    let result = match_engine(
                        &combined,
                        &cmd_tokens[head..],
                        definitions,
                        steps,
                        captures.as_deref_mut(),
                        extract.as_mut().map(|(c, a)| (&mut **c, &mut **a)),
                        after_double_dash,
                        var_captures,
                        flag_group_captures,
                    );
                    if matches!(result, Ok(true)) {
                        return Ok(true);
                    }
                    after_double_dash.set(saved_dd);
                    *var_captures.borrow_mut() = saved_vc;
                    *flag_group_captures.borrow_mut() = saved_fg;
                }
                return Ok(false);
            }

            if token_matching::match_var_ref(name, cmd_tokens[0], definitions) {
                // Capture the matched command token for this var reference.
                // For path-type vars, store the actual matched token (as-is).
                var_captures
                    .borrow_mut()
                    .insert(name.clone(), cmd_tokens[0].to_string());
                match_engine(
                    rest,
                    &cmd_tokens[1..],
                    definitions,
                    steps,
                    captures,
                    extract,
                    after_double_dash,
                    var_captures,
                    flag_group_captures,
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
                        if cmd_tokens.is_empty() || cmd_tokens[0].starts_with('-') {
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
                        // <cmd> must not capture a sequence starting with a flag
                        if is_cmd && cmd_tokens[0].starts_with('-') {
                            break;
                        }
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
                            var_captures,
                            flag_group_captures,
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
                    var_captures,
                    flag_group_captures,
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
                var_captures,
                flag_group_captures,
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
                var_captures,
                flag_group_captures,
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
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
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
            var_captures,
            flag_group_captures,
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
            var_captures,
            flag_group_captures,
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
            var_captures,
            flag_group_captures,
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
