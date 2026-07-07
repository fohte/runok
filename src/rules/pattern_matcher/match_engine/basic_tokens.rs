//! Match arm functions for `Wildcard`, `Literal`, and `PathRef` pattern tokens.
//!
//! Each function here is the body of one `match_engine` arm, extracted
//! verbatim, and recurses back into `match_engine` for the rest of the
//! pattern.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::pattern_parser::PatternToken;

use super::super::token_matching::{literal_matches, normalize_path, resolve_paths};
use super::helpers::{collect_value_flag_aliases, find_first_positional, remove_indices};
use super::match_engine;

/// Match `PatternToken::Wildcard`: try every possible number of `cmd_tokens`
/// consumed (0 through all of them), recursing on the remainder for each.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_wildcard<'a>(
    rest: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    mut captures: Option<&mut Vec<&'a str>>,
    mut extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
) -> Result<bool, RuleError> {
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

/// Match `PatternToken::Literal`: exact (or glob) match against a single
/// command token, either at a fixed position (after `--`, or for flag-like
/// literals) or order-independently against the first non-flag token.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_literal<'a>(
    s: &str,
    rest: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    captures: Option<&mut Vec<&'a str>>,
    extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
) -> Result<bool, RuleError> {
    if cmd_tokens.is_empty() {
        return Ok(false);
    }
    // After `--`, all tokens are positional — no flag skipping.
    // Also, flag-like literals (e.g. `-m` from parse_multi) remain
    // positional to avoid mismatches with value-flag arguments.
    let is_flag_literal = s.starts_with('-') && s != "--";
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
    if s == "--" {
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

/// Match `PatternToken::PathRef`: the command token must normalize to one of
/// the paths listed under `definitions.paths[name]`.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_path_ref<'a>(
    name: &str,
    rest: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    captures: Option<&mut Vec<&'a str>>,
    extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
) -> Result<bool, RuleError> {
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
