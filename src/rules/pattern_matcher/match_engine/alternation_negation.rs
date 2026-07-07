//! Match arm functions for `Alternation` and `Negation` pattern tokens.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::pattern_parser::PatternToken;

use super::super::flag_utils::{is_flag_only_negation, split_flag_equals};
use super::super::token_matching::{
    literal_matches, match_flag_token_with_equals, match_single_token,
};
use super::helpers::{collect_value_flag_aliases, find_first_positional, remove_indices};
use super::match_engine;

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_alternation<'a>(
    alts: &[String],
    rest: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    mut captures: Option<&mut Vec<&'a str>>,
    extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
) -> Result<bool, RuleError> {
    if cmd_tokens.is_empty() {
        return Ok(false);
    }

    let is_extract = extract.is_some();
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

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_negation<'a>(
    inner: &PatternToken,
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
