//! Match arm functions for `FlagGroupRef` and `FlagWithValue` pattern tokens.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::pattern_parser::PatternToken;

use super::super::flag_utils::{split_flag_equals, split_short_flag_value};
use super::super::token_matching::match_single_token;
use super::helpers::remove_indices;
use super::match_engine;

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_flag_group_ref<'a>(
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
                if let Some((_flag_part, value_part)) = split_short_flag_value(token, aliases)
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
                if aliases.iter().any(|a| a.as_str() == token) && !matched_indices.contains(&i) {
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
        .entry(name.to_string())
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

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_flag_with_value<'a>(
    aliases: &[String],
    value: &PatternToken,
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
    for i in 0..cmd_tokens.len() {
        // Case 1: space-separated flag and value (e.g. `--sort value`)
        if aliases.iter().any(|a| a.as_str() == cmd_tokens[i])
            && i + 1 < cmd_tokens.len()
            && match_single_token(value, cmd_tokens[i + 1], definitions)
        {
            let remaining = remove_indices(cmd_tokens, &[i, i + 1]);
            let capture_val = matches!(value, PatternToken::Wildcard).then_some(cmd_tokens[i + 1]);
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
            let capture_val = matches!(value, PatternToken::Wildcard).then_some(value_part);
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
        if let Some((_flag_part, value_part)) = split_short_flag_value(cmd_tokens[i], aliases)
            && match_single_token(value, value_part, definitions)
        {
            let remaining = remove_indices(cmd_tokens, &[i]);
            let capture_val = matches!(value, PatternToken::Wildcard).then_some(value_part);
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
