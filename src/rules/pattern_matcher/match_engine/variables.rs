//! Match arm functions for `Optional`, `VarRef`, and `Placeholder` pattern tokens.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::pattern_parser::{CommandPattern, PatternToken};

use super::super::flag_utils::optional_flags_absent;
use super::super::token_matching;
use super::match_engine;

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_optional<'a>(
    inner_tokens: &[PatternToken],
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

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_var_ref<'a>(
    name: &str,
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
                .insert(name.to_string(), cmd_tokens[0].to_string());

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
            .insert(name.to_string(), cmd_tokens[0].to_string());
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

#[expect(
    clippy::too_many_arguments,
    reason = "mirrors match_engine signature for this arm"
)]
pub(super) fn match_placeholder<'a>(
    name: &str,
    rest: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    captures: Option<&mut Vec<&'a str>>,
    mut extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
) -> Result<bool, RuleError> {
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
