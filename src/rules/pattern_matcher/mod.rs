//! Pattern-to-command matching engine.
//!
//! Matches a [`Pattern`] against the raw tokens of a [`ParsedCommand`],
//! supporting wildcards, alternations, negations, optional groups,
//! and path-variable expansion via [`Definitions`].

mod flag_utils;
mod match_engine;
mod token_matching;

pub(crate) use token_matching::literal_matches;

use match_engine::match_engine;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::command_parser::ParsedCommand;
use crate::rules::pattern_parser::{CommandPattern, Pattern};

use token_matching::match_var_ref_multi;

/// Result of a successful pattern match, containing wildcard captures,
/// variable reference captures, and flag group captures.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchCaptures {
    /// Tokens captured by wildcards (`*`) in the pattern.
    pub wildcards: Vec<String>,
    /// Values captured by `<var:name>` references, keyed by variable name.
    pub vars: HashMap<String, String>,
    /// Values captured by `<flag:name>` references, keyed by flag group name.
    /// Always populated as a list (even when only one value matched) so that
    /// `when` clauses can use list-aware CEL macros (`exists`, `all`, etc.)
    /// uniformly. Groups defined in `definitions.flag_groups` but not present
    /// in the matched command are populated as empty lists by the rule engine.
    pub flag_groups: HashMap<String, Vec<String>>,
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
    definitions: &Definitions,
) -> (Vec<&'a str>, Vec<usize>) {
    match &pattern.command {
        CommandPattern::Wildcard => {
            let tokens = command.raw_tokens.iter().map(|s| s.as_str()).collect();
            let len = command.raw_tokens.len();
            (tokens, (1..=len).collect())
        }
        CommandPattern::VarRef(name) => {
            // Try matching var values against the leading tokens to determine
            // how many tokens the command name consumes.
            let all_tokens: Vec<&str> = command.raw_tokens.iter().map(|s| s.as_str()).collect();
            let skip_values = match_var_ref_multi(name, &all_tokens, definitions);
            (all_tokens, skip_values)
        }
        _ => {
            let tokens = command.raw_tokens[1..].iter().map(|s| s.as_str()).collect();
            (tokens, vec![0])
        }
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

    let (cmd_tokens, skip_values) = prepare_wildcard_iteration(pattern, command, definitions);
    for skip in skip_values {
        let steps = Cell::new(0usize);
        let after_dd = Cell::new(false);
        let var_captures = RefCell::new(HashMap::new());
        let flag_group_captures = RefCell::new(HashMap::new());
        if match_engine(
            &pattern.tokens,
            &cmd_tokens[skip..],
            definitions,
            &steps,
            None,
            None,
            &after_dd,
            &var_captures,
            &flag_group_captures,
        )
        .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Like `matches`, but also returns the tokens captured by wildcards (`*`)
/// and `<var:name>` references.
///
/// Returns `Some(MatchCaptures)` if the pattern matches, `None` otherwise.
pub fn matches_with_captures(
    pattern: &Pattern,
    command: &ParsedCommand,
    definitions: &Definitions,
) -> Option<MatchCaptures> {
    if !pattern.command.matches(&command.command) {
        return None;
    }

    let (cmd_tokens, skip_values) = prepare_wildcard_iteration(pattern, command, definitions);
    for skip in skip_values {
        let steps = Cell::new(0usize);
        let after_dd = Cell::new(false);
        let mut captures = Vec::new();
        let var_captures = RefCell::new(HashMap::new());
        let flag_group_captures = RefCell::new(HashMap::new());

        // Capture command-position var ref value.
        if let CommandPattern::VarRef(name) = &pattern.command {
            let matched_tokens = &cmd_tokens[..skip];
            let matched_value = matched_tokens.join(" ");
            var_captures
                .borrow_mut()
                .insert(name.clone(), matched_value);
        }

        if match_engine(
            &pattern.tokens,
            &cmd_tokens[skip..],
            definitions,
            &steps,
            Some(&mut captures),
            None,
            &after_dd,
            &var_captures,
            &flag_group_captures,
        )
        .unwrap_or(false)
        {
            return Some(MatchCaptures {
                wildcards: captures.into_iter().map(|s| s.to_string()).collect(),
                vars: var_captures.into_inner(),
                flag_groups: flag_group_captures.into_inner(),
            });
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
pub fn extract_placeholder(
    pattern: &Pattern,
    command: &ParsedCommand,
    definitions: &Definitions,
) -> Result<Vec<Vec<String>>, RuleError> {
    if !pattern.command.matches(&command.command) {
        return Ok(Vec::new());
    }

    let (cmd_tokens, skip_values) = prepare_wildcard_iteration(pattern, command, definitions);
    let mut all_candidates: Vec<Vec<&str>> = Vec::new();
    for skip in skip_values {
        let steps = Cell::new(0usize);
        let after_dd = Cell::new(false);
        let mut captured = Vec::new();
        let var_captures = RefCell::new(HashMap::new());
        let flag_group_captures = RefCell::new(HashMap::new());
        match_engine(
            &pattern.tokens,
            &cmd_tokens[skip..],
            definitions,
            &steps,
            None,
            Some((&mut captured, &mut all_candidates)),
            &after_dd,
            &var_captures,
            &flag_group_captures,
        )?;
    }
    Ok(all_candidates
        .into_iter()
        .map(|c| c.into_iter().map(|s| s.to_string()).collect())
        .collect())
}

#[cfg(test)]
mod tests;
