//! Unified recursive pattern-matching engine.
//!
//! Implements the core backtracking algorithm that walks a pattern's tokens
//! against a command's tokens, handling wildcards, alternations, negations,
//! optional groups, flag groups, and variable/path references. Each match
//! arm below delegates to a function in a sibling module, grouped by the
//! kind of `PatternToken` it handles.
//!
//! Every arm function threads through the same five invariant parameters
//! (`definitions`, `steps`, `after_double_dash`, `var_captures`,
//! `flag_group_captures`) alongside the two that actually vary per call
//! (`captures`, `extract`). Bundling the invariant five into a context
//! struct (as `EvalContext`/`ExprContext` do elsewhere in `rules/`) would cut
//! down the repetition, but changes every call site; left as a follow-up
//! rather than folded into this move.

mod alternation_negation;
mod basic_tokens;
mod flags;
mod helpers;
mod variables;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::pattern_parser::PatternToken;

use alternation_negation::{match_alternation, match_negation};
use basic_tokens::{match_literal, match_path_ref, match_wildcard};
use flags::{match_flag_group_ref, match_flag_with_value};
use helpers::{consume_opts, consume_vars};
use variables::{match_optional, match_placeholder, match_var_ref};

/// Maximum number of recursive steps allowed during pattern matching.
/// Prevents exponential blowup from patterns with multiple consecutive wildcards.
const MAX_MATCH_STEPS: usize = 10_000;

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
    captures: Option<&mut Vec<&'a str>>,
    extract: Option<(&mut Vec<&'a str>, &mut Vec<Vec<&'a str>>)>,
    after_double_dash: &Cell<bool>,
    var_captures: &RefCell<HashMap<String, String>>,
    flag_group_captures: &RefCell<HashMap<String, Vec<String>>>,
) -> Result<bool, RuleError> {
    let count = steps.get() + 1;
    steps.set(count);
    if count > MAX_MATCH_STEPS {
        return Ok(false);
    }

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
        PatternToken::Wildcard => match_wildcard(
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::Literal(s) => match_literal(
            s,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::Alternation(alts) => match_alternation(
            alts,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::FlagGroupRef { name } => match_flag_group_ref(
            name,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::FlagWithValue { aliases, value } => match_flag_with_value(
            aliases,
            value,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::Negation(inner) => match_negation(
            inner,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::Optional(inner_tokens) => match_optional(
            inner_tokens,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::PathRef(name) => match_path_ref(
            name,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::VarRef(name) => match_var_ref(
            name,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
        PatternToken::Placeholder(name) => match_placeholder(
            name,
            rest,
            cmd_tokens,
            definitions,
            steps,
            captures,
            extract,
            after_double_dash,
            var_captures,
            flag_group_captures,
        ),
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
