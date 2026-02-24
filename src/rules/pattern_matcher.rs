//! Pattern-to-command matching engine.
//!
//! Matches a [`Pattern`] against the raw tokens of a [`ParsedCommand`],
//! supporting wildcards, alternations, negations, optional groups,
//! and path-variable expansion via [`Definitions`].

use std::cell::Cell;
use std::path::{Component, Path};

use crate::config::Definitions;
use crate::rules::RuleError;
use crate::rules::command_parser::ParsedCommand;
use crate::rules::pattern_parser::{Pattern, PatternToken};

/// Maximum number of recursive steps allowed during pattern matching.
/// Prevents exponential blowup from patterns with multiple consecutive wildcards.
const MAX_MATCH_STEPS: usize = 10_000;

/// Check whether `pattern` matches `command`.
///
/// Path references (`<path:name>`) are expanded using `definitions.paths`.
/// Returns `true` if any valid alignment of pattern tokens against
/// `command.raw_tokens` succeeds.
pub fn matches(pattern: &Pattern, command: &ParsedCommand, definitions: &Definitions) -> bool {
    if !pattern.command.matches(&command.command) {
        return false;
    }

    // Match pattern tokens against raw_tokens (excluding the command name at index 0)
    let cmd_tokens: Vec<&str> = command.raw_tokens[1..].iter().map(|s| s.as_str()).collect();
    let steps = Cell::new(0usize);
    match_tokens_core(&pattern.tokens, &cmd_tokens, definitions, &steps, None)
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

    let cmd_tokens: Vec<&str> = command.raw_tokens[1..].iter().map(|s| s.as_str()).collect();
    let steps = Cell::new(0usize);
    let mut captures = Vec::new();
    if match_tokens_core(
        &pattern.tokens,
        &cmd_tokens,
        definitions,
        &steps,
        Some(&mut captures),
    ) {
        Some(captures.into_iter().map(|s| s.to_string()).collect())
    } else {
        None
    }
}

/// Core recursive matcher operating on `&[&str]` slices.
///
/// When `captures` is `Some`, wildcard-matched tokens are recorded.
/// When `None`, only a boolean match result is produced.
///
/// `steps` tracks the total number of recursive calls to prevent exponential
/// blowup from patterns with multiple consecutive wildcards.
fn match_tokens_core<'a>(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    mut captures: Option<&mut Vec<&'a str>>,
) -> bool {
    let count = steps.get() + 1;
    steps.set(count);
    if count > MAX_MATCH_STEPS {
        return false;
    }

    // Base case: both exhausted
    let Some((first, rest)) = pattern_tokens.split_first() else {
        return cmd_tokens.is_empty();
    };

    match first {
        PatternToken::Wildcard => {
            // Wildcard matches zero or more tokens (greedy with backtracking)
            for skip in 0..=cmd_tokens.len() {
                if let Some(ref mut caps) = captures {
                    let saved_len = caps.len();
                    caps.extend_from_slice(&cmd_tokens[..skip]);
                    if match_tokens_core(rest, &cmd_tokens[skip..], definitions, steps, Some(*caps))
                    {
                        return true;
                    }
                    caps.truncate(saved_len);
                } else if match_tokens_core(rest, &cmd_tokens[skip..], definitions, steps, None) {
                    return true;
                }
            }
            false
        }

        PatternToken::Literal(s) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if cmd_tokens[0] == s.as_str() {
                match_tokens_core(rest, &cmd_tokens[1..], definitions, steps, captures)
            } else {
                false
            }
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if alts.iter().any(|a| a.as_str() == cmd_tokens[0]) {
                match_tokens_core(rest, &cmd_tokens[1..], definitions, steps, captures)
            } else {
                false
            }
        }

        PatternToken::FlagWithValue { aliases, value } => {
            // Search for the flag anywhere in the remaining command tokens
            // (order-independent matching)
            for i in 0..cmd_tokens.len() {
                if aliases.iter().any(|a| a.as_str() == cmd_tokens[i])
                    && i + 1 < cmd_tokens.len()
                    && match_single_token(value, cmd_tokens[i + 1], definitions)
                {
                    // Remove the flag and its value, continue matching
                    let remaining = remove_indices(cmd_tokens, &[i, i + 1]);
                    if let Some(ref mut caps) = captures {
                        let saved_len = caps.len();
                        // Capture the flag value when it matches a wildcard
                        if matches!(value.as_ref(), PatternToken::Wildcard) {
                            caps.push(cmd_tokens[i + 1]);
                        }
                        if match_tokens_core(rest, &remaining, definitions, steps, Some(*caps)) {
                            return true;
                        }
                        caps.truncate(saved_len);
                    } else if match_tokens_core(rest, &remaining, definitions, steps, None) {
                        return true;
                    }
                }
            }
            false
        }

        PatternToken::Negation(inner) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if !match_single_token(inner, cmd_tokens[0], definitions) {
                match_tokens_core(rest, &cmd_tokens[1..], definitions, steps, captures)
            } else {
                false
            }
        }

        PatternToken::Optional(inner_tokens) => {
            // Try matching with the optional tokens present by chaining them
            // with the remaining pattern tokens
            let combined: Vec<PatternToken> = inner_tokens
                .iter()
                .cloned()
                .chain(rest.iter().cloned())
                .collect();
            if let Some(ref mut caps) = captures {
                let saved_len = caps.len();
                if match_tokens_core(&combined, cmd_tokens, definitions, steps, Some(*caps)) {
                    return true;
                }
                caps.truncate(saved_len);
            } else if match_tokens_core(&combined, cmd_tokens, definitions, steps, None) {
                return true;
            }
            // Try matching without the optional tokens (skip the Optional entirely),
            // but verify that the optional's flags are actually absent from the command
            if optional_flags_absent(inner_tokens, cmd_tokens) {
                return match_tokens_core(rest, cmd_tokens, definitions, steps, captures);
            }
            false
        }

        PatternToken::PathRef(name) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            let paths = resolve_paths(name, definitions);
            let normalized_cmd = normalize_path(cmd_tokens[0]);
            if paths.iter().any(|p| normalize_path(p) == normalized_cmd) {
                match_tokens_core(rest, &cmd_tokens[1..], definitions, steps, captures)
            } else {
                false
            }
        }

        PatternToken::Placeholder(_) => {
            // Placeholder matches a single token (wrapper placeholders are
            // handled by the rule engine at a higher level; here we just
            // consume one token)
            if cmd_tokens.is_empty() {
                return false;
            }
            match_tokens_core(rest, &cmd_tokens[1..], definitions, steps, captures)
        }

        PatternToken::Opts => {
            // <opts> in non-wrapper context: consume flag-like tokens
            let skip = consume_opts(cmd_tokens);
            match_tokens_core(rest, &cmd_tokens[skip..], definitions, steps, captures)
        }

        PatternToken::Vars => {
            // <vars> in non-wrapper context: consume KEY=VALUE tokens
            let skip = consume_vars(cmd_tokens);
            match_tokens_core(rest, &cmd_tokens[skip..], definitions, steps, captures)
        }
    }
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

    let cmd_tokens: Vec<&str> = command.raw_tokens[1..].iter().map(|s| s.as_str()).collect();
    let steps = Cell::new(0usize);
    let mut captured = Vec::new();
    let mut all_candidates: Vec<Vec<&str>> = Vec::new();
    extract_placeholder_all(
        &pattern.tokens,
        &cmd_tokens,
        definitions,
        &steps,
        &mut captured,
        &mut all_candidates,
    )?;
    Ok(all_candidates
        .into_iter()
        .map(|c| c.into_iter().map(|s| s.to_string()).collect())
        .collect())
}

/// Collects all possible `<cmd>` captures from a wrapper pattern match.
///
/// Explores all valid alignments of pattern tokens against command tokens and
/// pushes each successful capture into `all_candidates`, ordered from shortest
/// to longest capture (since wildcards iterate from skip=0 upward). Only
/// `<cmd>` placeholders contribute to the captured tokens; other placeholder
/// names consume tokens without capturing. Empty captures (when the pattern
/// has no `<cmd>` or `<cmd>` would capture nothing) are excluded by requiring
/// at least one token for `<cmd>`.
fn extract_placeholder_all<'a>(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    captured: &mut Vec<&'a str>,
    all_candidates: &mut Vec<Vec<&'a str>>,
) -> Result<(), RuleError> {
    let count = steps.get() + 1;
    steps.set(count);
    if count > MAX_MATCH_STEPS {
        return Ok(());
    }

    let Some((first, rest)) = pattern_tokens.split_first() else {
        // Only record a candidate when all command tokens have been consumed
        // AND at least one token was captured by a <cmd> placeholder. Patterns
        // without <cmd> (or where <cmd> matched nothing) produce empty captures
        // that are not useful to the caller.
        if cmd_tokens.is_empty() && !captured.is_empty() {
            all_candidates.push(captured.clone());
        }
        return Ok(());
    };

    match first {
        PatternToken::Placeholder(name) => {
            let is_cmd = name == "cmd";
            if rest.is_empty() {
                if is_cmd {
                    // Empty <cmd> (e.g., `sudo` with no inner command) is not a
                    // valid command to evaluate, so skip it rather than adding an
                    // empty candidate.
                    if cmd_tokens.is_empty() {
                        return Ok(());
                    }
                    let saved_len = captured.len();
                    captured.extend_from_slice(cmd_tokens);
                    all_candidates.push(captured.clone());
                    captured.truncate(saved_len);
                } else if cmd_tokens.len() == 1 {
                    // Non-<cmd> placeholder at end of pattern consumes exactly
                    // one token without adding it to captured (only <cmd> tokens
                    // are captured). Only push if a <cmd> was captured earlier;
                    // otherwise this pattern has no <cmd> and the candidate is
                    // meaningless.
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
                    extract_placeholder_all(
                        rest,
                        &cmd_tokens[take..],
                        definitions,
                        steps,
                        captured,
                        all_candidates,
                    )?;
                    captured.truncate(saved_len);
                }
            }
            Ok(())
        }

        PatternToken::Literal(s) => {
            if !cmd_tokens.is_empty() && cmd_tokens[0] == s.as_str() {
                extract_placeholder_all(
                    rest,
                    &cmd_tokens[1..],
                    definitions,
                    steps,
                    captured,
                    all_candidates,
                )?;
            }
            Ok(())
        }

        PatternToken::Alternation(alts) => {
            if !cmd_tokens.is_empty() && alts.iter().any(|a| a.as_str() == cmd_tokens[0]) {
                extract_placeholder_all(
                    rest,
                    &cmd_tokens[1..],
                    definitions,
                    steps,
                    captured,
                    all_candidates,
                )?;
            }
            Ok(())
        }

        PatternToken::FlagWithValue { aliases, value } => {
            for i in 0..cmd_tokens.len() {
                if aliases.iter().any(|a| a.as_str() == cmd_tokens[i])
                    && i + 1 < cmd_tokens.len()
                    && match_single_token(value, cmd_tokens[i + 1], definitions)
                {
                    let remaining = remove_indices(cmd_tokens, &[i, i + 1]);
                    extract_placeholder_all(
                        rest,
                        &remaining,
                        definitions,
                        steps,
                        captured,
                        all_candidates,
                    )?;
                }
            }
            Ok(())
        }

        PatternToken::Wildcard => {
            for skip in 0..=cmd_tokens.len() {
                extract_placeholder_all(
                    rest,
                    &cmd_tokens[skip..],
                    definitions,
                    steps,
                    captured,
                    all_candidates,
                )?;
            }
            Ok(())
        }

        PatternToken::Negation(inner) => {
            if !cmd_tokens.is_empty() && !match_single_token(inner, cmd_tokens[0], definitions) {
                extract_placeholder_all(
                    rest,
                    &cmd_tokens[1..],
                    definitions,
                    steps,
                    captured,
                    all_candidates,
                )?;
            }
            Ok(())
        }

        PatternToken::Opts => {
            // Consume zero or more flag-like tokens (hyphen-prefixed).
            // When a flag is consumed and the next token is not hyphen-prefixed,
            // consume it as the flag's argument.
            let skip = consume_opts(cmd_tokens);
            extract_placeholder_all(
                rest,
                &cmd_tokens[skip..],
                definitions,
                steps,
                captured,
                all_candidates,
            )
        }

        PatternToken::Vars => {
            // Consume zero or more KEY=VALUE tokens.
            let skip = consume_vars(cmd_tokens);
            extract_placeholder_all(
                rest,
                &cmd_tokens[skip..],
                definitions,
                steps,
                captured,
                all_candidates,
            )
        }

        PatternToken::Optional(_) => Err(RuleError::UnsupportedWrapperToken(
            "Optional ([...])".into(),
        )),

        PatternToken::PathRef(name) => Err(RuleError::UnsupportedWrapperToken(format!(
            "PathRef (<path:{name}>)"
        ))),
    }
}

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

/// Check that flags referenced by the optional group are not present in
/// the command tokens. When we take the "absent" path for an Optional,
/// the flag itself must not appear in the remaining command tokens.
fn optional_flags_absent(optional_tokens: &[PatternToken], cmd_tokens: &[&str]) -> bool {
    for token in optional_tokens {
        match token {
            PatternToken::FlagWithValue { aliases, .. } => {
                if cmd_tokens
                    .iter()
                    .any(|t| aliases.iter().any(|a| a.as_str() == *t))
                {
                    return false;
                }
            }
            PatternToken::Literal(s) if s.starts_with('-') => {
                if cmd_tokens.contains(&s.as_str()) {
                    return false;
                }
            }
            PatternToken::Alternation(alts) if alts.iter().any(|a| a.starts_with('-')) => {
                if cmd_tokens
                    .iter()
                    .any(|t| alts.iter().any(|a| a.as_str() == *t))
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Check if a single pattern token matches a single command token.
fn match_single_token(token: &PatternToken, cmd_token: &str, definitions: &Definitions) -> bool {
    match token {
        PatternToken::Literal(s) => s.as_str() == cmd_token,
        PatternToken::Alternation(alts) => alts.iter().any(|a| a.as_str() == cmd_token),
        PatternToken::Wildcard => true,
        PatternToken::Negation(inner) => !match_single_token(inner, cmd_token, definitions),
        PatternToken::PathRef(name) => {
            let paths = resolve_paths(name, definitions);
            let normalized_cmd = normalize_path(cmd_token);
            paths.iter().any(|p| normalize_path(p) == normalized_cmd)
        }
        PatternToken::Placeholder(_) => true,
        // FlagWithValue, Optional, Opts, and Vars don't make sense as single-token matches
        PatternToken::FlagWithValue { .. }
        | PatternToken::Optional(_)
        | PatternToken::Opts
        | PatternToken::Vars => false,
    }
}

/// Normalize a file path by resolving `.` and `..` components without
/// touching the filesystem. This prevents traversal-based bypasses such
/// as `/etc/./passwd` or `/etc/../etc/passwd` when matching `<path:name>`.
fn normalize_path(path: &str) -> String {
    let mut components = Vec::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::ParentDir => {
                if matches!(components.last(), Some(Component::Normal(_))) {
                    // Pop the last normal component
                    components.pop();
                } else if !matches!(components.last(), Some(Component::RootDir)) {
                    // Preserve leading `..` in relative paths
                    components.push(comp);
                }
            }
            Component::CurDir => {
                // Skip `.`
            }
            _ => {
                components.push(comp);
            }
        }
    }
    if components.is_empty() {
        return ".".to_string();
    }
    let rebuilt: std::path::PathBuf = components.iter().collect();
    rebuilt.to_string_lossy().into_owned()
}

/// Resolve a path reference name from definitions, returning a borrowed slice.
fn resolve_paths<'a>(name: &str, definitions: &'a Definitions) -> &'a [String] {
    definitions
        .paths
        .as_ref()
        .and_then(|paths| paths.get(name))
        .map(|v| v.as_slice())
        .unwrap_or(&[])
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
    // Alias / alternation matching
    // ========================================

    #[rstest]
    #[case::first_alt("git push main|master", "git push main", true)]
    #[case::second_alt("git push main|master", "git push master", true)]
    #[case::no_alt_match("git push main|master", "git push develop", false)]
    #[case::subcommand_alt("kubectl describe|get|list *", "kubectl get pods", true)]
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
    #[case::wildcard_command_no_match_extra_args("*", "git status", false)]
    #[case::wildcard_command_flag_mismatch("* --help", "git --version", false)]
    #[case::wildcard_command_missing_flag("* --help", "git", false)]
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
    // normalize_path unit tests
    // ========================================

    #[rstest]
    #[case::identity("/etc/passwd", "/etc/passwd")]
    #[case::dot("/etc/./passwd", "/etc/passwd")]
    #[case::dotdot("/etc/../etc/passwd", "/etc/passwd")]
    #[case::multiple_dots("/a/./b/./c", "/a/b/c")]
    #[case::dotdot_at_root("/../etc/passwd", "/etc/passwd")]
    #[case::relative("foo/./bar", "foo/bar")]
    #[case::relative_dotdot("foo/bar/../baz", "foo/baz")]
    #[case::leading_dotdot("../etc/passwd", "../etc/passwd")]
    #[case::leading_double_dotdot("../../etc/passwd", "../../etc/passwd")]
    fn normalize_path_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(normalize_path(input), expected);
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
        vec![vec!["echo", "hello"]],
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
    fn extract_placeholder_with_alternation(empty_defs: Definitions) {
        // Alternation token before <cmd>
        let result = check_extract("run fast|slow <cmd>", "run fast echo hello", &empty_defs);
        assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
    }

    #[rstest]
    fn extract_placeholder_with_flag_with_value(empty_defs: Definitions) {
        // FlagWithValue token before <cmd>
        let result = check_extract(
            "run -m|--mode debug <cmd>",
            "run -m debug echo hello",
            &empty_defs,
        );
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
}
