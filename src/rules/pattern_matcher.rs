//! Pattern-to-command matching engine.
//!
//! Matches a [`Pattern`] against the raw tokens of a [`ParsedCommand`],
//! supporting wildcards, alternations, negations, optional groups,
//! and path-variable expansion via [`Definitions`].

use std::cell::Cell;
use std::path::{Component, Path};

use crate::config::Definitions;
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
    if pattern.command != command.command {
        return false;
    }

    // Match pattern tokens against raw_tokens (excluding the command name at index 0)
    let cmd_tokens: Vec<&str> = command.raw_tokens[1..].iter().map(|s| s.as_str()).collect();
    let steps = Cell::new(0usize);
    match_tokens_inner(&pattern.tokens, &cmd_tokens, definitions, &steps)
}

/// Core recursive matcher operating on `&[&str]` slices.
///
/// `steps` tracks the total number of recursive calls to prevent exponential
/// blowup from patterns with multiple consecutive wildcards.
fn match_tokens_inner(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&str],
    definitions: &Definitions,
    steps: &Cell<usize>,
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
                if match_tokens_inner(rest, &cmd_tokens[skip..], definitions, steps) {
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
                match_tokens_inner(rest, &cmd_tokens[1..], definitions, steps)
            } else {
                false
            }
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if alts.iter().any(|a| a.as_str() == cmd_tokens[0]) {
                match_tokens_inner(rest, &cmd_tokens[1..], definitions, steps)
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
                    if match_tokens_inner(rest, &remaining, definitions, steps) {
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
                match_tokens_inner(rest, &cmd_tokens[1..], definitions, steps)
            } else {
                false
            }
        }

        PatternToken::Optional(inner_tokens) => {
            // Try matching with the optional tokens present (consuming command tokens)
            if match_optional_present(inner_tokens, rest, cmd_tokens, definitions, steps) {
                return true;
            }
            // Try matching without the optional tokens (skip the Optional entirely),
            // but verify that the optional's flags are actually absent from the command
            if optional_flags_absent(inner_tokens, cmd_tokens) {
                return match_tokens_inner(rest, cmd_tokens, definitions, steps);
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
                match_tokens_inner(rest, &cmd_tokens[1..], definitions, steps)
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
            match_tokens_inner(rest, &cmd_tokens[1..], definitions, steps)
        }
    }
}

/// Try to match a wrapper pattern against a command and extract the tokens
/// captured by the `<cmd>` placeholder.
///
/// Returns `Some(captured_command)` if the pattern matches and contains a
/// `<cmd>` placeholder, where `captured_command` is the space-joined
/// reconstruction of the captured tokens at the placeholder position.
/// Returns `None` if the pattern does not match or has no `<cmd>` placeholder.
pub fn extract_placeholder(
    pattern: &Pattern,
    command: &ParsedCommand,
    definitions: &Definitions,
) -> Option<String> {
    if pattern.command != command.command {
        return None;
    }

    let cmd_tokens: Vec<&str> = command.raw_tokens[1..].iter().map(|s| s.as_str()).collect();
    let steps = Cell::new(0usize);
    let mut captured = Vec::new();
    if extract_placeholder_inner(
        &pattern.tokens,
        &cmd_tokens,
        definitions,
        &steps,
        &mut captured,
    ) {
        if captured.is_empty() {
            None
        } else {
            Some(captured.join(" "))
        }
    } else {
        None
    }
}

/// Core recursive extractor that matches pattern tokens against command tokens,
/// capturing the tokens that align with a `Placeholder("cmd")` token.
///
/// Only `<cmd>` placeholders contribute to the `captured` vector; other
/// placeholder names (e.g., `<user>`) are consumed without capturing.
fn extract_placeholder_inner<'a>(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&'a str],
    definitions: &Definitions,
    steps: &Cell<usize>,
    captured: &mut Vec<&'a str>,
) -> bool {
    let count = steps.get() + 1;
    steps.set(count);
    if count > MAX_MATCH_STEPS {
        return false;
    }

    let Some((first, rest)) = pattern_tokens.split_first() else {
        return cmd_tokens.is_empty();
    };

    match first {
        PatternToken::Placeholder(name) => {
            let is_cmd = name == "cmd";
            if rest.is_empty() {
                // Last token in pattern: capture all remaining command tokens
                if is_cmd {
                    captured.extend_from_slice(cmd_tokens);
                }
                true
            } else if cmd_tokens.is_empty() {
                false
            } else {
                let saved_len = captured.len();
                if is_cmd {
                    captured.push(cmd_tokens[0]);
                }
                if extract_placeholder_inner(rest, &cmd_tokens[1..], definitions, steps, captured) {
                    true
                } else {
                    captured.truncate(saved_len);
                    false
                }
            }
        }

        PatternToken::Literal(s) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if cmd_tokens[0] == s.as_str() {
                extract_placeholder_inner(rest, &cmd_tokens[1..], definitions, steps, captured)
            } else {
                false
            }
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if alts.iter().any(|a| a.as_str() == cmd_tokens[0]) {
                extract_placeholder_inner(rest, &cmd_tokens[1..], definitions, steps, captured)
            } else {
                false
            }
        }

        PatternToken::FlagWithValue { aliases, value } => {
            for i in 0..cmd_tokens.len() {
                if aliases.iter().any(|a| a.as_str() == cmd_tokens[i])
                    && i + 1 < cmd_tokens.len()
                    && match_single_token(value, cmd_tokens[i + 1], definitions)
                {
                    let saved_len = captured.len();
                    let remaining = remove_indices(cmd_tokens, &[i, i + 1]);
                    if extract_placeholder_inner(rest, &remaining, definitions, steps, captured) {
                        return true;
                    }
                    captured.truncate(saved_len);
                }
            }
            false
        }

        PatternToken::Wildcard => {
            for skip in 0..=cmd_tokens.len() {
                let saved_len = captured.len();
                if extract_placeholder_inner(
                    rest,
                    &cmd_tokens[skip..],
                    definitions,
                    steps,
                    captured,
                ) {
                    return true;
                }
                captured.truncate(saved_len);
            }
            false
        }

        PatternToken::Negation(inner) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if !match_single_token(inner, cmd_tokens[0], definitions) {
                extract_placeholder_inner(rest, &cmd_tokens[1..], definitions, steps, captured)
            } else {
                false
            }
        }

        PatternToken::Optional(_) | PatternToken::PathRef(_) => {
            // Wrapper patterns are simple; Optional and PathRef are not
            // expected in practice. Fall back to basic matching without capture.
            match_tokens_inner(pattern_tokens, cmd_tokens, definitions, steps)
        }
    }
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

/// Try to match optional inner tokens against the beginning of cmd_tokens
/// using order-independent matching for FlagWithValue tokens within the
/// optional group.
fn match_optional_present(
    optional_tokens: &[PatternToken],
    remaining_pattern: &[PatternToken],
    cmd_tokens: &[&str],
    definitions: &Definitions,
    steps: &Cell<usize>,
) -> bool {
    // Chain optional tokens with remaining pattern to avoid cloning.
    let combined: Vec<&PatternToken> = optional_tokens
        .iter()
        .chain(remaining_pattern.iter())
        .collect();
    match_tokens_ref(&combined, cmd_tokens, definitions, steps)
}

/// Same as [`match_tokens_inner`] but operates on `&[&PatternToken]` to avoid
/// cloning when chaining optional groups with the remaining pattern.
fn match_tokens_ref(
    pattern_tokens: &[&PatternToken],
    cmd_tokens: &[&str],
    definitions: &Definitions,
    steps: &Cell<usize>,
) -> bool {
    let count = steps.get() + 1;
    steps.set(count);
    if count > MAX_MATCH_STEPS {
        return false;
    }

    let Some((first, rest)) = pattern_tokens.split_first() else {
        return cmd_tokens.is_empty();
    };

    match first {
        PatternToken::Wildcard => {
            for skip in 0..=cmd_tokens.len() {
                if match_tokens_ref(rest, &cmd_tokens[skip..], definitions, steps) {
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
                match_tokens_ref(rest, &cmd_tokens[1..], definitions, steps)
            } else {
                false
            }
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if alts.iter().any(|a| a.as_str() == cmd_tokens[0]) {
                match_tokens_ref(rest, &cmd_tokens[1..], definitions, steps)
            } else {
                false
            }
        }

        PatternToken::FlagWithValue { aliases, value } => {
            for i in 0..cmd_tokens.len() {
                if aliases.iter().any(|a| a.as_str() == cmd_tokens[i])
                    && i + 1 < cmd_tokens.len()
                    && match_single_token(value, cmd_tokens[i + 1], definitions)
                {
                    let remaining = remove_indices(cmd_tokens, &[i, i + 1]);
                    if match_tokens_ref(rest, &remaining, definitions, steps) {
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
                match_tokens_ref(rest, &cmd_tokens[1..], definitions, steps)
            } else {
                false
            }
        }

        PatternToken::Optional(inner_tokens) => {
            // "present" path: chain inner tokens with rest
            let combined: Vec<&PatternToken> =
                inner_tokens.iter().chain(rest.iter().copied()).collect();
            if match_tokens_ref(&combined, cmd_tokens, definitions, steps) {
                return true;
            }
            // "absent" path
            if optional_flags_absent(inner_tokens, cmd_tokens) {
                return match_tokens_ref(rest, cmd_tokens, definitions, steps);
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
                match_tokens_ref(rest, &cmd_tokens[1..], definitions, steps)
            } else {
                false
            }
        }

        PatternToken::Placeholder(_) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            match_tokens_ref(rest, &cmd_tokens[1..], definitions, steps)
        }
    }
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
        // FlagWithValue and Optional don't make sense as single-token matches
        PatternToken::FlagWithValue { .. } | PatternToken::Optional(_) => false,
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
}
