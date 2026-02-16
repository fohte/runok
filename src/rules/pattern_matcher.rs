//! Pattern-to-command matching engine.
//!
//! Matches a [`Pattern`] against the raw tokens of a [`ParsedCommand`],
//! supporting wildcards, alternations, negations, optional groups,
//! and path-variable expansion via [`Definitions`].

use crate::config::Definitions;
use crate::rules::command_parser::ParsedCommand;
use crate::rules::pattern_parser::{Pattern, PatternToken};

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
    match_tokens_inner(&pattern.tokens, &cmd_tokens, definitions)
}

/// Core recursive matcher operating on `&[&str]` slices.
fn match_tokens_inner(
    pattern_tokens: &[PatternToken],
    cmd_tokens: &[&str],
    definitions: &Definitions,
) -> bool {
    // Base case: both exhausted
    let Some((first, rest)) = pattern_tokens.split_first() else {
        return cmd_tokens.is_empty();
    };

    match first {
        PatternToken::Wildcard => {
            // Wildcard matches zero or more tokens (greedy with backtracking)
            for skip in 0..=cmd_tokens.len() {
                if match_tokens_inner(rest, &cmd_tokens[skip..], definitions) {
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
                match_tokens_inner(rest, &cmd_tokens[1..], definitions)
            } else {
                false
            }
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if alts.iter().any(|a| a.as_str() == cmd_tokens[0]) {
                match_tokens_inner(rest, &cmd_tokens[1..], definitions)
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
                    if match_tokens_inner(rest, &remaining, definitions) {
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
                match_tokens_inner(rest, &cmd_tokens[1..], definitions)
            } else {
                false
            }
        }

        PatternToken::Optional(inner_tokens) => {
            // Try matching with the optional tokens present (consuming command tokens)
            if match_optional_present(inner_tokens, rest, cmd_tokens, definitions) {
                return true;
            }
            // Try matching without the optional tokens (skip the Optional entirely),
            // but verify that the optional's flags are actually absent from the command
            if optional_flags_absent(inner_tokens, cmd_tokens) {
                return match_tokens_inner(rest, cmd_tokens, definitions);
            }
            false
        }

        PatternToken::PathRef(name) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            let paths = resolve_paths(name, definitions);
            if paths.iter().any(|p| p.as_str() == cmd_tokens[0]) {
                match_tokens_inner(rest, &cmd_tokens[1..], definitions)
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
            match_tokens_inner(rest, &cmd_tokens[1..], definitions)
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
) -> bool {
    // Chain optional tokens with remaining pattern to avoid cloning.
    let combined: Vec<&PatternToken> = optional_tokens
        .iter()
        .chain(remaining_pattern.iter())
        .collect();
    match_tokens_ref(&combined, cmd_tokens, definitions)
}

/// Same as [`match_tokens_inner`] but operates on `&[&PatternToken]` to avoid
/// cloning when chaining optional groups with the remaining pattern.
fn match_tokens_ref(
    pattern_tokens: &[&PatternToken],
    cmd_tokens: &[&str],
    definitions: &Definitions,
) -> bool {
    let Some((first, rest)) = pattern_tokens.split_first() else {
        return cmd_tokens.is_empty();
    };

    match first {
        PatternToken::Wildcard => {
            for skip in 0..=cmd_tokens.len() {
                if match_tokens_ref(rest, &cmd_tokens[skip..], definitions) {
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
                match_tokens_ref(rest, &cmd_tokens[1..], definitions)
            } else {
                false
            }
        }

        PatternToken::Alternation(alts) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            if alts.iter().any(|a| a.as_str() == cmd_tokens[0]) {
                match_tokens_ref(rest, &cmd_tokens[1..], definitions)
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
                    if match_tokens_ref(rest, &remaining, definitions) {
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
                match_tokens_ref(rest, &cmd_tokens[1..], definitions)
            } else {
                false
            }
        }

        PatternToken::Optional(inner_tokens) => {
            // "present" path: chain inner tokens with rest
            let combined: Vec<&PatternToken> =
                inner_tokens.iter().chain(rest.iter().copied()).collect();
            if match_tokens_ref(&combined, cmd_tokens, definitions) {
                return true;
            }
            // "absent" path
            if optional_flags_absent(inner_tokens, cmd_tokens) {
                return match_tokens_ref(rest, cmd_tokens, definitions);
            }
            false
        }

        PatternToken::PathRef(name) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            let paths = resolve_paths(name, definitions);
            if paths.iter().any(|p| p.as_str() == cmd_tokens[0]) {
                match_tokens_ref(rest, &cmd_tokens[1..], definitions)
            } else {
                false
            }
        }

        PatternToken::Placeholder(_) => {
            if cmd_tokens.is_empty() {
                return false;
            }
            match_tokens_ref(rest, &cmd_tokens[1..], definitions)
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
            paths.iter().any(|p| p.as_str() == cmd_token)
        }
        PatternToken::Placeholder(_) => true,
        // FlagWithValue and Optional don't make sense as single-token matches
        PatternToken::FlagWithValue { .. } | PatternToken::Optional(_) => false,
    }
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
}
