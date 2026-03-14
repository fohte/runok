//! Flag normalization and flag-related matching utilities.
//!
//! Centralizes `=`-joined flag splitting and flag-presence checks used
//! by the matching engine and optional-group logic.

use crate::rules::pattern_parser::PatternToken;

use super::token_matching::literal_matches;

/// Split an `=`-joined flag token (e.g. `--flag=value`) into its flag and
/// value parts. Only recognizes standard flag forms: short flags (`-X=val`)
/// and long flags (`--flag=val`). Non-standard forms like `-Denv=prod` (where
/// `-D` + key is fused into a single token) are not split, because they
/// represent a single semantic token rather than a flag-value pair.
pub(crate) fn split_flag_equals(token: &str) -> Option<(&str, &str)> {
    let eq_pos = token.find('=')?;
    let flag_part = &token[..eq_pos];
    if flag_part.starts_with("--") {
        // Long flag: --flag=value
        Some((flag_part, &token[eq_pos + 1..]))
    } else if flag_part.len() == 2 && flag_part.starts_with('-') {
        // Short flag: -X=value (dash + single char)
        Some((flag_part, &token[eq_pos + 1..]))
    } else {
        None
    }
}

/// Split a fused short flag token (e.g. `-n3`) into its flag and value parts.
/// Only recognizes single-character short flags with a value directly attached
/// (e.g. `-n3` → `("-n", "3")`). Does not split combined boolean flags like
/// `-rf` since those are indistinguishable without context; the caller must
/// only invoke this when a `FlagWithValue` pattern declares the flag takes a
/// value.
pub(crate) fn split_short_flag_value<'a>(
    token: &'a str,
    aliases: &[String],
) -> Option<(&'a str, &'a str)> {
    // Token must start with `-`, be longer than 2 bytes, not start with `--`,
    // and byte index 2 must be a char boundary (i.e. the second char is ASCII).
    if token.len() <= 2
        || !token.starts_with('-')
        || token.starts_with("--")
        || !token.is_char_boundary(2)
    {
        return None;
    }
    // Extract the first two bytes (e.g. `-n`) as the flag part.
    let flag_part = &token[..2];
    if aliases.iter().any(|a| a.as_str() == flag_part) {
        Some((flag_part, &token[2..]))
    } else {
        None
    }
}

/// Check if any of the `aliases` match a command token, considering both
/// the token itself, the flag portion of an `=`-joined token, and the flag
/// portion of a fused short flag token (e.g. `-n3`).
pub(crate) fn flag_aliases_match_token(aliases: &[String], cmd_token: &str) -> bool {
    aliases.iter().any(|a| a.as_str() == cmd_token)
        || split_flag_equals(cmd_token)
            .is_some_and(|(flag_part, _)| aliases.iter().any(|a| a.as_str() == flag_part))
        || split_short_flag_value(cmd_token, aliases).is_some()
}

/// Check if a negation's inner pattern is flag-only (all alternatives start
/// with `-` and none is the bare `--` separator).
pub(crate) fn is_flag_only_negation(inner: &PatternToken) -> bool {
    match inner {
        PatternToken::Literal(s) => s.starts_with('-') && s != "--",
        PatternToken::Alternation(alts) => alts.iter().all(|a| a.starts_with('-') && a != "--"),
        _ => false,
    }
}

/// Check that flags referenced by the optional group are not present in
/// the command tokens. When we take the "absent" path for an Optional,
/// the flag itself must not appear in the remaining command tokens.
pub(crate) fn optional_flags_absent(optional_tokens: &[PatternToken], cmd_tokens: &[&str]) -> bool {
    for token in optional_tokens {
        match token {
            PatternToken::FlagWithValue { aliases, .. } => {
                if cmd_tokens
                    .iter()
                    .any(|t| flag_aliases_match_token(aliases, t))
                {
                    return false;
                }
            }
            PatternToken::Literal(s) | PatternToken::QuotedLiteral(s) if s.starts_with('-') => {
                if cmd_tokens.contains(&s.as_str()) {
                    return false;
                }
            }
            PatternToken::Alternation(alts) if alts.iter().any(|a| a.starts_with('-')) => {
                if cmd_tokens
                    .iter()
                    .any(|t| alts.iter().any(|a| literal_matches(a, t)))
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::long_flag("--flag=value", Some(("--flag", "value")))]
    #[case::short_flag("-f=val", Some(("-f", "val")))]
    #[case::empty_value("--flag=", Some(("--flag", "")))]
    #[case::multiple_equals("--flag=a=b", Some(("--flag", "a=b")))]
    #[case::no_equals("--flag", None)]
    #[case::java_system_property("-Denv=prod", None)]
    #[case::combined_short_flags_with_equals("-rf=/path", None)]
    #[case::no_dash("KEY=VALUE", None)]
    #[case::equals_only("=value", None)]
    #[case::empty("", None)]
    #[case::dash_only("-", None)]
    fn split_flag_equals_cases(#[case] input: &str, #[case] expected: Option<(&str, &str)>) {
        assert_eq!(
            split_flag_equals(input),
            expected,
            "split_flag_equals({input:?})",
        );
    }

    #[rstest]
    #[case::fused_value("-n3", &["-n"], Some(("-n", "3")))]
    #[case::fused_multichar_value("-n100", &["-n"], Some(("-n", "100")))]
    #[case::no_match("-n3", &["-x"], None)]
    #[case::long_flag("--num3", &["-n"], None)]
    #[case::exact_short_flag("-n", &["-n"], None)]
    #[case::dash_only("-", &["-n"], None)]
    #[case::empty("", &["-n"], None)]
    #[case::multiple_aliases("-n3", &["-n", "--num"], Some(("-n", "3")))]
    #[case::non_ascii_after_dash("-é3", &["-é"], None)]
    fn split_short_flag_value_cases(
        #[case] input: &str,
        #[case] aliases: &[&str],
        #[case] expected: Option<(&str, &str)>,
    ) {
        let aliases: Vec<String> = aliases.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            split_short_flag_value(input, &aliases),
            expected,
            "split_short_flag_value({input:?}, {aliases:?})",
        );
    }
}
