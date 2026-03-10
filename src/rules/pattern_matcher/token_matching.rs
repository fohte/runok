//! Single-token matching utilities.
//!
//! Functions in this module compare a single pattern element (literal, glob,
//! alternation, etc.) against a single command token.

use std::path::{Component, Path};

use crate::config::Definitions;
use crate::rules::pattern_parser::PatternToken;

/// Check if a pattern string matches a command token.
///
/// If the pattern contains `*`, it is treated as a glob pattern
/// where `*` matches zero or more arbitrary characters. Otherwise, an
/// exact string comparison is performed.
pub(crate) fn literal_matches(pattern: &str, token: &str) -> bool {
    if pattern.contains('\\') {
        // Strip backslash escapes so that pattern `\;` matches command token `;`.
        // The pattern lexer preserves backslash-escaped characters as-is (e.g. `\;`),
        // while the command tokenizer resolves them (e.g. `\;` -> `;`).
        // Uses sentinel-based matching so that `\*` is treated as a literal `*`,
        // not a glob, even when the same token also contains a bare `*`.
        unescape_and_match(pattern, token)
    } else if pattern.contains('*') {
        glob_match(pattern, token)
    } else {
        pattern == token
    }
}

/// Remove backslash escapes and perform matching that correctly distinguishes
/// escaped characters from glob wildcards.
///
/// `\;` → matches `;`, `\*` → matches literal `*` (not a glob), `\\` → matches `\`.
///
/// When the pattern contains both `\*` (literal) and bare `*` (glob), the
/// escaped `*` characters are temporarily replaced with a sentinel (`\x00`)
/// during glob expansion so they are not treated as wildcards.
fn unescape_and_match(pattern: &str, token: &str) -> bool {
    let mut unescaped = String::with_capacity(pattern.len());
    let mut has_unescaped_glob = false;
    let mut has_escaped_star = false;
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                if next == '*' {
                    // Use sentinel for escaped `*` so glob_match won't treat it
                    // as a wildcard. We restore it after matching.
                    unescaped.push('\x00');
                    has_escaped_star = true;
                } else {
                    unescaped.push(next);
                }
            }
        } else {
            if ch == '*' {
                has_unescaped_glob = true;
            }
            unescaped.push(ch);
        }
    }
    if has_unescaped_glob {
        glob_match(&unescaped, token)
    } else {
        // No glob — restore sentinels to `*` and do exact comparison.
        if has_escaped_star {
            let plain = unescaped.replace('\x00', "*");
            plain == token
        } else {
            unescaped == token
        }
    }
}

/// Simple glob matching where `*` matches zero or more arbitrary characters.
///
/// Only supports `*` as a wildcard; no other glob syntax (e.g. `?`, `[...]`)
/// is supported.
///
/// When the pattern contains the sentinel character `\x00` (used by
/// [`unescape_and_match`] for escaped `\*`), sentinels are restored to `*`
/// in each literal segment before comparison so they match a literal `*` in
/// the text rather than acting as a wildcard.
pub(super) fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    // Single `*` (or only `*`s): match anything
    if parts.iter().all(|p| p.is_empty()) {
        return true;
    }

    let has_sentinel = pattern.contains('\x00');
    let mut pos = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        // Restore sentinel `\x00` back to `*` for literal comparison when needed.
        let owned;
        let segment: &str = if has_sentinel && part.contains('\x00') {
            owned = part.replace('\x00', "*");
            &owned
        } else {
            part
        };
        if i == 0 {
            if !text.starts_with(segment) {
                return false;
            }
            pos = segment.len();
        } else if i == parts.len() - 1 {
            if !text[pos..].ends_with(segment) {
                return false;
            }
            pos = text.len();
        } else {
            match text[pos..].find(segment) {
                Some(offset) => pos += offset + segment.len(),
                None => return false,
            }
        }
    }

    // If pattern doesn't end with `*`, we must have consumed the entire text
    if !pattern.ends_with('*') {
        return pos == text.len();
    }

    true
}

/// Check if a single pattern token matches a single command token.
pub(crate) fn match_single_token(
    token: &PatternToken,
    cmd_token: &str,
    definitions: &Definitions,
) -> bool {
    match token {
        PatternToken::Literal(s) => literal_matches(s, cmd_token),
        PatternToken::QuotedLiteral(s) => s == cmd_token,
        PatternToken::Alternation(alts) => alts.iter().any(|a| literal_matches(a, cmd_token)),
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

/// Like [`match_single_token`] but also matches the flag portion of
/// `=`-joined command tokens via [`super::flag_utils::split_flag_equals`]
/// (e.g. `--pre=pdftotext` matches pattern `--pre`). This is the negation
/// counterpart of [`super::flag_utils::flag_aliases_match_token`]: both
/// delegate `=`-joined splitting to `split_flag_equals`, but this function
/// operates on a `PatternToken` (for Negation) rather than a `&[String]`
/// alias list.
pub(crate) fn match_flag_token_with_equals(
    pattern: &PatternToken,
    cmd_token: &str,
    definitions: &Definitions,
) -> bool {
    if match_single_token(pattern, cmd_token, definitions) {
        return true;
    }
    if let Some((flag_part, _)) = super::flag_utils::split_flag_equals(cmd_token) {
        return match_single_token(pattern, flag_part, definitions);
    }
    false
}

/// Normalize a file path by resolving `.` and `..` components without
/// touching the filesystem. This prevents traversal-based bypasses such
/// as `/etc/./passwd` or `/etc/../etc/passwd` when matching `<path:name>`.
pub(crate) fn normalize_path(path: &str) -> String {
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
pub(crate) fn resolve_paths<'a>(name: &str, definitions: &'a Definitions) -> &'a [String] {
    definitions
        .paths
        .as_ref()
        .and_then(|paths| paths.get(name))
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === glob_match unit tests ===

    #[rstest]
    #[case::prefix_glob("list-*", "list-buckets", true)]
    #[case::prefix_glob_short("list-*", "list-", true)]
    #[case::prefix_glob_no_match("list-*", "get-buckets", false)]
    #[case::prefix_glob_no_match_partial("list-*", "lis", false)]
    #[case::suffix_glob("*-buckets", "list-buckets", true)]
    #[case::suffix_glob_no_match("*-buckets", "list-pods", false)]
    #[case::middle_glob("pre*suf", "pre-middle-suf", true)]
    #[case::middle_glob_exact("pre*suf", "presuf", true)]
    #[case::middle_glob_no_match("pre*suf", "pre-middle-end", false)]
    #[case::exact_no_glob("list", "list", true)]
    #[case::exact_no_glob_no_match("list", "list-buckets", false)]
    #[case::star_only("*", "anything", true)]
    #[case::star_only_empty("*", "", true)]
    #[case::multiple_stars("a*b*c", "axbxc", true)]
    #[case::multiple_stars_no_match("a*b*c", "axdxe", false)]
    fn test_glob_match(#[case] pattern: &str, #[case] text: &str, #[case] expected: bool) {
        assert_eq!(
            glob_match(pattern, text),
            expected,
            "glob_match({pattern:?}, {text:?})",
        );
    }

    // === literal_matches: backslash escape ===

    #[rstest]
    #[case::backslash_semicolon(r"\;", ";", true)]
    #[case::backslash_semicolon_no_match(r"\;", "x", false)]
    #[case::backslash_star_literal(r"\*", "*", true)]
    #[case::backslash_star_not_glob(r"\*", "foo", false)]
    #[case::escaped_and_bare_glob(r"\*.*", "*.foo", true)]
    #[case::escaped_and_bare_glob_no_match(r"\*.*", "foo.bar", false)]
    #[case::no_backslash("foo", "foo", true)]
    #[case::plain_glob("fo*", "foobar", true)]
    fn literal_matches_cases(#[case] pattern: &str, #[case] token: &str, #[case] expected: bool) {
        assert_eq!(
            literal_matches(pattern, token),
            expected,
            "literal_matches({pattern:?}, {token:?})",
        );
    }

    // === normalize_path unit tests ===

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
