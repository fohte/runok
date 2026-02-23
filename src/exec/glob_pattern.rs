/// Classification of deny path patterns for SBPL filter selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenyPathKind {
    /// Absolute path without glob characters (e.g., `/etc/shadow`).
    /// Uses SBPL `(subpath ...)` filter.
    AbsoluteLiteral,
    /// Relative path without glob characters (e.g., `.git`, `.secrets`).
    /// Resolved against each writable_root, then uses `(subpath ...)`.
    RelativeLiteral,
    /// Path containing glob characters `*` or `**` (e.g., `.env*`, `/etc/**`).
    /// Converted to SBPL `(regex ...)` filter.
    GlobPattern,
}

/// Classify a deny path to determine the appropriate SBPL filter type.
pub(crate) fn classify_deny_path(path: &str) -> DenyPathKind {
    if path.contains('*') || path.contains('?') || path.contains('[') || path.contains('{') {
        DenyPathKind::GlobPattern
    } else if path.starts_with('/') {
        DenyPathKind::AbsoluteLiteral
    } else {
        DenyPathKind::RelativeLiteral
    }
}

/// Convert a glob pattern to a POSIX ERE regex string for SBPL `(regex ...)` filter.
///
/// Generates POSIX ERE directly to avoid compatibility issues with external crates
/// whose regex output may use Rust-specific syntax unsupported by SBPL.
///
/// Conversion rules:
/// - `**` matches any characters including `/` (directory separator) → `.*`
/// - `*` matches any characters except `/` → `[^/]*`
/// - `?` matches any single character except `/` → `[^/]`
/// - `[...]` is passed through as a POSIX character class
/// - `{a,b,c}` is converted to alternation `(a|b|c)`
/// - Regex metacharacters in literal context are escaped
pub(crate) fn glob_to_sbpl_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '*' && i + 1 < len && chars[i + 1] == '*' {
            regex.push_str(".*");
            i += 2;
            // Skip trailing `/` after `**` only when `**` is at the end of the pattern
            // (e.g., `/etc/**`). When followed by more path components (e.g., `**/config`),
            // keep the `/` so the regex correctly requires a directory separator.
            if i < len && chars[i] == '/' && i + 1 >= len {
                i += 1;
            }
        } else if chars[i] == '*' {
            regex.push_str("[^/]*");
            i += 1;
        } else if chars[i] == '?' {
            regex.push_str("[^/]");
            i += 1;
        } else if chars[i] == '[' {
            // Pass through character class `[...]` as-is
            regex.push('[');
            i += 1;
            while i < len && chars[i] != ']' {
                regex.push(chars[i]);
                i += 1;
            }
            if i < len {
                regex.push(']');
                i += 1;
            }
        } else if chars[i] == '{' {
            // Convert brace expansion `{a,b,c}` to alternation `(a|b|c)`.
            // Each alternative is recursively converted through the same rules.
            i += 1;
            let mut alternatives: Vec<String> = Vec::new();
            let mut current = String::new();
            let mut depth = 1;
            while i < len && depth > 0 {
                if chars[i] == '{' {
                    current.push(chars[i]);
                    depth += 1;
                } else if chars[i] == '}' {
                    depth -= 1;
                    if depth == 0 {
                        alternatives.push(current);
                        current = String::new();
                    } else {
                        current.push(chars[i]);
                    }
                } else if chars[i] == ',' && depth == 1 {
                    alternatives.push(current);
                    current = String::new();
                } else {
                    current.push(chars[i]);
                }
                i += 1;
            }
            // Convert each alternative through glob_to_sbpl_regex and strip the `^` anchor
            let alt_regexes: Vec<String> = alternatives
                .iter()
                .map(|alt| {
                    let r = glob_to_sbpl_regex(alt);
                    // Strip the leading `^` since we embed inside a group
                    r.strip_prefix('^').unwrap_or(&r).to_string()
                })
                .collect();
            regex.push('(');
            regex.push_str(&alt_regexes.join("|"));
            regex.push(')');
        } else if is_regex_metachar(chars[i]) {
            regex.push('\\');
            regex.push(chars[i]);
            i += 1;
        } else {
            regex.push(chars[i]);
            i += 1;
        }
    }

    regex
}

fn is_regex_metachar(c: char) -> bool {
    matches!(c, '.' | '+' | '(' | ')' | '|' | '^' | '$' | '\\')
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === classify_deny_path ===

    #[rstest]
    #[case::absolute_path("/etc/shadow", DenyPathKind::AbsoluteLiteral)]
    #[case::absolute_dir("/home/user/.git", DenyPathKind::AbsoluteLiteral)]
    #[case::relative_dotfile(".git", DenyPathKind::RelativeLiteral)]
    #[case::relative_secrets(".secrets", DenyPathKind::RelativeLiteral)]
    #[case::relative_dotenv(".env", DenyPathKind::RelativeLiteral)]
    #[case::glob_relative(".env*", DenyPathKind::GlobPattern)]
    #[case::glob_absolute("/etc/**", DenyPathKind::GlobPattern)]
    #[case::glob_deep("/home/user/.ssh/**", DenyPathKind::GlobPattern)]
    #[case::glob_single_star("/tmp/*.log", DenyPathKind::GlobPattern)]
    #[case::glob_question_mark("file?.txt", DenyPathKind::GlobPattern)]
    #[case::glob_char_class("/tmp/log[0-9].txt", DenyPathKind::GlobPattern)]
    #[case::glob_brace("*.{js,ts}", DenyPathKind::GlobPattern)]
    fn classify_deny_path_cases(#[case] input: &str, #[case] expected: DenyPathKind) {
        assert_eq!(classify_deny_path(input), expected);
    }

    // === glob_to_sbpl_regex ===

    #[rstest]
    #[case::single_star(".env*", r"^\.env[^/]*")]
    #[case::double_star("/etc/**", "^/etc/.*")]
    #[case::double_star_nested("/home/user/.ssh/**", r"^/home/user/\.ssh/.*")]
    #[case::no_glob("/etc/passwd", "^/etc/passwd")]
    #[case::dotfile(".envrc", r"^\.envrc")]
    #[case::star_in_middle("/tmp/*.log", r"^/tmp/[^/]*\.log")]
    #[case::double_star_with_suffix("/home/**/config", r"^/home/.*/config")]
    #[case::question_mark("file?.txt", r"^file[^/]\.txt")]
    #[case::char_class("/tmp/log[0-9].txt", r"^/tmp/log[0-9]\.txt")]
    #[case::brace_expansion("*.{js,ts}", r"^[^/]*\.(js|ts)")]
    #[case::brace_with_path("/home/**/*.{conf,cfg}", r"^/home/.*/[^/]*\.(conf|cfg)")]
    fn glob_to_sbpl_regex_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(glob_to_sbpl_regex(input), expected);
    }
}
