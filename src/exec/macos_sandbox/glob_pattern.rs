/// Classification of deny path patterns for SBPL filter selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DenyPathKind {
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
pub(super) fn classify_deny_path(path: &str) -> DenyPathKind {
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
pub(super) fn glob_to_sbpl_regex(pattern: &str) -> String {
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
            // Pass through character class `[...]`, converting glob negation
            // `!` to regex negation `^`
            regex.push('[');
            i += 1;
            if i < len && chars[i] == '!' {
                regex.push('^');
                i += 1;
            }
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
            // Use shared expand_braces to extract alternatives, then convert each
            // through glob_to_sbpl_regex.
            //
            // Extract the brace group from the current position and expand it in
            // isolation so that we get the individual alternatives without
            // prefix/suffix interference.
            let mut depth = 0;
            let mut close = i;
            for (j, &c) in chars.iter().enumerate().skip(i) {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = j;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if close == i {
                // Unmatched `{` — treat as literal
                regex.push_str(r"\{");
                i += 1;
                continue;
            }
            let brace_group: String = chars[i..=close].iter().collect();
            let alternatives = crate::exec::glob_utils::expand_braces(&brace_group);
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
            i = close + 1;
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
    //
    // Each case verifies both the generated regex string AND actual match behavior.
    // `should_match` / `should_not_match` are optional path lists tested against the
    // generated regex using the `regex` crate, catching semantic bugs that string
    // comparison alone cannot detect (e.g., `*` incorrectly matching across `/`).
    //
    // Note: SBPL `(regex ...)` uses partial matching (no implicit `$` anchor),
    // so the generated regex intentionally omits `$`. This means `^a/[^/]*/b`
    // will match `a/foo/bar/b` because SBPL treats any prefix match as a hit.
    // Tests reflect this SBPL behavior.

    #[rstest]
    // --- single star ---
    #[case::single_star(
        ".env*", r"^\.env[^/]*",
        &[".env", ".env.local", ".env.production"],
        &["not.env"],
    )]
    #[case::star_in_middle(
        "/tmp/*.log", r"^/tmp/[^/]*\.log",
        &["/tmp/app.log", "/tmp/my-app.log"],
        &["/tmp/sub/app.log"],
    )]
    // --- double star ---
    #[case::double_star(
        "/etc/**", "^/etc/.*",
        &["/etc/shadow", "/etc/ssl/certs/ca.pem"],
        &["/etcx/shadow"],
    )]
    #[case::double_star_nested(
        "/home/user/.ssh/**", r"^/home/user/\.ssh/.*",
        &["/home/user/.ssh/id_rsa", "/home/user/.ssh/config"],
        &["/home/user/.sshx/id_rsa"],
    )]
    #[case::double_star_with_suffix(
        "/home/**/config", r"^/home/.*/config",
        &["/home/user/config", "/home/user/.config/app/config"],
        &["/homex/.config/config"],
    )]
    #[case::bare_double_star(
        "**", "^.*",
        &["anything", "a/b/c", "/absolute/path"],
        &[],
    )]
    #[case::double_star_prefix(
        "**/*.log", r"^.*/[^/]*\.log",
        &["/var/log/app.log", "/a/b/c/d.log"],
        &[],
    )]
    #[case::double_star_trailing(
        "a/**", "^a/.*",
        &["a/b", "a/b/c/d"],
        &["ax/b"],
    )]
    #[case::double_star_multiple(
        "a/**/b/**/c", "^a/.*/b/.*/c",
        &["a/x/b/y/c", "a/x/y/b/z/w/c"],
        &[],
    )]
    // --- no glob (literal) ---
    #[case::no_glob(
        "/etc/passwd", "^/etc/passwd",
        &["/etc/passwd"],
        &["/etc/shadow"],
    )]
    #[case::dotfile(
        ".envrc", r"^\.envrc",
        &[".envrc"],
        &["envrc", "x.envrc"],
    )]
    // --- question mark ---
    #[case::question_mark(
        "file?.txt", r"^file[^/]\.txt",
        &["fileA.txt", "file1.txt"],
        &["file.txt", "fileAB.txt"],
    )]
    #[case::multiple_question_marks(
        "f??", "^f[^/][^/]",
        &["foo", "f12"],
        &["f1"],
    )]
    // --- character class ---
    #[case::char_class(
        "/tmp/log[0-9].txt", r"^/tmp/log[0-9]\.txt",
        &["/tmp/log3.txt", "/tmp/log0.txt"],
        &["/tmp/loga.txt"],
    )]
    #[case::char_class_negation(
        "[!a-z]", "^[^a-z]",
        &["1", "A", "!"],
        &["a", "m", "z"],
    )]
    #[case::char_class_multiple(
        "[abc][0-9]", "^[abc][0-9]",
        &["a1", "b9", "c0"],
        &["d1", "a"],
    )]
    // --- brace expansion ---
    #[case::brace_expansion(
        "*.{js,ts}", r"^[^/]*\.(js|ts)",
        &["app.js", "index.ts"],
        &["app.rs"],
    )]
    #[case::brace_with_path(
        "/home/**/*.{conf,cfg}", r"^/home/.*/[^/]*\.(conf|cfg)",
        &["/home/user/.config/app.conf", "/home/user/my.cfg"],
        &["/home/user/app.ini"],
    )]
    #[case::brace_empty_alternative(
        "ts{x,}", "^ts(x|)",
        &["tsx", "ts"],
        &[],
    )]
    #[case::brace_nested(
        "{a,{b,c}}", "^(a|b|c)",
        &["a", "b", "c"],
        &["d"],
    )]
    #[case::brace_dot_in_alt(
        "*.{tar.gz,zip}", r"^[^/]*\.(tar\.gz|zip)",
        &["archive.tar.gz", "file.zip"],
        &["file.rar"],
    )]
    #[case::brace_with_glob(
        "{src,lib}/**/*.rs", r"^(src|lib)/.*/[^/]*\.rs",
        &["src/foo/main.rs", "lib/util/helper.rs"],
        &["test/foo/main.rs"],
    )]
    // --- metacharacter escaping ---
    #[case::dots_escaped(
        "file.*.bak", r"^file\.[^/]*\.bak",
        &["file.old.bak"],
        &[],
    )]
    #[case::plus_escaped("a+b", r"^a\+b", &["a+b"], &["aab"])]
    #[case::parens_escaped("(test)", r"^\(test\)", &["(test)"], &["test"])]
    #[case::pipe_escaped("a|b", r"^a\|b", &["a|b"], &[])]
    // --- unmatched brace ---
    #[case::unmatched_brace(
        "{unclosed", r"^\{unclosed",
        &["{unclosed"],
        &["unclosed"],
    )]
    // --- misc ---
    #[case::empty_pattern("", "^", &[], &[])]
    #[case::star_and_question(
        "*.t?t", r"^[^/]*\.t[^/]t",
        &["file.txt", "a.tAt"],
        &["file.toot"],
    )]
    fn glob_to_sbpl_regex_cases(
        #[case] input: &str,
        #[case] expected: &str,
        #[case] should_match: &[&str],
        #[case] should_not_match: &[&str],
    ) {
        let actual = glob_to_sbpl_regex(input);
        assert_eq!(actual, expected);

        let re = regex::Regex::new(&actual)
            .unwrap_or_else(|e| panic!("invalid regex {actual:?} from glob {input:?}: {e}"));

        for path in should_match {
            assert!(
                re.is_match(path),
                "glob {input:?} (regex {actual:?}) should match {path:?}"
            );
        }
        for path in should_not_match {
            assert!(
                !re.is_match(path),
                "glob {input:?} (regex {actual:?}) should NOT match {path:?}"
            );
        }
    }
}
