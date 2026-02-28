/// Expand brace patterns (`{a,b,c}`) into multiple strings.
///
/// For example, `*.{js,ts}` becomes `["*.js", "*.ts"]`.
/// Nested braces are supported: `{a,{b,c}}` becomes `["a", "b", "c"]`.
/// Patterns without braces return a single-element vector unchanged.
pub fn expand_braces(pattern: &str) -> Vec<String> {
    let chars: Vec<char> = pattern.chars().collect();

    // Find the first top-level `{`
    let Some(open) = chars.iter().position(|&c| c == '{') else {
        return vec![pattern.to_string()];
    };

    // Find the matching `}`
    let mut depth = 0;
    let mut close = None;
    for (i, &c) in chars.iter().enumerate().skip(open) {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }

    let Some(close) = close else {
        // Unmatched `{` — treat as literal
        return vec![pattern.to_string()];
    };

    let prefix: String = chars[..open].iter().collect();
    let suffix: String = chars[close + 1..].iter().collect();
    let inner: String = chars[open + 1..close].iter().collect();

    // Split on top-level commas only
    let mut alternatives = Vec::new();
    let mut current = String::new();
    let mut brace_depth = 0;
    for c in inner.chars() {
        match c {
            '{' => {
                brace_depth += 1;
                current.push(c);
            }
            '}' => {
                brace_depth -= 1;
                current.push(c);
            }
            ',' if brace_depth == 0 => {
                alternatives.push(current);
                current = String::new();
            }
            _ => current.push(c),
        }
    }
    alternatives.push(current);

    // Recursively expand each alternative (handles nested braces and
    // braces in the suffix)
    let mut results = Vec::new();
    for alt in alternatives {
        let combined = format!("{prefix}{alt}{suffix}");
        results.extend(expand_braces(&combined));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::simple("{a,b}", &["a", "b"])]
    #[case::with_prefix("pre{a,b}", &["prea", "preb"])]
    #[case::with_suffix("{a,b}suf", &["asuf", "bsuf"])]
    #[case::with_both("pre{a,b}suf", &["preasuf", "prebsuf"])]
    #[case::three_alt("{a,b,c}", &["a", "b", "c"])]
    #[case::nested("{a,{b,c}}", &["a", "b", "c"])]
    #[case::no_braces("plain", &["plain"])]
    #[case::glob_with_brace("*.{js,ts}", &["*.js", "*.ts"])]
    #[case::unmatched_open("{a,b", &["{a,b"])]
    #[case::empty_alternative("{a,}", &["a", ""])]
    fn expand_braces_cases(#[case] input: &str, #[case] expected: &[&str]) {
        let result = expand_braces(input);
        let expected_vec: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        assert_eq!(result, expected_vec);
    }
}
