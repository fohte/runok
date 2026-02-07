use super::PatternParseError;

/// Raw token produced by the pattern lexer.
/// The lexer splits a pattern string into these tokens;
/// the parser (task 2.2) will convert them into a structured Pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexToken {
    /// A plain literal string (e.g. "git", "status", "-f")
    Literal(String),
    /// A pipe-separated alternation (e.g. "-X|--request" -> ["-X", "--request"])
    Alternation(Vec<String>),
    /// The wildcard token `*`
    Wildcard,
    /// A negated value (e.g. "!GET" -> Negation("GET"), "!a|b" -> NegationAlternation)
    Negation(String),
    /// A negated alternation (e.g. "!describe|get|list-*")
    NegationAlternation(Vec<String>),
    /// Opening square bracket `[`
    OpenBracket,
    /// Closing square bracket `]`
    CloseBracket,
    /// Angle-bracket placeholder (e.g. "<cmd>", "<path:name>")
    Placeholder(String),
}

/// Tokenize a pattern string into a sequence of `LexToken`s.
pub fn tokenize(pattern: &str) -> Result<Vec<LexToken>, PatternParseError> {
    let mut tokens = Vec::new();
    let mut chars = pattern.char_indices().peekable();
    let mut in_bracket = false;
    let mut bracket_start: Option<usize> = None;

    while let Some(&(pos, ch)) = chars.peek() {
        match ch {
            // Skip whitespace
            ' ' | '\t' => {
                chars.next();
            }

            // Quoted string -> Literal (content without quotes)
            '"' | '\'' => {
                let quote = ch;
                chars.next(); // consume opening quote
                let mut value = String::new();
                let mut closed = false;
                while let Some(&(_, c)) = chars.peek() {
                    chars.next();
                    if c == quote {
                        closed = true;
                        break;
                    }
                    value.push(c);
                }
                if !closed {
                    return Err(PatternParseError::InvalidSyntax(format!(
                        "unclosed quote starting at position {pos}"
                    )));
                }
                tokens.push(LexToken::Literal(value));
            }

            // Angle bracket placeholder: <cmd>, <path:name>
            '<' => {
                chars.next(); // consume '<'
                let mut content = String::new();
                let mut closed = false;
                while let Some(&(_, c)) = chars.peek() {
                    chars.next();
                    if c == '>' {
                        closed = true;
                        break;
                    }
                    content.push(c);
                }
                if !closed {
                    return Err(PatternParseError::UnclosedBracket(pos));
                }
                tokens.push(LexToken::Placeholder(content));
            }

            // Square bracket open
            '[' => {
                if in_bracket {
                    return Err(PatternParseError::NestedSquareBracket);
                }
                in_bracket = true;
                bracket_start = Some(pos);
                tokens.push(LexToken::OpenBracket);
                chars.next();
            }

            // Square bracket close
            ']' => {
                if !in_bracket {
                    return Err(PatternParseError::InvalidSyntax(format!(
                        "unexpected closing bracket at position {pos}"
                    )));
                }
                in_bracket = false;
                bracket_start = None;
                tokens.push(LexToken::CloseBracket);
                chars.next();
            }

            // Negation: !value or !a|b|c
            '!' => {
                chars.next(); // consume '!'
                let word = consume_word(&mut chars, None);
                if word.is_empty() {
                    return Err(PatternParseError::InvalidSyntax(
                        "empty negation".to_string(),
                    ));
                }
                tokens.push(classify_negation(&word)?);
            }

            // Any other character: consume a word (until whitespace, bracket, or angle bracket)
            _ => {
                let word = consume_word(&mut chars, Some(ch));
                tokens.push(classify_word(&word)?);
            }
        }
    }

    if in_bracket {
        return Err(PatternParseError::UnclosedSquareBracket(
            bracket_start.unwrap_or(0),
        ));
    }

    Ok(tokens)
}

/// Consume characters forming a "word" (non-whitespace, non-bracket, non-angle-bracket).
/// If `prefix` is provided, it is prepended to the result.
fn consume_word(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    prefix: Option<char>,
) -> String {
    let mut word = match prefix {
        Some(c) => {
            chars.next(); // consume the prefixed char
            String::from(c)
        }
        None => String::new(),
    };
    while let Some(&(_, c)) = chars.peek() {
        if is_word_boundary(c) {
            break;
        }
        word.push(c);
        chars.next();
    }
    word
}

fn is_word_boundary(c: char) -> bool {
    matches!(c, ' ' | '\t' | '[' | ']' | '<')
}

/// Classify a raw word into the appropriate LexToken.
fn classify_word(word: &str) -> Result<LexToken, PatternParseError> {
    if word == "*" {
        Ok(LexToken::Wildcard)
    } else if word.contains('|') {
        let parts = validate_alternation_parts(word)?;
        Ok(LexToken::Alternation(parts))
    } else {
        Ok(LexToken::Literal(word.to_string()))
    }
}

/// Classify a negation word (after '!') into the appropriate LexToken.
fn classify_negation(word: &str) -> Result<LexToken, PatternParseError> {
    if word.contains('|') {
        let parts = validate_alternation_parts(word)?;
        Ok(LexToken::NegationAlternation(parts))
    } else {
        Ok(LexToken::Negation(word.to_string()))
    }
}

/// Split on '|' and validate that no part is empty.
fn validate_alternation_parts(word: &str) -> Result<Vec<String>, PatternParseError> {
    let parts: Vec<String> = word.split('|').map(|s| s.to_string()).collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(PatternParseError::EmptyAlternation);
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === Basic literal tokens ===

    #[rstest]
    #[case("git status", vec![
        LexToken::Literal("git".into()),
        LexToken::Literal("status".into()),
    ])]
    #[case("rm -rf /", vec![
        LexToken::Literal("rm".into()),
        LexToken::Literal("-rf".into()),
        LexToken::Literal("/".into()),
    ])]
    fn tokenize_literals(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Alternation (pipe-separated, no spaces around pipe) ===

    #[rstest]
    #[case("-X|--request", vec![
        LexToken::Alternation(vec!["-X".into(), "--request".into()]),
    ])]
    #[case("POST|PUT|PATCH", vec![
        LexToken::Alternation(vec!["POST".into(), "PUT".into(), "PATCH".into()]),
    ])]
    #[case("curl -X|--request POST", vec![
        LexToken::Literal("curl".into()),
        LexToken::Alternation(vec!["-X".into(), "--request".into()]),
        LexToken::Literal("POST".into()),
    ])]
    fn tokenize_alternation(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Wildcard ===

    #[rstest]
    #[case("curl *", vec![
        LexToken::Literal("curl".into()),
        LexToken::Wildcard,
    ])]
    #[case("git push *", vec![
        LexToken::Literal("git".into()),
        LexToken::Literal("push".into()),
        LexToken::Wildcard,
    ])]
    fn tokenize_wildcard(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Negation ===

    #[rstest]
    #[case("!GET", vec![
        LexToken::Negation("GET".into()),
    ])]
    #[case("!prod", vec![
        LexToken::Negation("prod".into()),
    ])]
    #[case("!describe|get|list-*", vec![
        LexToken::NegationAlternation(vec!["describe".into(), "get".into(), "list-*".into()]),
    ])]
    fn tokenize_negation(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Square brackets (optional syntax) ===

    #[rstest]
    #[case("[-f]", vec![
        LexToken::OpenBracket,
        LexToken::Literal("-f".into()),
        LexToken::CloseBracket,
    ])]
    #[case("[-X|--request GET]", vec![
        LexToken::OpenBracket,
        LexToken::Alternation(vec!["-X".into(), "--request".into()]),
        LexToken::Literal("GET".into()),
        LexToken::CloseBracket,
    ])]
    #[case("git [-C *] status", vec![
        LexToken::Literal("git".into()),
        LexToken::OpenBracket,
        LexToken::Literal("-C".into()),
        LexToken::Wildcard,
        LexToken::CloseBracket,
        LexToken::Literal("status".into()),
    ])]
    fn tokenize_brackets(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Placeholders (<cmd>, <path:name>) ===

    #[rstest]
    #[case("sudo <cmd>", vec![
        LexToken::Literal("sudo".into()),
        LexToken::Placeholder("cmd".into()),
    ])]
    #[case("cat <path:sensitive>", vec![
        LexToken::Literal("cat".into()),
        LexToken::Placeholder("path:sensitive".into()),
    ])]
    #[case("bash -c <cmd>", vec![
        LexToken::Literal("bash".into()),
        LexToken::Literal("-c".into()),
        LexToken::Placeholder("cmd".into()),
    ])]
    fn tokenize_placeholders(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Quoted strings ===

    #[rstest]
    #[case(r#"git commit -m "WIP*""#, vec![
        LexToken::Literal("git".into()),
        LexToken::Literal("commit".into()),
        LexToken::Literal("-m".into()),
        LexToken::Literal("WIP*".into()),
    ])]
    #[case("echo 'hello world'", vec![
        LexToken::Literal("echo".into()),
        LexToken::Literal("hello world".into()),
    ])]
    fn tokenize_quoted(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Complex patterns ===

    #[rstest]
    #[case("curl -X|--request POST *", vec![
        LexToken::Literal("curl".into()),
        LexToken::Alternation(vec!["-X".into(), "--request".into()]),
        LexToken::Literal("POST".into()),
        LexToken::Wildcard,
    ])]
    #[case("curl -X|--request !GET *", vec![
        LexToken::Literal("curl".into()),
        LexToken::Alternation(vec!["-X".into(), "--request".into()]),
        LexToken::Negation("GET".into()),
        LexToken::Wildcard,
    ])]
    #[case("curl [-X|--request GET] *", vec![
        LexToken::Literal("curl".into()),
        LexToken::OpenBracket,
        LexToken::Alternation(vec!["-X".into(), "--request".into()]),
        LexToken::Literal("GET".into()),
        LexToken::CloseBracket,
        LexToken::Wildcard,
    ])]
    fn tokenize_complex(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Whitespace handling ===

    #[test]
    fn tokenize_multiple_spaces() {
        let result = tokenize("git   status").unwrap();
        assert_eq!(
            result,
            vec![
                LexToken::Literal("git".into()),
                LexToken::Literal("status".into()),
            ]
        );
    }

    #[test]
    fn tokenize_leading_trailing_spaces() {
        let result = tokenize("  git status  ").unwrap();
        assert_eq!(
            result,
            vec![
                LexToken::Literal("git".into()),
                LexToken::Literal("status".into()),
            ]
        );
    }

    // === Error cases ===

    #[test]
    fn tokenize_unclosed_angle_bracket() {
        let result = tokenize("cat <path:sensitive");
        assert!(matches!(result, Err(PatternParseError::UnclosedBracket(_))));
    }

    #[test]
    fn tokenize_unclosed_square_bracket() {
        let result = tokenize("git [-C *");
        assert!(matches!(
            result,
            Err(PatternParseError::UnclosedSquareBracket(_))
        ));
    }

    #[test]
    fn tokenize_nested_square_brackets() {
        let result = tokenize("[[-f]]");
        assert!(matches!(
            result,
            Err(PatternParseError::NestedSquareBracket)
        ));
    }

    #[test]
    fn tokenize_unclosed_quote() {
        let result = tokenize(r#"git commit -m "WIP"#);
        assert!(matches!(result, Err(PatternParseError::InvalidSyntax(_))));
    }

    #[rstest]
    #[case("a||b")]
    #[case("-X|")]
    #[case("|--request")]
    #[case("||")]
    fn tokenize_empty_alternation(#[case] input: &str) {
        let result = tokenize(input);
        assert!(
            matches!(result, Err(PatternParseError::EmptyAlternation)),
            "expected EmptyAlternation for {input:?}, got {result:?}"
        );
    }

    #[rstest]
    #[case("!a||b")]
    #[case("!|b")]
    #[case("!a|")]
    fn tokenize_empty_negation_alternation(#[case] input: &str) {
        let result = tokenize(input);
        assert!(
            matches!(result, Err(PatternParseError::EmptyAlternation)),
            "expected EmptyAlternation for {input:?}, got {result:?}"
        );
    }

    // === Edge cases from design spec ===

    #[test]
    fn tokenize_joined_token_with_equals() {
        // -Denv=prod is a single literal token (joined with =)
        let result = tokenize("java -Denv=prod").unwrap();
        assert_eq!(
            result,
            vec![
                LexToken::Literal("java".into()),
                LexToken::Literal("-Denv=prod".into()),
            ]
        );
    }

    #[test]
    fn tokenize_backslash_escaped_semicolon() {
        // find * -exec <cmd> \; pattern
        let result = tokenize(r"find * -exec <cmd> \;").unwrap();
        assert_eq!(
            result,
            vec![
                LexToken::Literal("find".into()),
                LexToken::Wildcard,
                LexToken::Literal("-exec".into()),
                LexToken::Placeholder("cmd".into()),
                LexToken::Literal(r"\;".into()),
            ]
        );
    }

    #[test]
    fn tokenize_flag_alternation_with_force() {
        let result = tokenize("git push -f|--force *").unwrap();
        assert_eq!(
            result,
            vec![
                LexToken::Literal("git".into()),
                LexToken::Literal("push".into()),
                LexToken::Alternation(vec!["-f".into(), "--force".into()]),
                LexToken::Wildcard,
            ]
        );
    }

    #[test]
    fn tokenize_multiple_optional_groups() {
        let result = tokenize("git [-C *] [--no-pager] log *").unwrap();
        assert_eq!(
            result,
            vec![
                LexToken::Literal("git".into()),
                LexToken::OpenBracket,
                LexToken::Literal("-C".into()),
                LexToken::Wildcard,
                LexToken::CloseBracket,
                LexToken::OpenBracket,
                LexToken::Literal("--no-pager".into()),
                LexToken::CloseBracket,
                LexToken::Literal("log".into()),
                LexToken::Wildcard,
            ]
        );
    }

    #[test]
    fn tokenize_placeholder_directly_after_bracket() {
        // Ensure <placeholder> immediately after ] works
        let result = tokenize("[-v] <cmd>").unwrap();
        assert_eq!(
            result,
            vec![
                LexToken::OpenBracket,
                LexToken::Literal("-v".into()),
                LexToken::CloseBracket,
                LexToken::Placeholder("cmd".into()),
            ]
        );
    }

    #[test]
    fn tokenize_single_literal() {
        let result = tokenize("ls").unwrap();
        assert_eq!(result, vec![LexToken::Literal("ls".into())]);
    }

    #[test]
    fn tokenize_empty_input() {
        let result = tokenize("").unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn tokenize_whitespace_only() {
        let result = tokenize("   ").unwrap();
        assert_eq!(result, vec![]);
    }
}
