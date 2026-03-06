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
    /// A multi-word alternation where at least one alternative contains spaces.
    /// e.g., `"npx prettier"|prettier` -> [["npx", "prettier"], ["prettier"]]
    MultiWordAlternation(Vec<Vec<String>>),
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

            // Quoted string -> Literal (content without quotes), or
            // multi-word alternation if followed by `|`
            '"' | '\'' => {
                let quote = ch;
                chars.next(); // consume opening quote
                let value = consume_until(&mut chars, quote).ok_or_else(|| {
                    PatternParseError::InvalidSyntax(format!(
                        "unclosed quote starting at position {pos}"
                    ))
                })?;
                // Check if this starts a multi-word alternation: "quoted"|...
                if let Some(&(_, '|')) = chars.peek() {
                    let first_words: Vec<String> =
                        value.split_whitespace().map(|s| s.to_string()).collect();
                    let token = consume_alternation_continuation(&mut chars, first_words)?;
                    tokens.push(token);
                } else {
                    tokens.push(LexToken::Literal(value));
                }
            }

            // Angle bracket placeholder: <cmd>, <path:name>
            '<' => {
                chars.next(); // consume '<'
                let content = consume_until(&mut chars, '>')
                    .ok_or(PatternParseError::UnclosedBracket(pos))?;
                tokens.push(LexToken::Placeholder(content));
            }

            // Square bracket open
            '[' => {
                // Distinguish optional-group `[-f]` from literal `[` command.
                // When `[` is followed by a space (or is at end of input), it is
                // the POSIX `[` (test) command used as a literal token.
                // When `[` is followed by a non-space character, it starts an
                // optional group.
                let is_literal = {
                    let mut lookahead = chars.clone();
                    lookahead.next(); // consume '['
                    match lookahead.peek() {
                        None => true,                   // `[` at end of input
                        Some(&(_, ' ' | '\t')) => true, // `[ -f ...]` (literal `[` command)
                        _ => false,                     // `[-f]` (optional group)
                    }
                };

                if is_literal {
                    tokens.push(LexToken::Literal("[".to_string()));
                    chars.next();
                } else {
                    if in_bracket {
                        return Err(PatternParseError::NestedSquareBracket);
                    }
                    in_bracket = true;
                    bracket_start = Some(pos);
                    tokens.push(LexToken::OpenBracket);
                    chars.next();
                }
            }

            // Square bracket close
            ']' => {
                if in_bracket {
                    in_bracket = false;
                    bracket_start = None;
                    tokens.push(LexToken::CloseBracket);
                } else {
                    // `]` outside a bracket group is a literal (e.g., the
                    // closing `]` of the POSIX `[` test command)
                    tokens.push(LexToken::Literal("]".to_string()));
                }
                chars.next();
            }

            // Negation: !value or !a|b|c
            '!' => {
                chars.next(); // consume '!'
                let word = consume_word(&mut chars, None, None);
                if word.is_empty() {
                    return Err(PatternParseError::InvalidSyntax(
                        "empty negation".to_string(),
                    ));
                }
                tokens.push(classify_negation(&word)?);
            }

            // Any other character: consume a word (until whitespace, bracket, angle bracket, or quote)
            _ => {
                let word = consume_word(&mut chars, Some(ch), None);
                // Check if the word ends with `|` and next char is a quote,
                // indicating a multi-word alternation like `prettier|"npx prettier"`
                if word.ends_with('|') {
                    if let Some(&(qpos, q @ ('"' | '\''))) = chars.peek() {
                        let prefix = &word[..word.len() - 1];
                        // Split existing pipe-separated parts into individual alternatives
                        let mut alternatives: Vec<Vec<String>> = prefix
                            .split('|')
                            .map(|part| {
                                if part.is_empty() {
                                    Err(PatternParseError::EmptyAlternation)
                                } else {
                                    Ok(vec![part.to_string()])
                                }
                            })
                            .collect::<Result<_, _>>()?;
                        // Now consume the quoted part and any further alternatives
                        chars.next(); // consume opening quote
                        let quoted = consume_until(&mut chars, q).ok_or_else(|| {
                            PatternParseError::InvalidSyntax(format!(
                                "unclosed quote starting at position {qpos}"
                            ))
                        })?;
                        let quoted_words: Vec<String> =
                            quoted.split_whitespace().map(|s| s.to_string()).collect();
                        if quoted_words.is_empty() {
                            return Err(PatternParseError::EmptyAlternation);
                        }
                        // Continue consuming further alternatives if more `|` follow
                        let token = consume_alternation_continuation(&mut chars, quoted_words)?;
                        // Merge: prepend the bare-word alternatives to the continuation result
                        match token {
                            LexToken::MultiWordAlternation(mut rest) => {
                                alternatives.append(&mut rest);
                                tokens.push(classify_multi_word_alternation(alternatives)?);
                            }
                            LexToken::Alternation(rest_alts) => {
                                alternatives.extend(rest_alts.into_iter().map(|alt| vec![alt]));
                                tokens.push(classify_multi_word_alternation(alternatives)?);
                            }
                            _ => unreachable!(
                                "consume_alternation_continuation returned unexpected: {token:?}"
                            ),
                        }
                    } else {
                        // Trailing `|` without a following quote: delegate to classify_word
                        // which will report EmptyAlternation
                        tokens.push(classify_word(&word)?);
                    }
                } else {
                    tokens.push(classify_word(&word)?);
                }
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
/// If `extra_stop` is provided, the function also stops at that character.
fn consume_word(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    prefix: Option<char>,
    extra_stop: Option<char>,
) -> String {
    let mut word = match prefix {
        Some(c) => {
            chars.next(); // consume the prefixed char
            String::from(c)
        }
        None => String::new(),
    };
    while let Some(&(_, c)) = chars.peek() {
        if c == '\\' {
            chars.next(); // consume backslash
            word.push('\\');
            if let Some(&(_, next)) = chars.peek() {
                word.push(next);
                chars.next();
            }
            continue;
        }
        if is_word_boundary(c) || extra_stop == Some(c) {
            break;
        }
        word.push(c);
        chars.next();
    }
    word
}

/// Consume characters until `end_char` is found. Returns `None` if input ends first.
/// Backslash escapes are preserved in the output (e.g., `\*` stays as `\*`)
/// so the matcher can distinguish escaped wildcards from glob wildcards.
fn consume_until(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    end_char: char,
) -> Option<String> {
    let mut s = String::new();
    while let Some((_, c)) = chars.next() {
        if c == '\\' {
            s.push('\\');
            if let Some((_, next)) = chars.next() {
                s.push(next);
            }
            continue;
        }
        if c == end_char {
            return Some(s);
        }
        s.push(c);
    }
    None
}

fn is_word_boundary(c: char) -> bool {
    matches!(c, ' ' | '\t' | '[' | ']' | '<' | '"' | '\'')
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

/// Consume remaining alternatives in a multi-word alternation.
///
/// Called after the first alternative has already been parsed (either quoted or bare word).
/// `first_words` is the word list of the first alternative.
/// Expects the iterator to be positioned at a `|` character (or past the first alternative).
/// Returns a `MultiWordAlternation` token (which may be downgraded to `Alternation` if all
/// alternatives are single-word).
fn consume_alternation_continuation(
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    first_words: Vec<String>,
) -> Result<LexToken, PatternParseError> {
    let mut alternatives = vec![first_words];

    while let Some(&(_, '|')) = chars.peek() {
        chars.next(); // consume '|'

        match chars.peek() {
            Some(&(pos, q @ ('"' | '\''))) => {
                chars.next(); // consume opening quote
                let quoted = consume_until(chars, q).ok_or_else(|| {
                    PatternParseError::InvalidSyntax(format!(
                        "unclosed quote starting at position {pos}"
                    ))
                })?;
                let words: Vec<String> = quoted.split_whitespace().map(|s| s.to_string()).collect();
                if words.is_empty() {
                    return Err(PatternParseError::EmptyAlternation);
                }
                alternatives.push(words);
            }
            Some(&(_, c)) if !is_word_boundary(c) => {
                let word = consume_word(chars, Some(c), Some('|'));
                if word.is_empty() {
                    return Err(PatternParseError::EmptyAlternation);
                }
                alternatives.push(vec![word]);
            }
            _ => {
                return Err(PatternParseError::EmptyAlternation);
            }
        }
    }

    classify_multi_word_alternation(alternatives)
}

/// Classify a list of word-list alternatives into the appropriate LexToken.
///
/// If all alternatives are single-word, returns `Alternation`.
/// Otherwise returns `MultiWordAlternation`.
fn classify_multi_word_alternation(
    alternatives: Vec<Vec<String>>,
) -> Result<LexToken, PatternParseError> {
    if alternatives.iter().all(|alt| alt.len() == 1) {
        // All single-word: use regular Alternation
        let parts: Vec<String> = alternatives.into_iter().map(|mut v| v.remove(0)).collect();
        validate_alternation_parts_vec(&parts)?;
        Ok(LexToken::Alternation(parts))
    } else {
        // At least one multi-word alternative
        for alt in &alternatives {
            if alt.is_empty() {
                return Err(PatternParseError::EmptyAlternation);
            }
        }
        Ok(LexToken::MultiWordAlternation(alternatives))
    }
}

/// Validate that no part in a pre-split alternation is empty.
fn validate_alternation_parts_vec(parts: &[String]) -> Result<(), PatternParseError> {
    for part in parts {
        if part.is_empty() {
            return Err(PatternParseError::EmptyAlternation);
        }
    }
    Ok(())
}

/// Split on '|' and validate that no part is empty.
fn validate_alternation_parts(word: &str) -> Result<Vec<String>, PatternParseError> {
    word.split('|')
        .map(|s| {
            if s.is_empty() {
                Err(PatternParseError::EmptyAlternation)
            } else {
                Ok(s.to_string())
            }
        })
        .collect()
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

    // === Literal bracket (POSIX `[` test command) ===

    #[rstest]
    #[case::bracket_command_wildcard("[ *", vec![
        LexToken::Literal("[".into()),
        LexToken::Wildcard,
    ])]
    #[case::bracket_command_with_args("[ -f file ]", vec![
        LexToken::Literal("[".into()),
        LexToken::Literal("-f".into()),
        LexToken::Literal("file".into()),
        LexToken::Literal("]".into()),
    ])]
    #[case::bracket_at_end("[", vec![
        LexToken::Literal("[".into()),
    ])]
    #[case::close_bracket_outside_group("] foo", vec![
        LexToken::Literal("]".into()),
        LexToken::Literal("foo".into()),
    ])]
    fn tokenize_literal_brackets(#[case] input: &str, #[case] expected: Vec<LexToken>) {
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
    #[case::double_quoted_glob(r#"git commit -m "WIP*""#, vec![
        LexToken::Literal("git".into()),
        LexToken::Literal("commit".into()),
        LexToken::Literal("-m".into()),
        LexToken::Literal("WIP*".into()),
    ])]
    #[case::single_quoted_with_space("echo 'hello world'", vec![
        LexToken::Literal("echo".into()),
        LexToken::Literal("hello world".into()),
    ])]
    #[case::escaped_star_in_quotes(r#"git commit -m "WIP\*""#, vec![
        LexToken::Literal("git".into()),
        LexToken::Literal("commit".into()),
        LexToken::Literal("-m".into()),
        LexToken::Literal(r"WIP\*".into()),
    ])]
    #[case::escaped_star_unquoted(r"cmd WIP\*", vec![
        LexToken::Literal("cmd".into()),
        LexToken::Literal(r"WIP\*".into()),
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

    // === Multi-word alternation ===

    #[rstest]
    #[case::quoted_then_bare(
        r#""npx prettier"|prettier"#,
        vec![LexToken::MultiWordAlternation(vec![
            vec!["npx".into(), "prettier".into()],
            vec!["prettier".into()],
        ])]
    )]
    #[case::bare_then_quoted(
        r#"prettier|"npx prettier""#,
        vec![LexToken::MultiWordAlternation(vec![
            vec!["prettier".into()],
            vec!["npx".into(), "prettier".into()],
        ])]
    )]
    #[case::three_alternatives(
        r#""npx prettier"|"bunx prettier"|prettier"#,
        vec![LexToken::MultiWordAlternation(vec![
            vec!["npx".into(), "prettier".into()],
            vec!["bunx".into(), "prettier".into()],
            vec!["prettier".into()],
        ])]
    )]
    #[case::multi_word_with_trailing_tokens(
        r#""npx prettier"|prettier *"#,
        vec![
            LexToken::MultiWordAlternation(vec![
                vec!["npx".into(), "prettier".into()],
                vec!["prettier".into()],
            ]),
            LexToken::Wildcard,
        ]
    )]
    #[case::all_single_word_quoted_becomes_alternation(
        r#""ast-grep"|sg"#,
        vec![LexToken::Alternation(vec!["ast-grep".into(), "sg".into()])]
    )]
    #[case::mixed_single_and_multi_word(
        r#"prettier|"npx prettier"|"bunx prettier""#,
        vec![LexToken::MultiWordAlternation(vec![
            vec!["prettier".into()],
            vec!["npx".into(), "prettier".into()],
            vec!["bunx".into(), "prettier".into()],
        ])]
    )]
    #[case::single_quoted_multi_word(
        "prettier|'npx prettier'",
        vec![LexToken::MultiWordAlternation(vec![
            vec!["prettier".into()],
            vec!["npx".into(), "prettier".into()],
        ])]
    )]
    #[case::all_single_word_via_bare_and_quoted(
        r#"foo|"bar""#,
        vec![LexToken::Alternation(vec!["foo".into(), "bar".into()])]
    )]
    #[case::three_bare_and_quoted_single_word(
        r#"foo|"bar"|baz"#,
        vec![LexToken::Alternation(vec!["foo".into(), "bar".into(), "baz".into()])]
    )]
    #[case::quoted_multi_then_two_bare(
        r#""npx prettier"|foo|bar"#,
        vec![LexToken::MultiWordAlternation(vec![
            vec!["npx".into(), "prettier".into()],
            vec!["foo".into()],
            vec!["bar".into()],
        ])]
    )]
    #[case::bare_pipe_bare_pipe_quoted(
        r#"foo|bar|"npx prettier""#,
        vec![LexToken::MultiWordAlternation(vec![
            vec!["foo".into()],
            vec!["bar".into()],
            vec!["npx".into(), "prettier".into()],
        ])]
    )]
    fn tokenize_multi_word_alternation(#[case] input: &str, #[case] expected: Vec<LexToken>) {
        assert_eq!(tokenize(input).unwrap(), expected);
    }

    // === Multi-word alternation error cases ===

    #[rstest]
    #[case::empty_quoted_alternative(r#"""|prettier"#)]
    #[case::trailing_pipe_after_quoted(r#""npx prettier"|"#)]
    fn tokenize_multi_word_alternation_errors(#[case] input: &str) {
        let result = tokenize(input);
        assert!(
            matches!(result, Err(PatternParseError::EmptyAlternation)),
            "expected EmptyAlternation for {input:?}, got {result:?}"
        );
    }

    #[rstest]
    #[case::bare_then_unclosed_quote(
        r#"prettier|"npx prettier"#,
        "invalid syntax: unclosed quote starting at position 9"
    )]
    #[case::quoted_then_unclosed_quote(
        r#""npx prettier"|"bunx prettier"#,
        "invalid syntax: unclosed quote starting at position 15"
    )]
    fn tokenize_multi_word_unclosed_quote_reports_quote_position(
        #[case] input: &str,
        #[case] expected_msg: &str,
    ) {
        let err = tokenize(input).expect_err(&format!("expected error for: {input:?}"));
        assert_eq!(err.to_string(), expected_msg);
    }

    // === Backward compatibility: single-word alternation unchanged ===

    #[test]
    fn tokenize_single_word_alternation_unchanged() {
        // Existing single-word alternation should still produce Alternation, not MultiWordAlternation
        let result = tokenize("ast-grep|sg").unwrap();
        assert_eq!(
            result,
            vec![LexToken::Alternation(vec!["ast-grep".into(), "sg".into()])]
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
