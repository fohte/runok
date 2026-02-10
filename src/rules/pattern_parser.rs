//! Pattern and PatternToken data types, and the parser that converts
//! pattern strings into structured Pattern values.

use super::pattern_lexer::LexToken;

/// A parsed pattern consisting of a command name and a sequence of tokens.
#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub command: String,
    pub tokens: Vec<PatternToken>,
}

/// Individual tokens within a pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum PatternToken {
    /// Fixed string (e.g., "git", "status")
    Literal(String),
    /// Alternation (e.g., -X|--request -> ["-X", "--request"])
    Alternation(Vec<String>),
    /// Flag with its value (e.g., -X|--request POST -> aliases + value)
    FlagWithValue {
        aliases: Vec<String>,
        value: Box<PatternToken>,
    },
    /// Negation (e.g., !GET, !describe|get|list-*)
    Negation(Box<PatternToken>),
    /// Optional group (e.g., [-X GET] -> matches with or without)
    Optional(Vec<PatternToken>),
    /// Wildcard: matches zero or more arbitrary tokens
    Wildcard,
    /// Path variable reference (e.g., <path:sensitive>)
    PathRef(String),
    /// Wrapper placeholder (e.g., <cmd>)
    Placeholder(String),
}

/// Parse a pattern string into a Pattern struct.
///
/// The first whitespace-delimited token becomes the command name.
/// Remaining tokens are converted to PatternToken variants based on syntax:
/// - `*` -> Wildcard
/// - `<path:name>` -> PathRef
/// - `<cmd>` -> Placeholder (single word, no pipe, no colon)
/// - `!value` -> Negation
/// - `[...]` -> Optional group
/// - `-X|--request value` -> FlagWithValue (alternation signals value-taking flag)
/// - `word|word` -> Alternation
/// - everything else -> Literal
pub fn parse(pattern: &str) -> Result<Pattern, super::PatternParseError> {
    use super::PatternParseError;

    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
    }

    let lex_tokens = super::pattern_lexer::tokenize(trimmed)?;
    if lex_tokens.is_empty() {
        return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
    }

    let command = match &lex_tokens[0] {
        LexToken::Literal(s) => s.clone(),
        other => {
            return Err(PatternParseError::InvalidSyntax(format!(
                "expected command name, got {other:?}"
            )));
        }
    };

    let rest = &lex_tokens[1..];
    let tokens = build_pattern_tokens(rest, false)?;

    Ok(Pattern { command, tokens })
}

/// Convert LexTokens into PatternToken values, handling
/// flag-with-value association, optional groups, and other pattern syntax.
fn build_pattern_tokens(
    lex_tokens: &[LexToken],
    inside_group: bool,
) -> Result<Vec<PatternToken>, super::PatternParseError> {
    use super::PatternParseError;

    let mut result = Vec::new();
    let mut iter = lex_tokens.iter().enumerate().peekable();

    while let Some((i, token)) = iter.next() {
        match token {
            LexToken::Wildcard => {
                result.push(PatternToken::Wildcard);
            }

            LexToken::Literal(s) => {
                result.push(PatternToken::Literal(s.clone()));
            }

            LexToken::Alternation(alts) => {
                if alts.iter().any(|a| is_flag(a)) {
                    // Check if the next token should be consumed as a flag value
                    if let Some(&(j, next)) = iter.peek() {
                        if should_consume_as_value(next, j + 1 < lex_tokens.len(), inside_group) {
                            let (_, next_token) = iter.next().ok_or(
                                PatternParseError::InvalidSyntax("unexpected end of tokens".into()),
                            )?;
                            let value = lex_to_pattern_value(next_token)?;
                            result.push(PatternToken::FlagWithValue {
                                aliases: alts.clone(),
                                value: Box::new(value),
                            });
                        } else {
                            result.push(PatternToken::Alternation(alts.clone()));
                        }
                    } else {
                        result.push(PatternToken::Alternation(alts.clone()));
                    }
                } else {
                    result.push(PatternToken::Alternation(alts.clone()));
                }
            }

            LexToken::Negation(s) => {
                result.push(PatternToken::Negation(Box::new(PatternToken::Literal(
                    s.clone(),
                ))));
            }

            LexToken::NegationAlternation(alts) => {
                result.push(PatternToken::Negation(Box::new(PatternToken::Alternation(
                    alts.clone(),
                ))));
            }

            LexToken::Placeholder(content) => {
                let pt = parse_placeholder(content)?;
                result.push(pt);
            }

            LexToken::OpenBracket => {
                // Collect tokens until CloseBracket
                let mut inner = Vec::new();
                let bracket_pos = i;
                loop {
                    match iter.next() {
                        Some((_, LexToken::CloseBracket)) => break,
                        Some((_, t)) => inner.push(t.clone()),
                        None => {
                            return Err(PatternParseError::UnclosedSquareBracket(bracket_pos));
                        }
                    }
                }
                let inner_tokens = build_pattern_tokens(&inner, true)?;
                result.push(PatternToken::Optional(inner_tokens));
            }

            LexToken::CloseBracket => {
                return Err(PatternParseError::InvalidSyntax(
                    "unexpected closing bracket".into(),
                ));
            }
        }
    }

    Ok(result)
}

/// Convert a single LexToken into a PatternToken for use as a flag value.
fn lex_to_pattern_value(token: &LexToken) -> Result<PatternToken, super::PatternParseError> {
    match token {
        LexToken::Wildcard => Ok(PatternToken::Wildcard),
        LexToken::Literal(s) => Ok(PatternToken::Literal(s.clone())),
        LexToken::Negation(s) => Ok(PatternToken::Negation(Box::new(PatternToken::Literal(
            s.clone(),
        )))),
        LexToken::NegationAlternation(alts) => Ok(PatternToken::Negation(Box::new(
            PatternToken::Alternation(alts.clone()),
        ))),
        LexToken::Placeholder(content) => parse_placeholder(content),
        LexToken::Alternation(alts) => Ok(PatternToken::Alternation(alts.clone())),
        LexToken::OpenBracket | LexToken::CloseBracket => Err(
            super::PatternParseError::InvalidSyntax("bracket cannot be used as flag value".into()),
        ),
    }
}

/// Parse angle-bracket placeholder content into PathRef or Placeholder.
fn parse_placeholder(content: &str) -> Result<PatternToken, super::PatternParseError> {
    if content.is_empty() {
        return Err(super::PatternParseError::InvalidSyntax(
            "empty angle brackets".into(),
        ));
    }

    if content.contains('|') {
        return Err(super::PatternParseError::InvalidSyntax(format!(
            "alternation inside angle brackets is not supported, use bare pipe: {content}"
        )));
    }

    if let Some(name) = content.strip_prefix("path:") {
        return Ok(PatternToken::PathRef(name.to_string()));
    }

    Ok(PatternToken::Placeholder(content.to_string()))
}

/// Determine whether a LexToken should be consumed as a flag's value.
///
/// A token is consumed as a value when:
/// - It is a non-wildcard token that doesn't look like a flag itself, OR
/// - It is `Wildcard` AND there are more tokens after it (so `*` is the value, not the trailing wildcard).
///
/// This prevents `-f|--force *` (where `*` is the last token) from being parsed as
/// FlagWithValue, while allowing `-X|--request * *` to parse the first `*` as a value.
fn should_consume_as_value(next: &LexToken, has_more_after: bool, inside_group: bool) -> bool {
    match next {
        LexToken::OpenBracket | LexToken::CloseBracket => false,
        LexToken::Literal(s) if is_flag(s) => false,
        LexToken::Alternation(alts) if alts.iter().any(|a| is_flag(a)) => false,
        LexToken::Wildcard => inside_group || has_more_after,
        _ => true,
    }
}

/// Check if a string looks like a flag (starts with `-`).
fn is_flag(s: &str) -> bool {
    s.starts_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn assert_parse(input: &str, expected_command: &str, expected_tokens: Vec<PatternToken>) {
        let result = parse(input).unwrap();
        assert_eq!(result.command, expected_command);
        assert_eq!(result.tokens, expected_tokens);
    }

    #[rstest]
    #[case::command_only("git", "git", vec![])]
    #[case::simple("git status", "git", vec![
        PatternToken::Literal("status".into()),
    ])]
    #[case::multiple("git remote add origin", "git", vec![
        PatternToken::Literal("remote".into()),
        PatternToken::Literal("add".into()),
        PatternToken::Literal("origin".into()),
    ])]
    #[case::joined_equals("java -Denv=prod", "java", vec![
        PatternToken::Literal("-Denv=prod".into()),
    ])]
    #[case::single_quoted("git commit -m 'WIP*'", "git", vec![
        PatternToken::Literal("commit".into()),
        PatternToken::Literal("-m".into()),
        PatternToken::Literal("WIP*".into()),
    ])]
    #[case::double_quoted(r#"git commit -m "WIP*""#, "git", vec![
        PatternToken::Literal("commit".into()),
        PatternToken::Literal("-m".into()),
        PatternToken::Literal("WIP*".into()),
    ])]
    fn parse_literals(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::standalone("git *", "git", vec![PatternToken::Wildcard])]
    #[case::between_literals("git push * --force", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Wildcard,
        PatternToken::Literal("--force".into()),
    ])]
    fn parse_wildcard(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::value_alternation("git push origin main|master", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Literal("origin".into()),
        PatternToken::Alternation(vec!["main".into(), "master".into()]),
    ])]
    #[case::non_flag("kubectl describe|get|list *", "kubectl", vec![
        PatternToken::Alternation(vec!["describe".into(), "get".into(), "list".into()]),
        PatternToken::Wildcard,
    ])]
    fn parse_alternation(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::literal_value("curl -X|--request POST *", "curl", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-X".into(), "--request".into()],
            value: Box::new(PatternToken::Literal("POST".into())),
        },
        PatternToken::Wildcard,
    ])]
    #[case::wildcard_value("curl -X|--request * *", "curl", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-X".into(), "--request".into()],
            value: Box::new(PatternToken::Wildcard),
        },
        PatternToken::Wildcard,
    ])]
    #[case::named_value("aws -p|--profile prod *", "aws", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-p".into(), "--profile".into()],
            value: Box::new(PatternToken::Literal("prod".into())),
        },
        PatternToken::Wildcard,
    ])]
    #[case::trailing_wildcard_not_consumed("git commit -m|--message *", "git", vec![
        PatternToken::Literal("commit".into()),
        PatternToken::Alternation(vec!["-m".into(), "--message".into()]),
        PatternToken::Wildcard,
    ])]
    #[case::boolean_flag("git push -f|--force *", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Alternation(vec!["-f".into(), "--force".into()]),
        PatternToken::Wildcard,
    ])]
    #[case::placeholder_value("cmd -o|--option <cmd>", "cmd", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-o".into(), "--option".into()],
            value: Box::new(PatternToken::Placeholder("cmd".into())),
        },
    ])]
    #[case::path_ref_value("cmd -c|--config <path:config>", "cmd", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-c".into(), "--config".into()],
            value: Box::new(PatternToken::PathRef("config".into())),
        },
    ])]
    fn parse_flag_with_value(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::long_flag("aws --profile prod *", "aws", vec![
        PatternToken::Literal("--profile".into()),
        PatternToken::Literal("prod".into()),
        PatternToken::Wildcard,
    ])]
    #[case::short_flag("git -C /tmp status", "git", vec![
        PatternToken::Literal("-C".into()),
        PatternToken::Literal("/tmp".into()),
        PatternToken::Literal("status".into()),
    ])]
    #[case::not_consuming_positional("git push --force origin", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Literal("--force".into()),
        PatternToken::Literal("origin".into()),
    ])]
    #[case::not_consuming_wildcard("git --verbose *", "git", vec![
        PatternToken::Literal("--verbose".into()),
        PatternToken::Wildcard,
    ])]
    #[case::at_end("git push --force", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Literal("--force".into()),
    ])]
    #[case::multi_char_short("rm -rf /", "rm", vec![
        PatternToken::Literal("-rf".into()),
        PatternToken::Literal("/".into()),
    ])]
    fn parse_single_flag_as_literal(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::literal("aws --profile !prod *", "aws", vec![
        PatternToken::Literal("--profile".into()),
        PatternToken::Negation(Box::new(PatternToken::Literal("prod".into()))),
        PatternToken::Wildcard,
    ])]
    #[case::alternation("kubectl !describe|get|list *", "kubectl", vec![
        PatternToken::Negation(Box::new(PatternToken::Alternation(vec![
            "describe".into(), "get".into(), "list".into(),
        ]))),
        PatternToken::Wildcard,
    ])]
    fn parse_negation(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::single_flag("rm [-f] *", "rm", vec![
        PatternToken::Optional(vec![PatternToken::Literal("-f".into())]),
        PatternToken::Wildcard,
    ])]
    #[case::flag_with_value("curl [-X|--request GET] *", "curl", vec![
        PatternToken::Optional(vec![PatternToken::FlagWithValue {
            aliases: vec!["-X".into(), "--request".into()],
            value: Box::new(PatternToken::Literal("GET".into())),
        }]),
        PatternToken::Wildcard,
    ])]
    #[case::multiple_tokens("git [-C *] status", "git", vec![
        PatternToken::Optional(vec![
            PatternToken::Literal("-C".into()),
            PatternToken::Wildcard,
        ]),
        PatternToken::Literal("status".into()),
    ])]
    fn parse_optional(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::placeholder("sudo <cmd>", "sudo", vec![
        PatternToken::Placeholder("cmd".into()),
    ])]
    #[case::path_ref("cat <path:sensitive>", "cat", vec![
        PatternToken::PathRef("sensitive".into()),
    ])]
    fn parse_placeholder(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::empty_string("", "InvalidSyntax")]
    #[case::whitespace_only("   ", "InvalidSyntax")]
    #[case::unclosed_angle_bracket("curl <cmd", "UnclosedBracket")]
    #[case::unclosed_square_bracket("rm [-f *", "UnclosedSquareBracket")]
    #[case::nested_square_brackets("git [[-C *]] status", "NestedSquareBracket")]
    #[case::empty_angle_brackets("curl <> GET", "InvalidSyntax")]
    #[case::angle_bracket_with_pipe("curl <-X|--request> POST *", "InvalidSyntax")]
    #[case::angle_bracket_value_alternation("git push origin <main|master>", "InvalidSyntax")]
    #[case::empty_alternation("kubectl describe| *", "EmptyAlternation")]
    #[case::empty_negation_alternation("kubectl !a||b *", "EmptyAlternation")]
    #[case::unclosed_single_quote("git commit -m 'WIP", "InvalidSyntax")]
    #[case::unclosed_double_quote(r#"git commit -m "WIP"#, "InvalidSyntax")]
    fn parse_err(#[case] input: &str, #[case] expected_variant: &str) {
        let err = parse(input).expect_err(&format!("expected error for: {input:?}"));
        let debug = format!("{err:?}");
        assert!(
            debug.starts_with(expected_variant),
            "wrong error variant for {input:?}: expected {expected_variant}, got {debug}"
        );
    }
}
