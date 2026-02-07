use super::{Pattern, PatternParser, PatternToken};
use crate::rules::PatternParseError;

/// Default implementation of the PatternParser trait.
pub struct DefaultPatternParser;

impl PatternParser for DefaultPatternParser {
    fn parse(&self, pattern: &str) -> Result<Pattern, PatternParseError> {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
        }

        let raw_tokens = tokenize(trimmed)?;
        if raw_tokens.is_empty() {
            return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
        }

        let command = match &raw_tokens[0] {
            RawToken::Text(s) => s.clone(),
            _ => {
                return Err(PatternParseError::InvalidSyntax(
                    "pattern must start with a command name".into(),
                ));
            }
        };

        let mut tokens = Vec::new();
        for raw in &raw_tokens[1..] {
            tokens.push(convert_token(raw)?);
        }

        Ok(Pattern { command, tokens })
    }
}

// Internal raw token from the tokenizer, before semantic conversion.
#[derive(Debug)]
enum RawToken {
    Text(String),
    Wildcard,
    AngleBracket(String),
    SquareBracket(Vec<RawToken>),
}

/// Tokenize the pattern string into raw tokens, handling brackets and whitespace.
fn tokenize(input: &str) -> Result<Vec<RawToken>, PatternParseError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Skip whitespace
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        match chars[i] {
            '[' => {
                let start = i;
                i += 1;
                let inner = parse_square_bracket(&chars, &mut i, start)?;
                tokens.push(RawToken::SquareBracket(inner));
            }
            '<' => {
                let start = i;
                i += 1;
                let content = parse_angle_bracket(&chars, &mut i, start)?;
                tokens.push(RawToken::AngleBracket(content));
            }
            '*' => {
                tokens.push(RawToken::Wildcard);
                i += 1;
            }
            _ => {
                let word = read_word(&chars, &mut i);
                if word == "*" {
                    tokens.push(RawToken::Wildcard);
                } else {
                    tokens.push(RawToken::Text(word));
                }
            }
        }
    }

    Ok(tokens)
}

/// Read a whitespace-delimited word, stopping at whitespace or bracket chars.
fn read_word(chars: &[char], i: &mut usize) -> String {
    let mut word = String::new();
    while *i < chars.len() && !chars[*i].is_whitespace() && chars[*i] != '[' && chars[*i] != '<' {
        word.push(chars[*i]);
        *i += 1;
    }
    word
}

/// Parse the contents inside [...], returning the inner tokens.
/// `i` should point to the character after `[`. Updated to point past `]`.
fn parse_square_bracket(
    chars: &[char],
    i: &mut usize,
    start: usize,
) -> Result<Vec<RawToken>, PatternParseError> {
    let mut inner_tokens = Vec::new();

    while *i < chars.len() {
        if chars[*i] == ']' {
            *i += 1;
            return Ok(inner_tokens);
        }

        if chars[*i] == '[' {
            return Err(PatternParseError::NestedSquareBracket);
        }

        if chars[*i].is_whitespace() {
            *i += 1;
            continue;
        }

        match chars[*i] {
            '<' => {
                let angle_start = *i;
                *i += 1;
                let content = parse_angle_bracket(chars, i, angle_start)?;
                inner_tokens.push(RawToken::AngleBracket(content));
            }
            '*' => {
                inner_tokens.push(RawToken::Wildcard);
                *i += 1;
            }
            _ => {
                let word = read_word_in_bracket(chars, i);
                if word == "*" {
                    inner_tokens.push(RawToken::Wildcard);
                } else {
                    inner_tokens.push(RawToken::Text(word));
                }
            }
        }
    }

    Err(PatternParseError::UnclosedSquareBracket(start))
}

/// Read a word inside square brackets, stopping at whitespace, `]`, or `[`.
fn read_word_in_bracket(chars: &[char], i: &mut usize) -> String {
    let mut word = String::new();
    while *i < chars.len()
        && !chars[*i].is_whitespace()
        && chars[*i] != ']'
        && chars[*i] != '['
        && chars[*i] != '<'
    {
        word.push(chars[*i]);
        *i += 1;
    }
    word
}

/// Parse the contents inside <...>, returning the inner string.
/// `i` should point to the character after `<`. Updated to point past `>`.
fn parse_angle_bracket(
    chars: &[char],
    i: &mut usize,
    start: usize,
) -> Result<String, PatternParseError> {
    let mut content = String::new();
    while *i < chars.len() {
        if chars[*i] == '>' {
            *i += 1;
            return Ok(content);
        }
        content.push(chars[*i]);
        *i += 1;
    }
    Err(PatternParseError::UnclosedBracket(start))
}

/// Convert a RawToken into a semantic PatternToken.
fn convert_token(raw: &RawToken) -> Result<PatternToken, PatternParseError> {
    match raw {
        RawToken::Wildcard => Ok(PatternToken::Wildcard),
        RawToken::AngleBracket(content) => parse_angle_content(content),
        RawToken::SquareBracket(inner) => {
            let mut tokens = Vec::new();
            for t in inner {
                tokens.push(convert_token(t)?);
            }
            Ok(PatternToken::Optional(tokens))
        }
        RawToken::Text(text) => parse_text_token(text),
    }
}

/// Parse angle bracket content: <path:name> -> PathRef, <name> -> Placeholder.
fn parse_angle_content(content: &str) -> Result<PatternToken, PatternParseError> {
    if let Some(name) = content.strip_prefix("path:") {
        Ok(PatternToken::PathRef(name.into()))
    } else {
        Ok(PatternToken::Placeholder(content.into()))
    }
}

/// Parse a text token, recognizing negation (`!`) and alternation (`|`).
fn parse_text_token(text: &str) -> Result<PatternToken, PatternParseError> {
    if let Some(rest) = text.strip_prefix('!') {
        if rest.is_empty() {
            return Err(PatternParseError::InvalidSyntax(
                "negation without value".into(),
            ));
        }
        let inner = parse_text_token(rest)?;
        Ok(PatternToken::Negation(Box::new(inner)))
    } else if text.contains('|') {
        let parts: Vec<&str> = text.split('|').collect();
        for part in &parts {
            if part.is_empty() {
                return Err(PatternParseError::EmptyAlternation);
            }
        }
        Ok(PatternToken::Alternation(
            parts.into_iter().map(String::from).collect(),
        ))
    } else {
        Ok(PatternToken::Literal(text.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::rules::PatternParseError;
    use rstest::rstest;

    fn parse(input: &str) -> Result<Pattern, PatternParseError> {
        DefaultPatternParser.parse(input)
    }

    // =========================================================================
    // Normal cases
    // =========================================================================

    // --- Simple patterns (Req 1.1) ---

    #[rstest]
    #[case("git status", "git", &[PatternToken::Literal("status".into())])]
    #[case("rm -rf /", "rm", &[PatternToken::Literal("-rf".into()), PatternToken::Literal("/".into())])]
    #[case("echo hello world", "echo", &[PatternToken::Literal("hello".into()), PatternToken::Literal("world".into())])]
    fn parse_simple_pattern(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: &[PatternToken],
    ) {
        let pattern = parse(input).unwrap();
        assert_eq!(pattern.command, expected_command);
        assert_eq!(pattern.tokens, expected_tokens);
    }

    // --- Alternation / Alias (Req 1.2, 1.3, 1.4) ---

    #[rstest]
    #[case(
        "curl -X|--request POST",
        "curl",
        &[
            PatternToken::Alternation(vec!["-X".into(), "--request".into()]),
            PatternToken::Literal("POST".into()),
        ]
    )]
    #[case(
        "git -f|--force",
        "git",
        &[
            PatternToken::Alternation(vec!["-f".into(), "--force".into()]),
        ]
    )]
    #[case(
        "kubectl describe|get|list",
        "kubectl",
        &[
            PatternToken::Alternation(vec!["describe".into(), "get".into(), "list".into()]),
        ]
    )]
    fn parse_alternation(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: &[PatternToken],
    ) {
        let pattern = parse(input).unwrap();
        assert_eq!(pattern.command, expected_command);
        assert_eq!(pattern.tokens, expected_tokens);
    }

    // --- Wildcard (Req 1.5) ---

    #[rstest]
    #[case(
        "git push *",
        "git",
        &[PatternToken::Literal("push".into()), PatternToken::Wildcard]
    )]
    #[case(
        "python3 *",
        "python3",
        &[PatternToken::Wildcard]
    )]
    #[case(
        "curl -X|--request POST *",
        "curl",
        &[
            PatternToken::Alternation(vec!["-X".into(), "--request".into()]),
            PatternToken::Literal("POST".into()),
            PatternToken::Wildcard,
        ]
    )]
    fn parse_wildcard(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: &[PatternToken],
    ) {
        let pattern = parse(input).unwrap();
        assert_eq!(pattern.command, expected_command);
        assert_eq!(pattern.tokens, expected_tokens);
    }

    // --- Negation (Req 1.4, 4.4) ---

    #[rstest]
    #[case(
        "curl -X|--request !GET *",
        "curl",
        &[
            PatternToken::Alternation(vec!["-X".into(), "--request".into()]),
            PatternToken::Negation(Box::new(PatternToken::Literal("GET".into()))),
            PatternToken::Wildcard,
        ]
    )]
    #[case(
        "kubectl !describe|get|list *",
        "kubectl",
        &[
            PatternToken::Negation(Box::new(PatternToken::Alternation(
                vec!["describe".into(), "get".into(), "list".into()]
            ))),
            PatternToken::Wildcard,
        ]
    )]
    #[case(
        "aws --profile !prod *",
        "aws",
        &[
            PatternToken::Literal("--profile".into()),
            PatternToken::Negation(Box::new(PatternToken::Literal("prod".into()))),
            PatternToken::Wildcard,
        ]
    )]
    fn parse_negation(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: &[PatternToken],
    ) {
        let pattern = parse(input).unwrap();
        assert_eq!(pattern.command, expected_command);
        assert_eq!(pattern.tokens, expected_tokens);
    }

    // --- Optional brackets (Req 1.7, 1.8, 1.9) ---

    #[rstest]
    #[case(
        "git [-C *] status",
        "git",
        &[
            PatternToken::Optional(vec![
                PatternToken::Literal("-C".into()),
                PatternToken::Wildcard,
            ]),
            PatternToken::Literal("status".into()),
        ]
    )]
    #[case(
        "rm [-f] *",
        "rm",
        &[
            PatternToken::Optional(vec![PatternToken::Literal("-f".into())]),
            PatternToken::Wildcard,
        ]
    )]
    #[case(
        "curl [-X|--request GET] *",
        "curl",
        &[
            PatternToken::Optional(vec![
                PatternToken::Alternation(vec!["-X".into(), "--request".into()]),
                PatternToken::Literal("GET".into()),
            ]),
            PatternToken::Wildcard,
        ]
    )]
    fn parse_optional(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: &[PatternToken],
    ) {
        let pattern = parse(input).unwrap();
        assert_eq!(pattern.command, expected_command);
        assert_eq!(pattern.tokens, expected_tokens);
    }

    // --- Compound patterns ---

    #[rstest]
    #[case(
        "git [-C *] [--no-pager] log *",
        "git",
        &[
            PatternToken::Optional(vec![
                PatternToken::Literal("-C".into()),
                PatternToken::Wildcard,
            ]),
            PatternToken::Optional(vec![
                PatternToken::Literal("--no-pager".into()),
            ]),
            PatternToken::Literal("log".into()),
            PatternToken::Wildcard,
        ]
    )]
    #[case(
        "git push -f|--force *",
        "git",
        &[
            PatternToken::Literal("push".into()),
            PatternToken::Alternation(vec!["-f".into(), "--force".into()]),
            PatternToken::Wildcard,
        ]
    )]
    fn parse_compound_pattern(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: &[PatternToken],
    ) {
        let pattern = parse(input).unwrap();
        assert_eq!(pattern.command, expected_command);
        assert_eq!(pattern.tokens, expected_tokens);
    }

    // --- Path references and placeholders ---

    #[rstest]
    #[case(
        "cat <path:sensitive>",
        "cat",
        &[PatternToken::PathRef("sensitive".into())]
    )]
    #[case(
        "sudo <cmd>",
        "sudo",
        &[PatternToken::Placeholder("cmd".into())]
    )]
    #[case(
        "bash -c <cmd>",
        "bash",
        &[PatternToken::Literal("-c".into()), PatternToken::Placeholder("cmd".into())]
    )]
    fn parse_angle_bracket_tokens(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: &[PatternToken],
    ) {
        let pattern = parse(input).unwrap();
        assert_eq!(pattern.command, expected_command);
        assert_eq!(pattern.tokens, expected_tokens);
    }

    // --- Single-word pattern (command only, no arguments) ---

    #[test]
    fn parse_command_only() {
        let pattern = parse("ls").unwrap();
        assert_eq!(pattern.command, "ls");
        assert!(pattern.tokens.is_empty());
    }

    // =========================================================================
    // Error cases
    // =========================================================================

    #[test]
    fn parse_unclosed_angle_bracket() {
        let err = parse("cat <path:sensitive").unwrap_err();
        assert!(matches!(err, PatternParseError::UnclosedBracket(_)));
    }

    #[test]
    fn parse_unclosed_square_bracket() {
        let err = parse("git [-C *").unwrap_err();
        assert!(matches!(err, PatternParseError::UnclosedSquareBracket(_)));
    }

    #[test]
    fn parse_nested_square_brackets() {
        let err = parse("git [[-C *]] status").unwrap_err();
        assert!(matches!(err, PatternParseError::NestedSquareBracket));
    }

    #[rstest]
    #[case("curl -X| *")]
    #[case("curl |--request *")]
    fn parse_empty_alternation(#[case] input: &str) {
        let err = parse(input).unwrap_err();
        assert!(matches!(err, PatternParseError::EmptyAlternation));
    }

    #[test]
    fn parse_bare_negation() {
        let err = parse("cmd !").unwrap_err();
        assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
    }

    #[rstest]
    #[case("* foo")]
    #[case("[--verbose] git status")]
    #[case("<cmd> foo")]
    fn parse_pattern_starting_with_non_command(#[case] input: &str) {
        let err = parse(input).unwrap_err();
        assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
    }

    #[test]
    fn parse_empty_input() {
        let err = parse("").unwrap_err();
        assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
    }

    #[test]
    fn parse_whitespace_only() {
        let err = parse("   ").unwrap_err();
        assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
    }
}
