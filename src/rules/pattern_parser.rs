//! Pattern and PatternToken data types, and the parser that converts
//! pattern strings into structured Pattern values.

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
/// - `<-X|--request>` -> flag-like Alternation (consumed with next token as FlagWithValue)
/// - `<main|master>` -> non-flag Alternation
/// - `<path:name>` -> PathRef
/// - `<cmd>` -> Placeholder (single word, no pipe, no colon)
/// - `!value` -> Negation
/// - `[...]` -> Optional group
/// - `--flag`/`-X` followed by non-flag value -> FlagWithValue
/// - bare `word|word` -> Alternation
/// - everything else -> Literal
pub fn parse(pattern: &str) -> Result<Pattern, super::PatternParseError> {
    use super::PatternParseError;

    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
    }

    let raw_tokens = tokenize(trimmed)?;
    if raw_tokens.is_empty() {
        return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
    }

    let command = raw_tokens[0].clone();
    let rest = &raw_tokens[1..];
    let tokens = build_pattern_tokens(rest)?;

    Ok(Pattern { command, tokens })
}

/// Split the pattern string into raw tokens, respecting:
/// - `<...>` angle bracket groups (kept as single tokens including delimiters)
/// - `[...]` square bracket groups (kept as single tokens including delimiters)
/// - single/double quoted strings (quotes stripped, content kept as one token)
/// - whitespace separation
fn tokenize(input: &str) -> Result<Vec<String>, super::PatternParseError> {
    use super::PatternParseError;

    let mut tokens = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '<' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                let start = i;
                i += 1;
                let mut content = String::new();
                while i < chars.len() && chars[i] != '>' {
                    content.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(PatternParseError::UnclosedBracket(start));
                }
                i += 1; // skip '>'
                tokens.push(format!("<{content}>"));
            }
            '[' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                let start = i;
                i += 1;
                let mut content = String::new();
                while i < chars.len() {
                    if chars[i] == '[' {
                        return Err(PatternParseError::NestedSquareBracket);
                    }
                    if chars[i] == ']' {
                        break;
                    }
                    content.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(PatternParseError::UnclosedSquareBracket(start));
                }
                i += 1; // skip ']'
                tokens.push(format!("[{content}]"));
            }
            '\'' | '"' => {
                let quote = chars[i];
                i += 1;
                let mut quoted = String::new();
                while i < chars.len() && chars[i] != quote {
                    quoted.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    i += 1; // skip closing quote
                }
                // Append quoted content to current token (allows for adjacent text)
                current.push_str(&quoted);
            }
            ' ' | '\t' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                i += 1;
            }
            c => {
                current.push(c);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}

/// Convert raw token strings into PatternToken values, handling
/// flag-with-value association and other pattern syntax.
fn build_pattern_tokens(
    raw_tokens: &[String],
) -> Result<Vec<PatternToken>, super::PatternParseError> {
    build_pattern_tokens_inner(raw_tokens, false)
}

fn build_pattern_tokens_inner(
    raw_tokens: &[String],
    inside_group: bool,
) -> Result<Vec<PatternToken>, super::PatternParseError> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < raw_tokens.len() {
        let token = &raw_tokens[i];

        if token.starts_with('[') && token.ends_with(']') {
            // Optional group: parse the inner content recursively
            let inner = &token[1..token.len() - 1];
            let inner_raw = tokenize(inner)?;
            let inner_tokens = build_pattern_tokens_inner(&inner_raw, true)?;
            result.push(PatternToken::Optional(inner_tokens));
            i += 1;
        } else if token.starts_with('<') && token.ends_with('>') {
            // Angle bracket group
            let pt = parse_angle_bracket_token(token)?;
            // If it's a flag-like alternation, check if the next token is a value
            match &pt {
                PatternToken::Alternation(alts) if alts.iter().any(|a| is_flag(a)) => {
                    if i + 1 < raw_tokens.len()
                        && should_consume_as_value(raw_tokens, i + 1, inside_group)
                    {
                        let next = &raw_tokens[i + 1];
                        let value_token = parse_single_value_token(next)?;
                        result.push(PatternToken::FlagWithValue {
                            aliases: alts.clone(),
                            value: Box::new(value_token),
                        });
                        i += 2;
                    } else {
                        result.push(pt);
                        i += 1;
                    }
                }
                _ => {
                    result.push(pt);
                    i += 1;
                }
            }
        } else if token == "*" {
            result.push(PatternToken::Wildcard);
            i += 1;
        } else if let Some(inner) = token.strip_prefix('!') {
            let inner_token = parse_value_or_alternation(inner);
            result.push(PatternToken::Negation(Box::new(inner_token)));
            i += 1;
        } else if token.contains('|') && !token.starts_with('<') {
            // Bare pipe alternation
            let alts: Vec<String> = token.split('|').map(|s| s.to_string()).collect();
            if alts.iter().any(|a| a.is_empty()) {
                return Err(super::PatternParseError::EmptyAlternation);
            }
            // If flag-like, check for value
            if alts.iter().any(|a| is_flag(a))
                && i + 1 < raw_tokens.len()
                && should_consume_as_value(raw_tokens, i + 1, inside_group)
            {
                let next = &raw_tokens[i + 1];
                let value_token = parse_single_value_token(next)?;
                result.push(PatternToken::FlagWithValue {
                    aliases: alts,
                    value: Box::new(value_token),
                });
                i += 2;
            } else {
                result.push(PatternToken::Alternation(alts));
                i += 1;
            }
        } else if is_single_flag(token)
            && i + 1 < raw_tokens.len()
            && should_consume_as_value(raw_tokens, i + 1, inside_group)
        {
            // Single flag (e.g., --profile, -C) followed by a value
            let next = &raw_tokens[i + 1];
            let value_token = parse_single_value_token(next)?;
            result.push(PatternToken::FlagWithValue {
                aliases: vec![token.clone()],
                value: Box::new(value_token),
            });
            i += 2;
        } else {
            result.push(PatternToken::Literal(token.clone()));
            i += 1;
        }
    }

    Ok(result)
}

/// Parse the content inside angle brackets: `<-X|--request>`, `<cmd>`, `<path:name>`.
fn parse_angle_bracket_token(token: &str) -> Result<PatternToken, super::PatternParseError> {
    let inner = &token[1..token.len() - 1];

    if inner.is_empty() {
        return Err(super::PatternParseError::EmptyAlternation);
    }

    if let Some(name) = inner.strip_prefix("path:") {
        return Ok(PatternToken::PathRef(name.to_string()));
    }

    // Check if it contains pipe -> Alternation
    if inner.contains('|') {
        let alts: Vec<String> = inner.split('|').map(|s| s.to_string()).collect();
        if alts.iter().any(|a| a.is_empty()) {
            return Err(super::PatternParseError::EmptyAlternation);
        }
        return Ok(PatternToken::Alternation(alts));
    }

    // Single word without pipe or colon -> Placeholder
    Ok(PatternToken::Placeholder(inner.to_string()))
}

/// Parse a single raw token as a value (not a flag itself).
/// Used for the value part of a FlagWithValue.
fn parse_single_value_token(token: &str) -> Result<PatternToken, super::PatternParseError> {
    if token == "*" {
        Ok(PatternToken::Wildcard)
    } else if let Some(inner) = token.strip_prefix('!') {
        let inner_token = parse_value_or_alternation(inner);
        Ok(PatternToken::Negation(Box::new(inner_token)))
    } else {
        Ok(PatternToken::Literal(token.to_string()))
    }
}

/// Parse a string that might be a bare alternation (contains `|`) or a literal.
fn parse_value_or_alternation(s: &str) -> PatternToken {
    if s.contains('|') {
        let alts: Vec<String> = s.split('|').map(|s| s.to_string()).collect();
        PatternToken::Alternation(alts)
    } else {
        PatternToken::Literal(s.to_string())
    }
}

/// Determine whether the token at `idx` should be consumed as a flag's value.
///
/// A token is consumed as a value when:
/// - It is a non-wildcard token (literal, negation, etc.) that doesn't look like a flag itself, OR
/// - It is `*` AND there are more tokens after it (so `*` is the value, not the trailing wildcard).
///
/// This prevents `<-f|--force> *` (where `*` is the last token) from being parsed as
/// FlagWithValue, while allowing `<-X|--request> * *` to parse the first `*` as a value.
fn should_consume_as_value(raw_tokens: &[String], idx: usize, inside_group: bool) -> bool {
    let token = &raw_tokens[idx];

    if token.starts_with('[') {
        return false;
    }

    // Flags (e.g., --force, -v) are not consumed as values for a preceding flag.
    // Negation tokens (e.g., !prod) are valid values though.
    if is_flag(token) {
        return false;
    }

    // Wildcard: inside a group (e.g., [-C *]), always consume as value.
    // At top level, only consume if there are more tokens after it,
    // so a trailing wildcard stays independent.
    if token == "*" {
        return inside_group || idx + 1 < raw_tokens.len();
    }

    true
}

/// Check if a string looks like a flag (starts with `-`).
fn is_flag(s: &str) -> bool {
    s.starts_with('-')
}

/// Check if a token is a "single" flag that takes a value.
/// Single flags are:
/// - `--long-form` (long flags)
/// - `-X` (single character short flags)
///
/// Multi-character short flags like `-rf` are NOT single flags (they are combined booleans).
fn is_single_flag(s: &str) -> bool {
    if s.starts_with("--") {
        // Long flag (e.g., --profile, --force)
        // But only if followed by a non-flag value
        return s.len() > 2;
    }
    if s.starts_with('-') && !s.starts_with("--") {
        // Short flag: only single char like -X, -C, -m
        return s.len() == 2;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::PatternParseError;
    use rstest::rstest;

    // === Simple patterns ===

    #[test]
    fn parse_simple_command() {
        let result = parse("git status").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(result.tokens, vec![PatternToken::Literal("status".into())]);
    }

    #[test]
    fn parse_command_only() {
        let result = parse("git").unwrap();
        assert_eq!(result.command, "git");
        assert!(result.tokens.is_empty());
    }

    #[test]
    fn parse_command_with_multiple_literals() {
        let result = parse("git remote add origin").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("remote".into()),
                PatternToken::Literal("add".into()),
                PatternToken::Literal("origin".into()),
            ]
        );
    }

    // === Wildcard ===

    #[test]
    fn parse_wildcard() {
        let result = parse("git *").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(result.tokens, vec![PatternToken::Wildcard]);
    }

    #[test]
    fn parse_wildcard_with_literals() {
        let result = parse("git push * --force").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("push".into()),
                PatternToken::Wildcard,
                PatternToken::Literal("--force".into()),
            ]
        );
    }

    // === Alternation (alias) with angle brackets ===

    #[test]
    fn parse_alternation_in_angle_brackets() {
        let result = parse("curl <-X|--request> GET *").unwrap();
        assert_eq!(result.command, "curl");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::FlagWithValue {
                    aliases: vec!["-X".into(), "--request".into()],
                    value: Box::new(PatternToken::Literal("GET".into())),
                },
                PatternToken::Wildcard,
            ]
        );
    }

    #[test]
    fn parse_alternation_without_value() {
        // Alternation that is not a flag (e.g., value alternation)
        let result = parse("git push origin <main|master>").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("push".into()),
                PatternToken::Literal("origin".into()),
                PatternToken::Alternation(vec!["main".into(), "master".into()]),
            ]
        );
    }

    // === FlagWithValue ===

    #[test]
    fn parse_flag_with_value_single_flag() {
        let result = parse("curl <-X|--request> POST *").unwrap();
        assert_eq!(result.command, "curl");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::FlagWithValue {
                    aliases: vec!["-X".into(), "--request".into()],
                    value: Box::new(PatternToken::Literal("POST".into())),
                },
                PatternToken::Wildcard,
            ]
        );
    }

    #[test]
    fn parse_flag_with_wildcard_value() {
        let result = parse("curl <-X|--request> * *").unwrap();
        assert_eq!(result.command, "curl");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::FlagWithValue {
                    aliases: vec!["-X".into(), "--request".into()],
                    value: Box::new(PatternToken::Wildcard),
                },
                PatternToken::Wildcard,
            ]
        );
    }

    // === Negation ===

    #[test]
    fn parse_negation_literal() {
        let result = parse("aws --profile !prod *").unwrap();
        assert_eq!(result.command, "aws");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::FlagWithValue {
                    aliases: vec!["--profile".into()],
                    value: Box::new(PatternToken::Negation(Box::new(PatternToken::Literal(
                        "prod".into()
                    )))),
                },
                PatternToken::Wildcard,
            ]
        );
    }

    #[test]
    fn parse_negation_alternation() {
        let result = parse("kubectl !describe|get|list *").unwrap();
        assert_eq!(result.command, "kubectl");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Negation(Box::new(PatternToken::Alternation(vec![
                    "describe".into(),
                    "get".into(),
                    "list".into(),
                ]))),
                PatternToken::Wildcard,
            ]
        );
    }

    // === Optional group ===

    #[test]
    fn parse_optional_flag() {
        let result = parse("rm [-f] *").unwrap();
        assert_eq!(result.command, "rm");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Optional(vec![PatternToken::Literal("-f".into())]),
                PatternToken::Wildcard,
            ]
        );
    }

    #[test]
    fn parse_optional_flag_with_value() {
        let result = parse("curl [-X|--request GET] *").unwrap();
        assert_eq!(result.command, "curl");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Optional(vec![PatternToken::FlagWithValue {
                    aliases: vec!["-X".into(), "--request".into()],
                    value: Box::new(PatternToken::Literal("GET".into())),
                }]),
                PatternToken::Wildcard,
            ]
        );
    }

    #[test]
    fn parse_optional_with_multiple_tokens() {
        let result = parse("git [-C *] status").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Optional(vec![PatternToken::FlagWithValue {
                    aliases: vec!["-C".into()],
                    value: Box::new(PatternToken::Wildcard),
                }]),
                PatternToken::Literal("status".into()),
            ]
        );
    }

    // === Placeholder ===

    #[test]
    fn parse_placeholder() {
        let result = parse("sudo <cmd>").unwrap();
        assert_eq!(result.command, "sudo");
        assert_eq!(result.tokens, vec![PatternToken::Placeholder("cmd".into())]);
    }

    #[test]
    fn parse_path_ref() {
        let result = parse("cat <path:sensitive>").unwrap();
        assert_eq!(result.command, "cat");
        assert_eq!(
            result.tokens,
            vec![PatternToken::PathRef("sensitive".into())]
        );
    }

    // === Combined tokens (Joined token with =) ===

    #[test]
    fn parse_joined_equals_token() {
        // "java -Denv=prod" -> -Denv=prod is a single literal token
        let result = parse("java -Denv=prod").unwrap();
        assert_eq!(result.command, "java");
        assert_eq!(
            result.tokens,
            vec![PatternToken::Literal("-Denv=prod".into())]
        );
    }

    // === Complex patterns ===

    #[test]
    fn parse_complex_deny_pattern() {
        let result = parse("curl <-X|--request> POST *").unwrap();
        assert_eq!(result.command, "curl");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::FlagWithValue {
                    aliases: vec!["-X".into(), "--request".into()],
                    value: Box::new(PatternToken::Literal("POST".into())),
                },
                PatternToken::Wildcard,
            ]
        );
    }

    #[test]
    fn parse_rm_rf_pattern() {
        let result = parse("rm -rf /").unwrap();
        assert_eq!(result.command, "rm");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("-rf".into()),
                PatternToken::Literal("/".into()),
            ]
        );
    }

    #[test]
    fn parse_git_push_force_pattern() {
        let result = parse("git push <-f|--force> *").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("push".into()),
                PatternToken::Alternation(vec!["-f".into(), "--force".into()]),
                PatternToken::Wildcard,
            ]
        );
    }

    // === Error cases ===

    #[test]
    fn parse_empty_string_returns_error() {
        let result = parse("");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatternParseError::InvalidSyntax(_)
        ));
    }

    #[test]
    fn parse_whitespace_only_returns_error() {
        let result = parse("   ");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatternParseError::InvalidSyntax(_)
        ));
    }

    #[test]
    fn parse_unclosed_angle_bracket() {
        let result = parse("curl <-X|--request GET");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatternParseError::UnclosedBracket(_)
        ));
    }

    #[test]
    fn parse_unclosed_square_bracket() {
        let result = parse("rm [-f *");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatternParseError::UnclosedSquareBracket(_)
        ));
    }

    #[test]
    fn parse_nested_square_brackets() {
        let result = parse("git [[-C *]] status");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatternParseError::NestedSquareBracket
        ));
    }

    #[test]
    fn parse_empty_alternation() {
        let result = parse("curl <> GET");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatternParseError::EmptyAlternation
        ));
    }

    // === Bare pipe alternation (without angle brackets) ===

    #[test]
    fn parse_bare_pipe_alternation() {
        let result = parse("kubectl describe|get|list *").unwrap();
        assert_eq!(result.command, "kubectl");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Alternation(vec!["describe".into(), "get".into(), "list".into(),]),
                PatternToken::Wildcard,
            ]
        );
    }

    // === Flag detection: flag-like alternation followed by a value ===

    #[rstest]
    #[case(
        "curl <-X|--request> POST *",
        "curl",
        vec![
            PatternToken::FlagWithValue {
                aliases: vec!["-X".into(), "--request".into()],
                value: Box::new(PatternToken::Literal("POST".into())),
            },
            PatternToken::Wildcard,
        ]
    )]
    #[case(
        "git commit <-m|--message> *",
        "git",
        vec![
            PatternToken::Literal("commit".into()),
            // When * is the last token, it's treated as an independent wildcard,
            // not as the flag's value. Use explicit value to bind: <-m|--message> 'msg'
            PatternToken::Alternation(vec!["-m".into(), "--message".into()]),
            PatternToken::Wildcard,
        ]
    )]
    fn parse_parameterized(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        let result = parse(input).unwrap();
        assert_eq!(result.command, expected_command);
        assert_eq!(result.tokens, expected_tokens);
    }

    // === Detect flag-like single token followed by value as FlagWithValue ===

    #[test]
    fn parse_single_flag_with_value() {
        // --profile is a flag-like literal, followed by a non-flag value
        let result = parse("aws --profile prod *").unwrap();
        assert_eq!(result.command, "aws");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::FlagWithValue {
                    aliases: vec!["--profile".into()],
                    value: Box::new(PatternToken::Literal("prod".into())),
                },
                PatternToken::Wildcard,
            ]
        );
    }

    #[test]
    fn parse_single_short_flag_with_value() {
        let result = parse("git -C /tmp status").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::FlagWithValue {
                    aliases: vec!["-C".into()],
                    value: Box::new(PatternToken::Literal("/tmp".into())),
                },
                PatternToken::Literal("status".into()),
            ]
        );
    }

    // === Boolean flags (no value follows) ===

    #[test]
    fn parse_boolean_flags_not_followed_by_value() {
        // -rf are combined boolean flags, / is the argument, not a flag value
        // However in pattern syntax, "-rf" is just a literal token
        let result = parse("rm -rf /").unwrap();
        assert_eq!(result.command, "rm");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("-rf".into()),
                PatternToken::Literal("/".into()),
            ]
        );
    }

    #[test]
    fn parse_flag_at_end_is_literal() {
        // A flag at the end of the pattern with no value is a literal
        let result = parse("git push --force").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("push".into()),
                PatternToken::Literal("--force".into()),
            ]
        );
    }

    // === Quoted strings ===

    #[test]
    fn parse_single_quoted_string() {
        let result = parse("git commit -m 'WIP*'").unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("commit".into()),
                PatternToken::FlagWithValue {
                    aliases: vec!["-m".into()],
                    value: Box::new(PatternToken::Literal("WIP*".into())),
                },
            ]
        );
    }

    #[test]
    fn parse_double_quoted_string() {
        let result = parse(r#"git commit -m "WIP*""#).unwrap();
        assert_eq!(result.command, "git");
        assert_eq!(
            result.tokens,
            vec![
                PatternToken::Literal("commit".into()),
                PatternToken::FlagWithValue {
                    aliases: vec!["-m".into()],
                    value: Box::new(PatternToken::Literal("WIP*".into())),
                },
            ]
        );
    }
}
