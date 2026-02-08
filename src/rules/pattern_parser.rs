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
                let start = i;
                i += 1;
                let mut quoted = String::new();
                while i < chars.len() && chars[i] != quote {
                    quoted.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(PatternParseError::InvalidSyntax(format!(
                        "unclosed quote starting at position {start}"
                    )));
                }
                i += 1; // skip closing quote
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
            // Angle bracket: exclusively PathRef or Placeholder
            let pt = parse_angle_bracket_token(token)?;
            result.push(pt);
            i += 1;
        } else if token == "*" {
            result.push(PatternToken::Wildcard);
            i += 1;
        } else if let Some(inner) = token.strip_prefix('!') {
            let inner_token = parse_value_or_alternation(inner)?;
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
        } else {
            result.push(PatternToken::Literal(token.clone()));
            i += 1;
        }
    }

    Ok(result)
}

/// Parse the content inside angle brackets.
///
/// Angle brackets are exclusively for:
/// - `<path:name>` -> PathRef
/// - `<cmd>` -> Placeholder (single word, no pipe)
///
/// Alternation uses bare pipe syntax (`-X|--request`) without angle brackets.
fn parse_angle_bracket_token(token: &str) -> Result<PatternToken, super::PatternParseError> {
    let inner = &token[1..token.len() - 1];

    if inner.is_empty() {
        return Err(super::PatternParseError::InvalidSyntax(
            "empty angle brackets".into(),
        ));
    }

    // Alternation (pipe) inside angle brackets is not allowed
    if inner.contains('|') {
        return Err(super::PatternParseError::InvalidSyntax(format!(
            "alternation inside angle brackets is not supported, use bare pipe: {inner}"
        )));
    }

    if let Some(name) = inner.strip_prefix("path:") {
        return Ok(PatternToken::PathRef(name.to_string()));
    }

    Ok(PatternToken::Placeholder(inner.to_string()))
}

/// Parse a single raw token as a value (not a flag itself).
/// Used for the value part of a FlagWithValue.
fn parse_single_value_token(token: &str) -> Result<PatternToken, super::PatternParseError> {
    if token == "*" {
        Ok(PatternToken::Wildcard)
    } else if token.starts_with('<') && token.ends_with('>') {
        parse_angle_bracket_token(token)
    } else if let Some(inner) = token.strip_prefix('!') {
        let inner_token = parse_value_or_alternation(inner)?;
        Ok(PatternToken::Negation(Box::new(inner_token)))
    } else {
        Ok(PatternToken::Literal(token.to_string()))
    }
}

/// Parse a string that might be a bare alternation (contains `|`) or a literal.
fn parse_value_or_alternation(s: &str) -> Result<PatternToken, super::PatternParseError> {
    if s.contains('|') {
        let alts: Vec<String> = s.split('|').map(|s| s.to_string()).collect();
        if alts.iter().any(|a| a.is_empty()) {
            return Err(super::PatternParseError::EmptyAlternation);
        }
        Ok(PatternToken::Alternation(alts))
    } else {
        Ok(PatternToken::Literal(s.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === Successful parsing (rstest parameterized) ===

    #[rstest]
    // --- Simple patterns ---
    #[case::command_only("git", "git", vec![])]
    #[case::simple_command("git status", "git", vec![
        PatternToken::Literal("status".into()),
    ])]
    #[case::multiple_literals("git remote add origin", "git", vec![
        PatternToken::Literal("remote".into()),
        PatternToken::Literal("add".into()),
        PatternToken::Literal("origin".into()),
    ])]
    // --- Wildcard ---
    #[case::wildcard("git *", "git", vec![PatternToken::Wildcard])]
    #[case::wildcard_with_literals("git push * --force", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Wildcard,
        PatternToken::Literal("--force".into()),
    ])]
    // --- Alternation (bare pipe) ---
    #[case::value_alternation("git push origin main|master", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Literal("origin".into()),
        PatternToken::Alternation(vec!["main".into(), "master".into()]),
    ])]
    #[case::non_flag_alternation("kubectl describe|get|list *", "kubectl", vec![
        PatternToken::Alternation(vec!["describe".into(), "get".into(), "list".into()]),
        PatternToken::Wildcard,
    ])]
    // --- FlagWithValue (only via alternation) ---
    #[case::flag_with_literal_value("curl -X|--request POST *", "curl", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-X".into(), "--request".into()],
            value: Box::new(PatternToken::Literal("POST".into())),
        },
        PatternToken::Wildcard,
    ])]
    #[case::flag_with_wildcard_value("curl -X|--request * *", "curl", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-X".into(), "--request".into()],
            value: Box::new(PatternToken::Wildcard),
        },
        PatternToken::Wildcard,
    ])]
    #[case::flag_alternation_with_value("aws -p|--profile prod *", "aws", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-p".into(), "--profile".into()],
            value: Box::new(PatternToken::Literal("prod".into())),
        },
        PatternToken::Wildcard,
    ])]
    // Trailing * is an independent wildcard, not consumed as the flag's value
    #[case::flag_alternation_trailing_wildcard("git commit -m|--message *", "git", vec![
        PatternToken::Literal("commit".into()),
        PatternToken::Alternation(vec!["-m".into(), "--message".into()]),
        PatternToken::Wildcard,
    ])]
    // Boolean flag alternation (no value)
    #[case::boolean_flag_alternation("git push -f|--force *", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Alternation(vec!["-f".into(), "--force".into()]),
        PatternToken::Wildcard,
    ])]
    // --- Single flags without alternation are literals ---
    #[case::long_flag_is_literal("aws --profile prod *", "aws", vec![
        PatternToken::Literal("--profile".into()),
        PatternToken::Literal("prod".into()),
        PatternToken::Wildcard,
    ])]
    #[case::short_flag_is_literal("git -C /tmp status", "git", vec![
        PatternToken::Literal("-C".into()),
        PatternToken::Literal("/tmp".into()),
        PatternToken::Literal("status".into()),
    ])]
    #[case::long_flag_not_consuming_positional("git push --force origin", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Literal("--force".into()),
        PatternToken::Literal("origin".into()),
    ])]
    #[case::long_flag_not_consuming_wildcard("git --verbose *", "git", vec![
        PatternToken::Literal("--verbose".into()),
        PatternToken::Wildcard,
    ])]
    #[case::flag_at_end("git push --force", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Literal("--force".into()),
    ])]
    #[case::multi_char_short_flag("rm -rf /", "rm", vec![
        PatternToken::Literal("-rf".into()),
        PatternToken::Literal("/".into()),
    ])]
    // --- Negation ---
    #[case::negation_literal("aws --profile !prod *", "aws", vec![
        PatternToken::Literal("--profile".into()),
        PatternToken::Negation(Box::new(PatternToken::Literal("prod".into()))),
        PatternToken::Wildcard,
    ])]
    #[case::negation_alternation("kubectl !describe|get|list *", "kubectl", vec![
        PatternToken::Negation(Box::new(PatternToken::Alternation(vec![
            "describe".into(), "get".into(), "list".into(),
        ]))),
        PatternToken::Wildcard,
    ])]
    // --- Optional groups ---
    #[case::optional_flag("rm [-f] *", "rm", vec![
        PatternToken::Optional(vec![PatternToken::Literal("-f".into())]),
        PatternToken::Wildcard,
    ])]
    #[case::optional_flag_with_value("curl [-X|--request GET] *", "curl", vec![
        PatternToken::Optional(vec![PatternToken::FlagWithValue {
            aliases: vec!["-X".into(), "--request".into()],
            value: Box::new(PatternToken::Literal("GET".into())),
        }]),
        PatternToken::Wildcard,
    ])]
    #[case::optional_multiple_tokens("git [-C *] status", "git", vec![
        PatternToken::Optional(vec![
            PatternToken::Literal("-C".into()),
            PatternToken::Wildcard,
        ]),
        PatternToken::Literal("status".into()),
    ])]
    // --- Placeholder and PathRef ---
    #[case::placeholder("sudo <cmd>", "sudo", vec![
        PatternToken::Placeholder("cmd".into()),
    ])]
    #[case::path_ref("cat <path:sensitive>", "cat", vec![
        PatternToken::PathRef("sensitive".into()),
    ])]
    // Flag value as Placeholder/PathRef
    #[case::flag_value_placeholder("cmd -o|--option <cmd>", "cmd", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-o".into(), "--option".into()],
            value: Box::new(PatternToken::Placeholder("cmd".into())),
        },
    ])]
    #[case::flag_value_path_ref("cmd -c|--config <path:config>", "cmd", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-c".into(), "--config".into()],
            value: Box::new(PatternToken::PathRef("config".into())),
        },
    ])]
    // --- Joined token (=) ---
    #[case::joined_equals("java -Denv=prod", "java", vec![
        PatternToken::Literal("-Denv=prod".into()),
    ])]
    // --- Quoted strings ---
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
    fn parse_ok(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        let result = parse(input).unwrap();
        assert_eq!(result.command, expected_command);
        assert_eq!(result.tokens, expected_tokens);
    }

    // === Error cases (rstest parameterized) ===

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
