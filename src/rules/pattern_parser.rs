//! Pattern and PatternToken data types, and the parser that converts
//! pattern strings into structured Pattern values.

use super::pattern_lexer::LexToken;

/// Represents the command name part of a pattern, which can be
/// either a literal string, an alternation of names, or a wildcard (`*`)
/// that matches any command.
#[derive(Debug, Clone, PartialEq)]
pub enum CommandPattern {
    /// Matches a specific command name (e.g., "git", "curl").
    Literal(String),
    /// Matches any of the given command names (e.g., "ast-grep|sg").
    Alternation(Vec<String>),
    /// Matches any command name (`*`).
    Wildcard,
    /// Matches command name(s) via a `<var:name>` variable reference.
    /// Multi-word var values consume multiple leading tokens.
    VarRef(String),
}

impl CommandPattern {
    /// Check if this command pattern matches the given command name.
    ///
    /// For `VarRef`, always returns `true` — actual matching is deferred to
    /// the pattern matcher which handles multi-word values and type-aware comparison.
    pub fn matches(&self, command: &str) -> bool {
        match self {
            CommandPattern::Literal(s) => s == command,
            CommandPattern::Alternation(alts) => alts.iter().any(|s| s == command),
            CommandPattern::Wildcard => true,
            CommandPattern::VarRef(_) => true,
        }
    }
}

/// A parsed pattern consisting of a command name and a sequence of tokens.
#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub command: CommandPattern,
    pub tokens: Vec<PatternToken>,
}

/// Individual tokens within a pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum PatternToken {
    /// Fixed string (e.g., "git", "status"). `*` is treated as a glob wildcard.
    Literal(String),
    /// Alternation (e.g., -X|--request -> ["-X", "--request"])
    Alternation(Vec<String>),
    /// Flag with its value (e.g., -X|--request POST -> aliases + value)
    FlagWithValue {
        aliases: Vec<String>,
        value: Box<PatternToken>,
    },
    /// Flag group reference (e.g., `<flag:field-flag>`).
    /// Resolved at evaluation time using the pattern string in
    /// `definitions.flag_groups[name]`, which encodes the flag aliases
    /// and an optional value pattern (e.g. `"-f|--field *"`).
    /// Every match is captured into the `flag_groups` map available
    /// in `when` clauses.
    FlagGroupRef { name: String },
    /// Negation (e.g., !GET, !describe|get|list-*)
    Negation(Box<PatternToken>),
    /// Optional group (e.g., [-X GET] -> matches with or without)
    Optional(Vec<PatternToken>),
    /// Wildcard: matches zero or more arbitrary tokens
    Wildcard,
    /// Path variable reference (e.g., <path:sensitive>)
    PathRef(String),
    /// Typed variable reference (e.g., <var:instance-ids>)
    VarRef(String),
    /// Wrapper placeholder (e.g., <cmd>)
    Placeholder(String),
    /// Options placeholder for wrapper patterns (e.g., <opts>).
    /// Consumes zero or more flag-like tokens (hyphen-prefixed) and their
    /// arguments in the command.
    Opts,
    /// Variable-assignment placeholder for wrapper patterns (e.g., <vars>).
    /// Consumes zero or more `KEY=VALUE` tokens from the command.
    Vars,
}

/// Parse a pattern string into a Pattern struct.
///
/// The first whitespace-delimited token becomes the command name.
/// Remaining tokens are converted to PatternToken variants based on syntax:
/// - `*` -> Wildcard
/// - `<path:name>` -> PathRef
/// - `<var:name>` -> VarRef
/// - `<cmd>` -> Placeholder (single word, no pipe, no colon)
/// - `!value` -> Negation
/// - `[...]` -> Optional group
/// - `-X|--request value` -> FlagWithValue (alternation signals value-taking flag)
/// - `word|word` -> Alternation
/// - everything else -> Literal
pub fn parse(pattern: &str) -> Result<Pattern, super::PatternParseError> {
    let lex_tokens = tokenize_pattern(pattern)?;
    build_pattern_from_tokens(&lex_tokens)
}

/// Parse a pattern string that may contain multi-word alternation.
///
/// For patterns with multi-word alternation (e.g., `"npx prettier"|prettier *`),
/// returns multiple `Pattern` instances — one for each alternative:
///   - `Pattern { command: "npx", tokens: [Literal("prettier"), Wildcard] }`
///   - `Pattern { command: "prettier", tokens: [Wildcard] }`
///
/// For regular patterns (no multi-word alternation), returns a single `Pattern`
/// in the vector, equivalent to calling `parse`.
pub fn parse_multi(pattern: &str) -> Result<Vec<Pattern>, super::PatternParseError> {
    let lex_tokens = tokenize_pattern(pattern)?;

    match &lex_tokens[0] {
        LexToken::MultiWordAlternation(alternatives) => {
            let rest = &lex_tokens[1..];
            let rest_tokens = build_pattern_tokens(rest, false)?;
            let mut patterns = Vec::with_capacity(alternatives.len());

            for alt in alternatives {
                // Each alternative is a list of words; the first word is the command name,
                // the rest are prepended as Literal tokens before the shared remaining tokens.
                let command = CommandPattern::Literal(alt[0].clone());
                let prefix_tokens: Vec<PatternToken> = alt[1..]
                    .iter()
                    .map(|w| PatternToken::Literal(w.clone()))
                    .collect();

                let mut tokens = prefix_tokens;
                tokens.extend(rest_tokens.clone());

                patterns.push(Pattern { command, tokens });
            }

            Ok(patterns)
        }
        _ => {
            let pattern = build_pattern_from_tokens(&lex_tokens)?;
            Ok(vec![pattern])
        }
    }
}

/// Tokenize a pattern string, returning an error if empty.
fn tokenize_pattern(pattern: &str) -> Result<Vec<LexToken>, super::PatternParseError> {
    use super::PatternParseError;

    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
    }

    let lex_tokens = super::pattern_lexer::tokenize(trimmed)?;
    if lex_tokens.is_empty() {
        return Err(PatternParseError::InvalidSyntax("empty pattern".into()));
    }

    Ok(lex_tokens)
}

/// Build a single Pattern from already-tokenized lex tokens.
/// The first token becomes the command name, the rest become pattern tokens.
fn build_pattern_from_tokens(lex_tokens: &[LexToken]) -> Result<Pattern, super::PatternParseError> {
    use super::PatternParseError;

    let command = match &lex_tokens[0] {
        LexToken::Literal(s) | LexToken::QuotedLiteral(s) => CommandPattern::Literal(s.clone()),
        LexToken::Alternation(alts) => CommandPattern::Alternation(alts.clone()),
        LexToken::Wildcard => CommandPattern::Wildcard,
        LexToken::Placeholder(name) if name.starts_with("var:") => {
            CommandPattern::VarRef(name["var:".len()..].to_string())
        }
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

            LexToken::Literal(s) if is_flag(s) => {
                // A bare flag (e.g. `-X`) is treated like a single-element
                // alternation so that flag-with-value and order-independent
                // matching work the same as for `-X|--request` style patterns.
                if let Some(&(j, next)) = iter.peek() {
                    if should_consume_as_value(next, j + 1 < lex_tokens.len(), inside_group) {
                        let (_, next_token) = iter.next().ok_or(
                            PatternParseError::InvalidSyntax("unexpected end of tokens".into()),
                        )?;
                        let value = lex_to_pattern_value(next_token)?;
                        result.push(PatternToken::FlagWithValue {
                            aliases: vec![s.clone()],
                            value: Box::new(value),
                        });
                    } else {
                        result.push(PatternToken::Alternation(vec![s.clone()]));
                    }
                } else {
                    result.push(PatternToken::Alternation(vec![s.clone()]));
                }
            }

            LexToken::Literal(s) | LexToken::QuotedLiteral(s) => {
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
                if let Some(name) = content.strip_prefix("flag:") {
                    if name.is_empty() {
                        return Err(PatternParseError::InvalidSyntax(
                            "<flag:> placeholder requires a group name (e.g. <flag:field-flag>)"
                                .into(),
                        ));
                    }
                    // Reject `<flag:name>` inside `[...]` Optional groups.
                    // `optional_flags_absent` only knows about FlagWithValue
                    // aliases, so it cannot detect that grouped flags are
                    // still present in the command tokens — taking the
                    // "absent" path would silently drop captured values and
                    // produce an incorrect match. Disallow the construct
                    // upfront until matching gains first-class support.
                    if inside_group {
                        return Err(PatternParseError::InvalidSyntax(format!(
                            "<flag:{name}> is not supported inside an optional group `[...]`"
                        )));
                    }
                    result.push(PatternToken::FlagGroupRef {
                        name: name.to_string(),
                    });
                } else {
                    let pt = parse_placeholder(content)?;
                    result.push(pt);
                }
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

            LexToken::MultiWordAlternation(_) => {
                return Err(PatternParseError::InvalidSyntax(
                    "multi-word alternation is only supported in command position".into(),
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
        LexToken::Literal(s) | LexToken::QuotedLiteral(s) => Ok(PatternToken::Literal(s.clone())),
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
        LexToken::MultiWordAlternation(_) => Err(super::PatternParseError::InvalidSyntax(
            "multi-word alternation cannot be used as flag value".into(),
        )),
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

    if let Some(name) = content.strip_prefix("var:") {
        return Ok(PatternToken::VarRef(name.to_string()));
    }

    if content.starts_with("flag:") {
        // <flag:name> is processed by build_pattern_tokens directly.
        // Reaching this branch means the placeholder appeared in a
        // position that does not allow it (e.g. as a flag value or
        // wrapper-pattern token).
        return Err(super::PatternParseError::InvalidSyntax(format!(
            "<{content}> can only appear in argument position (e.g. <{content}>)"
        )));
    }

    if content == "opts" {
        return Ok(PatternToken::Opts);
    }

    if content == "vars" {
        return Ok(PatternToken::Vars);
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
        // When `[` is used as a literal command name, the lexer emits `]` as
        // `Literal("]")` rather than `CloseBracket`.  Prevent flags from
        // consuming this closing delimiter as a value.
        LexToken::Literal(s) if s == "]" => false,
        // Flags and the bare `--` separator must not be consumed as values.
        LexToken::Literal(s) if is_flag(s) || s == "--" => false,
        LexToken::Alternation(alts) if alts.iter().any(|a| is_flag(a)) => false,
        LexToken::Placeholder(_) => false,
        LexToken::Wildcard => inside_group || has_more_after,
        // A negation whose inner value is a flag (e.g., `!--in-place`) should
        // not be consumed as a flag value — it is an independent negation token.
        LexToken::Negation(s) if is_flag(s) => false,
        LexToken::NegationAlternation(alts) if alts.iter().any(|a| is_flag(a)) => false,
        _ => true,
    }
}

/// Check if a string looks like a flag (starts with `-`).
///
/// The bare double-dash `--` is excluded because it is a positional
/// separator, not a flag.  Treating it as a flag would cause order-
/// independent matching to ignore its position in the command.
fn is_flag(s: &str) -> bool {
    s.starts_with('-') && s != "--"
}

/// Parsed representation of a flag group definition string.
///
/// A definition like `"-f|-F|--field *"` is parsed into aliases
/// `["-f", "-F", "--field"]` with `value_pattern = Some(Wildcard)`.
/// A definition like `"-v|--verbose"` is parsed into aliases
/// `["-v", "--verbose"]` with `value_pattern = None` (bool flag).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedFlagGroup {
    pub aliases: Vec<String>,
    pub value_pattern: Option<PatternToken>,
}

/// Parse a flag group definition string into aliases and an optional value pattern.
///
/// The definition string uses the same syntax as rule patterns:
/// - Aliases are separated by `|` (e.g. `"-f|-F|--field"`)
/// - An optional value pattern follows after a space (e.g. `"-f|--field *"`)
/// - Value patterns can be wildcards (`*`), literals, or alternations
///
/// Returns an error if the definition is empty, contains no valid flags,
/// or has an invalid value pattern.
pub fn parse_flag_group_definition(
    definition: &str,
) -> Result<ParsedFlagGroup, super::PatternParseError> {
    let definition = definition.trim();
    if definition.is_empty() {
        return Err(super::PatternParseError::InvalidSyntax(
            "flag group definition must not be empty".into(),
        ));
    }

    // Split into space-separated parts. The first part is the flag aliases
    // (pipe-separated), and the remaining parts form the value pattern.
    let parts: Vec<&str> = definition.split_whitespace().collect();

    // Parse aliases from the first part
    let aliases: Vec<String> = parts[0].split('|').map(|s| s.to_string()).collect();

    if aliases.is_empty() {
        return Err(super::PatternParseError::InvalidSyntax(
            "flag group definition must contain at least one flag".into(),
        ));
    }

    // Validate that all aliases look like flags
    for alias in &aliases {
        if !is_flag(alias) {
            return Err(super::PatternParseError::InvalidSyntax(format!(
                "'{alias}' is not a valid flag name \
                 (must start with `-` and not be the bare `--` separator)"
            )));
        }
    }

    // Parse the value pattern from remaining parts, if any
    let value_pattern = if parts.len() > 1 {
        let value_str = parts[1..].join(" ");
        // Check for alternation in the value pattern
        if value_str.contains('|') {
            let alts: Vec<String> = value_str.split('|').map(|s| s.to_string()).collect();
            Some(PatternToken::Alternation(alts))
        } else if value_str == "*" {
            Some(PatternToken::Wildcard)
        } else {
            Some(PatternToken::Literal(value_str))
        }
    } else {
        None
    };

    Ok(ParsedFlagGroup {
        aliases,
        value_pattern,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn assert_parse(input: &str, expected_command: &str, expected_tokens: Vec<PatternToken>) {
        let result = parse(input).unwrap();
        assert_eq!(
            result.command,
            CommandPattern::Literal(expected_command.to_string())
        );
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
        PatternToken::Alternation(vec!["-Denv=prod".into()]),
    ])]
    #[case::single_quoted("git commit -m 'WIP*'", "git", vec![
        PatternToken::Literal("commit".into()),
        PatternToken::FlagWithValue {
            aliases: vec!["-m".into()],
            value: Box::new(PatternToken::Literal("WIP*".into())),
        },
    ])]
    #[case::double_quoted(r#"git commit -m "WIP*""#, "git", vec![
        PatternToken::Literal("commit".into()),
        PatternToken::FlagWithValue {
            aliases: vec!["-m".into()],
            value: Box::new(PatternToken::Literal("WIP*".into())),
        },
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
        PatternToken::Alternation(vec!["--force".into()]),
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
    #[case::placeholder_not_consumed_as_flag_value("cmd -o|--option <cmd>", "cmd", vec![
        PatternToken::Alternation(vec!["-o".into(), "--option".into()]),
        PatternToken::Placeholder("cmd".into()),
    ])]
    #[case::path_ref_value("cmd -c|--config <path:config>", "cmd", vec![
        PatternToken::Alternation(vec!["-c".into(), "--config".into()]),
        PatternToken::PathRef("config".into()),
    ])]
    fn parse_flag_with_value(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::flag_with_value("aws --profile prod *", "aws", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["--profile".into()],
            value: Box::new(PatternToken::Literal("prod".into())),
        },
        PatternToken::Wildcard,
    ])]
    #[case::short_flag_with_value("git -C /tmp status", "git", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-C".into()],
            value: Box::new(PatternToken::Literal("/tmp".into())),
        },
        PatternToken::Literal("status".into()),
    ])]
    #[case::flag_consumes_next_non_flag("git push --force origin", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::FlagWithValue {
            aliases: vec!["--force".into()],
            value: Box::new(PatternToken::Literal("origin".into())),
        },
    ])]
    #[case::flag_not_consuming_trailing_wildcard("git --verbose *", "git", vec![
        PatternToken::Alternation(vec!["--verbose".into()]),
        PatternToken::Wildcard,
    ])]
    #[case::flag_at_end("git push --force", "git", vec![
        PatternToken::Literal("push".into()),
        PatternToken::Alternation(vec!["--force".into()]),
    ])]
    #[case::combined_short_flag_with_value("rm -rf /", "rm", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-rf".into()],
            value: Box::new(PatternToken::Literal("/".into())),
        },
    ])]
    #[case::flag_not_consuming_flag_negation("git --parse !--in-place *", "git", vec![
        PatternToken::Alternation(vec!["--parse".into()]),
        PatternToken::Negation(Box::new(PatternToken::Literal("--in-place".into()))),
        PatternToken::Wildcard,
    ])]
    fn parse_bare_flag(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::literal("aws --profile !prod *", "aws", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["--profile".into()],
            value: Box::new(PatternToken::Negation(Box::new(PatternToken::Literal("prod".into())))),
        },
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
        PatternToken::Optional(vec![PatternToken::Alternation(vec!["-f".into()])]),
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
            PatternToken::FlagWithValue {
                aliases: vec!["-C".into()],
                value: Box::new(PatternToken::Wildcard),
            },
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
    #[case::bracket_command_wildcard("[ *", "[", vec![
        PatternToken::Wildcard,
    ])]
    #[case::bracket_command_boolean_flag("[ -f ]", "[", vec![
        PatternToken::Alternation(vec!["-f".into()]),
        PatternToken::Literal("]".into()),
    ])]
    #[case::bracket_command_with_args("[ -f file ]", "[", vec![
        PatternToken::FlagWithValue {
            aliases: vec!["-f".into()],
            value: Box::new(PatternToken::Literal("file".into())),
        },
        PatternToken::Literal("]".into()),
    ])]
    fn parse_literal_bracket_command(
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
    #[case::flag_alternation_then_placeholder(
        r"find * -exec|-execdir|-ok|-okdir <cmd> \;|+",
        "find",
        vec![
            PatternToken::Wildcard,
            PatternToken::Alternation(vec![
                "-exec".into(), "-execdir".into(), "-ok".into(), "-okdir".into(),
            ]),
            PatternToken::Placeholder("cmd".into()),
            PatternToken::Alternation(vec![r"\;".into(), "+".into()]),
        ],
    )]
    #[case::var_ref("cat <var:instance-ids>", "cat", vec![
        PatternToken::VarRef("instance-ids".into()),
    ])]
    #[case::var_ref_after_flag("aws ec2 terminate-instances --instance-ids <var:instance-ids> *", "aws", vec![
        PatternToken::Literal("ec2".into()),
        PatternToken::Literal("terminate-instances".into()),
        PatternToken::Alternation(vec!["--instance-ids".into()]),
        PatternToken::VarRef("instance-ids".into()),
        PatternToken::Wildcard,
    ])]
    fn parse_placeholder(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    #[rstest]
    #[case::wildcard_with_flag("* --help", vec![
        PatternToken::Alternation(vec!["--help".into()]),
    ])]
    #[case::wildcard_with_version("* --version", vec![
        PatternToken::Alternation(vec!["--version".into()]),
    ])]
    #[case::wildcard_only("*", vec![])]
    #[case::wildcard_with_wildcard_args("* *", vec![PatternToken::Wildcard])]
    fn parse_wildcard_command(#[case] input: &str, #[case] expected_tokens: Vec<PatternToken>) {
        let result = parse(input).unwrap();
        assert_eq!(result.command, CommandPattern::Wildcard);
        assert_eq!(result.tokens, expected_tokens);
    }

    #[rstest]
    #[case::two_aliases(
        "ast-grep|sg scan *",
        vec!["ast-grep".into(), "sg".into()],
        vec![
            PatternToken::Literal("scan".into()),
            PatternToken::Wildcard,
        ],
    )]
    #[case::three_aliases(
        "vim|nvim|vi *",
        vec!["vim".into(), "nvim".into(), "vi".into()],
        vec![PatternToken::Wildcard],
    )]
    #[case::aliases_no_args(
        "python|python3",
        vec!["python".into(), "python3".into()],
        vec![],
    )]
    fn parse_command_alternation(
        #[case] input: &str,
        #[case] expected_alts: Vec<String>,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        let result = parse(input).unwrap();
        assert_eq!(result.command, CommandPattern::Alternation(expected_alts));
        assert_eq!(result.tokens, expected_tokens);
    }

    #[rstest]
    #[case::matches_first("ast-grep|sg", "ast-grep", true)]
    #[case::matches_second("ast-grep|sg", "sg", true)]
    #[case::no_match("ast-grep|sg", "rg", false)]
    fn command_alternation_matches(
        #[case] pattern: &str,
        #[case] command: &str,
        #[case] expected: bool,
    ) {
        let parsed = parse(pattern).unwrap();
        assert_eq!(parsed.command.matches(command), expected);
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

    // === Double-dash (--) parsed as Literal, not flag ===

    #[rstest]
    #[case::double_dash_with_wildcard("git checkout -- *", "git", vec![
        PatternToken::Literal("checkout".into()),
        PatternToken::Literal("--".into()),
        PatternToken::Wildcard,
    ])]
    #[case::flag_before_double_dash("git --force -- *", "git", vec![
        PatternToken::Alternation(vec!["--force".into()]),
        PatternToken::Literal("--".into()),
        PatternToken::Wildcard,
    ])]
    #[case::double_dash_with_optional("git [-C *] checkout -- *", "git", vec![
        PatternToken::Optional(vec![
            PatternToken::FlagWithValue {
                aliases: vec!["-C".into()],
                value: Box::new(PatternToken::Wildcard),
            },
        ]),
        PatternToken::Literal("checkout".into()),
        PatternToken::Literal("--".into()),
        PatternToken::Wildcard,
    ])]
    fn parse_double_dash_as_literal(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    // === Multi-word alternation (parse_multi) ===

    #[rstest]
    #[case::two_alternatives(
        r#""npx prettier"|prettier *"#,
        vec![
            Pattern {
                command: CommandPattern::Literal("npx".into()),
                tokens: vec![PatternToken::Literal("prettier".into()), PatternToken::Wildcard],
            },
            Pattern {
                command: CommandPattern::Literal("prettier".into()),
                tokens: vec![PatternToken::Wildcard],
            },
        ]
    )]
    #[case::three_alternatives(
        r#""npx prettier"|"bunx prettier"|prettier *"#,
        vec![
            Pattern {
                command: CommandPattern::Literal("npx".into()),
                tokens: vec![PatternToken::Literal("prettier".into()), PatternToken::Wildcard],
            },
            Pattern {
                command: CommandPattern::Literal("bunx".into()),
                tokens: vec![PatternToken::Literal("prettier".into()), PatternToken::Wildcard],
            },
            Pattern {
                command: CommandPattern::Literal("prettier".into()),
                tokens: vec![PatternToken::Wildcard],
            },
        ]
    )]
    #[case::multi_word_with_subcommand(
        r#""python -m pytest"|pytest *"#,
        vec![
            Pattern {
                command: CommandPattern::Literal("python".into()),
                tokens: vec![
                    PatternToken::Literal("-m".into()),
                    PatternToken::Literal("pytest".into()),
                    PatternToken::Wildcard,
                ],
            },
            Pattern {
                command: CommandPattern::Literal("pytest".into()),
                tokens: vec![PatternToken::Wildcard],
            },
        ]
    )]
    fn parse_multi_expands_alternatives(#[case] input: &str, #[case] expected: Vec<Pattern>) {
        let result = parse_multi(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::single_word_alternation("ast-grep|sg scan *", 1)]
    #[case::simple_literal("git status", 1)]
    #[case::wildcard_command("* --help", 1)]
    fn parse_multi_no_expansion(#[case] input: &str, #[case] expected_count: usize) {
        let result = parse_multi(input).unwrap();
        assert_eq!(
            result.len(),
            expected_count,
            "expected {expected_count} patterns for {input:?}, got {}",
            result.len()
        );
    }

    // === <var:name> in command position ===

    #[rstest]
    #[case::with_literal_arg(
        "<var:runok> check",
        CommandPattern::VarRef("runok".to_string()),
        vec![PatternToken::Literal("check".into())],
    )]
    #[case::with_wildcard_arg(
        "<var:prettier> *",
        CommandPattern::VarRef("prettier".to_string()),
        vec![PatternToken::Wildcard],
    )]
    fn parse_var_ref_command_position(
        #[case] input: &str,
        #[case] expected_command: CommandPattern,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        let result = parse(input).unwrap();
        assert_eq!(result.command, expected_command);
        assert_eq!(result.tokens, expected_tokens);
    }

    #[test]
    fn parse_path_ref_command_position_rejected() {
        let result = parse("<path:foo> bar");
        assert!(result.is_err());
    }

    // === <flag:name> placeholder ===

    #[rstest]
    #[case::standalone("gh api graphql <flag:field-flag> *", "gh", vec![
        PatternToken::Literal("api".into()),
        PatternToken::Literal("graphql".into()),
        PatternToken::FlagGroupRef {
            name: "field-flag".to_string(),
        },
        PatternToken::Wildcard,
    ])]
    #[case::with_trailing_literal("curl <flag:data-flag> https://example.com", "curl", vec![
        PatternToken::FlagGroupRef {
            name: "data-flag".to_string(),
        },
        PatternToken::Literal("https://example.com".into()),
    ])]
    #[case::with_trailing_wildcard("curl <flag:header-flag> *", "curl", vec![
        PatternToken::FlagGroupRef {
            name: "header-flag".to_string(),
        },
        PatternToken::Wildcard,
    ])]
    #[case::no_trailing_token("gh api graphql <flag:verbose>", "gh", vec![
        PatternToken::Literal("api".into()),
        PatternToken::Literal("graphql".into()),
        PatternToken::FlagGroupRef {
            name: "verbose".to_string(),
        },
    ])]
    fn parse_flag_group_ref(
        #[case] input: &str,
        #[case] expected_command: &str,
        #[case] expected_tokens: Vec<PatternToken>,
    ) {
        assert_parse(input, expected_command, expected_tokens);
    }

    fn assert_err_message_contains(err: &super::super::PatternParseError, needle: &str) {
        let msg = format!("{err}");
        if !msg.contains(needle) {
            panic!("expected error message to contain {needle:?}, got: {msg}");
        }
    }

    #[test]
    fn parse_flag_group_ref_empty_name_is_error() {
        let err = parse("gh <flag:> *").unwrap_err();
        assert_err_message_contains(&err, "requires a group name");
    }

    #[test]
    fn parse_flag_group_ref_inside_optional_group_is_error() {
        let err = parse("gh api graphql [<flag:field-flag>]").unwrap_err();
        assert_err_message_contains(&err, "not supported inside an optional group");
    }

    // === parse_flag_group_definition ===

    #[rstest]
    #[case::value_flag_wildcard(
        "-f|-F|--field *",
        ParsedFlagGroup {
            aliases: vec!["-f".into(), "-F".into(), "--field".into()],
            value_pattern: Some(PatternToken::Wildcard),
        },
    )]
    #[case::bool_flag(
        "-v|--verbose",
        ParsedFlagGroup {
            aliases: vec!["-v".into(), "--verbose".into()],
            value_pattern: None,
        },
    )]
    #[case::value_restriction(
        "-X|--method GET|HEAD|OPTIONS",
        ParsedFlagGroup {
            aliases: vec!["-X".into(), "--method".into()],
            value_pattern: Some(PatternToken::Alternation(vec!["GET".into(), "HEAD".into(), "OPTIONS".into()])),
        },
    )]
    #[case::single_flag_with_value(
        "--field *",
        ParsedFlagGroup {
            aliases: vec!["--field".into()],
            value_pattern: Some(PatternToken::Wildcard),
        },
    )]
    #[case::single_bool_flag(
        "--force",
        ParsedFlagGroup {
            aliases: vec!["--force".into()],
            value_pattern: None,
        },
    )]
    fn test_parse_flag_group_definition(#[case] input: &str, #[case] expected: ParsedFlagGroup) {
        assert_eq!(parse_flag_group_definition(input).unwrap(), expected);
    }

    #[rstest]
    #[case::empty("")]
    #[case::not_a_flag("notaflag")]
    #[case::bare_double_dash("--")]
    fn test_parse_flag_group_definition_errors(#[case] input: &str) {
        assert!(parse_flag_group_definition(input).is_err());
    }
}
