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
