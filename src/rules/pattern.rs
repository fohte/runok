mod parser;

#[cfg(test)]
mod tests;

pub use parser::DefaultPatternParser;

use super::PatternParseError;

/// Parsed pattern structure containing the original command name and token list.
#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub command: String,
    pub tokens: Vec<PatternToken>,
}

/// Individual tokens that make up a parsed pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum PatternToken {
    /// Fixed string (e.g., "git", "status")
    Literal(String),
    /// Alternation of equivalent forms (e.g., -X|--request -> ["-X", "--request"])
    Alternation(Vec<String>),
    /// Negation (e.g., !GET, !describe|get|list-*)
    Negation(Box<PatternToken>),
    /// Optional tokens (e.g., [-X GET] -> flag present/absent both match)
    Optional(Vec<PatternToken>),
    /// Wildcard: matches zero or more arbitrary tokens
    Wildcard,
    /// Path variable reference (e.g., <path:sensitive>)
    PathRef(String),
    /// Wrapper placeholder (e.g., <cmd>)
    Placeholder(String),
}

/// Trait for parsing pattern strings into structured Pattern representations.
pub trait PatternParser {
    fn parse(&self, pattern: &str) -> Result<Pattern, PatternParseError>;
}
