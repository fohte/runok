#[derive(Debug, thiserror::Error)]
pub enum PatternParseError {
    #[error("unclosed angle bracket at position {0}")]
    UnclosedBracket(usize),
    #[error("unclosed square bracket at position {0}")]
    UnclosedSquareBracket(usize),
    #[error("nested square brackets are not allowed")]
    NestedSquareBracket,
    #[error("empty alternation")]
    EmptyAlternation,
    #[error("invalid syntax: {0}")]
    InvalidSyntax(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CommandParseError {
    #[error("unclosed quote")]
    UnclosedQuote,
    #[error("empty command")]
    EmptyCommand,
    #[error("syntax error in command")]
    SyntaxError,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("pattern parse error: {0}")]
    PatternParse(#[from] PatternParseError),
    #[error("command parse error: {0}")]
    CommandParse(#[from] CommandParseError),
    #[error("expression evaluation error: {0}")]
    ExprEval(#[from] ExprError),
    #[error("recursion depth exceeded (max: {0})")]
    RecursionDepthExceeded(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum ExprError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("evaluation error: {0}")]
    Eval(String),
    #[error("type error: expected bool, got {0}")]
    TypeError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === PatternParseError ===

    #[rstest]
    #[case(
        PatternParseError::UnclosedBracket(5),
        "unclosed angle bracket at position 5"
    )]
    #[case(
        PatternParseError::UnclosedSquareBracket(10),
        "unclosed square bracket at position 10"
    )]
    #[case(
        PatternParseError::NestedSquareBracket,
        "nested square brackets are not allowed"
    )]
    #[case(PatternParseError::EmptyAlternation, "empty alternation")]
    #[case(PatternParseError::InvalidSyntax("unexpected token".to_string()), "invalid syntax: unexpected token")]
    fn pattern_parse_error_display(#[case] error: PatternParseError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn pattern_parse_error_implements_std_error() {
        let error: &dyn std::error::Error = &PatternParseError::EmptyAlternation;
        assert!(error.source().is_none());
    }

    #[test]
    fn pattern_parse_error_is_debug() {
        let error = PatternParseError::UnclosedBracket(3);
        let debug = format!("{:?}", error);
        assert!(debug.contains("UnclosedBracket"));
    }

    // === CommandParseError ===

    #[rstest]
    #[case(CommandParseError::UnclosedQuote, "unclosed quote")]
    #[case(CommandParseError::EmptyCommand, "empty command")]
    fn command_parse_error_display(#[case] error: CommandParseError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn command_parse_error_implements_std_error() {
        let error: &dyn std::error::Error = &CommandParseError::UnclosedQuote;
        assert!(error.source().is_none());
    }

    // === RuleError ===

    #[test]
    fn rule_error_from_pattern_parse_error() {
        let pattern_err = PatternParseError::EmptyAlternation;
        let rule_err: RuleError = pattern_err.into();
        assert_eq!(
            rule_err.to_string(),
            "pattern parse error: empty alternation"
        );
    }

    #[test]
    fn rule_error_from_command_parse_error() {
        let cmd_err = CommandParseError::UnclosedQuote;
        let rule_err: RuleError = cmd_err.into();
        assert_eq!(rule_err.to_string(), "command parse error: unclosed quote");
    }

    #[test]
    fn rule_error_from_expr_error() {
        let expr_err = ExprError::Parse("undefined variable 'x'".to_string());
        let rule_err: RuleError = expr_err.into();
        assert_eq!(
            rule_err.to_string(),
            "expression evaluation error: parse error: undefined variable 'x'"
        );
    }

    #[test]
    fn rule_error_recursion_depth_exceeded() {
        let error = RuleError::RecursionDepthExceeded(10);
        assert_eq!(error.to_string(), "recursion depth exceeded (max: 10)");
    }

    #[test]
    fn rule_error_pattern_parse_has_source() {
        let error = RuleError::PatternParse(PatternParseError::EmptyAlternation);
        let source = std::error::Error::source(&error);
        assert!(source.is_some());
    }

    #[test]
    fn rule_error_command_parse_has_source() {
        let error = RuleError::CommandParse(CommandParseError::UnclosedQuote);
        let source = std::error::Error::source(&error);
        assert!(source.is_some());
    }

    #[test]
    fn rule_error_expr_eval_has_source() {
        let error = RuleError::ExprEval(ExprError::Eval("test".to_string()));
        let source = std::error::Error::source(&error);
        assert!(source.is_some());
    }

    // === ExprError ===

    #[rstest]
    #[case(ExprError::Parse("unexpected token at position 5".to_string()), "parse error: unexpected token at position 5")]
    #[case(ExprError::Eval("division by zero".to_string()), "evaluation error: division by zero")]
    #[case(ExprError::TypeError("string".to_string()), "type error: expected bool, got string")]
    fn expr_error_display(#[case] error: ExprError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn expr_error_implements_std_error() {
        let error: &dyn std::error::Error = &ExprError::Parse("test".to_string());
        assert!(error.source().is_none());
    }

    // === anyhow integration ===

    #[test]
    fn pattern_parse_error_into_anyhow() {
        let error = PatternParseError::UnclosedBracket(5);
        let anyhow_err: anyhow::Error = error.into();
        assert_eq!(
            anyhow_err.to_string(),
            "unclosed angle bracket at position 5"
        );
    }

    #[test]
    fn rule_error_into_anyhow() {
        let error = RuleError::RecursionDepthExceeded(10);
        let anyhow_err: anyhow::Error = error.into();
        assert_eq!(anyhow_err.to_string(), "recursion depth exceeded (max: 10)");
    }

    #[test]
    fn anyhow_error_chain_preserves_source() {
        let pattern_err = PatternParseError::EmptyAlternation;
        let rule_err = RuleError::PatternParse(pattern_err);
        let anyhow_err: anyhow::Error = rule_err.into();

        // anyhow preserves the error chain
        let chain: Vec<String> = anyhow_err.chain().map(|e| e.to_string()).collect();
        assert_eq!(chain[0], "pattern parse error: empty alternation");
        assert_eq!(chain[1], "empty alternation");
    }
}
