use super::*;
use crate::rules::PatternParseError;
use rstest::rstest;

fn parse(input: &str) -> Result<Pattern, PatternParseError> {
    DefaultPatternParser.parse(input)
}

// =============================================================================
// Normal cases
// =============================================================================

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

// =============================================================================
// Error cases
// =============================================================================

// --- Unclosed angle bracket ---

#[test]
fn parse_unclosed_angle_bracket() {
    let err = parse("cat <path:sensitive").unwrap_err();
    assert!(matches!(err, PatternParseError::UnclosedBracket(_)));
}

// --- Unclosed square bracket ---

#[test]
fn parse_unclosed_square_bracket() {
    let err = parse("git [-C *").unwrap_err();
    assert!(matches!(err, PatternParseError::UnclosedSquareBracket(_)));
}

// --- Nested square brackets ---

#[test]
fn parse_nested_square_brackets() {
    let err = parse("git [[-C *]] status").unwrap_err();
    assert!(matches!(err, PatternParseError::NestedSquareBracket));
}

// --- Empty alternation ---

#[rstest]
#[case("curl -X| *")]
#[case("curl |--request *")]
fn parse_empty_alternation(#[case] input: &str) {
    let err = parse(input).unwrap_err();
    assert!(matches!(err, PatternParseError::EmptyAlternation));
}

// --- Bare negation (! without value) ---

#[test]
fn parse_bare_negation() {
    let err = parse("cmd !").unwrap_err();
    assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
}

// --- Pattern starting with non-command token ---

#[rstest]
#[case("* foo")]
#[case("[--verbose] git status")]
#[case("<cmd> foo")]
fn parse_pattern_starting_with_non_command(#[case] input: &str) {
    let err = parse(input).unwrap_err();
    assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
}

// --- Empty input ---

#[test]
fn parse_empty_input() {
    let err = parse("").unwrap_err();
    assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
}

// --- Whitespace only ---

#[test]
fn parse_whitespace_only() {
    let err = parse("   ").unwrap_err();
    assert!(matches!(err, PatternParseError::InvalidSyntax(_)));
}
