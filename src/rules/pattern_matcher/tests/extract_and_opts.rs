use super::*;
use rstest::rstest;

// ========================================
// <opts> matching in non-wrapper context
// ========================================

#[rstest]
#[case::opts_consumes_flags("cmd <opts> arg", "cmd -v --debug arg", true)]
#[case::opts_no_flags("cmd <opts> arg", "cmd arg", true)]
#[case::opts_with_short_flag_value("cmd <opts> arg", "cmd -n 5 arg", true)]
#[case::opts_mismatch_trailing("cmd <opts> arg", "cmd -v other", false)]
#[case::opts_digit_flag_not_consuming("cmd <opts> arg", "cmd -0 arg", true)]
#[case::opts_end_of_options_marker("cmd <opts> arg", "cmd -- arg", true)]
#[case::opts_end_of_options_with_flags("cmd <opts> arg", "cmd -v -- arg", true)]
fn opts_non_wrapper_matching(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
    empty_defs: Definitions,
) {
    assert_eq!(check_match(pattern_str, command_str, &empty_defs), expected);
}

// ========================================
// extract_placeholder tests
// ========================================

/// Helper: extract placeholder candidates from a wrapper pattern.
fn check_extract(
    pattern_str: &str,
    command_str: &str,
    definitions: &Definitions,
) -> Vec<Vec<String>> {
    let pattern = parse_pattern(pattern_str).unwrap();
    let schema = build_schema_from_pattern(&pattern, definitions);
    let command = parse_command(command_str, &schema).unwrap();
    extract_placeholder(&pattern, &command, definitions).unwrap()
}

#[rstest]
#[case::simple_placeholder(
    "sudo <cmd>",
    "sudo echo hello",
    vec![vec!["echo", "hello"]],
)]
#[case::literal_before_cmd(
    "run exec <cmd>",
    "run exec echo hello",
    vec![vec!["echo", "hello"]],
)]
#[case::wildcard_before_cmd(
    "xargs * <cmd>",
    "xargs -I{} echo hello",
    // Wildcard tries skip=0,1,2: skip=0 is rejected because <cmd> would
    // start with a flag ("-I{}"), so only skip=1 and skip=2 produce candidates.
    vec![vec!["echo", "hello"], vec!["hello"]],
)]
#[case::no_match(
    "sudo <cmd>",
    "bash echo hello",
    Vec::<Vec<&str>>::new(),
)]
#[case::opts_before_cmd(
    "xargs <opts> <cmd>",
    "xargs -0 -I{} echo hello",
    vec![vec!["echo", "hello"]],
)]
#[case::negation_before_cmd(
    "run !--dry-run <cmd>",
    "run --verbose echo hello",
    // <cmd> rejects capture starting with a flag ("--verbose"), so no match.
    Vec::<Vec<&str>>::new(),
)]
#[case::positional_negation_before_cmd(
    "run !exec <cmd>",
    "run start echo hello",
    vec![vec!["echo", "hello"]],
)]
#[case::positional_negation_empty_tokens(
    "run !exec <cmd>",
    "run",
    Vec::<Vec<&str>>::new(),
)]
#[case::flag_negation_empty_tokens_before_cmd(
    "run !--dry-run <cmd>",
    "run",
    Vec::<Vec<&str>>::new(),
)]
#[case::flag_negation_rejected_before_cmd(
    "run !--dry-run <cmd>",
    "run --dry-run echo hello",
    Vec::<Vec<&str>>::new(),
)]
#[case::positional_negation_rejected_before_cmd(
    "run !exec <cmd>",
    "run exec echo hello",
    Vec::<Vec<&str>>::new(),
)]
#[case::flag_like_literal_bash_c(
    "bash -c <cmd>",
    "bash -c 'rm -rf /'",
    vec![vec!["rm -rf /"]],
)]
#[case::flag_like_literal_before_cmd(
    "run -v <cmd>",
    "run -v echo hello",
    vec![vec!["echo", "hello"]],
)]
#[case::cmd_rejects_flag_start(
    "command <cmd>",
    "command -v a",
    Vec::<Vec<&str>>::new(),
)]
#[case::cmd_accepts_non_flag(
    "command <cmd>",
    "command ls",
    vec![vec!["ls"]],
)]
fn extract_placeholder_cases(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: Vec<Vec<&str>>,
    empty_defs: Definitions,
) {
    let result = check_extract(pattern_str, command_str, &empty_defs);
    let expected: Vec<Vec<String>> = expected
        .into_iter()
        .map(|v| v.into_iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(result, expected);
}

#[rstest]
fn extract_placeholder_with_alternation(empty_defs: Definitions) {
    // Alternation token before <cmd>
    let result = check_extract("run fast|slow <cmd>", "run fast echo hello", &empty_defs);
    assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
}

#[rstest]
#[case::space_separated("run -m debug echo hello")]
#[case::equals_joined("run -m=debug echo hello")]
fn extract_placeholder_with_flag_with_value(#[case] command_str: &str, empty_defs: Definitions) {
    let result = check_extract("run -m|--mode debug <cmd>", command_str, &empty_defs);
    assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
}

#[rstest]
fn extract_placeholder_with_non_cmd_trailing(empty_defs: Definitions) {
    // Pattern with <cmd> followed by a non-<cmd> placeholder at the end.
    // The non-<cmd> placeholder consumes one token, <cmd> captures the rest.
    let result = check_extract("wrap <cmd> <suffix>", "wrap echo hello world", &empty_defs);
    // <cmd> tries take=1 ("echo"), take=2 ("echo hello") — for each,
    // <suffix> must consume exactly the remaining single token.
    // take=1: <cmd>=["echo"], <suffix> gets ["hello", "world"] -> 2 tokens, doesn't match
    // take=2: <cmd>=["echo", "hello"], <suffix> gets ["world"] -> 1 token, matches
    assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
}

#[rstest]
fn extract_placeholder_cmd_followed_by_literal(empty_defs: Definitions) {
    // <cmd> in middle position followed by a literal sentinel.
    // Exercises the base case where captured is non-empty.
    let result = check_extract("wrap <cmd> done", "wrap echo hello done", &empty_defs);
    assert_eq!(result, vec![vec!["echo".to_string(), "hello".to_string()]]);
}
