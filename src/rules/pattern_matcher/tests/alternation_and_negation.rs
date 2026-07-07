//! Tests for `Alternation` and `Negation` matching, including glob wildcards
//! within alternatives, multi-word alternation (`parse_multi`), and negation
//! as a flag value.

use super::*;
use rstest::rstest;

// ========================================
// Alias / alternation matching
// ========================================

#[rstest]
#[case::first_alt("git push main|master", "git push main", true)]
#[case::second_alt("git push main|master", "git push master", true)]
#[case::no_alt_match("git push main|master", "git push develop", false)]
#[case::subcommand_alt("kubectl describe|get|list *", "kubectl get pods", true)]
#[case::non_flag_alt_skips_flags("git push main|master *", "git push -v main origin", true)]
#[case::non_flag_alt_skips_flags_second(
    "git push main|master *",
    "git push -v master origin",
    true
)]
#[case::non_flag_alt_after_double_dash_no_skip("cmd -- main|master", "cmd -- -v main", false)]
#[case::mixed_flag_nonflag_alt_flag_variant("cmd -v|verbose *", "cmd -v foo", true)]
#[case::mixed_flag_nonflag_alt_nonflag_variant("cmd -v|verbose *", "cmd verbose foo", true)]
fn alternation_matching(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected
    );
}

// ========================================
// Negation matching
// ========================================

#[rstest]
#[case::negation_matches("kubectl !describe *", "kubectl get pods", true)]
#[case::negation_rejects("kubectl !describe *", "kubectl describe pods", false)]
#[case::negation_alternation("kubectl !describe|get|list *", "kubectl delete pods", true)]
#[case::negation_alternation_reject("kubectl !describe|get|list *", "kubectl get pods", false)]
// Flag-only negation: order-independent matching
#[case::flag_negation_rejects_at_end("find !-delete *", "find . -delete", false)]
#[case::flag_negation_rejects_at_start("find !-delete *", "find -delete .", false)]
#[case::flag_negation_allows_no_flag("find !-delete *", "find . -name foo", true)]
#[case::flag_negation_alt_rejects("find !-delete|-fprint|-fls *", "find . -type f -delete", false)]
#[case::flag_negation_alt_allows("find !-delete|-fprint|-fls *", "find . -type f -name foo", true)]
// Flag-only negation with `=`-joined tokens
#[case::flag_negation_rejects_equals_form("rg !--pre *", "rg --pre=pdftotext pattern", false)]
#[case::flag_negation_allows_different_flag_equals(
    "rg !--pre *",
    "rg --color=always pattern",
    true
)]
#[case::flag_negation_alt_rejects_equals_form(
    "sort !-o|--output|--compress-program *",
    "sort --output=result.txt file.txt",
    false
)]
#[case::flag_negation_alt_allows_equals_different_flag(
    "sort !-o|--output|--compress-program *",
    "sort --reverse=true file.txt",
    true
)]
// Flag-only negation with empty command tokens (no arguments after command)
#[case::flag_negation_empty_tokens_single("sort !-o *", "sort", true)]
#[case::flag_negation_empty_tokens_alt("sort !-o|--output|--compress-program *", "sort", true)]
#[case::flag_negation_empty_tokens_find("find !-delete *", "find", true)]
// Long flag negation with preceding literals
#[case::long_flag_negation_empty_after_literals(
    "git interpret-trailers --parse !--in-place *",
    "git interpret-trailers --parse",
    true
)]
#[case::long_flag_negation_with_safe_arg(
    "git interpret-trailers --parse !--in-place *",
    "git interpret-trailers --parse file.txt",
    true
)]
#[case::long_flag_negation_rejects_banned(
    "git interpret-trailers --parse !--in-place *",
    "git interpret-trailers --parse --in-place",
    false
)]
// Positional negation with empty tokens should still be false
#[case::positional_negation_empty_tokens("kubectl !describe *", "kubectl", false)]
fn negation_matching(#[case] pattern_str: &str, #[case] command_str: &str, #[case] expected: bool) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected
    );
}

// ========================================
// Negation as flag value
// ========================================

#[test]
fn flag_with_negation_value() {
    // Pattern: deny curl with any method except GET
    assert!(check_match(
        "curl -X|--request !GET *",
        "curl -X POST https://example.com",
        &empty_defs()
    ));
    assert!(!check_match(
        "curl -X|--request !GET *",
        "curl -X GET https://example.com",
        &empty_defs()
    ));
}

// ========================================
// Multi-word alternation matching
// ========================================

/// Helper: parse pattern with parse_multi, then check if any expanded pattern matches.
fn check_multi_match(pattern_str: &str, command_str: &str, definitions: &Definitions) -> bool {
    use crate::rules::pattern_parser::parse_multi;

    let patterns = parse_multi(pattern_str).unwrap();
    for pattern in &patterns {
        let schema = build_schema_from_pattern(pattern, definitions);
        let command = parse_command(command_str, &schema).unwrap();
        if matches(pattern, &command, definitions) {
            return true;
        }
    }
    false
}

#[rstest]
#[case::npx_variant(r#""npx prettier"|prettier *"#, "npx prettier --write .", true)]
#[case::bare_variant(r#""npx prettier"|prettier *"#, "prettier --write .", true)]
#[case::no_match_different_runner(r#""npx prettier"|prettier *"#, "yarn prettier --write .", false)]
#[case::no_match_different_tool(r#""npx prettier"|prettier *"#, "npx eslint --fix .", false)]
#[case::three_alternatives_first(
    r#""npx prettier"|"bunx prettier"|prettier *"#,
    "npx prettier --write .",
    true
)]
#[case::three_alternatives_second(
    r#""npx prettier"|"bunx prettier"|prettier *"#,
    "bunx prettier --write .",
    true
)]
#[case::three_alternatives_third(
    r#""npx prettier"|"bunx prettier"|prettier *"#,
    "prettier --write .",
    true
)]
#[case::python_pytest_module(r#""python -m pytest"|pytest *"#, "python -m pytest tests/", true)]
#[case::python_pytest_bare(r#""python -m pytest"|pytest *"#, "pytest tests/", true)]
#[case::python_pytest_no_match(r#""python -m pytest"|pytest *"#, "python -m mypy", false)]
fn multi_word_alternation_matching(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        check_multi_match(pattern_str, command_str, &empty_defs()),
        expected,
        "pattern {pattern_str:?} vs command {command_str:?}",
    );
}

#[rstest]
#[case::backward_compat_first("ast-grep|sg scan *", "ast-grep scan foo", true)]
#[case::backward_compat_second("ast-grep|sg scan *", "sg scan foo", true)]
#[case::backward_compat_no_match("ast-grep|sg scan *", "rg scan foo", false)]
fn multi_word_alternation_backward_compat(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        check_multi_match(pattern_str, command_str, &empty_defs()),
        expected,
    );
}

// === Alternation with glob wildcard matching ===

#[rstest]
#[case::glob_alt_match(
    "kubectl describe|get|list-* *",
    "kubectl list-buckets my-bucket",
    true
)]
#[case::glob_alt_exact_still_works(
    "kubectl describe|get|list-* *",
    "kubectl describe my-pod",
    true
)]
#[case::glob_alt_no_match("kubectl describe|get|list-* *", "kubectl delete my-pod", false)]
#[case::glob_alt_list_instances(
    "aws * describe-*|get-*|list-* *",
    "aws ec2 list-instances --region us-east-1",
    true
)]
#[case::glob_alt_describe_prefix(
    "aws * describe-*|get-*|list-* *",
    "aws ec2 describe-instances --region us-east-1",
    true
)]
fn alternation_glob_matching(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected,
        "pattern {pattern_str:?} vs command {command_str:?}",
    );
}

// === Negation alternation with glob wildcard ===

#[rstest]
#[case::negated_glob_blocks_match(
    "kubectl !describe|get|list-* *",
    "kubectl list-pods my-pod",
    false
)]
#[case::negated_glob_allows_non_match(
    "kubectl !describe|get|list-* *",
    "kubectl delete my-pod",
    true
)]
#[case::negated_glob_blocks_exact(
    "kubectl !describe|get|list-* *",
    "kubectl describe my-pod",
    false
)]
#[case::negated_glob_blocks_exact_get("kubectl !describe|get|list-* *", "kubectl get pods", false)]
fn negation_alternation_glob_matching(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected,
        "pattern {pattern_str:?} vs command {command_str:?}",
    );
}

// === Alternation flag with `=`-joined command token ===

#[rstest]
#[case::long_flag_equals_joined(
    "curl * -o|--output *",
    "curl --output=/tmp/out https://example.com",
    true
)]
#[case::short_flag_equals_joined(
    "curl * -o|--output *",
    "curl -o=/tmp/out https://example.com",
    true
)]
#[case::equals_joined_no_match_wrong_flag(
    "curl * -o|--output *",
    "curl --header=Accept https://example.com",
    false
)]
fn alternation_flag_equals_joined(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected,
        "pattern {pattern_str:?} vs command {command_str:?}",
    );
}
