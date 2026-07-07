use super::*;
use rstest::rstest;

// ========================================
// Optional matching
// ========================================

#[rstest]
#[case::with_optional_flag("rm [-f] *", "rm -f file.txt", true)]
#[case::without_optional_flag("rm [-f] *", "rm file.txt", true)]
#[case::optional_flag_with_value(
    "curl [-X|--request GET] *",
    "curl -X GET https://example.com",
    true
)]
#[case::optional_absent("curl [-X|--request GET] *", "curl https://example.com", true)]
#[case::optional_wrong_value(
    "curl [-X|--request GET] *",
    "curl -X POST https://example.com",
    false
)]
#[case::optional_flag_with_value_after_arg(
    "curl [-X|--request GET] *",
    "curl https://example.com -X GET",
    true
)]
#[case::optional_dir("git [-C *] status", "git -C /tmp status", true)]
#[case::optional_dir_absent("git [-C *] status", "git status", true)]
// Multiple optional bare flags in any order
#[case::optional_bare_flags_reversed(
    "curl [-s] [-X GET] *",
    "curl -X GET -s https://example.com",
    true
)]
#[case::optional_bare_flags_after_arg(
    "curl [-s] [-X GET] *",
    "curl https://example.com -X GET -s",
    true
)]
#[case::optional_bare_flags_interleaved(
    "curl [-s] [-X GET] *",
    "curl -X GET https://example.com -s",
    true
)]
#[case::optional_bare_flags_in_order(
    "curl [-s] [-X GET] *",
    "curl -s -X GET https://example.com",
    true
)]
#[case::optional_bare_flags_all_absent("curl [-s] [-X GET] *", "curl https://example.com", true)]
#[case::optional_bare_flags_only_s("curl [-s] [-X GET] *", "curl -s https://example.com", true)]
#[case::optional_bare_flags_only_x("curl [-s] [-X GET] *", "curl -X GET https://example.com", true)]
// Wrong flag values must still be rejected
#[case::optional_bare_flags_wrong_value_reversed(
    "curl [-s] [-X GET] *",
    "curl -X POST -s https://example.com",
    false
)]
#[case::optional_bare_flags_wrong_value_after_arg(
    "curl [-s] [-X GET] *",
    "curl https://example.com -X POST -s",
    false
)]
#[case::optional_bare_flags_wrong_value_interleaved(
    "curl [-s] [-X GET] *",
    "curl -X POST https://example.com -s",
    false
)]
// `=`-joined flag with value
#[case::optional_flag_with_value_equals_joined(
    "git branch [--sort *]",
    "git branch --sort=-committerdate",
    true
)]
#[case::optional_flag_with_value_equals_joined_absent("git branch [--sort *]", "git branch", true)]
#[case::optional_flag_with_value_equals_joined_with_other_flags(
    "git branch [-a] [--sort *]",
    "git branch -a --sort=-committerdate",
    true
)]
#[case::optional_flag_with_value_equals_joined_specific_value(
    "curl [-X|--request GET] *",
    "curl -X=GET https://example.com",
    true
)]
#[case::optional_flag_with_value_equals_joined_wrong_value(
    "curl [-X|--request GET] *",
    "curl -X=POST https://example.com",
    false
)]
fn optional_matching(#[case] pattern_str: &str, #[case] command_str: &str, #[case] expected: bool) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected
    );
}

// ========================================
// Combined patterns
// ========================================

#[test]
fn combined_optional_and_wildcard() {
    // git [-C *] [--no-pager] log *
    let pattern_str = "git [-C *] status";
    assert!(check_match(pattern_str, "git status", &empty_defs()));
    assert!(check_match(
        pattern_str,
        "git -C /tmp status",
        &empty_defs()
    ));
    assert!(check_match(
        pattern_str,
        "git -C /home/user/repo status",
        &empty_defs()
    ));
}

#[test]
fn equals_joined_token() {
    assert!(check_match(
        "java -Denv=prod",
        "java -Denv=prod",
        &empty_defs()
    ));
    assert!(!check_match(
        "java -Denv=prod",
        "java -Denv=staging",
        &empty_defs()
    ));
}

// ========================================
// matches_with_captures tests
// ========================================

#[rstest]
#[case::no_wildcard("git status", "git status", Some(vec![]))]
#[case::single_wildcard("git *", "git status", Some(vec!["status".to_string()]))]
#[case::wildcard_multiple_tokens(
    "git *",
    "git remote add origin",
    Some(vec!["remote".to_string(), "add".to_string(), "origin".to_string()])
)]
#[case::wildcard_in_optional(
    "git [-C *] status",
    "git -C /tmp status",
    Some(vec!["/tmp".to_string()])
)]
#[case::optional_absent_no_captures(
    "git [-C *] status",
    "git status",
    Some(vec![])
)]
#[case::no_match("git status", "ls -la", None)]
#[case::different_command("git *", "ls -la", None)]
#[case::wildcard_command_captures("* *", "git status", Some(vec!["status".to_string()]))]
#[case::wildcard_command_no_args("*", "git", Some(vec![]))]
fn matches_with_captures_returns_expected(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: Option<Vec<String>>,
    empty_defs: Definitions,
) {
    assert_eq!(
        check_captures(pattern_str, command_str, &empty_defs),
        expected
    );
}

// ========================================
// var_captures from matches_with_captures
// ========================================

#[rstest]
#[case::literal_var_captured(
    "aws ec2 terminate-instances --instance-ids <var:instance-ids>",
    "aws ec2 terminate-instances --instance-ids i-abc123",
    Some(HashMap::from([("instance-ids".to_string(), "i-abc123".to_string())])),
)]
#[case::no_match_returns_none(
    "aws ec2 terminate-instances --instance-ids <var:instance-ids>",
    "aws ec2 terminate-instances --instance-ids i-UNKNOWN",
    None
)]
#[case::path_var_captured(
    "bash <var:test-script>",
    "bash ./tests/run",
    Some(HashMap::from([("test-script".to_string(), "./tests/run".to_string())])),
)]
fn var_captures_returns_expected(
    #[case] pattern_str: &str,
    #[case] command_str: &str,
    #[case] expected: Option<HashMap<String, String>>,
) {
    let definitions = Definitions {
        vars: Some(HashMap::from([
            (
                "instance-ids".to_string(),
                crate::config::VarDefinition {
                    var_type: crate::config::VarType::Literal,
                    values: vec!["i-abc123".into(), "i-def456".into()],
                },
            ),
            (
                "test-script".to_string(),
                crate::config::VarDefinition {
                    var_type: crate::config::VarType::Path,
                    values: vec!["./tests/run".into()],
                },
            ),
        ])),
        ..Default::default()
    };
    assert_eq!(
        check_var_captures(pattern_str, command_str, &definitions),
        expected,
    );
}

// ========================================
// var_captures backtracking: stale entries must not persist
// ========================================

#[test]
fn var_captures_not_stale_after_optional_backtrack() {
    // Pattern: `cmd [<var:name>] other`
    // Command: `cmd other`
    //
    // Optional "with" branch tries `<var:name> other` against ["other"].
    // <var:name> matches "other" (it's in values) and captures name=other,
    // but then the remaining `other` pattern has no tokens left → fails.
    // On backtrack, the stale capture name=other must be removed.
    // Optional "without" branch matches `other` against ["other"] → success.
    // Final vars should be empty (no <var:name> was matched in the
    // successful branch).
    let definitions = Definitions {
        vars: Some(HashMap::from([(
            "name".to_string(),
            crate::config::VarDefinition {
                var_type: crate::config::VarType::Literal,
                values: vec!["other".into(), "val".into()],
            },
        )])),
        ..Default::default()
    };
    let result = check_var_captures("cmd [<var:name>] other", "cmd other", &definitions);
    assert_eq!(
        result,
        Some(HashMap::new()),
        "var_captures should be empty when <var:name> only matched in a backtracked branch",
    );
}
