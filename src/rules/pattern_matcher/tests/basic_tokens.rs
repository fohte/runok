use super::*;
use rstest::rstest;

// ========================================
// Simple literal matching
// ========================================

#[rstest]
#[case::exact_match("git status", "git status", true)]
#[case::exact_multi("git remote add origin", "git remote add origin", true)]
#[case::command_mismatch("git status", "hg status", false)]
#[case::too_few_args("git remote add", "git remote add origin", false)]
#[case::too_many_args("git remote add origin", "git remote add", false)]
#[case::command_only("git", "git", true)]
#[case::command_only_mismatch("git", "git status", false)]
fn simple_matching(#[case] pattern_str: &str, #[case] command_str: &str, #[case] expected: bool) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected
    );
}

// ========================================
// Order-independent literal matching
// ========================================

#[rstest]
#[case::flag_before_literal("gh api -X GET *", "gh -X GET api /", true)]
#[case::literal_at_normal_position("gh api -X GET *", "gh api -X GET /", true)]
#[case::multiple_flags_before_literal("gh api -X GET *", "gh -X GET -v api /", true)]
#[case::extra_flag_not_in_pattern_no_match(
    "git remote add origin",
    "git -v remote add origin",
    false
)]
#[case::double_dash_stays_positional("cmd foo -- bar", "cmd -- foo bar", false)]
#[case::double_dash_at_correct_position("cmd foo -- bar", "cmd foo -- bar", true)]
#[case::literal_mismatch_still_fails("gh api -X GET *", "gh -X GET issues /", false)]
#[case::flag_literal_remains_positional("cmd -v status", "cmd status -v", false)]
#[case::flag_after_double_dash_is_positional("cmd -- status *", "cmd -- -v status foo", false)]
#[case::flag_not_consumed_means_no_match("rm /tmp/*", "rm -rf /tmp/foo", false)]
#[case::flag_skip_leaves_flag_unconsumed("rm file", "rm -f file", false)]
#[case::skipped_flag_consumed_by_wildcard("git [-C *] commit *", "git -v commit -m fix", true)]
#[case::negation_bypass_with_flag("kubectl !describe *", "kubectl -v describe pods", false)]
#[case::skipped_flag_unconsumed_without_wildcard("git [-C *] commit", "git -v commit", false)]
fn order_independent_literal_matching(
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

// ========================================
// Wildcard matching
// ========================================

#[rstest]
#[case::trailing_wildcard("git push *", "git push origin main", true)]
#[case::wildcard_zero("git push *", "git push", true)]
#[case::wildcard_many("git *", "git remote add origin", true)]
#[case::wildcard_with_flags("git push *", "git push --force origin", true)]
#[case::middle_wildcard("git * status", "git -C /tmp status", true)]
#[case::middle_wildcard_multi("git * status", "git -C /tmp --no-pager status", true)]
fn wildcard_matching(#[case] pattern_str: &str, #[case] command_str: &str, #[case] expected: bool) {
    assert_eq!(
        check_match(pattern_str, command_str, &empty_defs()),
        expected
    );
}

// ========================================
// PathRef expansion matching
// ========================================

#[test]
fn path_ref_matches_listed_path() {
    let defs = Definitions {
        paths: Some(HashMap::from([(
            "sensitive".to_string(),
            vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()],
        )])),
        ..Default::default()
    };
    assert!(check_match(
        "cat <path:sensitive>",
        "cat /etc/passwd",
        &defs
    ));
    assert!(check_match(
        "cat <path:sensitive>",
        "cat /etc/shadow",
        &defs
    ));
}

#[test]
fn path_ref_rejects_unlisted_path() {
    let defs = Definitions {
        paths: Some(HashMap::from([(
            "sensitive".to_string(),
            vec!["/etc/passwd".to_string()],
        )])),
        ..Default::default()
    };
    assert!(!check_match(
        "cat <path:sensitive>",
        "cat /tmp/file.txt",
        &defs
    ));
}

#[test]
fn path_ref_undefined_name_never_matches() {
    let defs = empty_defs();
    assert!(!check_match(
        "cat <path:undefined>",
        "cat /etc/passwd",
        &defs
    ));
}

// ========================================
// Wildcard command name matching
// ========================================

#[rstest]
#[case::help_flag("* --help", "git --help", true)]
#[case::version_flag("* --version", "node --version", true)]
#[case::any_command_any_args("* *", "ls -la", true)]
#[case::wildcard_only("*", "git", true)]
#[case::wildcard_command_multi_word("*", "git status", true)]
#[case::wildcard_command_flag_mismatch("* --help", "git --version", false)]
#[case::wildcard_command_missing_flag("* --help", "git", false)]
#[case::wildcard_help_multi_word("* --help", "git branch --help", true)]
#[case::wildcard_help_three_words("* --help", "cargo test --help", true)]
#[case::wildcard_help_deep_subcommand("* --help", "docker compose up --help", true)]
#[case::wildcard_with_args_multi_word("* *", "git branch -a", true)]
fn wildcard_command_matching(
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
// Unmatched cases
// ========================================

#[rstest]
#[case::different_command("git status", "hg status")]
#[case::extra_args("git status", "git status --short")]
#[case::missing_args("git push origin main", "git push origin")]
fn no_match(#[case] pattern_str: &str, #[case] command_str: &str) {
    assert!(!check_match(pattern_str, command_str, &empty_defs()));
}

// ========================================
// Literal bracket command (`[`) matching
// ========================================

#[rstest]
#[case::bracket_wildcard("[ *", "[ -f file ]", true)]
#[case::bracket_exact_args("[ -f file ]", "[ -f file ]", true)]
#[case::bracket_wildcard_no_args("[ *", "[ ]", true)]
#[case::bracket_command_mismatch("[ *", "test -f file", false)]
#[case::bracket_wrong_args("[ -f file ]", "[ -d dir ]", false)]
fn bracket_command_matching(
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
// Path normalization
// ========================================

#[rstest]
#[case::dot_segment("cat /etc/./passwd", true)]
#[case::dotdot_segment("cat /etc/../etc/passwd", true)]
#[case::multiple_dots("cat /etc/./././passwd", true)]
#[case::complex_traversal("cat /tmp/../etc/passwd", true)]
#[case::unrelated_path("cat /tmp/file.txt", false)]
fn path_ref_normalized(#[case] command_str: &str, #[case] expected: bool) {
    let defs = Definitions {
        paths: Some(HashMap::from([(
            "sensitive".to_string(),
            vec!["/etc/passwd".to_string()],
        )])),
        ..Default::default()
    };
    assert_eq!(
        check_match("cat <path:sensitive>", command_str, &defs),
        expected
    );
}

#[test]
fn path_ref_definition_normalized() {
    // Definition itself contains non-canonical path
    let defs = Definitions {
        paths: Some(HashMap::from([(
            "sensitive".to_string(),
            vec!["/etc/./passwd".to_string()],
        )])),
        ..Default::default()
    };
    assert!(check_match(
        "cat <path:sensitive>",
        "cat /etc/passwd",
        &defs
    ));
}

// ========================================
// Wildcard DoS prevention
// ========================================

#[test]
fn wildcard_dos_terminates() {
    // Many consecutive wildcards against non-matching input would cause
    // exponential blowup without the step limit. This test verifies
    // that the matcher terminates quickly by returning false.
    let pattern_str = "cmd * * * * * * * * * * a";
    let command_str = "cmd b b b b b b b b b b b b b b b b b b b b";
    assert!(!check_match(pattern_str, command_str, &empty_defs()));
}

// === Literal token with glob wildcard ===

#[rstest]
#[case::literal_glob_prefix("aws ssm get-* *", "aws ssm get-parameter --name foo", true)]
#[case::literal_glob_no_match("aws ssm get-* *", "aws ssm put-parameter --name foo", false)]
#[case::literal_glob_exact_still_works(
    "aws ssm get-parameter *",
    "aws ssm get-parameter --name foo",
    true
)]
#[case::literal_glob_suffix("cmd *.txt", "cmd readme.txt", true)]
#[case::literal_glob_suffix_no_match("cmd *.txt", "cmd readme.md", false)]
#[case::literal_glob_middle("cmd foo*bar", "cmd fooXbar", true)]
#[case::literal_glob_middle_no_match("cmd foo*bar", "cmd fooXbaz", false)]
#[case::negated_literal_glob_blocks("aws ssm !get-* *", "aws ssm get-parameter --name foo", false)]
#[case::negated_literal_glob_allows("aws ssm !get-* *", "aws ssm put-parameter --name foo", true)]
fn literal_glob_matching(
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

// === Double-dash (--) positional matching ===

#[rstest]
#[case::double_dash_exact("git checkout -- *", "git checkout -- README.md", true)]
#[case::double_dash_multiple_files(
    "git checkout -- *",
    "git checkout -- README.md docs/index.md",
    true
)]
#[case::double_dash_with_optional_c("git [-C *] checkout -- *", "git checkout -- README.md", true)]
#[case::double_dash_with_optional_c_present(
    "git [-C *] checkout -- *",
    "git -C /tmp checkout -- README.md",
    true
)]
#[case::double_dash_rejects_args_before(
    "git [-C *] checkout -- *",
    "git checkout HEAD~1 -- README.md",
    false
)]
#[case::double_dash_rejects_no_separator("git checkout -- *", "git checkout HEAD~1", false)]
fn double_dash_matching(
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

// === Quoted strings: `*` is glob, `\*` is literal ===

#[rstest]
#[case::quoted_star_glob_matches(r#"git commit -m "WIP*""#, "git commit -m WIPfoo", true)]
#[case::quoted_star_glob_exact(r#"git commit -m "WIP*""#, "git commit -m WIP*", true)]
#[case::quoted_star_glob_no_match(r#"git commit -m "WIP*""#, "git commit -m DONE", false)]
#[case::quoted_star_only_glob(r#"cmd "*""#, "cmd hello", true)]
#[case::escaped_star_exact_match(r#"git commit -m "WIP\*""#, "git commit -m WIP*", true)]
#[case::escaped_star_no_glob(r#"git commit -m "WIP\*""#, "git commit -m WIPfoo", false)]
#[case::escaped_star_only(r#"cmd "\*""#, "cmd *", true)]
#[case::escaped_star_only_no_glob(r#"cmd "\*""#, "cmd hello", false)]
fn quoted_literal_matching(
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
