use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command};

// ========================================
// Optional notation: curl [-X|--request GET] *
// ========================================

#[rstest]
#[case::without_flag("curl https://example.com", assert_allow as ActionAssertion)]
#[case::with_short_flag("curl -X GET https://example.com", assert_allow as ActionAssertion)]
#[case::with_long_flag("curl --request GET https://example.com", assert_allow as ActionAssertion)]
#[case::with_wrong_value("curl -X POST https://example.com", assert_ask as ActionAssertion)]
fn optional_flag_with_value(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'curl [-X|--request GET] *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Optional notation: git [-C *] status
// ========================================

#[rstest]
#[case::without_c("git status", assert_allow as ActionAssertion)]
#[case::with_c("git -C /some/path status", assert_allow as ActionAssertion)]
#[case::with_c_different_path("git -C /another/path status", assert_allow as ActionAssertion)]
fn optional_flag_with_wildcard_value(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git [-C *] status'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Optional notation: rm [-f] *
// ========================================

#[rstest]
#[case::without_f("rm file.txt", assert_allow as ActionAssertion)]
#[case::with_f("rm -f file.txt", assert_allow as ActionAssertion)]
fn optional_boolean_flag(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'rm [-f] *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Path reference: deny cat <path:sensitive>
// ========================================

#[rstest]
#[case::env_file("cat .env", assert_deny as ActionAssertion)]
#[case::env_local("cat .envrc", assert_deny as ActionAssertion)]
#[case::etc_passwd("cat /etc/passwd", assert_deny as ActionAssertion)]
#[case::etc_shadow("cat /etc/shadow", assert_deny as ActionAssertion)]
#[case::safe_file("cat /tmp/safe.txt", assert_ask as ActionAssertion)]
#[case::readme("cat README.md", assert_ask as ActionAssertion)]
fn path_ref_matches_defined_paths(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'cat <path:sensitive>'
        definitions:
          paths:
            sensitive:
              - .env
              - .envrc
              - /etc/passwd
              - /etc/shadow
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Path reference with multiple path groups
// ========================================

#[rstest]
#[case::log_read_denied("cat /var/log/syslog", assert_deny as ActionAssertion)]
#[case::config_read_denied("cat /etc/config.yml", assert_deny as ActionAssertion)]
#[case::safe_allowed("cat /tmp/notes.txt", assert_ask as ActionAssertion)]
fn multiple_path_groups(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'cat <path:logs>'
          - deny: 'cat <path:config>'
        definitions:
          paths:
            logs:
              - /var/log/syslog
              - /var/log/auth.log
            config:
              - /etc/config.yml
              - /etc/app.conf
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Optional notation combined with deny
// ========================================

#[rstest]
#[case::without_force("git push origin main", assert_deny as ActionAssertion)]
#[case::with_force("git push --force origin main", assert_deny as ActionAssertion)]
#[case::with_short_force("git push -f origin main", assert_deny as ActionAssertion)]
fn optional_flag_in_deny_rule(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push [-f|--force] *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Combined: optional notation + path reference
// ========================================

#[rstest]
#[case::sensitive_no_flag("rm .env", assert_deny as ActionAssertion)]
#[case::sensitive_with_flag("rm -f .envrc", assert_deny as ActionAssertion)]
#[case::safe_no_flag("rm temp.txt", assert_ask as ActionAssertion)]
#[case::safe_with_flag("rm -f temp.txt", assert_ask as ActionAssertion)]
fn optional_flag_with_path_ref(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm [-f] <path:sensitive>'
        definitions:
          paths:
            sensitive:
              - .env
              - .envrc
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Alternation in non-optional context
// ========================================

#[rstest]
#[case::post("curl -X POST https://api.com", assert_deny as ActionAssertion)]
#[case::put("curl -X PUT https://api.com", assert_deny as ActionAssertion)]
#[case::patch("curl -X PATCH https://api.com", assert_deny as ActionAssertion)]
#[case::get("curl -X GET https://api.com", assert_ask as ActionAssertion)]
fn alternation_matches_any_variant(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'curl -X|--request POST|PUT|PATCH *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Negation in rules
// ========================================

#[rstest]
#[case::post_denied("curl -X POST https://api.com", assert_ask as ActionAssertion)]
#[case::delete_denied("curl -X DELETE https://api.com", assert_ask as ActionAssertion)]
#[case::get_not_matched("curl -X GET https://api.com", assert_ask as ActionAssertion)]
fn negation_matches_everything_except(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - ask: 'curl -X|--request !GET *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Path normalization: ../  and ./ are resolved before matching
// ========================================

#[rstest]
#[case::dotdot_resolves_to_match(
    "cat /etc/../etc/passwd",
    assert_deny as ActionAssertion,
)]
#[case::dot_resolves_to_match(
    "cat /etc/./passwd",
    assert_deny as ActionAssertion,
)]
#[case::multiple_dotdot_resolves(
    "cat /usr/local/../../../etc/passwd",
    assert_deny as ActionAssertion,
)]
#[case::clean_path_still_matches(
    "cat /etc/passwd",
    assert_deny as ActionAssertion,
)]
#[case::unrelated_path_not_matched(
    "cat /tmp/safe.txt",
    assert_ask as ActionAssertion,
)]
fn path_normalization_resolves_traversal(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'cat <path:sensitive>'
        definitions:
          paths:
            sensitive:
              - /etc/passwd
              - /etc/shadow
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// FlagWithValue position independence
// ========================================

#[rstest]
#[case::flag_before_url(
    "curl -X POST https://example.com",
    assert_deny as ActionAssertion,
)]
#[case::flag_after_url(
    "curl https://example.com -X POST",
    assert_deny as ActionAssertion,
)]
#[case::long_flag_before_url(
    "curl --request POST https://example.com",
    assert_deny as ActionAssertion,
)]
#[case::long_flag_after_url(
    "curl https://example.com --request POST",
    assert_deny as ActionAssertion,
)]
#[case::flag_between_args(
    "curl -H 'Content-Type: application/json' -X POST https://example.com",
    assert_deny as ActionAssertion,
)]
fn flag_with_value_position_independence(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'curl -X|--request POST *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Path ref + alternation + wildcard combination
// ========================================

#[rstest]
#[case::cat_sensitive_denied("cat .env", assert_deny as ActionAssertion)]
#[case::less_sensitive_denied("less /etc/passwd", assert_deny as ActionAssertion)]
#[case::head_sensitive_denied("head .envrc", assert_deny as ActionAssertion)]
#[case::cat_safe_default("cat README.md", assert_ask as ActionAssertion)]
#[case::vim_sensitive_default("vim .env", assert_ask as ActionAssertion)]
fn path_ref_with_alternation_command(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'cat|less|head <path:sensitive>'
        definitions:
          paths:
            sensitive:
              - .env
              - .envrc
              - /etc/passwd
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Optional notation + negation combination
// ========================================

#[rstest]
#[case::force_push_main_denied("git push --force main", assert_deny as ActionAssertion)]
#[case::force_push_master_denied("git push -f master", assert_deny as ActionAssertion)]
#[case::force_push_develop_default("git push --force develop", assert_ask as ActionAssertion)]
#[case::normal_push_main_default("git push main", assert_ask as ActionAssertion)]
fn optional_flag_with_negation(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push -f|--force main|master'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}
