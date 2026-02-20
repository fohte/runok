use std::collections::HashMap;
use std::path::PathBuf;

use indoc::indoc;
use rstest::{fixture, rstest};
use runok::config::parse_config;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command};

#[fixture]
fn empty_context() -> EvalContext {
    EvalContext {
        env: HashMap::new(),
        cwd: PathBuf::from("/tmp"),
    }
}

// ========================================
// Optional notation: curl [-X|--request GET] *
// ========================================

#[rstest]
#[case::without_flag("curl https://example.com", ExpectedAction::Allow)]
#[case::with_short_flag("curl -X GET https://example.com", ExpectedAction::Allow)]
#[case::with_long_flag("curl --request GET https://example.com", ExpectedAction::Allow)]
#[case::with_wrong_value("curl -X POST https://example.com", ExpectedAction::Default)]
fn optional_flag_with_value(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'curl [-X|--request GET] *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Optional notation: git [-C *] status
// ========================================

#[rstest]
#[case::without_c("git status", ExpectedAction::Allow)]
#[case::with_c("git -C /some/path status", ExpectedAction::Allow)]
#[case::with_c_different_path("git -C /another/path status", ExpectedAction::Allow)]
fn optional_flag_with_wildcard_value(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git [-C *] status'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Optional notation: rm [-f] *
// ========================================

#[rstest]
#[case::without_f("rm file.txt", ExpectedAction::Allow)]
#[case::with_f("rm -f file.txt", ExpectedAction::Allow)]
fn optional_boolean_flag(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'rm [-f] *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Path reference: deny cat <path:sensitive>
// ========================================

#[rstest]
#[case::env_file("cat .env", ExpectedAction::Deny)]
#[case::env_local("cat .envrc", ExpectedAction::Deny)]
#[case::etc_passwd("cat /etc/passwd", ExpectedAction::Deny)]
#[case::etc_shadow("cat /etc/shadow", ExpectedAction::Deny)]
#[case::safe_file("cat /tmp/safe.txt", ExpectedAction::Default)]
#[case::readme("cat README.md", ExpectedAction::Default)]
fn path_ref_matches_defined_paths(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
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
    expected.assert_matches(&result.action);
}

// ========================================
// Path reference with multiple path groups
// ========================================

#[rstest]
#[case::log_read_denied("cat /var/log/syslog", ExpectedAction::Deny)]
#[case::config_read_denied("cat /etc/config.yml", ExpectedAction::Deny)]
#[case::safe_allowed("cat /tmp/notes.txt", ExpectedAction::Default)]
fn multiple_path_groups(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
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
    expected.assert_matches(&result.action);
}

// ========================================
// Optional notation combined with deny
// ========================================

#[rstest]
#[case::without_force("git push origin main", ExpectedAction::Deny)]
#[case::with_force("git push --force origin main", ExpectedAction::Deny)]
#[case::with_short_force("git push -f origin main", ExpectedAction::Deny)]
fn optional_flag_in_deny_rule(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push [-f|--force] *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Combined: optional notation + path reference
// ========================================

#[rstest]
#[case::sensitive_no_flag("rm .env", ExpectedAction::Deny)]
#[case::sensitive_with_flag("rm -f .envrc", ExpectedAction::Deny)]
#[case::safe_no_flag("rm temp.txt", ExpectedAction::Default)]
#[case::safe_with_flag("rm -f temp.txt", ExpectedAction::Default)]
fn optional_flag_with_path_ref(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
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
    expected.assert_matches(&result.action);
}

// ========================================
// Alternation in non-optional context
// ========================================

#[rstest]
#[case::post("curl -X POST https://api.com", ExpectedAction::Deny)]
#[case::put("curl -X PUT https://api.com", ExpectedAction::Deny)]
#[case::patch("curl -X PATCH https://api.com", ExpectedAction::Deny)]
#[case::get("curl -X GET https://api.com", ExpectedAction::Default)]
fn alternation_matches_any_variant(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'curl -X|--request POST|PUT|PATCH *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Negation in rules
// ========================================

#[rstest]
#[case::post_denied("curl -X POST https://api.com", ExpectedAction::Ask)]
#[case::delete_denied("curl -X DELETE https://api.com", ExpectedAction::Ask)]
#[case::get_not_matched("curl -X GET https://api.com", ExpectedAction::Default)]
fn negation_matches_everything_except(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - ask: 'curl -X|--request !GET *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Helper
// ========================================

/// Test-only enum for parameterizing expected actions in `#[case]` attributes.
#[derive(Debug)]
enum ExpectedAction {
    Allow,
    Deny,
    Ask,
    Default,
}

impl ExpectedAction {
    fn assert_matches(&self, actual: &Action) {
        match self {
            ExpectedAction::Allow => {
                assert_eq!(*actual, Action::Allow, "expected Allow, got {:?}", actual)
            }
            ExpectedAction::Deny => assert!(
                matches!(actual, Action::Deny(_)),
                "expected Deny, got {:?}",
                actual
            ),
            ExpectedAction::Ask => assert!(
                matches!(actual, Action::Ask(_)),
                "expected Ask, got {:?}",
                actual
            ),
            ExpectedAction::Default => assert_eq!(
                *actual,
                Action::Default,
                "expected Default, got {:?}",
                actual
            ),
        }
    }
}
