mod common;

use std::collections::HashMap;
use std::path::PathBuf;

use common::ExpectedAction;
use indoc::indoc;
use rstest::{fixture, rstest};
use runok::config::{Config, parse_config};
use runok::rules::RuleError;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command};

#[fixture]
fn empty_context() -> EvalContext {
    EvalContext {
        env: HashMap::new(),
        cwd: PathBuf::from("/tmp"),
    }
}

fn config_with_standard_wrappers() -> &'static str {
    indoc! {"
        definitions:
          wrappers:
            - 'sudo <cmd>'
            - 'bash -c <cmd>'
            - 'sh -c <cmd>'
    "}
}

// ========================================
// sudo wrapper: inner command is evaluated
// ========================================

#[rstest]
#[case::sudo_rm_denied("sudo rm -rf /", ExpectedAction::Deny)]
#[case::sudo_safe_allowed("sudo ls -la", ExpectedAction::Allow)]
#[case::sudo_unmatched_default("sudo hg status", ExpectedAction::Default)]
fn sudo_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'ls *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// bash -c wrapper: inner command is evaluated
// ========================================

#[rstest]
#[case::bash_c_curl_post_denied("bash -c 'curl -X POST https://example.com'", ExpectedAction::Deny)]
#[case::bash_c_curl_get_allowed("bash -c 'curl -X GET https://example.com'", ExpectedAction::Allow)]
fn bash_c_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'curl -X|--request POST *'\n  - allow: 'curl -X|--request GET *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Nested wrappers: sudo bash -c
// ========================================

#[rstest]
#[case::sudo_bash_c_rm("sudo bash -c 'rm -rf /'", ExpectedAction::Deny)]
#[case::sudo_sh_c_rm("sudo sh -c 'rm -rf /'", ExpectedAction::Deny)]
#[case::sudo_bash_c_safe("sudo bash -c 'echo hello'", ExpectedAction::Allow)]
fn nested_wrappers_evaluate_recursively(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'echo *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Compound commands inside wrappers
// ========================================

#[rstest]
#[case::compound_with_deny("bash -c 'ls -la; rm -rf /'", ExpectedAction::Deny)]
#[case::compound_all_safe("bash -c 'ls -la && echo done'", ExpectedAction::Allow)]
fn compound_commands_inside_wrapper(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'ls *'\n  - allow: 'echo *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Deny wins over direct rule allow (wrapper inner takes priority)
// ========================================

#[rstest]
fn deny_from_inner_wins_over_direct_allow(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'sudo *'
          - deny: 'rm -rf *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, "sudo rm -rf /", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

// ========================================
// Recursion depth limit
// ========================================

#[rstest]
fn deeply_nested_wrappers_hit_recursion_limit(empty_context: EvalContext) {
    let config = Config {
        rules: Some(vec![]),
        definitions: Some(runok::config::Definitions {
            wrappers: Some(vec!["a <cmd>".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    };

    // 12 levels of "a" nesting exceeds MAX_WRAPPER_DEPTH (10)
    let result = evaluate_command(&config, "a a a a a a a a a a a a", &empty_context);
    assert!(
        matches!(result, Err(RuleError::RecursionDepthExceeded(_))),
        "expected RecursionDepthExceeded, got {:?}",
        result
    );
}

// ========================================
// No wrappers defined: sudo is not unwrapped
// ========================================

#[rstest]
fn without_wrappers_sudo_is_not_unwrapped(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm -rf *'
    "})
    .unwrap();

    // Without wrappers, "sudo rm -rf /" is just "sudo" command, not unwrapped
    let result = evaluate_command(&config, "sudo rm -rf /", &empty_context).unwrap();
    assert_eq!(result.action, Action::Default);
}

// ========================================
// Wrapper preserves quoting
// ========================================

#[rstest]
fn wrapper_preserves_quoted_arguments(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'echo *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, "sudo echo 'hello world'", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}
