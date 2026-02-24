use super::{ActionAssertion, assert_allow, assert_default, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::{Config, parse_config};
use runok::rules::RuleError;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command, evaluate_compound};

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
#[case::sudo_rm_denied("sudo rm -rf /", assert_deny as ActionAssertion)]
#[case::sudo_safe_allowed("sudo ls -la", assert_allow as ActionAssertion)]
#[case::sudo_unmatched_default("sudo hg status", assert_default as ActionAssertion)]
fn sudo_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'ls *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// bash -c wrapper: inner command is evaluated
// ========================================

#[rstest]
#[case::bash_c_curl_post_denied("bash -c 'curl -X POST https://example.com'", assert_deny as ActionAssertion)]
#[case::bash_c_curl_get_allowed("bash -c 'curl -X GET https://example.com'", assert_allow as ActionAssertion)]
fn bash_c_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'curl -X|--request POST *'\n  - allow: 'curl -X|--request GET *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Nested wrappers: sudo bash -c
// ========================================

#[rstest]
#[case::sudo_bash_c_rm("sudo bash -c 'rm -rf /'", assert_deny as ActionAssertion)]
#[case::sudo_sh_c_rm("sudo sh -c 'rm -rf /'", assert_deny as ActionAssertion)]
#[case::sudo_bash_c_safe("sudo bash -c 'echo hello'", assert_allow as ActionAssertion)]
fn nested_wrappers_evaluate_recursively(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'echo *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Compound commands inside wrappers
// ========================================

#[rstest]
#[case::compound_with_deny("bash -c 'ls -la; rm -rf /'", assert_deny as ActionAssertion)]
#[case::compound_all_safe("bash -c 'ls -la && echo done'", assert_allow as ActionAssertion)]
fn compound_commands_inside_wrapper(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'ls *'\n  - allow: 'echo *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Compound commands inside wrappers: unmatched resolved via defaults.action
// ========================================

#[rstest]
fn compound_in_wrapper_unmatched_uses_defaults_action(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'bash -c <cmd>'
    "})
    .unwrap();

    // "echo hello" matches allow, "unknown_cmd" is unmatched.
    // With defaults.action = ask, the unmatched sub-command resolves to Ask.
    let result =
        evaluate_command(&config, "bash -c 'echo hello; unknown_cmd'", &empty_context).unwrap();
    assert!(
        matches!(result.action, Action::Ask(_)),
        "expected Ask, got {:?}",
        result.action
    );
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

// ========================================
// env wrapper: env-prefix variables are consumed by wildcard,
// inner command is correctly evaluated
// ========================================

#[rstest]
#[case::env_var_echo_allowed("env FOO=bar echo hello", assert_allow as ActionAssertion)]
#[case::env_var_rm_denied("env FOO=bar rm -rf /", assert_deny as ActionAssertion)]
#[case::env_multiple_vars("env FOO=bar BAZ=qux echo hello", assert_allow as ActionAssertion)]
#[case::env_var_unmatched_default("env FOO=bar hg status", assert_default as ActionAssertion)]
fn env_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'env * <cmd>'
    "};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Bare env-prefix command (no `env` wrapper):
// FOO=bar echo hello is evaluated as echo hello via evaluate_compound,
// which calls extract_commands to strip variable assignments.
// ========================================

#[rstest]
#[case::bare_env_prefix_allowed("FOO=bar echo hello", assert_allow as ActionAssertion)]
#[case::bare_env_prefix_denied("FOO=bar rm -rf /", assert_deny as ActionAssertion)]
fn bare_env_prefix_evaluates_stripped_command(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'echo *'
    "};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
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
