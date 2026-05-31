//! End-to-end alias expansion: YAML config -> parse_config -> evaluate_command
//! -> matched rules + alias chain on the result.
//!
//! These complement the unit tests in `src/rules/alias_expander.rs` by
//! exercising the full evaluation pipeline, including audit-relevant fields.

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command, evaluate_compound};

use crate::empty_context;

#[rstest]
#[case::expand_to_allow(
    "cargo run --quiet -- doctor",
    Action::Allow,
    vec!["a"],
)]
#[case::expand_release_to_allow(
    "cargo run --release -- ai draft foo",
    Action::Allow,
    vec!["a"],
)]
fn alias_expands_then_normal_rules_apply(
    empty_context: EvalContext,
    #[case] command: &str,
    #[case] expected: Action,
    #[case] expected_chain: Vec<&str>,
) {
    let config = parse_config(indoc! {"
        aliases:
          a:
            - 'cargo run [--quiet] [--release] --'
        rules:
          - allow: 'a *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    assert_eq!(result.action, expected);
    let chain: Vec<&str> = result.alias_chain.iter().map(String::as_str).collect();
    assert_eq!(chain, expected_chain);
}

#[rstest]
fn alias_does_not_swallow_other_commands(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        aliases:
          a:
            - 'cargo run --'
        rules:
          - allow: 'a *'
    "})
    .unwrap();

    // `git status` has no alias match — falls through to default Ask.
    let result = evaluate_command(&config, "git status", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Ask(_)));
    assert!(result.alias_chain.is_empty());
}

#[rstest]
fn deny_still_fires_for_injected_branch_after_alias(empty_context: EvalContext) {
    // Even when the first branch is alias-expanded and would be allowed,
    // the second branch (`rm -rf /`) must still hit the deny rule.
    let config = parse_config(indoc! {"
        aliases:
          a:
            - 'cargo run --'
        rules:
          - allow: 'a *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result =
        evaluate_compound(&config, "cargo run -- doctor && rm -rf /", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

#[rstest]
fn alias_chain_records_recursive_expansion(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        aliases:
          a:
            - 'b'
          b:
            - 'cargo special'
        rules:
          - allow: 'a *'
    "})
    .unwrap();

    let result = evaluate_command(&config, "cargo special foo", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.alias_chain, vec!["b".to_string(), "a".to_string()]);
}
