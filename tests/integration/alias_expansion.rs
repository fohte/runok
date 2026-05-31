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
    "cargo run --quiet -- check ls",
    Action::Allow,
    vec!["runok"],
)]
#[case::expand_release_to_allow(
    "cargo run --release -- check ls --strict",
    Action::Allow,
    vec!["runok"],
)]
fn alias_expands_then_normal_rules_apply(
    empty_context: EvalContext,
    #[case] command: &str,
    #[case] expected: Action,
    #[case] expected_chain: Vec<&str>,
) {
    let config = parse_config(indoc! {"
        aliases:
          runok:
            - 'cargo run [--quiet] [--release] --'
        rules:
          - allow: 'runok check *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    assert_eq!(result.action, expected);
    let chain: Vec<&str> = result.alias_chain.iter().map(String::as_str).collect();
    assert_eq!(chain, expected_chain);
}

#[rstest]
fn alias_only_grants_listed_subcommands(empty_context: EvalContext) {
    // The alias rewrites the prefix, but the rule is narrower than `runok *`:
    // only `runok check ...` is allowed, so `runok exec ...` must NOT be
    // covered by the same alias path — it falls through to the default.
    let config = parse_config(indoc! {"
        aliases:
          runok:
            - 'cargo run [--quiet] [--release] --'
        rules:
          - allow: 'runok check *'
    "})
    .unwrap();

    let result = evaluate_command(&config, "cargo run -- exec git status", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Ask(_)));
    assert_eq!(result.alias_chain, vec!["runok".to_string()]);
}

#[rstest]
fn alias_does_not_swallow_other_commands(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        aliases:
          runok:
            - 'cargo run --'
        rules:
          - allow: 'runok check *'
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
          runok:
            - 'cargo run --'
        rules:
          - allow: 'runok check *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result =
        evaluate_compound(&config, "cargo run -- check ls && rm -rf /", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

#[rstest]
fn alias_chain_records_recursive_expansion(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        aliases:
          outer:
            - 'inner'
          inner:
            - 'cargo special'
        rules:
          - allow: 'outer *'
    "})
    .unwrap();

    let result = evaluate_command(&config, "cargo special foo", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(
        result.alias_chain,
        vec!["inner".to_string(), "outer".to_string()]
    );
}
