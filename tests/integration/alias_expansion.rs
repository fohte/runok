//! End-to-end alias expansion: YAML config -> parse_config -> evaluate_command
//! -> matched rules + alias chain on the result.
//!
//! Aliases are factor-out macros applied at rule-load time: a rule whose
//! leading token equals an alias name is rewritten by substituting the
//! alias pattern in for the alias name. See `src/rules/alias_expander.rs`
//! for unit-level coverage of the expansion algorithm.

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command, evaluate_compound};

use crate::empty_context;

#[rstest]
#[case::no_flag("kubectl get pods")]
#[case::short_flag("kubectl -n prod get pods")]
#[case::long_flag("kubectl --namespace prod get pods")]
fn kubectl_alias_factors_out_namespace_flag(empty_context: EvalContext, #[case] command: &str) {
    // The primary use-case: factor out a repeated optional flag prefix so a
    // single rule `kubectl get pods` covers every namespace variant.
    let config = parse_config(indoc! {"
        aliases:
          kubectl:
            - 'kubectl [--namespace|-n *]'
        rules:
          - allow: 'kubectl get pods'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.alias_chain, vec!["kubectl".to_string()]);
}

#[rstest]
fn alias_does_not_grant_unlisted_subcommands(empty_context: EvalContext) {
    // The rule `kubectl get pods` (alias-expanded) must not cover
    // `kubectl delete pods` — `delete pods` is not the tail of the rule.
    let config = parse_config(indoc! {"
        aliases:
          kubectl:
            - 'kubectl [--namespace|-n *]'
        rules:
          - allow: 'kubectl get pods'
    "})
    .unwrap();

    let result = evaluate_command(&config, "kubectl -n prod delete pods", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Ask(_)));
    assert!(result.alias_chain.is_empty());
}

#[rstest]
fn rule_without_alias_head_is_unaffected(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        aliases:
          kubectl:
            - 'kubectl [--namespace|-n *]'
        rules:
          - allow: 'git status'
    "})
    .unwrap();

    let result = evaluate_command(&config, "git status", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert!(result.alias_chain.is_empty());
}

#[rstest]
fn alias_with_multiple_patterns_expands_to_multiple_rules(empty_context: EvalContext) {
    // An alias with N patterns expands one rule into N expanded rules; any
    // of them firing yields an allow.
    let config = parse_config(indoc! {"
        aliases:
          k:
            - 'kubectl'
            - 'kubectl --kubeconfig *'
        rules:
          - allow: 'k get pods'
    "})
    .unwrap();

    let plain = evaluate_command(&config, "kubectl get pods", &empty_context).unwrap();
    assert_eq!(plain.action, Action::Allow);
    assert_eq!(plain.alias_chain, vec!["k".to_string()]);

    let configured = evaluate_command(
        &config,
        "kubectl --kubeconfig /tmp/cfg get pods",
        &empty_context,
    )
    .unwrap();
    assert_eq!(configured.action, Action::Allow);
    assert_eq!(configured.alias_chain, vec!["k".to_string()]);
}

#[rstest]
fn deny_still_fires_on_compound_branch_after_alias(empty_context: EvalContext) {
    // Even when an alias-expanded rule would allow one branch, an unrelated
    // deny rule must still fire on the other branch of a compound command.
    let config = parse_config(indoc! {"
        aliases:
          kubectl:
            - 'kubectl [--namespace|-n *]'
        rules:
          - allow: 'kubectl get pods'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "kubectl -n prod get pods && rm -rf /",
        &empty_context,
    )
    .unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

#[rstest]
fn recursive_alias_expansion_records_full_chain(empty_context: EvalContext) {
    // outer -> inner -> kubectl: the matched rule's chain lists aliases
    // in expansion order, outermost-rule reference first.
    let config = parse_config(indoc! {"
        aliases:
          outer:
            - 'inner'
          inner:
            - 'kubectl'
        rules:
          - allow: 'outer get pods'
    "})
    .unwrap();

    let result = evaluate_command(&config, "kubectl get pods", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(
        result.alias_chain,
        vec!["outer".to_string(), "inner".to_string()]
    );
}

#[rstest]
fn cyclic_aliases_are_broken_without_panic(empty_context: EvalContext) {
    // x -> y -> x cycles; expansion stops on the cycle and the original
    // rule pattern is preserved (so `x foo` still matches the literal
    // command `x foo`).
    let config = parse_config(indoc! {"
        aliases:
          x:
            - 'y'
          y:
            - 'x'
        rules:
          - allow: 'x foo'
    "})
    .unwrap();

    let result = evaluate_command(&config, "x foo", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.alias_chain, vec!["x".to_string(), "y".to_string()]);
}

#[rstest]
fn alias_pattern_order_decides_first_match(empty_context: EvalContext) {
    // When multiple expanded variants could match the same command, the
    // alias's YAML list order picks the winner. Authors should put more
    // specific variants before more general ones.
    let config = parse_config(indoc! {"
        aliases:
          k:
            - 'kubectl --kubeconfig *'
            - 'kubectl'
        rules:
          - allow: 'k get pods'
    "})
    .unwrap();

    let result = evaluate_command(
        &config,
        "kubectl --kubeconfig /tmp/cfg get pods",
        &empty_context,
    )
    .unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.alias_chain, vec!["k".to_string()]);
}

#[rstest]
fn trailing_positional_wildcard_in_alias_consumes_rule_tail(empty_context: EvalContext) {
    // Documented caveat (see `expand_rule_pattern` doc): when an alias
    // ends with a bare `*` and the rule appends a non-empty tail, the
    // `*` greedily consumes the tail. The alias author should use
    // `[--flag *]` / `<flag:name>` for value-taking flags instead.
    let config = parse_config(indoc! {"
        aliases:
          k:
            - 'kubectl *'
        rules:
          - allow: 'k get pods'
    "})
    .unwrap();

    // The expanded rule is `kubectl * get pods`. The trailing `*`
    // greedily eats `intermediate` tokens, which is the caveat — any
    // command of shape `kubectl ... get pods` matches.
    let result =
        evaluate_command(&config, "kubectl any tokens here get pods", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
}
