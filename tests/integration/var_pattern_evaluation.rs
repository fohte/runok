#![allow(clippy::panic, reason = "test helper for substring assertions")]

use super::{ActionAssertion, assert_allow, assert_ask, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command};

// ========================================
// <var:name> with type: pattern -- happy path
// ========================================

const KUBECTL_PATTERN_YAML: &str = indoc! {r#"
    definitions:
      vars:
        kubectl:
          type: pattern
          values:
            - "kubectl [-n|--namespace *] [--context *] [--cluster *] [--user *] [--kubeconfig *]"
    rules:
      - allow: "<var:kubectl> get|describe|logs *"
      - allow: "<var:kubectl> top node|pod|nodes|pods *"
      - allow: "<var:kubectl> auth can-i|whoami *"
"#};

#[rstest]
#[case::no_flags("kubectl get pods")]
#[case::context_long("kubectl --context foo get pods")]
#[case::context_equals("kubectl --context=foo get pods")]
#[case::multi_flags("kubectl --kubeconfig ~/.kube/work --context prod get pods -A")]
#[case::short_namespace_then_context("kubectl -n default --context foo describe pod bar")]
#[case::top_subcommand("kubectl --context prod top pods")]
#[case::auth_subcommand("kubectl auth can-i list pods")]
#[case::logs_subcommand("kubectl --namespace kube-system logs my-pod")]
fn pattern_var_kubectl_allows(#[case] command: &str, empty_context: EvalContext) {
    let config = parse_config(KUBECTL_PATTERN_YAML).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    assert_allow(&result.action);
}

#[rstest]
#[case::wrong_subcommand("kubectl delete pod foo")]
#[case::wrong_command("helm get pods")]
fn pattern_var_kubectl_does_not_match(#[case] command: &str, empty_context: EvalContext) {
    let config = parse_config(KUBECTL_PATTERN_YAML).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    // No allow rule matched -> falls through to default action (ask).
    assert_ask(&result.action);
}

// ========================================
// Multiple values with alternative patterns
// ========================================

#[rstest]
#[case::first_alternative("kubectl get pods", assert_allow as ActionAssertion)]
#[case::second_alternative("oc get pods", assert_allow as ActionAssertion)]
#[case::neither("crictl get pods", assert_ask as ActionAssertion)]
fn pattern_var_multiple_values(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = indoc! {r#"
        definitions:
          vars:
            k8s-cli:
              type: pattern
              values:
                - "kubectl [-n|--namespace *]"
                - "oc [-n|--namespace *]"
        rules:
          - allow: "<var:k8s-cli> get *"
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Per-value type override (mixed pattern + literal)
// ========================================

#[rstest]
fn pattern_var_per_value_pattern_override(empty_context: EvalContext) {
    // Definition-level type is `literal`, but a single value opts into
    // `pattern` via the `{ type, value }` form.
    let yaml = indoc! {r#"
        definitions:
          vars:
            k8s:
              values:
                - kubectl
                - type: pattern
                  value: "minikube kubectl --"
        rules:
          - allow: "<var:k8s> get pods"
    "#};
    let config = parse_config(yaml).unwrap();

    let r1 = evaluate_command(&config, "kubectl get pods", &empty_context).unwrap();
    assert_allow(&r1.action);

    let r2 = evaluate_command(&config, "minikube kubectl -- get pods", &empty_context).unwrap();
    assert_allow(&r2.action);
}

// ========================================
// Validation errors
// ========================================

/// Assert that `haystack` contains every fragment in `needles`. Used to keep
/// substring checks out of `assert!(x.contains(...))` (rejected by ast-grep).
fn assert_message_contains(haystack: &str, needles: &[&str]) {
    let missing: Vec<&str> = needles
        .iter()
        .copied()
        .filter(|n| !haystack.contains(n))
        .collect();
    if !missing.is_empty() {
        panic!("expected message to contain {missing:?}, got: {haystack}");
    }
}

#[rstest]
#[case::nested_var_ref(
    indoc! {r#"
        definitions:
          vars:
            inner:
              values:
                - foo
            outer:
              type: pattern
              values:
                - "kubectl <var:inner>"
    "#},
    &["definitions.vars.outer", "<var:inner>", "Nested placeholders"],
)]
#[case::nested_path_ref(
    indoc! {r#"
        definitions:
          paths:
            sensitive:
              - /etc/passwd
          vars:
            outer:
              type: pattern
              values:
                - "cat <path:sensitive>"
    "#},
    &["definitions.vars.outer", "<path:sensitive>", "Nested placeholders"],
)]
#[case::nested_flag_group_ref(
    indoc! {r#"
        definitions:
          flag_groups:
            verbose: "-v|--verbose"
          vars:
            outer:
              type: pattern
              values:
                - "gh api graphql <flag:verbose>"
    "#},
    &["definitions.vars.outer", "<flag:verbose>", "Nested placeholders"],
)]
#[case::nested_cmd_placeholder(
    indoc! {r#"
        definitions:
          vars:
            outer:
              type: pattern
              values:
                - "sudo <cmd>"
    "#},
    &["definitions.vars.outer", "<cmd>", "Nested placeholders"],
)]
#[case::nested_opts_placeholder(
    indoc! {r#"
        definitions:
          vars:
            outer:
              type: pattern
              values:
                - "kubectl <opts>"
    "#},
    &["definitions.vars.outer", "<opts>", "Nested placeholders"],
)]
#[case::pattern_value_parse_error(
    indoc! {r#"
        definitions:
          vars:
            outer:
              type: pattern
              values:
                - "kubectl [-X"
    "#},
    &["definitions.vars.outer", "failed to parse"],
)]
fn pattern_var_validation_errors(#[case] yaml: &str, #[case] needles: &[&str]) {
    let mut config = parse_config(yaml).unwrap();
    let err = config.validate().unwrap_err();
    assert_message_contains(&err.to_string(), needles);
}

#[rstest]
fn pattern_var_inside_optional_group_is_rejected(empty_context: EvalContext) {
    // Pattern-typed `<var:name>` inside an optional group `[...]` is
    // rejected at validate() time, mirroring the rule for `<flag:name>`.
    let _ = empty_context;
    let yaml = indoc! {r#"
        definitions:
          vars:
            kubectl:
              type: pattern
              values:
                - "kubectl [-n|--namespace *]"
        rules:
          - allow: "echo [<var:kubectl>] get pods"
    "#};
    let mut config = parse_config(yaml).unwrap();
    let err = config.validate().unwrap_err();
    assert_message_contains(
        &err.to_string(),
        &["<var:kubectl>", "optional group", "Pattern-typed"],
    );
}

// ========================================
// Existing literal/path behavior is unaffected
// ========================================

#[rstest]
fn literal_var_inside_optional_is_not_rejected(empty_context: EvalContext) {
    // `<var:name>` for *non*-pattern-typed vars is allowed inside optional
    // groups; only pattern-typed vars are rejected.
    let yaml = indoc! {r#"
        definitions:
          vars:
            ids:
              values:
                - i-abc123
        rules:
          - allow: "aws ec2 terminate-instances [--instance-ids <var:ids>]"
    "#};
    let mut config = parse_config(yaml).unwrap();
    config.validate().expect("config must validate");

    let r = evaluate_command(
        &config,
        "aws ec2 terminate-instances --instance-ids i-abc123",
        &empty_context,
    )
    .unwrap();
    assert_allow(&r.action);
}
