#![allow(clippy::panic, reason = "test helper for substring assertions")]

use super::{ActionAssertion, assert_allow, assert_ask, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command};

// ========================================
// <flag:name> placeholder matching
// ========================================

const FIELD_FLAG_CONFIG: &str = indoc! {r#"
    definitions:
      flag_groups:
        field-flag: ["-f", "-F", "--raw-field", "--field"]
    rules:
      - ask: 'gh api graphql <flag:field-flag> *'
        when: 'flag_groups["field-flag"].exists(v, v.startsWith("query=mutation"))'
      - allow: 'gh api graphql <flag:field-flag> *'
"#};

#[rstest]
// Single value, no mutation -> allow
#[case::single_short_f("gh api graphql -f query=query{viewer{login}}", assert_allow as ActionAssertion)]
#[case::single_long_raw_field(
    "gh api graphql --raw-field query=query{viewer{login}}",
    assert_allow as ActionAssertion,
)]
#[case::single_short_capital_f(
    "gh api graphql -F query={viewer{login}}",
    assert_allow as ActionAssertion,
)]
#[case::single_long_field(
    "gh api graphql --field query={viewer{login}}",
    assert_allow as ActionAssertion,
)]
// Multiple values, none with mutation -> allow
#[case::multi_no_mutation(
    "gh api graphql -f query=query{viewer{login}} -f variables={}",
    assert_allow as ActionAssertion,
)]
#[case::multi_mixed_aliases_no_mutation(
    "gh api graphql --raw-field query=query{viewer{login}} -f variables={}",
    assert_allow as ActionAssertion,
)]
// Single value with mutation -> ask
#[case::single_mutation(
    "gh api graphql -f query=mutation{createIssue(input:{}){issue{id}}}",
    assert_ask as ActionAssertion,
)]
#[case::single_mutation_long(
    "gh api graphql --raw-field query=mutation{createIssue(input:{}){issue{id}}}",
    assert_ask as ActionAssertion,
)]
// Multiple values, one with mutation -> ask
#[case::multi_mutation_first(
    "gh api graphql -f query=mutation{createIssue(input:{}){issue{id}}} -f variables={}",
    assert_ask as ActionAssertion,
)]
#[case::multi_mutation_last(
    "gh api graphql -f variables={} -f query=mutation{createIssue(input:{}){issue{id}}}",
    assert_ask as ActionAssertion,
)]
fn field_flag_group_routes_mutation_to_ask(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(FIELD_FLAG_CONFIG).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// flag_groups CEL variable shape
// ========================================

#[rstest]
fn flag_groups_empty_when_no_flag_in_group_used(empty_context: EvalContext) {
    // The pattern uses no <flag:name>, but the group is declared. The CEL
    // expression observes flag_groups["field-flag"] as an empty list.
    let yaml = indoc! {r#"
        definitions:
          flag_groups:
            field-flag: ["-f", "--field"]
        rules:
          - allow: 'gh api graphql *'
            when: 'size(flag_groups["field-flag"]) == 0'
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, "gh api graphql something", &empty_context).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn flag_groups_collects_all_occurrences(empty_context: EvalContext) {
    let yaml = indoc! {r#"
        definitions:
          flag_groups:
            field-flag: ["-f", "--raw-field"]
        rules:
          - allow: 'gh api graphql <flag:field-flag> *'
            when: 'size(flag_groups["field-flag"]) == 3'
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(
        &config,
        "gh api graphql -f a=1 --raw-field b=2 -f c=3",
        &empty_context,
    )
    .unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn flag_groups_supports_equals_joined_values(empty_context: EvalContext) {
    let yaml = indoc! {r#"
        definitions:
          flag_groups:
            field-flag: ["-f", "--raw-field"]
        rules:
          - allow: 'gh api graphql <flag:field-flag> *'
            when: 'flag_groups["field-flag"].exists(v, v == "query=hello")'
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(
        &config,
        "gh api graphql --raw-field=query=hello",
        &empty_context,
    )
    .unwrap();
    assert_allow(&result.action);
}

// ========================================
// Multiple flag groups can coexist
// ========================================

#[rstest]
fn multiple_flag_groups_independent(empty_context: EvalContext) {
    let yaml = indoc! {r#"
        definitions:
          flag_groups:
            field-flag: ["-f", "--raw-field"]
            header-flag: ["-H", "--header"]
        rules:
          - allow: 'curl <flag:field-flag> * <flag:header-flag> * *'
            when: |
              flag_groups["field-flag"].exists(v, v.startsWith("data=")) &&
              flag_groups["header-flag"].exists(h, h.contains("Authorization"))
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(
        &config,
        "curl -f data=secret -H Authorization:Bearer https://example.com",
        &empty_context,
    )
    .unwrap();
    assert_allow(&result.action);
}

// ========================================
// Validation: undefined flag groups are rejected
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
        panic!("expected error to contain {missing:?}, got: {haystack}");
    }
}

#[rstest]
#[case::undefined_flag_group_reference(
    indoc! {r#"
        rules:
          - allow: 'gh api graphql <flag:undefined> *'
    "#},
    &["undefined flag group", "<flag:undefined>"],
)]
#[case::invalid_flag_name(
    indoc! {r#"
        definitions:
          flag_groups:
            bad: ["notaflag"]
    "#},
    &["not a valid flag name"],
)]
#[case::empty_flag_list(
    indoc! {r#"
        definitions:
          flag_groups:
            empty: []
    "#},
    &["must contain at least one flag"],
)]
fn flag_group_validation_errors(#[case] yaml: &str, #[case] needles: &[&str]) {
    let mut config = parse_config(yaml).unwrap();
    let err = config.validate().unwrap_err();
    assert_message_contains(&err.to_string(), needles);
}

// ========================================
// Existing functionality is unaffected
// ========================================

#[rstest]
fn config_without_flag_groups_still_works(empty_context: EvalContext) {
    let yaml = indoc! {r#"
        rules:
          - allow: 'git status'
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, "git status", &empty_context).unwrap();
    assert_allow(&result.action);
}
