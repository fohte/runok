use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command};

// ========================================
// <var:name> with type: literal
// ========================================

#[rstest]
#[case::literal_match(
    indoc! {"
        definitions:
          vars:
            instance-ids:
              values:
                - i-abc123
                - i-def456
                - i-ghi789
        rules:
          - allow: aws ec2 terminate-instances --instance-ids <var:instance-ids>
    "},
    "aws ec2 terminate-instances --instance-ids i-abc123",
    assert_allow as ActionAssertion,
)]
#[case::literal_second_value(
    indoc! {"
        definitions:
          vars:
            instance-ids:
              values:
                - i-abc123
                - i-def456
        rules:
          - allow: aws ec2 terminate-instances --instance-ids <var:instance-ids>
    "},
    "aws ec2 terminate-instances --instance-ids i-def456",
    assert_allow as ActionAssertion,
)]
#[case::literal_no_match(
    indoc! {"
        definitions:
          vars:
            instance-ids:
              values:
                - i-abc123
                - i-def456
        rules:
          - allow: aws ec2 terminate-instances --instance-ids <var:instance-ids>
    "},
    "aws ec2 terminate-instances --instance-ids i-UNKNOWN",
    assert_ask as ActionAssertion,
)]
#[case::literal_explicit_type(
    indoc! {"
        definitions:
          vars:
            regions:
              type: literal
              values:
                - us-east-1
                - eu-west-1
        rules:
          - allow: aws --region <var:regions> *
    "},
    "aws --region us-east-1 s3 ls",
    assert_allow as ActionAssertion,
)]
fn var_ref_literal(
    #[case] yaml: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// <var:name> with type: path
// ========================================

#[rstest]
#[case::path_exact(
    indoc! {"
        definitions:
          vars:
            test-script:
              type: path
              values:
                - ./tests/run
        rules:
          - allow: bash <var:test-script>
    "},
    "bash tests/run",
    assert_allow as ActionAssertion,
)]
#[case::path_dot_prefix(
    indoc! {"
        definitions:
          vars:
            test-script:
              type: path
              values:
                - ./tests/run
        rules:
          - allow: bash <var:test-script>
    "},
    "bash ./tests/run",
    assert_allow as ActionAssertion,
)]
#[case::path_no_match(
    indoc! {"
        definitions:
          vars:
            test-script:
              type: path
              values:
                - ./tests/run
        rules:
          - allow: bash <var:test-script>
    "},
    "bash ./scripts/deploy",
    assert_ask as ActionAssertion,
)]
#[case::path_dotdot_resolution(
    indoc! {"
        definitions:
          vars:
            test-script:
              type: path
              values:
                - ./tests/run
        rules:
          - allow: bash <var:test-script>
    "},
    "bash ./tests/../tests/run",
    assert_allow as ActionAssertion,
)]
fn var_ref_path(
    #[case] yaml: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// <var:name> in deny rules
// ========================================

#[rstest]
#[case::deny_matching_var(
    indoc! {"
        definitions:
          vars:
            dangerous-instances:
              values:
                - i-prod-001
                - i-prod-002
        rules:
          - deny: aws ec2 terminate-instances --instance-ids <var:dangerous-instances>
    "},
    "aws ec2 terminate-instances --instance-ids i-prod-001",
    assert_deny as ActionAssertion,
)]
#[case::deny_non_matching_var_falls_through(
    indoc! {"
        definitions:
          vars:
            dangerous-instances:
              values:
                - i-prod-001
        rules:
          - deny: aws ec2 terminate-instances --instance-ids <var:dangerous-instances>
          - allow: aws *
    "},
    "aws ec2 terminate-instances --instance-ids i-dev-001",
    assert_allow as ActionAssertion,
)]
fn var_ref_deny(
    #[case] yaml: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// <var:name> coexists with <path:name>
// ========================================

#[rstest]
fn var_ref_and_path_ref_coexist(empty_context: EvalContext) {
    let yaml = indoc! {"
        definitions:
          paths:
            sensitive:
              - /etc/passwd
          vars:
            safe-scripts:
              type: path
              values:
                - ./tests/run
        rules:
          - deny: cat <path:sensitive>
          - allow: bash <var:safe-scripts>
    "};
    let config = parse_config(yaml).unwrap();

    let deny_result = evaluate_command(&config, "cat /etc/passwd", &empty_context).unwrap();
    assert!(matches!(
        deny_result.action,
        runok::rules::rule_engine::Action::Deny(_)
    ));

    let allow_result = evaluate_command(&config, "bash ./tests/run", &empty_context).unwrap();
    assert_eq!(
        allow_result.action,
        runok::rules::rule_engine::Action::Allow
    );
}

// ========================================
// <var:name> captured values in when clause via vars context
// ========================================

#[rstest]
#[case::var_value_matches_when_condition(
    indoc! {"
        definitions:
          vars:
            instance-ids:
              values:
                - i-abc123
                - i-prod-001
        rules:
          - deny: aws ec2 terminate-instances --instance-ids <var:instance-ids>
            when: \"vars['instance-ids'] == 'i-prod-001'\"
          - allow: aws ec2 terminate-instances --instance-ids <var:instance-ids>
    "},
    "aws ec2 terminate-instances --instance-ids i-prod-001",
    assert_deny as ActionAssertion,
)]
#[case::var_value_does_not_match_when_falls_through(
    indoc! {"
        definitions:
          vars:
            instance-ids:
              values:
                - i-abc123
                - i-prod-001
        rules:
          - deny: aws ec2 terminate-instances --instance-ids <var:instance-ids>
            when: \"vars['instance-ids'] == 'i-prod-001'\"
          - allow: aws ec2 terminate-instances --instance-ids <var:instance-ids>
    "},
    "aws ec2 terminate-instances --instance-ids i-abc123",
    assert_allow as ActionAssertion,
)]
#[case::var_with_has_guard_and_starts_with(
    indoc! {"
        definitions:
          vars:
            regions:
              type: literal
              values:
                - us-east-1
                - eu-west-1
                - ap-southeast-1
        rules:
          - deny: aws --region <var:regions> *
            when: \"has(vars.regions) && vars.regions.startsWith('us-')\"
          - allow: aws --region <var:regions> *
    "},
    "aws --region us-east-1 s3 ls",
    assert_deny as ActionAssertion,
)]
#[case::var_with_has_guard_non_us_region_allowed(
    indoc! {"
        definitions:
          vars:
            regions:
              type: literal
              values:
                - us-east-1
                - eu-west-1
                - ap-southeast-1
        rules:
          - deny: aws --region <var:regions> *
            when: \"has(vars.regions) && vars.regions.startsWith('us-')\"
          - allow: aws --region <var:regions> *
    "},
    "aws --region eu-west-1 s3 ls",
    assert_allow as ActionAssertion,
)]
fn var_ref_when_clause_with_vars(
    #[case] yaml: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}
