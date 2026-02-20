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
// Environment variable conditions
// ========================================

#[rstest]
#[case::env_matches_deny("prod", ExpectedAction::Deny)]
#[case::env_does_not_match_default("dev", ExpectedAction::Default)]
fn env_variable_controls_rule_application(
    #[case] aws_profile: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
    "})
    .unwrap();

    let context = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), aws_profile.to_string())]),
        ..empty_context
    };

    let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
    expected.assert_matches(&result.action);
}

#[rstest]
fn env_variable_missing_returns_error(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
    "})
    .unwrap();

    // CEL raises an error when accessing a missing map key
    let result = evaluate_command(&config, "aws s3 ls", &empty_context);
    assert!(result.is_err());
}

#[rstest]
fn env_variable_with_has_macro_handles_missing_key(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"has(env.AWS_PROFILE) && env.AWS_PROFILE == 'prod'\"
    "})
    .unwrap();

    // With has() guard, missing key is handled gracefully
    let result = evaluate_command(&config, "aws s3 ls", &empty_context).unwrap();
    assert_eq!(result.action, Action::Default);
}

// ========================================
// When clause skipped -> falls back to other rules
// ========================================

#[rstest]
fn when_skipped_deny_falls_back_to_allow(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
          - allow: 'aws *'
    "})
    .unwrap();

    let context = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
        ..empty_context
    };

    let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
    assert_eq!(result.action, Action::Allow);
}

#[rstest]
fn when_satisfied_deny_wins_over_allow() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
          - allow: 'aws *'
    "})
    .unwrap();

    let context = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };

    let result = evaluate_command(&config, "aws s3 ls", &context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

// ========================================
// Flag conditions
// ========================================

#[rstest]
#[case::short_flag_post_denied("curl -X POST https://example.com", ExpectedAction::Deny)]
#[case::short_flag_get_default("curl -X GET https://example.com", ExpectedAction::Default)]
#[case::long_flag_post_denied("curl --request POST https://example.com", ExpectedAction::Deny)]
#[case::long_flag_get_default("curl --request GET https://example.com", ExpectedAction::Default)]
fn flag_condition_with_flag_with_value_pattern(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    // FlagWithValue pattern (-X|--request POST|*) tells the command parser
    // that -X/--request takes a value. The flag is then available in `flags`
    // with leading dashes stripped (e.g., flags.X or flags.request).
    let config = parse_config(indoc! {"
        rules:
          - deny: 'curl -X|--request * *'
            when: \"has(flags.X) && flags.X == 'POST' || has(flags.request) && flags.request == 'POST'\"
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Argument conditions
// ========================================

#[rstest]
#[case::prod_url_denied("curl https://prod.example.com/api", ExpectedAction::Deny)]
#[case::dev_url_default("curl https://dev.example.com/api", ExpectedAction::Default)]
fn argument_condition_controls_rule(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'curl *'
            when: \"args[0].startsWith('https://prod')\"
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// paths.sensitive access in when clause
// ========================================

#[rstest]
#[case::sensitive_path_denied("cat /etc/passwd", ExpectedAction::Deny)]
#[case::safe_path_default("cat /tmp/safe.txt", ExpectedAction::Default)]
fn paths_in_when_clause(
    #[case] command: &str,
    #[case] expected: ExpectedAction,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'cat *'
            when: \"args[0] in paths.sensitive\"
        definitions:
          paths:
            sensitive:
              - /etc/passwd
              - /etc/shadow
              - .env
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected.assert_matches(&result.action);
}

// ========================================
// Multiple when conditions on different rules
// ========================================

#[rstest]
fn multiple_rules_with_different_when_conditions() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
            message: 'Production AWS is forbidden'
          - ask: 'aws *'
            when: \"env.AWS_PROFILE == 'staging'\"
          - allow: 'aws *'
    "})
    .unwrap();

    // Production: deny wins
    let prod_ctx = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "aws s3 ls", &prod_ctx).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));

    // Staging: ask wins over allow
    let staging_ctx = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), "staging".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "aws s3 ls", &staging_ctx).unwrap();
    assert!(matches!(result.action, Action::Ask(_)));

    // Dev: only allow matches
    let dev_ctx = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "aws s3 ls", &dev_ctx).unwrap();
    assert_eq!(result.action, Action::Allow);
}

// ========================================
// Logical operators in when clause
// ========================================

#[rstest]
fn when_clause_with_logical_and() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'deploy *'
            when: \"env.ENV == 'prod' && env.FORCE != 'true'\"
    "})
    .unwrap();

    // Both conditions met: deny
    let ctx = EvalContext {
        env: HashMap::from([
            ("ENV".to_string(), "prod".to_string()),
            ("FORCE".to_string(), "false".to_string()),
        ]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "deploy app", &ctx).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));

    // FORCE=true: skip deny
    let ctx = EvalContext {
        env: HashMap::from([
            ("ENV".to_string(), "prod".to_string()),
            ("FORCE".to_string(), "true".to_string()),
        ]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "deploy app", &ctx).unwrap();
    assert_eq!(result.action, Action::Default);
}

// ========================================
// Helper
// ========================================

/// Test-only enum for parameterizing expected actions in `#[case]` attributes.
#[derive(Debug)]
#[expect(
    dead_code,
    reason = "all variants are needed for exhaustive matching even if not all are used in #[case] attributes"
)]
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
