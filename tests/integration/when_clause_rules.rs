use super::{ActionAssertion, assert_allow, assert_default, assert_deny, empty_context};

use std::collections::HashMap;
use std::path::PathBuf;

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command};

// ========================================
// Environment variable conditions
// ========================================

#[rstest]
#[case::env_matches_deny("prod", assert_deny as ActionAssertion)]
#[case::env_does_not_match_default("dev", assert_default as ActionAssertion)]
fn env_variable_controls_rule_application(
    #[case] aws_profile: &str,
    #[case] expected: ActionAssertion,
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
    expected(&result.action);
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
#[case::short_flag_post_denied("curl -X POST https://example.com", assert_deny as ActionAssertion)]
#[case::short_flag_get_default("curl -X GET https://example.com", assert_default as ActionAssertion)]
#[case::long_flag_post_denied("curl --request POST https://example.com", assert_deny as ActionAssertion)]
#[case::long_flag_get_default("curl --request GET https://example.com", assert_default as ActionAssertion)]
fn flag_condition_with_flag_with_value_pattern(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
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
    expected(&result.action);
}

// ========================================
// Argument conditions
// ========================================

#[rstest]
#[case::prod_url_denied("curl https://prod.example.com/api", assert_deny as ActionAssertion)]
#[case::dev_url_default("curl https://dev.example.com/api", assert_default as ActionAssertion)]
fn argument_condition_controls_rule(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'curl *'
            when: \"args[0].startsWith('https://prod')\"
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// paths.sensitive access in when clause
// ========================================

#[rstest]
#[case::sensitive_path_denied("cat /etc/passwd", assert_deny as ActionAssertion)]
#[case::safe_path_default("cat /tmp/safe.txt", assert_default as ActionAssertion)]
fn paths_in_when_clause(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
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
    expected(&result.action);
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
// when clause + compound command: different when results per sub-command
// ========================================

#[rstest]
fn when_clause_compound_different_results_per_subcommand() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
          - allow: 'echo *'
    "})
    .unwrap();

    let ctx = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };

    // echo hello && aws s3 ls
    // -> echo hello -> Allow (when clause on deny rule doesn't apply to echo)
    // -> aws s3 ls -> Deny (when clause matches for prod)
    // -> overall: Deny (strictest wins)
    let result =
        runok::rules::rule_engine::evaluate_compound(&config, "echo hello && aws s3 ls", &ctx)
            .unwrap();
    assert!(
        matches!(result.action, Action::Deny(_)),
        "expected Deny, got {:?}",
        result.action
    );
}

#[rstest]
fn when_clause_compound_all_skipped_falls_back() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
          - allow: 'echo *'
          - allow: 'aws *'
    "})
    .unwrap();

    let ctx = EvalContext {
        env: HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };

    // echo hello && aws s3 ls in dev
    // -> echo hello -> Allow
    // -> aws s3 ls -> when skipped, falls back to allow
    // -> overall: Allow
    let result =
        runok::rules::rule_engine::evaluate_compound(&config, "echo hello && aws s3 ls", &ctx)
            .unwrap();
    assert_eq!(result.action, Action::Allow);
}

// ========================================
// when clause with logical OR
// ========================================

#[rstest]
fn when_clause_with_logical_or() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'deploy *'
            when: \"env.ENV == 'prod' || env.ENV == 'staging'\"
          - allow: 'deploy *'
    "})
    .unwrap();

    // prod -> deny
    let ctx = EvalContext {
        env: HashMap::from([("ENV".to_string(), "prod".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "deploy app", &ctx).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));

    // staging -> deny
    let ctx = EvalContext {
        env: HashMap::from([("ENV".to_string(), "staging".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "deploy app", &ctx).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));

    // dev -> allow (deny skipped, allow matches)
    let ctx = EvalContext {
        env: HashMap::from([("ENV".to_string(), "dev".to_string())]),
        cwd: PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "deploy app", &ctx).unwrap();
    assert_eq!(result.action, Action::Allow);
}

// ========================================
// All when conditions false -> Default
// ========================================

#[rstest]
fn all_when_false_returns_default(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'deploy *'
            when: \"has(env.ENV) && env.ENV == 'prod'\"
          - ask: 'deploy *'
            when: \"has(env.ENV) && env.ENV == 'staging'\"
    "})
    .unwrap();

    // No matching env -> all when clauses false -> no rules match -> Default
    let result = evaluate_command(&config, "deploy app", &empty_context).unwrap();
    assert_eq!(result.action, Action::Default);
}

// ========================================
// Empty args with size guard in when clause
// ========================================

#[rstest]
#[case::no_args_allowed("git status", assert_allow as ActionAssertion)]
#[case::with_args_denied("git status --short", assert_deny as ActionAssertion)]
fn empty_args_size_guard(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    // args for "git status" are ["status"], for "git status --short"
    // args are ["status"] and flags include "short".
    // Use flags.size() to distinguish.
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git *'
            when: \"flags.size() == 0\"
          - deny: 'git *'
            when: \"flags.size() > 0\"
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Hyphenated flag name access in CEL (--no-verify -> flags["no-verify"])
// ========================================

#[rstest]
#[case::with_no_verify("git commit --no-verify", assert_deny as ActionAssertion)]
#[case::without_no_verify("git commit -m hello", assert_default as ActionAssertion)]
fn hyphenated_flag_name_in_cel(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    // Flags with hyphens (--no-verify) have leading dashes stripped
    // but internal hyphens preserved: key becomes "no-verify".
    // CEL's has() macro doesn't support bracket notation, so use "in" operator.
    let config = parse_config(indoc! {r#"
        rules:
          - deny: 'git commit *'
            when: '"no-verify" in flags'
    "#})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// When clause + path ref pattern combination
// ========================================

#[rstest]
#[case::sensitive_in_prod_denied("cat .env", "prod", assert_deny as ActionAssertion)]
#[case::sensitive_in_dev_default("cat .env", "dev", assert_default as ActionAssertion)]
#[case::safe_in_prod_default("cat README.md", "prod", assert_default as ActionAssertion)]
fn when_clause_with_path_ref(
    #[case] command: &str,
    #[case] env_value: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'cat <path:sensitive>'
            when: \"env.ENV == 'prod'\"
        definitions:
          paths:
            sensitive:
              - .env
              - .envrc
    "})
    .unwrap();

    let context = EvalContext {
        env: HashMap::from([("ENV".to_string(), env_value.to_string())]),
        ..empty_context
    };

    let result = evaluate_command(&config, command, &context).unwrap();
    expected(&result.action);
}
