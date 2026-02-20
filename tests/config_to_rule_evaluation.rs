mod common;

use std::collections::HashMap;
use std::path::PathBuf;

use common::{ActionAssertion, assert_allow, assert_ask, assert_default, assert_deny};
use indoc::indoc;
use rstest::{fixture, rstest};
use runok::config::{Config, ConfigError, RuleEntry, parse_config};
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command};

#[fixture]
fn empty_context() -> EvalContext {
    EvalContext {
        env: HashMap::new(),
        cwd: PathBuf::from("/tmp"),
    }
}

// ========================================
// YAML config loading and rule evaluation
// ========================================

#[rstest]
#[case::allow_matches(
    indoc! {"
        rules:
          - allow: 'git status'
    "},
    "git status",
    assert_allow as ActionAssertion,
)]
#[case::deny_matches(
    indoc! {"
        rules:
          - deny: 'rm -rf /'
    "},
    "rm -rf /",
    assert_deny as ActionAssertion,
)]
#[case::ask_matches(
    indoc! {"
        rules:
          - ask: 'git push *'
    "},
    "git push origin main",
    assert_ask as ActionAssertion,
)]
#[case::no_match_returns_default(
    indoc! {"
        rules:
          - allow: 'git status'
    "},
    "hg status",
    assert_default as ActionAssertion,
)]
fn yaml_config_evaluates_commands(
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
// Explicit Deny Wins priority
// ========================================

#[rstest]
#[case::deny_over_allow(
    indoc! {"
        rules:
          - allow: 'git *'
          - deny: 'git push -f|--force *'
    "},
    "git push --force origin",
    assert_deny as ActionAssertion,
)]
#[case::deny_over_ask(
    indoc! {"
        rules:
          - ask: 'git push *'
          - deny: 'git push -f|--force *'
    "},
    "git push --force origin",
    assert_deny as ActionAssertion,
)]
#[case::ask_over_allow(
    indoc! {"
        rules:
          - allow: 'git *'
          - ask: 'git push *'
    "},
    "git push origin",
    assert_ask as ActionAssertion,
)]
#[case::deny_wins_over_both(
    indoc! {"
        rules:
          - allow: 'git *'
          - ask: 'git push *'
          - deny: 'git push -f|--force *'
    "},
    "git push --force origin",
    assert_deny as ActionAssertion,
)]
fn explicit_deny_wins(
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
// Deny response details (message, fix_suggestion)
// ========================================

#[rstest]
fn deny_response_preserves_message_and_fix_suggestion(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push -f|--force *'
            message: 'Force push is not allowed'
            fix_suggestion: 'git push --force-with-lease'
    "})
    .unwrap();

    let result = evaluate_command(&config, "git push --force origin", &empty_context).unwrap();
    match &result.action {
        Action::Deny(resp) => {
            assert_eq!(resp.message.as_deref(), Some("Force push is not allowed"));
            assert_eq!(
                resp.fix_suggestion.as_deref(),
                Some("git push --force-with-lease")
            );
        }
        other => panic!("expected Deny, got {:?}", other),
    }
}

// ========================================
// Preset merge via Config::merge
// ========================================

#[rstest]
fn preset_merge_appends_rules_and_overrides_defaults(empty_context: EvalContext) {
    let preset = parse_config(indoc! {"
        defaults:
          action: deny
        rules:
          - deny: 'rm -rf /'
    "})
    .unwrap();

    let local = parse_config(indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'git status'
    "})
    .unwrap();

    let merged = preset.merge(local);

    // defaults.action is overridden by local
    assert_eq!(
        merged.defaults.as_ref().unwrap().action,
        Some(runok::config::ActionKind::Ask)
    );

    // rules are appended (preset + local)
    let rules = merged.rules.as_ref().unwrap();
    assert_eq!(rules.len(), 2);

    // deny from preset still works
    let result = evaluate_command(&merged, "rm -rf /", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));

    // allow from local works
    let result = evaluate_command(&merged, "git status", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
}

#[rstest]
fn preset_merge_paths_are_appended_per_key() {
    let preset = parse_config(indoc! {"
        definitions:
          paths:
            sensitive:
              - /etc/passwd
              - /etc/shadow
    "})
    .unwrap();

    let local = parse_config(indoc! {"
        definitions:
          paths:
            sensitive:
              - .env
              - /etc/passwd
    "})
    .unwrap();

    let merged = preset.merge(local);
    let paths = merged.definitions.unwrap().paths.unwrap();
    let sensitive = &paths["sensitive"];

    // All unique values are present and /etc/passwd is deduplicated
    let mut sorted = sensitive.clone();
    sorted.sort();
    assert_eq!(sorted, vec![".env", "/etc/passwd", "/etc/shadow"]);
}

#[rstest]
fn preset_merge_wrappers_appended() {
    let preset = parse_config(indoc! {"
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let local = parse_config(indoc! {"
        definitions:
          wrappers:
            - 'bash -c <cmd>'
    "})
    .unwrap();

    let merged = preset.merge(local);
    let wrappers = merged.definitions.unwrap().wrappers.unwrap();
    assert_eq!(wrappers, vec!["sudo <cmd>", "bash -c <cmd>"]);
}

// ========================================
// Config validation
// ========================================

#[rstest]
#[case::no_action_key(
    Config {
        rules: Some(vec![RuleEntry {
            deny: None,
            allow: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
        }]),
        ..Config::default()
    },
    "exactly one",
)]
#[case::deny_with_sandbox(
    parse_config(indoc! {"
        rules:
          - deny: 'rm -rf /'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "}).unwrap(),
    "deny rule cannot have a sandbox",
)]
fn config_validation_rejects_invalid(#[case] config: Config, #[case] expected_error: &str) {
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains(expected_error),
        "expected error containing '{}', got: {}",
        expected_error,
        err
    );
}

#[rstest]
fn config_validation_rejects_undefined_sandbox() {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'python3 *'
            sandbox: nonexistent
    "})
    .unwrap();

    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
    assert!(err.to_string().contains("not defined"));
}

#[rstest]
fn config_validation_collects_multiple_errors() {
    let config = Config {
        rules: Some(vec![
            RuleEntry {
                deny: None,
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
            },
            RuleEntry {
                deny: Some("curl *".to_string()),
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: Some("restricted".to_string()),
            },
        ]),
        ..Config::default()
    };

    match config.validate() {
        Err(ConfigError::Validation(errors)) => {
            assert_eq!(errors.len(), 3, "expected 3 errors, got: {:?}", errors);
        }
        other => panic!("expected Validation error, got: {:?}", other),
    }
}

// ========================================
// Sandbox preset from rule
// ========================================

#[rstest]
fn allow_rule_with_sandbox_propagates_preset(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'python3 *'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp, /tmp]
    "})
    .unwrap();

    let result = evaluate_command(&config, "python3 script.py", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.sandbox_preset.as_deref(), Some("restricted"));
}

// ========================================
// Full realistic config
// ========================================

#[rstest]
#[case::allowed_command("git status", assert_allow as ActionAssertion)]
#[case::denied_command("rm -rf /", assert_deny as ActionAssertion)]
#[case::asked_command("git push origin main", assert_ask as ActionAssertion)]
#[case::unmatched_command("hg status", assert_default as ActionAssertion)]
fn full_config_evaluates_correctly(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        defaults:
          action: ask
        rules:
          - deny: 'rm -rf /'
          - deny: 'git push -f|--force *'
            message: 'Force push is not allowed'
          - allow: 'git status'
          - allow: 'git diff *'
          - allow: 'git log *'
          - ask: 'git push *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}
