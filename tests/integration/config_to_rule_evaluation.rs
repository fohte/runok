use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::{formatdoc, indoc};
use rstest::rstest;
use runok::config::{Config, ConfigError, RuleEntry, parse_config};
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command};

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
    assert_ask as ActionAssertion,
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
            tests: None,
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
fn config_validation_rejects_invalid(#[case] mut config: Config, #[case] expected_error: &str) {
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
    let mut config = parse_config(indoc! {"
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
    let mut config = Config {
        rules: Some(vec![
            RuleEntry {
                deny: None,
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
                tests: None,
            },
            RuleEntry {
                deny: Some("curl *".to_string()),
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: Some("restricted".to_string()),
                tests: None,
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
#[case::unmatched_command("hg status", assert_ask as ActionAssertion)]
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

// ========================================
// Multi-word alternation (end-to-end via YAML config)
// ========================================

#[rstest]
#[case::npx_prettier_allowed(
    "npx prettier --write .",
    assert_allow as ActionAssertion,
)]
#[case::bunx_prettier_allowed(
    "bunx prettier --write .",
    assert_allow as ActionAssertion,
)]
#[case::bare_prettier_allowed(
    "prettier --write .",
    assert_allow as ActionAssertion,
)]
#[case::unrelated_command_default(
    "yarn prettier --write .",
    assert_ask as ActionAssertion,
)]
fn multi_word_alternation_config(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {r#"
        rules:
          - allow: '"npx prettier"|"bunx prettier"|prettier *'
    "#})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

#[rstest]
#[case::npx_denied("npx prettier --write /etc/passwd", assert_deny as ActionAssertion)]
#[case::bare_denied("prettier --write /etc/passwd", assert_deny as ActionAssertion)]
#[case::npx_allowed("npx prettier --write .", assert_allow as ActionAssertion)]
#[case::bare_allowed("prettier --write .", assert_allow as ActionAssertion)]
fn multi_word_alternation_allow_and_deny(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {r#"
        rules:
          - allow: '"npx prettier"|prettier *'
          - deny: '"npx prettier"|prettier --write /etc/passwd'
    "#})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Alternation with glob wildcard in config
// ========================================

#[rstest]
#[case::glob_alt_list_buckets(
    "aws s3api list-buckets",
    assert_allow as ActionAssertion,
)]
#[case::glob_alt_get_object(
    "aws s3api get-object my-bucket",
    assert_allow as ActionAssertion,
)]
#[case::glob_alt_describe_instances(
    "aws ec2 describe-instances",
    assert_allow as ActionAssertion,
)]
#[case::glob_alt_delete_blocked(
    "aws s3api delete-bucket my-bucket",
    assert_ask as ActionAssertion,
)]
fn alternation_glob_wildcard_config(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'aws * describe-*|get-*|list-* *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

#[rstest]
#[case::negated_glob_allows_delete(
    "kubectl delete my-pod",
    assert_allow as ActionAssertion,
)]
#[case::negated_glob_denies_list_pods(
    "kubectl list-pods",
    assert_deny as ActionAssertion,
)]
#[case::negated_glob_denies_describe(
    "kubectl describe my-pod",
    assert_deny as ActionAssertion,
)]
#[case::negated_glob_denies_get(
    "kubectl get pods",
    assert_deny as ActionAssertion,
)]
fn negation_alternation_glob_wildcard_config(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'kubectl *'
          - deny: 'kubectl describe|get|list-* *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Literal token with glob wildcard in config
// ========================================

#[rstest]
#[case::literal_glob_deny_matches(
    "aws ssm get-parameter --name foo --with-decryption",
    assert_deny as ActionAssertion,
)]
#[case::literal_glob_deny_matches_variant(
    "aws ssm get-parameters-by-path --path /prod",
    assert_deny as ActionAssertion,
)]
#[case::literal_glob_deny_no_match(
    "aws ssm put-parameter --name foo --value bar",
    assert_allow as ActionAssertion,
)]
fn literal_glob_wildcard_config(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'aws *'
          - deny: 'aws ssm get-* *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

#[rstest]
#[case::negated_literal_glob_allows(
    "aws ssm put-parameter --name foo",
    assert_allow as ActionAssertion,
)]
#[case::negated_literal_glob_denies(
    "aws ssm get-parameter --name foo",
    assert_deny as ActionAssertion,
)]
fn negated_literal_glob_wildcard_config(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'aws ssm !get-* *'
          - deny: 'aws ssm get-* *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Rule order independence: deny wins regardless of definition order
// ========================================

#[rstest]
#[case::deny_before_allow(
    indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'rm *'
    "},
    "rm -rf /tmp",
    assert_deny as ActionAssertion,
)]
#[case::allow_before_deny(
    indoc! {"
        rules:
          - allow: 'rm *'
          - deny: 'rm -rf *'
    "},
    "rm -rf /tmp",
    assert_deny as ActionAssertion,
)]
#[case::ask_before_deny(
    indoc! {"
        rules:
          - ask: 'git push *'
          - deny: 'git push -f|--force *'
    "},
    "git push --force origin",
    assert_deny as ActionAssertion,
)]
#[case::deny_before_ask(
    indoc! {"
        rules:
          - deny: 'git push -f|--force *'
          - ask: 'git push *'
    "},
    "git push --force origin",
    assert_deny as ActionAssertion,
)]
fn rule_order_independence(
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
// Wildcard command patterns
// ========================================

#[rstest]
#[case::star_help_matches_any_command(
    indoc! {"
        rules:
          - allow: '* --help'
    "},
    "git --help",
    assert_allow as ActionAssertion,
)]
#[case::star_help_matches_curl(
    indoc! {"
        rules:
          - allow: '* --help'
    "},
    "curl --help",
    assert_allow as ActionAssertion,
)]
#[case::deny_rm_star_vs_allow_star_help(
    indoc! {"
        rules:
          - deny: 'rm *'
          - allow: '* --help'
    "},
    "rm --help",
    assert_deny as ActionAssertion,
)]
#[case::allow_star_help_unmatched_without_flag(
    indoc! {"
        rules:
          - allow: '* --help'
    "},
    "git status",
    assert_ask as ActionAssertion,
)]
fn wildcard_command_patterns(
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
// Wildcard deny beats specific allow
// ========================================

#[rstest]
#[case::deny_git_star_overrides_allow_git_status(
    "git status",
    assert_deny as ActionAssertion,
)]
#[case::deny_git_star_overrides_allow_git_diff(
    "git diff HEAD",
    assert_deny as ActionAssertion,
)]
#[case::unrelated_command_not_affected(
    "echo hello",
    assert_ask as ActionAssertion,
)]
fn wildcard_deny_beats_specific_allow(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git status'
          - allow: 'git diff *'
          - deny: 'git *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// defaults.sandbox: no sandbox -> sandbox_preset is None
// ========================================

#[rstest]
fn no_sandbox_rule_returns_none_preset(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
    "})
    .unwrap();

    let result = evaluate_command(&config, "echo hello", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert!(
        result.sandbox_preset.is_none(),
        "expected sandbox_preset to be None, got {:?}",
        result.sandbox_preset
    );
}

#[rstest]
fn defaults_sandbox_does_not_apply_to_rules_without_sandbox(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        defaults:
          sandbox: restricted
        rules:
          - allow: 'echo *'
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "})
    .unwrap();

    let result = evaluate_command(&config, "echo hello", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    // defaults.sandbox does not automatically apply to rules that don't specify sandbox
    assert!(
        result.sandbox_preset.is_none(),
        "expected sandbox_preset to be None when rule has no sandbox, got {:?}",
        result.sandbox_preset
    );
}

// ========================================
// Ask response preserves message
// ========================================

#[rstest]
fn ask_response_preserves_message(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - ask: 'git push *'
            message: 'Are you sure you want to push?'
    "})
    .unwrap();

    let result = evaluate_command(&config, "git push origin main", &empty_context).unwrap();
    match &result.action {
        Action::Ask(msg) => {
            assert_eq!(msg.as_deref(), Some("Are you sure you want to push?"));
        }
        other => panic!("expected Ask, got {:?}", other),
    }
}

#[rstest]
fn ask_without_message_has_none(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - ask: 'git push *'
    "})
    .unwrap();

    let result = evaluate_command(&config, "git push origin main", &empty_context).unwrap();
    match &result.action {
        Action::Ask(msg) => {
            assert!(msg.is_none(), "expected None message, got {:?}", msg);
        }
        other => panic!("expected Ask, got {:?}", other),
    }
}

// ========================================
// Unicode in commands
// ========================================

#[rstest]
#[case::unicode_arg_allowed("echo こんにちは", assert_allow as ActionAssertion)]
#[case::unicode_in_path("cat /tmp/日本語.txt", assert_ask as ActionAssertion)]
fn unicode_in_commands(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Equals-sign in flag tokens
// ========================================

#[rstest]
#[case::equals_flag_matches("java -Denv=prod Main", assert_allow as ActionAssertion)]
#[case::different_value_no_match("java -Denv=staging Main", assert_ask as ActionAssertion)]
fn equals_sign_in_flag_token(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'java -Denv=prod *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Duplicate rules: deny still wins
// ========================================

#[rstest]
fn duplicate_rules_deny_wins(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git status'
          - allow: 'git status'
          - deny: 'git status'
    "})
    .unwrap();

    let result = evaluate_command(&config, "git status", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

// ========================================
// Empty rules list returns Default
// ========================================

#[rstest]
fn empty_rules_returns_default(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules: []
    "})
    .unwrap();

    let result = evaluate_command(&config, "echo hello", &empty_context).unwrap();
    assert_eq!(result.action, Action::Ask(None));
}

// ========================================
// Quoted `*` acts as glob; `\*` is literal
// ========================================

#[rstest]
// `*` acts as glob
#[case::quoted_star_glob_matches(
    r#"git commit -m "WIP*""#,
    "git commit -m 'WIP: fixup'",
    assert_deny as ActionAssertion,
)]
#[case::quoted_star_glob_exact(
    r#"git commit -m "WIP*""#,
    "git commit -m 'WIP*'",
    assert_deny as ActionAssertion,
)]
#[case::quoted_star_glob_no_match(
    r#"git commit -m "WIP*""#,
    "git commit -m 'DONE: release'",
    assert_ask as ActionAssertion,
)]
// `\*` is literal
#[case::escaped_star_exact_match(
    r#"git commit -m "WIP\*""#,
    "git commit -m 'WIP*'",
    assert_deny as ActionAssertion,
)]
#[case::escaped_star_no_glob(
    r#"git commit -m "WIP\*""#,
    "git commit -m 'WIP: fixup'",
    assert_ask as ActionAssertion,
)]
fn quoted_and_escaped_star_matching(
    #[case] pattern: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(&formatdoc! {r#"
        rules:
          - deny: '{pattern}'
    "#})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Quoted glob with spaces (primary use case)
// ========================================

#[rstest]
#[case::quoted_glob_with_space_matches(
    "npx --package renovate -c 'renovate-config-validator foo.json'",
    assert_allow as ActionAssertion,
)]
#[case::quoted_glob_with_space_no_match(
    "npx --package renovate -c 'other-tool foo.json'",
    assert_ask as ActionAssertion,
)]
fn quoted_glob_with_space(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {r#"
        rules:
          - allow: "npx --package renovate -c 'renovate-config-validator *'"
    "#})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Quoted flag-like values consumed as flag arguments
// ========================================

// Pattern `grep -e "-v" *` should parse `-e` as a value-taking flag with
// value `-v`, not as two independent boolean flags. When `-e` is properly
// a FlagWithValue, the command parser knows to consume the next token as
// its value, so `grep -e -v foo.txt` means `-e` takes value `-v`.
// Without FlagWithValue, `-e` and `-v` are both boolean flags and `foo.txt`
// becomes a positional arg, which changes match semantics.
#[rstest]
#[case::quoted_flag_value_different_order(
    "grep -e '-v' *",
    "grep foo.txt -e -v",
    assert_allow as ActionAssertion,
)]
#[case::quoted_flag_value_wrong_value_rejects(
    "grep -e '-v' *",
    "grep foo.txt -e -x",
    assert_ask as ActionAssertion,
)]
fn quoted_flag_like_value(
    #[case] pattern: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(&formatdoc! {r#"
        rules:
          - allow: "{pattern}"
    "#})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Backslash before closing quote is not an escape
// ========================================

#[rstest]
fn backslash_before_closing_quote(empty_context: EvalContext) {
    let config = parse_config(indoc! {r#"
        rules:
          - allow: "cmd 'hello\\'"
    "#})
    .unwrap();

    let result = evaluate_command(&config, r"cmd hello\", &empty_context).unwrap();
    assert_allow(&result.action);
}

// ========================================
// Double-dash (--) positional matching
// ========================================

#[rstest]
#[case::checkout_file_only(
    "git checkout -- README.md",
    assert_allow as ActionAssertion,
)]
#[case::checkout_file_only_with_c(
    "git -C /tmp checkout -- README.md",
    assert_allow as ActionAssertion,
)]
#[case::checkout_ref_then_double_dash_rejected(
    "git checkout HEAD~1 -- README.md",
    assert_ask as ActionAssertion,
)]
#[case::checkout_ref_then_double_dash_with_c_rejected(
    "git -C /tmp checkout HEAD~1 -- README.md",
    assert_ask as ActionAssertion,
)]
fn double_dash_positional_matching(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git [-C *] checkout -- *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Flag-only negation: order-independent matching
// ========================================

#[rstest]
#[case::flag_negation_rejects_at_any_position(
    "find . -delete",
    assert_ask as ActionAssertion,
)]
#[case::flag_negation_rejects_alt_at_any_position(
    "find . -type f -fprint output.txt",
    assert_ask as ActionAssertion,
)]
#[case::flag_negation_allows_safe_command(
    "find . -name foo -type f",
    assert_allow as ActionAssertion,
)]
fn flag_negation_order_independent(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'find !-delete|-fprint|-fprint0|-fprintf|-fls *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Order-independent literal matching
// ========================================

#[rstest]
#[case::flag_before_literal(
    "gh -X GET api /repos",
    assert_allow as ActionAssertion,
)]
#[case::literal_at_normal_position(
    "gh api -X GET /repos",
    assert_allow as ActionAssertion,
)]
#[case::flag_after_literal(
    "gh api /repos -X GET",
    assert_allow as ActionAssertion,
)]
#[case::literal_mismatch(
    "gh -X GET issues /repos",
    assert_ask as ActionAssertion,
)]
fn literal_order_independent(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'gh api -X GET *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

#[rstest]
#[case::double_dash_correct_position(
    "cmd foo -- bar",
    assert_allow as ActionAssertion,
)]
#[case::double_dash_wrong_position(
    "cmd -- foo bar",
    assert_ask as ActionAssertion,
)]
fn double_dash_remains_positional(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'cmd foo -- bar'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

#[rstest]
#[case::non_flag_alt_skips_flags(
    "git push -v main origin",
    assert_allow as ActionAssertion,
)]
#[case::non_flag_alt_second_variant(
    "git push -v master origin",
    assert_allow as ActionAssertion,
)]
#[case::non_flag_alt_no_flag(
    "git push main origin",
    assert_allow as ActionAssertion,
)]
#[case::non_flag_alt_mismatch(
    "git push -v develop origin",
    assert_ask as ActionAssertion,
)]
fn alternation_order_independent(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git push main|master *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Flag-only negation with `=`-joined tokens
// ========================================

#[rstest]
#[case::equals_form_rejected(
    "rg --pre=pdftotext pattern",
    assert_ask as ActionAssertion,
)]
#[case::space_form_rejected(
    "rg --pre pdftotext pattern",
    assert_ask as ActionAssertion,
)]
#[case::different_flag_equals_allowed(
    "rg --color=always pattern",
    assert_allow as ActionAssertion,
)]
#[case::no_flag_allowed(
    "rg pattern file.txt",
    assert_allow as ActionAssertion,
)]
#[case::alt_negation_equals_rejected(
    "sort --output=result.txt file.txt",
    assert_ask as ActionAssertion,
)]
#[case::alt_negation_equals_different_flag_allowed(
    "sort --reverse file.txt",
    assert_allow as ActionAssertion,
)]
fn flag_negation_equals_form(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'rg !--pre *'
          - allow: 'sort !-o|--output|--compress-program *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Flag-only negation with empty tokens (no arguments after command)
// ========================================

#[rstest]
#[case::sort_no_args_allowed(
    "sort",
    assert_allow as ActionAssertion,
)]
#[case::sort_safe_flag_allowed(
    "sort -r",
    assert_allow as ActionAssertion,
)]
#[case::sort_banned_flag_rejected(
    "sort -o result.txt",
    assert_ask as ActionAssertion,
)]
#[case::find_no_args_allowed(
    "find",
    assert_allow as ActionAssertion,
)]
#[case::find_safe_args_allowed(
    "find . -name foo",
    assert_allow as ActionAssertion,
)]
#[case::find_banned_flag_rejected(
    "find . -delete",
    assert_ask as ActionAssertion,
)]
fn flag_negation_empty_tokens(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'sort !-o|--output|--compress-program *'
          - allow: 'find !-delete *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Long flag negation with preceding literal tokens (no trailing arguments)
// ========================================

#[rstest]
#[case::no_trailing_args_allowed(
    "git interpret-trailers --parse",
    assert_allow as ActionAssertion,
)]
#[case::safe_trailing_arg_allowed(
    "git interpret-trailers --parse file.txt",
    assert_allow as ActionAssertion,
)]
#[case::banned_flag_rejected(
    "git interpret-trailers --parse --in-place",
    assert_ask as ActionAssertion,
)]
#[case::banned_flag_with_arg_rejected(
    "git interpret-trailers --parse --in-place file.txt",
    assert_ask as ActionAssertion,
)]
fn long_flag_negation_with_preceding_literals(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git interpret-trailers --parse !--in-place *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Boolean flag with trailing wildcard is not broken by equals splitting
// ========================================

#[rstest]
#[case::boolean_flag_space_separated(
    "git push --force origin",
    assert_deny as ActionAssertion,
)]
#[case::boolean_flag_with_multiple_args(
    "git push --force origin main",
    assert_deny as ActionAssertion,
)]
#[case::no_flag_allowed(
    "git push origin main",
    assert_allow as ActionAssertion,
)]
#[case::boolean_flag_equals_not_split(
    "git push --force=unexpected origin",
    assert_deny as ActionAssertion,
)]
fn boolean_flag_not_broken_by_equals_splitting(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push -f|--force *'
          - allow: 'git push *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Flag with equals-joined value matches wildcard value pattern
// ========================================

#[rstest]
#[case::space_separated_flag_matches(
    "curl --output /tmp/out https://example.com",
    assert_ask as ActionAssertion,
)]
#[case::equals_joined_flag_matches(
    "curl --output=/tmp/out https://example.com",
    assert_ask as ActionAssertion,
)]
#[case::short_flag_space_separated(
    "curl -o /tmp/out https://example.com",
    assert_ask as ActionAssertion,
)]
#[case::short_flag_equals_joined(
    "curl -o=/tmp/out https://example.com",
    assert_ask as ActionAssertion,
)]
#[case::no_output_flag_allowed(
    "curl https://example.com",
    assert_allow as ActionAssertion,
)]
fn flag_equals_value_with_wildcard_pattern(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - ask: 'curl * -o|--output *'
          - allow: 'curl *'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Fused short flag value matching (e.g. `-n3` for `-n *`)
// ========================================

#[rstest]
#[case::fused_short_flag_matches(
    "git tag -n3 v1.0",
    assert_allow as ActionAssertion,
)]
#[case::space_separated_still_works(
    "git tag -n 3 v1.0",
    assert_allow as ActionAssertion,
)]
#[case::fused_multichar_value(
    "git tag -n100 v1.0",
    assert_allow as ActionAssertion,
)]
#[case::optional_flag_absent_still_matches(
    "git tag v1.0",
    assert_allow as ActionAssertion,
)]
#[case::fused_in_optional_group(
    "git log -n5",
    assert_allow as ActionAssertion,
)]
#[case::optional_absent(
    "git log",
    assert_allow as ActionAssertion,
)]
#[case::optional_space_separated(
    "git log -n 10",
    assert_allow as ActionAssertion,
)]
fn fused_short_flag_value(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git tag [-n *] *'
          - allow: 'git log [-n *]'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}
