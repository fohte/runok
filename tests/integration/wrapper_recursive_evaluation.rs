use super::{
    ActionAssertion, assert_allow, assert_ask, assert_default, assert_deny, empty_context,
};

use indoc::indoc;
use rstest::rstest;
use runok::config::{Config, parse_config};
use runok::rules::RuleError;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command, evaluate_compound};

fn config_with_standard_wrappers() -> &'static str {
    indoc! {"
        definitions:
          wrappers:
            - 'sudo <cmd>'
            - 'bash -c <cmd>'
            - 'sh -c <cmd>'
    "}
}

// ========================================
// sudo wrapper: inner command is evaluated
// ========================================

#[rstest]
#[case::sudo_rm_denied("sudo rm -rf /", assert_deny as ActionAssertion)]
#[case::sudo_safe_allowed("sudo ls -la", assert_allow as ActionAssertion)]
#[case::sudo_unmatched_default("sudo hg status", assert_default as ActionAssertion)]
fn sudo_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'ls *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// bash -c wrapper: inner command is evaluated
// ========================================

#[rstest]
#[case::bash_c_curl_post_denied("bash -c 'curl -X POST https://example.com'", assert_deny as ActionAssertion)]
#[case::bash_c_curl_get_allowed("bash -c 'curl -X GET https://example.com'", assert_allow as ActionAssertion)]
fn bash_c_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'curl -X|--request POST *'\n  - allow: 'curl -X|--request GET *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Nested wrappers: sudo bash -c
// ========================================

#[rstest]
#[case::sudo_bash_c_rm("sudo bash -c 'rm -rf /'", assert_deny as ActionAssertion)]
#[case::sudo_sh_c_rm("sudo sh -c 'rm -rf /'", assert_deny as ActionAssertion)]
#[case::sudo_bash_c_safe("sudo bash -c 'echo hello'", assert_allow as ActionAssertion)]
fn nested_wrappers_evaluate_recursively(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'echo *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Compound commands inside wrappers
// ========================================

#[rstest]
#[case::compound_with_deny("bash -c 'ls -la; rm -rf /'", assert_deny as ActionAssertion)]
#[case::compound_all_safe("bash -c 'ls -la && echo done'", assert_allow as ActionAssertion)]
fn compound_commands_inside_wrapper(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = format!(
        "{}\nrules:\n  - deny: 'rm -rf *'\n  - allow: 'ls *'\n  - allow: 'echo *'\n",
        config_with_standard_wrappers()
    );
    let config = parse_config(&yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Compound commands inside wrappers: unmatched resolved via defaults.action
// ========================================

#[rstest]
fn compound_in_wrapper_unmatched_uses_defaults_action(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'bash -c <cmd>'
    "})
    .unwrap();

    // "echo hello" matches allow, "unknown_cmd" is unmatched.
    // With defaults.action = ask, the unmatched sub-command resolves to Ask.
    let result =
        evaluate_command(&config, "bash -c 'echo hello; unknown_cmd'", &empty_context).unwrap();
    assert!(
        matches!(result.action, Action::Ask(_)),
        "expected Ask, got {:?}",
        result.action
    );
}

// ========================================
// Deny wins over direct rule allow (wrapper inner takes priority)
// ========================================

#[rstest]
fn deny_from_inner_wins_over_direct_allow(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'sudo *'
          - deny: 'rm -rf *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, "sudo rm -rf /", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

// ========================================
// Recursion depth limit
// ========================================

#[rstest]
fn deeply_nested_wrappers_hit_recursion_limit(empty_context: EvalContext) {
    let config = Config {
        rules: Some(vec![]),
        definitions: Some(runok::config::Definitions {
            wrappers: Some(vec!["a <cmd>".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    };

    // 12 levels of "a" nesting exceeds MAX_WRAPPER_DEPTH (10)
    let result = evaluate_command(&config, "a a a a a a a a a a a a", &empty_context);
    assert!(
        matches!(result, Err(RuleError::RecursionDepthExceeded(_))),
        "expected RecursionDepthExceeded, got {:?}",
        result
    );
}

// ========================================
// No wrappers defined: sudo is not unwrapped
// ========================================

#[rstest]
fn without_wrappers_sudo_is_not_unwrapped(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm -rf *'
    "})
    .unwrap();

    // Without wrappers, "sudo rm -rf /" is just "sudo" command, not unwrapped
    let result = evaluate_command(&config, "sudo rm -rf /", &empty_context).unwrap();
    assert_eq!(result.action, Action::Default);
}

// ========================================
// Wrapper preserves quoting
// ========================================

// ========================================
// env wrapper: env-prefix variables are consumed by wildcard,
// inner command is correctly evaluated
// ========================================

#[rstest]
#[case::env_var_echo_allowed("env FOO=bar echo hello", assert_allow as ActionAssertion)]
#[case::env_var_rm_denied("env FOO=bar rm -rf /", assert_deny as ActionAssertion)]
#[case::env_multiple_vars("env FOO=bar BAZ=qux echo hello", assert_allow as ActionAssertion)]
#[case::env_var_unmatched_default("env FOO=bar hg status", assert_default as ActionAssertion)]
fn env_wrapper_evaluates_inner(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'env <opts> <vars> <cmd>'
    "};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Bare env-prefix command (no `env` wrapper):
// FOO=bar echo hello is evaluated as echo hello via evaluate_compound,
// which calls extract_commands to strip variable assignments.
// ========================================

#[rstest]
#[case::bare_env_prefix_allowed("FOO=bar echo hello", assert_allow as ActionAssertion)]
#[case::bare_env_prefix_denied("FOO=bar rm -rf /", assert_deny as ActionAssertion)]
fn bare_env_prefix_evaluates_stripped_command(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let yaml = indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'echo *'
    "};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Wrapper preserves quoting
// ========================================

#[rstest]
fn wrapper_preserves_quoted_arguments(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'echo *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, "sudo echo 'hello world'", &empty_context).unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
}

// ========================================
// Wildcard-with-placeholder wrapper: greedy wildcard consumes flags
// ========================================

#[rstest]
#[case::xargs_flags_echo_allowed("xargs -I{} echo hello", assert_allow as ActionAssertion)]
#[case::xargs_flags_rm_denied("xargs -I{} rm -rf /", assert_deny as ActionAssertion)]
#[case::xargs_no_flags_echo_allowed("xargs echo hello", assert_allow as ActionAssertion)]
#[case::xargs_multiple_flags_echo_allowed("xargs -0 -I{} echo hello", assert_allow as ActionAssertion)]
fn wildcard_wrapper_greedy_consumes_flags(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'xargs * <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// <opts> wrapper: consumes flags and their arguments
// ========================================

#[rstest]
#[case::opts_single_flag("xargs -I{} echo hello", assert_allow as ActionAssertion)]
#[case::opts_flag_rm_denied("xargs -I{} rm -rf /", assert_deny as ActionAssertion)]
#[case::opts_no_flags("xargs echo hello", assert_allow as ActionAssertion)]
#[case::opts_multiple_flags("xargs -0 -I{} echo hello", assert_allow as ActionAssertion)]
#[case::opts_flag_with_separate_arg("xargs -n 5 echo hello", assert_allow as ActionAssertion)]
#[case::opts_mixed_flags_and_args("xargs -0 -n 5 -I{} echo hello", assert_allow as ActionAssertion)]
#[case::opts_digit_flag_self_contained("xargs -0 echo hello", assert_allow as ActionAssertion)]
#[case::opts_end_of_options("xargs -- echo hello", assert_allow as ActionAssertion)]
#[case::opts_flags_then_end_of_options("xargs -0 -- echo hello", assert_allow as ActionAssertion)]
fn opts_wrapper_consumes_flags(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'xargs <opts> <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// <opts> wrapper with defaults.action: deny
// ========================================

#[rstest]
fn opts_wrapper_with_defaults_action_deny(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        defaults:
          action: deny
        rules:
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'xargs <opts> <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, "xargs -I{} echo hello", &empty_context).unwrap();
    assert!(
        matches!(result.action, Action::Allow),
        "expected Allow, got {:?}",
        result.action
    );
}

// ========================================
// <vars> wrapper: consumes KEY=VALUE tokens
// ========================================

#[rstest]
#[case::vars_single("env FOO=bar echo hello", assert_allow as ActionAssertion)]
#[case::vars_multiple("env FOO=bar BAZ=qux echo hello", assert_allow as ActionAssertion)]
#[case::vars_none("env echo hello", assert_allow as ActionAssertion)]
#[case::vars_with_opts("env -i FOO=bar echo hello", assert_allow as ActionAssertion)]
#[case::vars_with_opts_rm_denied("env -i FOO=bar rm -rf /", assert_deny as ActionAssertion)]
fn vars_wrapper_consumes_assignments(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm -rf *'
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'env <opts> <vars> <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// merge_results: direct rule + wrapper result merging
// ========================================

#[rstest]
#[case::direct_allow_wrapper_ask(
    indoc! {"
        rules:
          - allow: 'sudo *'
          - ask: 'rm *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "},
    "sudo rm file.txt",
    assert_ask as ActionAssertion,
)]
#[case::direct_allow_wrapper_deny(
    indoc! {"
        rules:
          - allow: 'sudo *'
          - deny: 'rm -rf *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "},
    "sudo rm -rf /",
    assert_deny as ActionAssertion,
)]
#[case::direct_ask_wrapper_deny(
    indoc! {"
        rules:
          - ask: 'sudo *'
          - deny: 'rm -rf *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "},
    "sudo rm -rf /",
    assert_deny as ActionAssertion,
)]
#[case::direct_default_wrapper_allow(
    indoc! {"
        rules:
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "},
    "sudo echo hello",
    assert_allow as ActionAssertion,
)]
#[case::direct_default_wrapper_deny(
    indoc! {"
        rules:
          - deny: 'rm -rf *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "},
    "sudo rm -rf /",
    assert_deny as ActionAssertion,
)]
fn merge_results_all_branches(
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
// when clause + wrapper combination
// ========================================

#[rstest]
fn when_clause_with_wrapper() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
          - allow: 'aws *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    // sudo aws s3 ls in prod -> deny (inner command matches when clause)
    let prod_ctx = EvalContext {
        env: std::collections::HashMap::from([("AWS_PROFILE".to_string(), "prod".to_string())]),
        cwd: std::path::PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "sudo aws s3 ls", &prod_ctx).unwrap();
    assert!(
        matches!(result.action, Action::Deny(_)),
        "expected Deny in prod, got {:?}",
        result.action
    );

    // sudo aws s3 ls in dev -> allow (when clause skipped, allow matches)
    let dev_ctx = EvalContext {
        env: std::collections::HashMap::from([("AWS_PROFILE".to_string(), "dev".to_string())]),
        cwd: std::path::PathBuf::from("/tmp"),
    };
    let result = evaluate_command(&config, "sudo aws s3 ls", &dev_ctx).unwrap();
    assert_eq!(result.action, Action::Allow);
}

// ========================================
// MAX_WRAPPER_DEPTH boundary value: depth=10 succeeds, depth=11 fails
// ========================================

#[rstest]
fn wrapper_depth_exactly_at_limit_succeeds(empty_context: EvalContext) {
    let config = Config {
        rules: Some(vec![]),
        definitions: Some(runok::config::Definitions {
            wrappers: Some(vec!["a <cmd>".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    };

    // 11 "a" tokens = depth 0 (outer) + 10 wrapper unwraps -> depth 10
    // depth check is `depth > 10`, so depth=10 should succeed
    let result = evaluate_command(&config, "a a a a a a a a a a a", &empty_context);
    assert!(result.is_ok(), "depth=10 should succeed, got {:?}", result);
}

#[rstest]
fn wrapper_depth_one_over_limit_fails(empty_context: EvalContext) {
    let config = Config {
        rules: Some(vec![]),
        definitions: Some(runok::config::Definitions {
            wrappers: Some(vec!["a <cmd>".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    };

    // 12 "a" tokens = 11 wrapper unwraps -> depth 11 > MAX_WRAPPER_DEPTH(10)
    let result = evaluate_command(&config, "a a a a a a a a a a a a", &empty_context);
    assert!(
        matches!(result, Err(RuleError::RecursionDepthExceeded(10))),
        "depth=11 should fail with RecursionDepthExceeded, got {:?}",
        result
    );
}

// ========================================
// Wrapper inner compound with sub-wrappers
// ========================================

#[rstest]
fn wrapper_inner_compound_with_sub_wrappers(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
            - 'bash -c <cmd>'
    "})
    .unwrap();

    // bash -c 'sudo echo hello && sudo rm -rf /'
    // -> compound: [sudo echo hello, sudo rm -rf /]
    // -> sudo echo hello -> echo hello -> Allow
    // -> sudo rm -rf / -> rm -rf / -> Deny
    // -> overall: Deny
    let result = evaluate_command(
        &config,
        "bash -c 'sudo echo hello && sudo rm -rf /'",
        &empty_context,
    )
    .unwrap();
    assert!(
        matches!(result.action, Action::Deny(_)),
        "expected Deny, got {:?}",
        result.action
    );
}

#[rstest]
fn wrapper_inner_compound_all_sub_wrappers_allowed(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'ls *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
            - 'bash -c <cmd>'
    "})
    .unwrap();

    // bash -c 'sudo echo hello && sudo ls -la'
    // -> compound: [sudo echo hello, sudo ls -la]
    // -> both inner commands -> Allow
    let result = evaluate_command(
        &config,
        "bash -c 'sudo echo hello && sudo ls -la'",
        &empty_context,
    )
    .unwrap();
    assert_eq!(result.action, Action::Allow);
}

// ========================================
// Wrapper + sandbox: inner command's sandbox preset survives
// when no direct rule matches the wrapper command
// ========================================

#[rstest]
fn wrapper_preserves_inner_sandbox_preset(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'python3 *'
            sandbox: restricted
        definitions:
          wrappers:
            - 'sudo <cmd>'
          sandbox:
            restricted:
              fs:
                writable: [/tmp]
                deny: [/etc]
              network:
                allow: false
    "})
    .unwrap();

    // sudo python3 script.py -> no direct rule for "sudo *",
    // wrapper unwraps to "python3 script.py" -> allow with sandbox "restricted"
    let result = evaluate_command(&config, "sudo python3 script.py", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.sandbox_preset.as_deref(), Some("restricted"));
}

// ========================================
// Wrapper + sandbox: direct rule overrides inner sandbox
// when direct rule has higher priority
// ========================================

#[rstest]
fn wrapper_direct_rule_overrides_inner_sandbox(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - ask: 'sudo *'
          - allow: 'python3 *'
            sandbox: restricted
        definitions:
          wrappers:
            - 'sudo <cmd>'
          sandbox:
            restricted:
              fs:
                writable: [/tmp]
                deny: [/etc]
              network:
                allow: false
    "})
    .unwrap();

    // sudo python3 script.py:
    // - direct: "sudo *" -> Ask (priority 2)
    // - wrapper: "python3 *" -> Allow (priority 1) with sandbox "restricted"
    // - merge_results: Ask wins (higher priority), its sandbox_preset (None) is used
    let result = evaluate_command(&config, "sudo python3 script.py", &empty_context).unwrap();
    assert!(
        matches!(result.action, Action::Ask(_)),
        "expected Ask, got {:?}",
        result.action
    );
    assert_eq!(result.sandbox_preset, None);
}

// ========================================
// bash -c with double quotes: same behavior as single quotes
// ========================================

#[rstest]
#[case::single_quoted(r#"bash -c 'echo hello'"#, assert_allow as ActionAssertion)]
#[case::double_quoted(r#"bash -c "echo hello""#, assert_allow as ActionAssertion)]
fn bash_c_double_vs_single_quotes(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
        definitions:
          wrappers:
            - 'bash -c <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Wrapper without <cmd> placeholder: no recursive evaluation
// ========================================

#[rstest]
fn wrapper_without_cmd_placeholder_no_recurse(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'ls *'
        definitions:
          wrappers:
            - 'time *'
    "})
    .unwrap();

    // "time ls -la": time * matches as wrapper but has no <cmd>,
    // so no recursive evaluation occurs. "time" itself has no rule -> Default
    let result = evaluate_command(&config, "time ls -la", &empty_context).unwrap();
    assert_eq!(result.action, Action::Default);
}

// ========================================
// Wrapper + compound + sandbox: merge_results picks sandbox_preset
// from the sub-command with the highest action priority.
// Both sub-commands have Allow (same priority), so the first one's
// sandbox_preset is kept.
// ========================================

#[rstest]
fn wrapper_compound_with_sandbox(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'python3 *'
            sandbox: py_sandbox
          - allow: 'node *'
            sandbox: node_sandbox
        definitions:
          wrappers:
            - 'bash -c <cmd>'
          sandbox:
            py_sandbox:
              fs:
                writable: [/tmp, /var/lib/python]
                deny: [/etc]
              network:
                allow: false
            node_sandbox:
              fs:
                writable: [/tmp, /var/lib/node]
                deny: [/etc, /sys]
              network:
                allow: false
    "})
    .unwrap();

    // bash -c 'python3 a.py && node b.js'
    // -> compound inside wrapper: merge_results picks one sandbox_preset
    //    based on action priority (both Allow -> first wins: py_sandbox)
    let result = evaluate_command(
        &config,
        "bash -c 'python3 a.py && node b.js'",
        &empty_context,
    )
    .unwrap();
    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.sandbox_preset.as_deref(), Some("py_sandbox"));
}
