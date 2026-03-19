use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::{MergedSandboxPolicy, parse_config};
use runok::exec::command_executor::CommandInput;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_command, evaluate_compound};

// ========================================
// Individual evaluation of each command in a compound expression
// ========================================

#[rstest]
#[case::pipe_all_allowed(
    "ls -la | grep foo",
    assert_allow as ActionAssertion,
)]
#[case::and_chain_all_allowed(
    "git status && git diff",
    assert_allow as ActionAssertion,
)]
#[case::pipe_and_chain_mixed(
    "curl https://example.com | jq '.data' && echo done",
    assert_allow as ActionAssertion,
)]
#[case::deny_in_pipe(
    "curl https://example.com | jq '.data' && rm -rf /tmp/data",
    assert_deny as ActionAssertion,
)]
#[case::deny_in_or_chain(
    "echo hello || rm -rf /tmp/data",
    assert_deny as ActionAssertion,
)]
fn each_command_in_compound_is_evaluated_individually(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'ls *'
          - allow: 'grep *'
          - allow: 'git status'
          - allow: 'git diff'
          - allow: 'curl *'
          - allow: 'jq *'
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Action aggregation: any deny -> overall deny
// ========================================

#[rstest]
#[case::one_deny_among_allows(
    "echo hello && rm -rf / || ls",
    assert_deny as ActionAssertion,
)]
#[case::deny_at_start(
    "rm -rf / | echo ok",
    assert_deny as ActionAssertion,
)]
#[case::deny_at_end(
    "echo hello | rm -rf /",
    assert_deny as ActionAssertion,
)]
fn any_deny_makes_overall_deny(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'ls'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

#[rstest]
#[case::ask_over_allow(
    "git status && git push origin",
    assert_ask as ActionAssertion,
)]
#[case::deny_over_ask_and_allow(
    "git status && git push origin && rm -rf /",
    assert_deny as ActionAssertion,
)]
fn action_aggregation_priority(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git status'
          - ask: 'git push *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Sandbox policy aggregation: Strictest Wins
// ========================================

#[rstest]
#[case::writable_roots_intersection(
    "cargo build --release | cargo test --all",
    indoc! {"
        rules:
          - allow: 'cargo build *'
            sandbox: preset_a
          - allow: 'cargo test *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              fs:
                writable: [./src, ./tmp]
            preset_b:
              fs:
                writable: [./tmp, ./build]
    "},
    MergedSandboxPolicy {
        writable: vec!["./tmp".to_string()],
        deny: vec![],
        read_deny: vec![],
        network_allowed: true,
    },
)]
#[case::deny_paths_union(
    "cmd_a run && cmd_b run",
    indoc! {"
        rules:
          - allow: 'cmd_a *'
            sandbox: preset_a
          - allow: 'cmd_b *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              fs:
                deny: [/etc/passwd]
            preset_b:
              fs:
                deny: [/etc/shadow]
    "},
    MergedSandboxPolicy {
        writable: vec![],
        deny: vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()],
        read_deny: vec![],
        network_allowed: true,
    },
)]
#[case::network_denied_by_any(
    "cmd_a run && cmd_b run",
    indoc! {"
        rules:
          - allow: 'cmd_a *'
            sandbox: preset_a
          - allow: 'cmd_b *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              network:
                allow: true
            preset_b:
              network:
                allow: false
    "},
    MergedSandboxPolicy {
        writable: vec![],
        deny: vec![],
        read_deny: vec![],
        network_allowed: false,
    },
)]
fn sandbox_strictest_wins_aggregation(
    #[case] command: &str,
    #[case] config_yaml: &str,
    #[case] expected_policy: MergedSandboxPolicy,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();

    assert_eq!(result.action, Action::Allow);
    assert_eq!(result.sandbox_policy.unwrap(), expected_policy);
}

// ========================================
// Sandbox policy contradiction -> ask escalation
// ========================================

#[rstest]
fn writable_contradiction_escalates_to_ask(empty_context: EvalContext) {
    // preset_a: writable [./src]
    // preset_b: writable [./build]
    // intersection is empty -> contradicts -> escalate to ask
    let config = parse_config(indoc! {"
        rules:
          - allow: 'cmd_a *'
            sandbox: preset_a
          - allow: 'cmd_b *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              fs:
                writable: [./src]
            preset_b:
              fs:
                writable: [./build]
    "})
    .unwrap();

    let result = evaluate_compound(&config, "cmd_a run && cmd_b run", &empty_context).unwrap();

    // Action escalated from Allow to Ask due to contradiction
    assert!(
        matches!(result.action, Action::Ask(Some(ref msg)) if msg.contains("contradictory")),
        "expected Ask with contradiction message, got {:?}",
        result.action
    );
    // Policy still present with empty writable roots
    let policy = result.sandbox_policy.unwrap();
    assert!(policy.writable.is_empty());
}

#[rstest]
fn writable_contradiction_does_not_downgrade_deny(empty_context: EvalContext) {
    // Even with contradiction, deny should not be downgraded to ask
    let config = parse_config(indoc! {"
        rules:
          - deny: 'cmd_a *'
            message: 'forbidden'
          - allow: 'cmd_b *'
            sandbox: preset_a
          - allow: 'cmd_c *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              fs:
                writable: [./src]
            preset_b:
              fs:
                writable: [./build]
    "})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "cmd_a run && cmd_b run && cmd_c run",
        &empty_context,
    )
    .unwrap();

    assert!(
        matches!(result.action, Action::Deny(_)),
        "deny must not be downgraded, got {:?}",
        result.action
    );
}

// ========================================
// Unmatched sub-commands resolved via defaults.action
// ========================================

#[rstest]
#[case::allow_plus_unmatched_defaults_ask(
    "echo hello; eval \"rm -rf /\"",
    indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::allow_plus_unmatched_defaults_deny(
    "echo hello; eval \"rm -rf /\"",
    indoc! {"
        defaults:
          action: deny
        rules:
          - allow: 'echo *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::allow_plus_unmatched_defaults_allow(
    "echo hello; unknown_cmd",
    indoc! {"
        defaults:
          action: allow
        rules:
          - allow: 'echo *'
    "},
    assert_allow as ActionAssertion,
)]
#[case::deny_rule_still_wins_over_resolved_default(
    "echo hello && rm -rf /",
    indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "},
    assert_deny as ActionAssertion,
)]
fn unmatched_sub_command_uses_defaults_action(
    #[case] command: &str,
    #[case] config_yaml: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Redirected statements: redirects are stripped before rule evaluation
// ========================================

#[rstest]
#[case::stdout_redirect(
    "echo hello > file.txt",
    assert_allow as ActionAssertion,
)]
#[case::stderr_redirect(
    "git branch --help 2>&1",
    assert_allow as ActionAssertion,
)]
#[case::devnull_redirect(
    "echo hello > /dev/null 2>&1",
    assert_allow as ActionAssertion,
)]
#[case::compound_with_redirect(
    r#"X="test" && echo "$X" 2>&1"#,
    assert_allow as ActionAssertion,
)]
#[case::deny_still_works_with_redirect(
    "rm -rf /tmp/data > /dev/null 2>&1",
    assert_deny as ActionAssertion,
)]
#[case::redirect_in_pipeline(
    "echo hello 2>&1 | grep world",
    assert_allow as ActionAssertion,
)]
fn redirected_statements_match_rules(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'git *'
          - allow: 'grep *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Execution mode: compound commands are represented as Shell input (sh -c)
// ========================================

#[rstest]
#[case::argv_is_not_compound(
    CommandInput::Argv(vec!["git".to_string(), "status".to_string()]),
    false,
)]
#[case::shell_is_compound(
    CommandInput::Shell("cmd1 && cmd2 | cmd3".to_string()),
    true,
)]
fn compound_command_uses_shell_input(#[case] input: CommandInput, #[case] expected_compound: bool) {
    assert_eq!(input.is_compound(), expected_compound);

    // Shell commands report "sh" as program (used for sh -c execution)
    if expected_compound {
        assert_eq!(input.program(), "sh");
    }
}

// ========================================
// Mixed operators: ;, |, && in a single compound
// ========================================

#[rstest]
#[case::semicolon_pipe_and(
    "echo hello; cat file.txt | grep pattern && echo done",
    assert_allow as ActionAssertion,
)]
#[case::mixed_with_deny(
    "echo hello; cat file.txt | rm -rf /tmp && echo done",
    assert_deny as ActionAssertion,
)]
#[case::pipe_then_semicolon(
    "ls -la | grep foo; echo done",
    assert_allow as ActionAssertion,
)]
fn mixed_operators_compound(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'cat *'
          - allow: 'grep *'
          - allow: 'ls *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Partial sandbox in compound: only some sub-commands have sandbox
// ========================================

#[rstest]
fn partial_sandbox_compound(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'python3 *'
            sandbox: restricted
          - allow: 'echo *'
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
              network:
                allow: false
    "})
    .unwrap();

    // python3 has sandbox, echo does not -> sandbox policy still present from python3
    let result =
        evaluate_compound(&config, "python3 script.py && echo done", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    let policy = result.sandbox_policy.unwrap();
    assert_eq!(policy.writable, vec!["./tmp".to_string()]);
    assert!(!policy.network_allowed);
}

// ========================================
// 3+ sandbox presets: progressive intersection
// ========================================

#[rstest]
fn three_preset_progressive_intersection(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'cmd_a *'
            sandbox: preset_a
          - allow: 'cmd_b *'
            sandbox: preset_b
          - allow: 'cmd_c *'
            sandbox: preset_c
        definitions:
          sandbox:
            preset_a:
              fs:
                writable: [./src, ./tmp, ./build]
                deny: [/etc/passwd]
              network:
                allow: true
            preset_b:
              fs:
                writable: [./tmp, ./build, ./dist]
                deny: [/etc/shadow]
              network:
                allow: true
            preset_c:
              fs:
                writable: [./tmp, ./dist, ./out]
                deny: [/root]
              network:
                allow: false
    "})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "cmd_a run && cmd_b run && cmd_c run",
        &empty_context,
    )
    .unwrap();
    assert_eq!(result.action, Action::Allow);

    let policy = result.sandbox_policy.unwrap();
    // writable: intersection of [src,tmp,build] & [tmp,build,dist] & [tmp,dist,out] = [tmp]
    assert_eq!(policy.writable, vec!["./tmp".to_string()]);
    // deny: union of [/etc/passwd] + [/etc/shadow] + [/root]
    let mut deny_sorted = policy.deny.clone();
    deny_sorted.sort();
    assert_eq!(
        deny_sorted,
        vec![
            "/etc/passwd".to_string(),
            "/etc/shadow".to_string(),
            "/root".to_string(),
        ]
    );
    // network: AND of true & true & false = false
    assert!(!policy.network_allowed);
}

// ========================================
// Sandbox contradiction preserves existing Ask
// ========================================

#[rstest]
fn sandbox_contradiction_preserves_existing_ask(empty_context: EvalContext) {
    // One command is Ask, plus writable contradiction -> Ask is preserved (not downgraded)
    let config = parse_config(indoc! {"
        rules:
          - ask: 'cmd_risky *'
            sandbox: preset_a
          - allow: 'cmd_safe *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              fs:
                writable: [./src]
            preset_b:
              fs:
                writable: [./build]
    "})
    .unwrap();

    let result =
        evaluate_compound(&config, "cmd_risky run && cmd_safe run", &empty_context).unwrap();
    // Ask from cmd_risky + writable contradiction -> Ask (contradiction doesn't downgrade)
    assert!(
        matches!(result.action, Action::Ask(_)),
        "expected Ask, got {:?}",
        result.action
    );
}

// ========================================
// defaults.action absent: unmatched sub-commands resolve to Ask
// ========================================

#[rstest]
#[case::no_defaults_unmatched_wins_over_allow(
    "echo hello && unknown_cmd",
    indoc! {"
        rules:
          - allow: 'echo *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::no_defaults_all_unmatched(
    "unknown_a && unknown_b",
    indoc! {"
        rules:
          - allow: 'echo *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::no_defaults_all_matched(
    "echo hello && echo world",
    indoc! {"
        rules:
          - allow: 'echo *'
    "},
    assert_allow as ActionAssertion,
)]
fn defaults_action_absent_compound_unmatched_asks(
    #[case] command: &str,
    #[case] config_yaml: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// for loop: sub-commands are extracted and evaluated
// ========================================

#[rstest]
#[case::for_loop_all_allowed(
    "for f in a b c; do echo $f; done",
    assert_allow as ActionAssertion,
)]
#[case::for_loop_with_deny(
    "for f in a b c; do rm -rf $f; done",
    assert_deny as ActionAssertion,
)]
#[case::for_loop_mixed(
    "for f in a b; do echo $f && rm -rf /; done",
    assert_deny as ActionAssertion,
)]
fn for_loop_subcommand_extraction(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Shell constructs: subshell, command substitution, backticks
// ========================================

#[rstest]
#[case::subshell_with_deny(
    "(echo hello && rm -rf /) | ls",
    assert_deny as ActionAssertion,
)]
#[case::subshell_all_allowed(
    "(echo hello && echo world) | grep hello",
    assert_allow as ActionAssertion,
)]
fn shell_construct_subcommand_extraction(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'grep *'
          - allow: 'ls *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Command substitution and backtick extraction
// ========================================

#[rstest]
#[case::command_substitution_deny(
    "echo $(rm -rf /tmp/data)",
    assert_deny as ActionAssertion,
)]
#[case::command_substitution_allowed(
    "echo $(echo inner)",
    assert_allow as ActionAssertion,
)]
#[case::backtick_substitution_deny(
    "echo `rm -rf /tmp/data`",
    assert_deny as ActionAssertion,
)]
fn command_substitution_extraction(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Control structures: if/while/case
// ========================================

#[rstest]
#[case::if_then_with_deny(
    "if true; then rm -rf /; fi",
    assert_deny as ActionAssertion,
)]
#[case::if_else_deny_in_else(
    "if true; then echo hello; else rm -rf /; fi",
    assert_deny as ActionAssertion,
)]
#[case::if_all_allowed(
    "if true; then echo hello; else echo world; fi",
    assert_allow as ActionAssertion,
)]
#[case::while_loop_with_deny(
    "while true; do rm -rf /; done",
    assert_deny as ActionAssertion,
)]
#[case::case_statement_with_deny(
    "case x in a) echo hello;; b) rm -rf /;; esac",
    assert_deny as ActionAssertion,
)]
fn control_structure_subcommand_extraction(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'true'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Function definition: body commands are extracted
// ========================================

#[rstest]
#[case::function_def_with_deny(
    "f() { rm -rf /; }",
    assert_deny as ActionAssertion,
)]
#[case::function_def_all_allowed(
    "f() { echo hello; }",
    assert_allow as ActionAssertion,
)]
fn function_definition_subcommand_extraction(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Empty rules list
// ========================================

#[rstest]
fn empty_rules_compound_returns_default(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules: []
    "})
    .unwrap();

    let result = evaluate_compound(&config, "echo hello && ls", &empty_context).unwrap();
    assert_eq!(result.action, Action::Ask(None));
}

// ========================================
// Sandbox: deny-only presets merge without contradiction
// ========================================

#[rstest]
fn deny_only_sandbox_presets_no_contradiction(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'cmd_a *'
            sandbox: preset_a
          - allow: 'cmd_b *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              fs:
                deny: [/etc/passwd]
            preset_b:
              fs:
                deny: [/etc/shadow]
    "})
    .unwrap();

    let result = evaluate_compound(&config, "cmd_a run && cmd_b run", &empty_context).unwrap();
    // No writable defined -> no contradiction -> stays Allow
    assert_eq!(result.action, Action::Allow);
    let policy = result.sandbox_policy.unwrap();
    assert!(policy.writable.is_empty());
    let mut deny_sorted = policy.deny.clone();
    deny_sorted.sort();
    assert_eq!(
        deny_sorted,
        vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()]
    );
}

// ========================================
// Single sandbox preset via evaluate_compound
// ========================================

#[rstest]
fn single_sandbox_preset_via_compound(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'python3 *'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
                deny: [/etc/passwd]
              network:
                allow: false
    "})
    .unwrap();

    let result = evaluate_compound(&config, "python3 script.py", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
    let policy = result.sandbox_policy.unwrap();
    assert_eq!(policy.writable, vec!["./tmp".to_string()]);
    assert_eq!(policy.deny, vec!["/etc/passwd".to_string()]);
    assert!(!policy.network_allowed);
}

// ========================================
// evaluate_command: compound command guard
// ========================================
// evaluate_command splits compound commands internally so that
// wildcard patterns do not greedily match across shell operators.

#[rstest]
#[case::cd_wildcard_does_not_match_entire_compound(
    "cd /path/to/dir && rm -rf dist .astro && pnpm build 2>&1",
    indoc! {"
        rules:
          - allow: 'cd *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::cd_and_rm_deny_wins(
    "cd /path && rm -rf dist",
    indoc! {"
        rules:
          - allow: 'cd *'
          - deny: 'rm *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::all_sub_commands_allowed(
    "cd /path && pnpm build",
    indoc! {"
        rules:
          - allow: 'cd *'
          - allow: 'pnpm *'
    "},
    assert_allow as ActionAssertion,
)]
#[case::unmatched_sub_command_escalates_to_ask(
    "cd /path && unknown-cmd",
    indoc! {"
        rules:
          - allow: 'cd *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::unmatched_with_defaults_action_deny(
    "cd /path && unknown-cmd",
    indoc! {"
        defaults:
          action: deny
        rules:
          - allow: 'cd *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::pipe_separated(
    "echo hello | grep world",
    indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'grep *'
    "},
    assert_allow as ActionAssertion,
)]
#[case::or_separated_deny(
    "false || rm -rf /",
    indoc! {"
        rules:
          - allow: 'false'
          - deny: 'rm *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::semicolon_separated_deny(
    "cd /path ; rm -rf /",
    indoc! {"
        rules:
          - allow: 'cd *'
          - deny: 'rm *'
    "},
    assert_deny as ActionAssertion,
)]
fn evaluate_command_splits_compound_before_matching(
    #[case] command: &str,
    #[case] config_yaml: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Command substitution with redirects and pipes (stack overflow regression)
// ========================================
// These tests verify that commands containing command substitution ($())
// combined with redirects (2>&1) and pipes do not cause infinite recursion.
// The bug was that extract_commands returns the parent command with slightly
// different whitespace (due to redirect stripping), causing the self-reference
// filter to miss it and re-enter evaluate_command_inner indefinitely.

#[rstest]
#[case::cmd_sub_with_redirect_and_pipe(
    "aws s3 ls --start-time $(date -d '1 hour ago') 2>&1 | jq '.data'",
    indoc! {"
        rules:
          - allow: 'aws *'
          - allow: 'date *'
          - allow: 'jq *'
    "},
    assert_allow as ActionAssertion,
)]
#[case::cmd_sub_with_redirect_deny_inner(
    "echo $(rm -rf /tmp) 2>&1 | grep result",
    indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'grep *'
          - deny: 'rm -rf *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::cmd_sub_simple_with_redirect(
    "echo $(date +%s) 2>&1",
    indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'date *'
    "},
    assert_allow as ActionAssertion,
)]
#[case::nested_cmd_sub_with_pipe(
    "curl -H \"Authorization: $(cat token)\" https://api.example.com 2>&1 | jq .",
    indoc! {"
        rules:
          - allow: 'curl *'
          - allow: 'cat *'
          - allow: 'jq *'
    "},
    assert_allow as ActionAssertion,
)]
fn command_substitution_with_redirects_no_stack_overflow(
    #[case] command: &str,
    #[case] config_yaml: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Command substitution in quoted strings and other constructs
// ========================================

#[rstest]
#[case::cmd_sub_in_double_quotes_deny(
    r#"curl -u "user:$(rm -rf /tmp/data)" https://example.com"#,
    indoc! {"
        rules:
          - allow: 'curl *'
          - deny: 'rm -rf *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::cmd_sub_in_double_quotes_all_allowed(
    r#"curl -u "user:$(cat token)" https://example.com"#,
    indoc! {"
        rules:
          - allow: 'curl *'
          - allow: 'cat *'
    "},
    assert_allow as ActionAssertion,
)]
#[case::cmd_sub_in_double_quotes_inner_unmatched_is_ask(
    r#"curl -u "user:$(printenv SECRET)" https://example.com"#,
    indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'curl *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::nested_wrapper_in_cmd_sub_in_quotes(
    r#"curl -u "user:$(mise x -- printenv SECRET)" https://example.com"#,
    indoc! {"
        defaults:
          action: ask
        definitions:
          wrappers:
            - 'mise x|exec -- <cmd>'
        rules:
          - allow: 'curl *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::single_quotes_no_substitution(
    "echo '$(rm -rf /)'",
    indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "},
    assert_allow as ActionAssertion,
)]
#[case::backtick_in_double_quotes_deny(
    r#"curl -u "user:`rm -rf /`" https://example.com"#,
    indoc! {"
        rules:
          - allow: 'curl *'
          - deny: 'rm -rf *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::docker_env_with_secret_cmd_sub(
    r#"docker run -e TOKEN="$(cat /tmp/secret)" nginx"#,
    indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'docker *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::git_commit_with_date_cmd_sub(
    r#"git commit -m "$(date +%Y-%m-%d): release""#,
    indoc! {"
        rules:
          - allow: 'git *'
          - allow: 'date *'
    "},
    assert_allow as ActionAssertion,
)]
fn command_substitution_in_strings(
    #[case] command: &str,
    #[case] config_yaml: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Security: command substitution must not bypass rule controls
// ========================================
// Regression test for the bug where a command substitution containing an
// allowed command (e.g. `echo test`) caused the *entire* compound to be
// evaluated as Allow, even when the outer command had no matching rule.

#[rstest]
#[case::gh_pr_edit_with_allowed_cmd_sub(
    r#"gh pr edit 10 --body "$(echo test)""#,
    indoc! {"
        rules:
          - allow: 'echo *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::unmatched_outer_with_allowed_inner_chain(
    "echo test && gh pr edit 10",
    indoc! {"
        rules:
          - allow: 'echo *'
    "},
    assert_ask as ActionAssertion,
)]
#[case::unmatched_outer_with_allowed_inner_defaults_deny(
    r#"gh pr edit 10 --body "$(echo test)""#,
    indoc! {"
        defaults:
          action: deny
        rules:
          - allow: 'echo *'
    "},
    assert_deny as ActionAssertion,
)]
#[case::all_matched_cmd_sub_is_still_allowed(
    r#"gh pr edit 10 --body "$(echo test)""#,
    indoc! {"
        rules:
          - allow: 'echo *'
          - allow: 'gh *'
    "},
    assert_allow as ActionAssertion,
)]
fn command_substitution_must_not_bypass_rules(
    #[case] command: &str,
    #[case] config_yaml: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Flag-only negation with empty tokens in compound commands
// ========================================

#[rstest]
#[case::sort_no_args_in_pipeline(
    "jq .type file | sort | uniq -c",
    assert_allow as ActionAssertion,
)]
#[case::sort_with_banned_flag_in_pipeline(
    "jq .type file | sort -o result.txt | uniq -c",
    assert_ask as ActionAssertion,
)]
fn flag_negation_empty_tokens_in_compound(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'jq *'
          - allow: 'sort !-o|--output|--compress-program *'
          - allow: 'uniq *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}
