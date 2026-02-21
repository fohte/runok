use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::{MergedSandboxPolicy, parse_config};
use runok::exec::command_executor::CommandInput;
use runok::rules::rule_engine::{Action, EvalContext, evaluate_compound};

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
