use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
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
// Realistic compound: curl | jq && rm
// ========================================

#[rstest]
fn curl_pipe_jq_and_rm_evaluates_each_command(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'curl *'
          - allow: 'jq *'
          - deny: 'rm *'
    "})
    .unwrap();

    // rm tmp.json triggers deny, so the entire compound is denied
    let result = evaluate_compound(
        &config,
        "curl url | jq '.data' && rm tmp.json",
        &empty_context,
    )
    .unwrap();
    assert!(matches!(result.action, Action::Deny(_)));
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
fn sandbox_strictest_wins_writable_roots_intersection(empty_context: EvalContext) {
    // preset_a: writable [./src, ./tmp]
    // preset_b: writable [./tmp, ./build]
    // intersection: [./tmp]
    let config = parse_config(indoc! {"
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
    "})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "cargo build --release | cargo test --all",
        &empty_context,
    )
    .unwrap();

    assert_eq!(result.action, Action::Allow);
    let policy = result.sandbox_policy.unwrap();
    assert_eq!(policy.writable, vec!["./tmp"]);
}

#[rstest]
fn sandbox_strictest_wins_deny_paths_union(empty_context: EvalContext) {
    // preset_a: deny [/etc/passwd]
    // preset_b: deny [/etc/shadow]
    // union: [/etc/passwd, /etc/shadow]
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

    assert_eq!(result.action, Action::Allow);
    let policy = result.sandbox_policy.unwrap();
    assert_eq!(policy.deny, vec!["/etc/passwd", "/etc/shadow"]);
}

#[rstest]
fn sandbox_strictest_wins_network_intersection(empty_context: EvalContext) {
    // preset_a: network allow [api.example.com, cdn.example.com]
    // preset_b: network allow [api.example.com, logs.example.com]
    // intersection: [api.example.com]
    let config = parse_config(indoc! {"
        rules:
          - allow: 'cmd_a *'
            sandbox: preset_a
          - allow: 'cmd_b *'
            sandbox: preset_b
        definitions:
          sandbox:
            preset_a:
              network:
                allow: [api.example.com, cdn.example.com]
            preset_b:
              network:
                allow: [api.example.com, logs.example.com]
    "})
    .unwrap();

    let result = evaluate_compound(&config, "cmd_a run && cmd_b run", &empty_context).unwrap();

    assert_eq!(result.action, Action::Allow);
    let policy = result.sandbox_policy.unwrap();
    assert_eq!(
        policy.network_allow,
        Some(vec!["api.example.com".to_string()])
    );
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
