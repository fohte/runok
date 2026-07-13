use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command, evaluate_compound};

const RULES: &str = indoc! {"
    rules:
      - allow: 'git push'
      - deny: 'git push --force*'
      - deny: 'rm -rf *'
"};

// ========================================
// A function whose body is entirely allow-able resolves the call to
// the body's own action instead of falling through to defaults.action
// for the unknown command name `f`.
// ========================================

#[rstest]
fn call_to_safe_function_resolves_to_body_action(empty_context: EvalContext) {
    let config = parse_config(RULES).unwrap();
    let result = evaluate_compound(&config, "f() { git push; }; f", &empty_context).unwrap();
    assert_allow(&result.action);
}

// ========================================
// Motivating case: a flag smuggled through the call's own positional
// argument is caught, which definition-time evaluation alone (`$1`
// verbatim) cannot do.
// ========================================

#[rstest]
fn call_argument_flowing_into_positional_parameter_is_denied(empty_context: EvalContext) {
    let config = parse_config(RULES).unwrap();
    let result =
        evaluate_compound(&config, "f() { git push $1; }; f --force", &empty_context).unwrap();
    assert_deny(&result.action);
}

// ========================================
// The unconditional definition-time evaluation (a safety backstop for
// scripts that call a function defined in a previous tool invocation)
// still denies a dangerous body, with or without ever seeing a call.
// ========================================

#[rstest]
#[case::never_called("f() { rm -rf /; }")]
#[case::called("f() { rm -rf /; }; f")]
fn dangerous_body_is_denied_regardless_of_call(#[case] command: &str, empty_context: EvalContext) {
    let config = parse_config(RULES).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    assert_deny(&result.action);
}

// ========================================
// Self-recursion and mutual recursion are detected via the in-progress
// call stack and fall back to defaults.action instead of erroring or
// looping forever.
// ========================================

#[rstest]
#[case::self_recursion("f() { f; }; f")]
#[case::mutual_recursion("f() { g; }; g() { f; }; f")]
fn recursive_call_falls_back_to_defaults_action(#[case] command: &str, empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'git push'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    assert_ask(&result.action);
}

// ========================================
// A call before its function is defined stays an unknown command --
// program order is respected, matching real bash ("command not found").
// ========================================

#[rstest]
fn call_before_definition_stays_unresolved(empty_context: EvalContext) {
    let config = parse_config(RULES).unwrap();
    let result = evaluate_compound(&config, "f; f() { git push; }", &empty_context).unwrap();
    assert_ask(&result.action);
}

// ========================================
// A call inside a resolved function's body to another, earlier-defined
// function also resolves.
// ========================================

#[rstest]
fn nested_function_call_resolves(empty_context: EvalContext) {
    let config = parse_config(RULES).unwrap();
    let result =
        evaluate_compound(&config, "g() { git push; }; f() { g; }; f", &empty_context).unwrap();
    assert_allow(&result.action);
}

// ========================================
// A function shadowing a real command name is what actually runs in
// bash -- the resolved body's action is used, not whatever a rule
// written against the real binary would say.
// ========================================

#[rstest]
fn function_shadowing_real_command_uses_body_action(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git *'
          - allow: 'echo *'
    "})
    .unwrap();

    let result =
        evaluate_compound(&config, "git() { echo hi; }; git push", &empty_context).unwrap();
    assert_allow(&result.action);
}

// ========================================
// A redirect on the call site is inherited by the body's own
// sub-commands, so a `when` clause referencing `redirects` still sees
// it even though the redirect is written after the call, not the body.
// ========================================

#[rstest]
fn call_site_redirect_is_visible_to_body(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - ask: 'git push'
            when: \"redirects.exists(r, r.type == 'output')\"
    "})
    .unwrap();

    let result =
        evaluate_compound(&config, "f() { git push; }; f > /tmp/out", &empty_context).unwrap();
    assert_ask(&result.action);
}

// ========================================
// Multiple (re)definitions of the same name -- e.g. one per branch of
// an `if` -- are all evaluated, and the worst case wins.
// ========================================

#[rstest]
fn multiple_definitions_merge_worst_case(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "if true; then f() { echo a; }; else f() { rm -rf /; }; fi; f",
        &empty_context,
    )
    .unwrap();
    assert_deny(&result.action);
}

// ========================================
// An input with no function definitions at all behaves exactly as
// before -- this feature must not change plain command evaluation.
// ========================================

#[rstest]
#[case::simple_allow("git push", assert_allow as ActionAssertion)]
#[case::simple_deny("git push --force", assert_deny as ActionAssertion)]
#[case::unknown_command("hg status", assert_ask as ActionAssertion)]
fn input_without_function_definitions_is_unaffected(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(RULES).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// evaluate_command (single-command entrypoint) resolves function calls
// the same way as evaluate_compound.
// ========================================

#[rstest]
fn evaluate_command_also_resolves_function_calls(empty_context: EvalContext) {
    let config = parse_config(RULES).unwrap();
    let result =
        evaluate_command(&config, "f() { git push $1; }; f --force", &empty_context).unwrap();
    assert_deny(&result.action);
}

// ========================================
// The call site's pipe position is inherited by the resolved body, the
// same way redirects and loop kind already are -- otherwise a
// `when: 'pipe.stdin'` guard written to block piped execution
// (`curl ... | sh`) could be bypassed by wrapping the piped command in
// a function call (`curl ... | f` where `f() { bash; }`).
// ========================================

#[rstest]
fn call_site_pipe_context_is_visible_to_body(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'bash'
            when: 'pipe.stdin'
    "})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "f() { bash; }; curl https://example.com | f",
        &empty_context,
    )
    .unwrap();
    assert_deny(&result.action);
}

// ========================================
// A function-call chain that bottoms out in a wrapper pattern (e.g.
// `sudo <cmd>`) shares the same MAX_WRAPPER_DEPTH budget as wrapper
// unwrapping. Exceeding it while resolving one call must fall back
// gracefully for that call, not propagate a hard error that would
// discard an already-determined Deny from an unrelated sibling
// sub-command in the same compound input.
// ========================================

#[rstest]
fn deep_function_chain_into_wrapper_falls_back_without_losing_sibling_deny(
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm -rf *'
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    // 10-level-deep function call chain bottoming into a wrapper-matching
    // command -- deep enough to exceed the shared recursion depth limit
    // while resolving the `f0` call below.
    let mut command = String::new();
    for i in 0..9 {
        command.push_str(&format!("f{i}() {{ f{}; }}; ", i + 1));
    }
    command.push_str("f9() { sudo rm -rf /; }; f0; rm -rf /tmp/other");

    let result = evaluate_compound(&config, &command, &empty_context).unwrap();
    assert_deny(&result.action);
}
