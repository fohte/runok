use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command, evaluate_compound};

// ========================================
// Motivating case: a flag value smuggled through a variable no longer
// evades a `deny` rule written against the flag's literal text.
// ========================================

#[rstest]
fn flag_value_via_variable_is_still_denied(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push --force*'
          - allow: 'git push *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, "F=--force; git push $F", &empty_context).unwrap();
    assert_deny(&result.action);
}

// ========================================
// A reassignment inside a subshell or command substitution must not
// leak out: it runs in a forked child shell, so the flag smuggled
// through the variable cannot be masked by wrapping a harmless-looking
// reassignment in `(...)` / `$(...)`.
// ========================================

#[rstest]
#[case::subshell_reassignment("F=--force; (F=--safe); git push $F")]
#[case::command_substitution_reassignment("F=--force; X=$(F=--safe); git push $F")]
fn reassignment_inside_forked_scope_does_not_mask_the_outer_value(
    #[case] command: &str,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push --force*'
          - allow: 'git push *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    assert_deny(&result.action);
}

// ========================================
// A reassignment on the right of `&&` / `||` may or may not run
// depending on the left side's exit status, so it must not be trusted
// as an unconditional value: it falls back to the pre-existing
// verbatim-token behavior, exactly like an `if`/`while` body would.
// ========================================

#[rstest]
#[case::and_guarded_reassignment("F=--force; false && F=--safe; git push $F")]
#[case::or_guarded_reassignment("F=--force; true || F=--safe; git push $F")]
fn conditional_list_reassignment_falls_back_to_defaults_action(
    #[case] command: &str,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push --force*'
          - allow: 'git push *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    // `$F` stays unresolved (`git push $F` matches neither rule
    // pattern), so the branch falls through to `defaults.action`
    // (unset here -> the safe `Ask` default) -- never to the `allow`
    // rule, which would mean the reassignment was wrongly trusted.
    assert_ask(&result.action);
}

// ========================================
// Motivating case: a fully static command hidden behind a variable is
// evaluated by its resolved value instead of falling through to the
// unknown-command default.
// ========================================

#[rstest]
#[case::quoted_value_becomes_the_command(
    r#"X="git status"; $X"#,
    assert_allow as ActionAssertion,
)]
#[case::command_name_position_resolves(
    "X=rm; $X -rf /",
    assert_deny as ActionAssertion,
)]
fn static_variable_resolves_to_its_value(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'git status'
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// A double-quoted whole-value expansion is a single argument (no IFS
// splitting), so it becomes an unknown one-word command name, exactly as
// real bash would resolve it -- not a match for `allow: 'git status'`.
// ========================================

#[rstest]
fn quoted_whole_value_is_not_the_two_word_command(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        defaults:
          action: ask
        rules:
          - allow: 'git status'
    "})
    .unwrap();

    let result = evaluate_compound(&config, r#"X="git status"; "$X""#, &empty_context).unwrap();
    assert_ask(&result.action);
}

// ========================================
// Anything not statically resolvable leaves `$X` as a literal,
// unresolved token, so it resolves through `defaults.action` like any
// other unknown command.
// ========================================

#[rstest]
#[case::dynamic_value_from_command_substitution(
    "X=$(cat f); $X",
    indoc! {"
        rules:
          - allow: 'cat *'
    "},
)]
#[case::reassigned_via_command_substitution(
    "X=1; X=$(date); echo $X",
    indoc! {"
        rules:
          - allow: 'date *'
    "},
)]
#[case::operator_expansion_not_resolved(
    "X=default; echo ${X:-fallback}",
    indoc! {"
        rules: []
    "},
)]
#[case::conditional_assignment_stays_unresolved(
    "if true; then X=rm; fi; $X /",
    indoc! {"
        rules:
          - allow: 'true'
          - deny: 'rm -rf *'
    "},
)]
#[case::loop_body_assignment_stays_unresolved(
    "for i in 1 2; do X=rm; done; $X /",
    indoc! {"
        rules:
          - allow: 'echo *'
          - deny: 'rm -rf *'
    "},
)]
#[case::array_subscript_assignment_poisons_base(
    "X=1; X[0]=2; echo $X",
    indoc! {"
        rules:
          - deny: 'echo 1'
    "},
)]
#[case::export_bare_name_poisons(
    "X=1; export X; echo $X",
    indoc! {"
        rules:
          - deny: 'echo 1'
    "},
)]
#[case::unset_poisons(
    "X=1; unset X; echo $X",
    indoc! {"
        rules:
          - deny: 'echo 1'
    "},
)]
fn unresolvable_assignment_falls_back_to_defaults_action(
    #[case] command: &str,
    #[case] config_yaml: &str,
    empty_context: EvalContext,
) {
    let config = parse_config(config_yaml).unwrap();
    let result = evaluate_compound(&config, command, &empty_context).unwrap();
    // `defaults.action` is unset in every case above, so an unresolved
    // `$X` (never matching a rule) always resolves to the safe default
    // (`Ask`), and never to a `deny` rule that would only match if `$X`
    // had incorrectly been resolved to a stale/guessed literal value.
    assert_ask(&result.action);
}

// ========================================
// A function body is not evaluated at definition time: an assignment
// inside it must not leak into the enclosing scope, and a variable
// reference inside it is never expanded using the definition-time
// environment (that requires call-time argument binding, which is out of
// scope for static resolution).
// ========================================

#[rstest]
fn function_body_assignment_does_not_leak_to_caller(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'echo 1'
    "})
    .unwrap();

    let result = evaluate_compound(&config, "f() { local X=1; }; echo $X", &empty_context).unwrap();
    assert_ask(&result.action);
}

// ========================================
// evaluate_command (single-command entrypoint) resolves variables the
// same way as evaluate_compound.
// ========================================

#[rstest]
fn evaluate_command_also_resolves_variables(empty_context: EvalContext) {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'git push --force*'
          - allow: 'git push *'
    "})
    .unwrap();

    let result = evaluate_command(&config, "F=--force; git push $F", &empty_context).unwrap();
    assert_deny(&result.action);
}
