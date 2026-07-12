use super::{ActionAssertion, assert_allow, assert_ask, empty_context};

use indoc::indoc;
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command};

// ========================================
// `?` on a FlagWithValue: flag required, value optional
// ========================================

const ABBREV_CONFIG: &str = indoc! {r#"
    rules:
      - allow: 'git branch --abbrev ?'
"#};

#[rstest]
// The value may be omitted entirely.
#[case::bare("git branch --abbrev", assert_allow as ActionAssertion)]
// Or attached via `=`.
#[case::equals_joined("git branch --abbrev=8", assert_allow as ActionAssertion)]
// The flag itself is still required.
#[case::flag_missing("git branch", assert_ask as ActionAssertion)]
// A space-separated following token is a separate positional argument, not
// the flag's value (mirrors real git: `git branch --abbrev 8` creates a
// branch named `8` rather than setting `--abbrev`'s value to `8`), so it is
// left over and the pattern (with no trailing wildcard) does not match.
#[case::space_separated_leaves_extra_token(
    "git branch --abbrev 8",
    assert_ask as ActionAssertion
)]
fn optional_flag_value_on_required_flag(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(ABBREV_CONFIG).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// `?` combined with `[...]`: flag and value both optional
// ========================================

const OPTIONAL_ABBREV_CONFIG: &str = indoc! {r#"
    rules:
      - allow: 'git branch [--abbrev ?] *'
"#};

#[rstest]
#[case::flag_absent("git branch", assert_allow as ActionAssertion)]
#[case::flag_bare("git branch --abbrev", assert_allow as ActionAssertion)]
#[case::flag_equals("git branch --abbrev=8", assert_allow as ActionAssertion)]
// With a trailing wildcard, the un-consumed space-separated token is simply
// matched as a positional argument instead.
#[case::flag_space_separated("git branch --abbrev 8", assert_allow as ActionAssertion)]
fn optional_flag_and_value_inside_optional_group(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(OPTIONAL_ABBREV_CONFIG).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// `?` on a short flag: fused and `=`-joined forms
// ========================================

const TAG_N_CONFIG: &str = indoc! {r#"
    rules:
      - allow: 'git tag -n ?'
"#};

#[rstest]
#[case::bare("git tag -n", assert_allow as ActionAssertion)]
#[case::fused("git tag -n3", assert_allow as ActionAssertion)]
#[case::equals("git tag -n=3", assert_allow as ActionAssertion)]
fn optional_flag_value_on_short_flag(
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config = parse_config(TAG_N_CONFIG).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// `?` inside a `<flag:name>` group definition
// ========================================

#[rstest]
fn optional_flag_value_in_flag_group_captures_equals_joined_value(empty_context: EvalContext) {
    let yaml = indoc! {r#"
        definitions:
          flag_groups:
            abbrev: "--abbrev ?"
        rules:
          - allow: 'git branch <flag:abbrev> *'
            when: 'flag_groups["abbrev"].exists(v, v == "8")'
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, "git branch --abbrev=8", &empty_context).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn optional_flag_value_in_flag_group_bare_occurrence_captures_empty_string(
    empty_context: EvalContext,
) {
    let yaml = indoc! {r#"
        definitions:
          flag_groups:
            abbrev: "--abbrev ?"
        rules:
          - allow: 'git branch <flag:abbrev> *'
            when: 'flag_groups["abbrev"].exists(v, v == "")'
    "#};
    let config = parse_config(yaml).unwrap();
    let result = evaluate_command(&config, "git branch --abbrev", &empty_context).unwrap();
    assert_allow(&result.action);
}
