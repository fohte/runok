use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use indoc::indoc;
use rstest::{fixture, rstest};
use runok::config::parse_config;
use runok::rules::rule_engine::{
    Action, CommandResolution, CommandResolver, DenyResponse, EvalContext, evaluate_command,
    evaluate_compound,
};

use super::{assert_allow, assert_ask, assert_deny};

/// Resolver that treats a fixed set of names as installed and everything
/// else as missing, so tests stay deterministic regardless of the host's
/// `$PATH`.
struct FoundOnlyResolver {
    found: HashSet<&'static str>,
}

impl CommandResolver for FoundOnlyResolver {
    fn resolve(&self, name: &str) -> CommandResolution {
        if self.found.contains(name) {
            CommandResolution::Found
        } else {
            CommandResolution::NotFound
        }
    }
}

#[fixture]
fn known_commands_context() -> EvalContext {
    EvalContext {
        env: HashMap::new(),
        cwd: PathBuf::from("/tmp"),
        resolver: Arc::new(FoundOnlyResolver {
            found: HashSet::from(["sudo", "terraform", "true", "echo"]),
        }),
    }
}

// ========================================
// Enabled: resolver outcome drives the action
// ========================================

#[rstest]
fn denies_unknown_command_when_enabled(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
    "})
    .unwrap();

    let result = evaluate_command(&config, "tarraform version", &known_commands_context).unwrap();
    assert_eq!(
        result.action,
        Action::Deny(DenyResponse {
            message: Some(
                "command 'tarraform' not found in PATH (experimental.require_command_in_path)"
                    .to_string()
            ),
            fix_suggestion: Some(
                "if 'tarraform' is a shell function or alias defined in your shell profile, \
                 add it to experimental.require_command_in_path.ignore, or add an allow rule \
                 for it instead. Otherwise, check for a typo."
                    .to_string()
            ),
            matched_rule: String::new(),
        })
    );
}

#[rstest]
fn asks_instead_of_denies_when_action_is_ask(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: ask
    "})
    .unwrap();

    let result = evaluate_command(&config, "tarraform version", &known_commands_context).unwrap();
    assert_ask(&result.action);
}

#[rstest]
fn known_command_is_not_flagged(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
    "})
    .unwrap();

    let result = evaluate_command(&config, "terraform version", &known_commands_context).unwrap();
    assert_ask(&result.action);
}

#[rstest]
fn disabled_check_falls_back_to_default_action(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: false
            action: deny
    "})
    .unwrap();

    let result = evaluate_command(&config, "tarraform version", &known_commands_context).unwrap();
    assert_ask(&result.action);
}

#[rstest]
fn not_configured_falls_back_to_default_action(known_commands_context: EvalContext) {
    let config = parse_config("{}").unwrap();

    let result = evaluate_command(&config, "tarraform version", &known_commands_context).unwrap();
    assert_ask(&result.action);
}

// ========================================
// Explicit rules and defaults.action interaction
// ========================================

#[rstest]
fn explicit_allow_rule_wins_over_the_check(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
        rules:
          - allow: 'tarraform *'
    "})
    .unwrap();

    let result = evaluate_command(&config, "tarraform version", &known_commands_context).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn check_still_denies_even_when_defaults_action_is_allow(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        defaults:
          action: allow
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
    "})
    .unwrap();

    let result = evaluate_command(&config, "tarraform version", &known_commands_context).unwrap();
    assert_deny(&result.action);
}

// ========================================
// Skip conditions (false-deny avoidance)
// ========================================

#[rstest]
fn ignored_command_is_not_flagged(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
            ignore:
              - tarraform
    "})
    .unwrap();

    let result = evaluate_command(&config, "tarraform version", &known_commands_context).unwrap();
    assert_ask(&result.action);
}

#[rstest]
#[case::relative_path("./tarraform version")]
#[case::absolute_path("/usr/local/bin/tarraform version")]
fn argv0_with_slash_is_not_flagged(#[case] command: &str, known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &known_commands_context).unwrap();
    assert_ask(&result.action);
}

#[rstest]
fn function_defined_in_same_command_string_is_not_flagged(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
    "})
    .unwrap();

    let result = evaluate_command(&config, "f() { true; }; f", &known_commands_context).unwrap();
    assert_ask(&result.action);
}

#[rstest]
fn source_anywhere_in_input_disables_the_check_for_the_whole_compound(
    known_commands_context: EvalContext,
) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
    "})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "source ~/.bashrc; tarraform version",
        &known_commands_context,
    )
    .unwrap();
    assert_ask(&result.action);
}

// ========================================
// Wrapper-unwrapped commands
// ========================================

#[rstest]
fn wrapper_inner_typo_is_flagged(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
        rules: []
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let result =
        evaluate_command(&config, "sudo tarraform version", &known_commands_context).unwrap();
    assert_eq!(
        result.action,
        Action::Deny(DenyResponse {
            message: Some(
                "command 'tarraform' not found in PATH (experimental.require_command_in_path)"
                    .to_string()
            ),
            fix_suggestion: Some(
                "if 'tarraform' is a shell function or alias defined in your shell profile, \
                 add it to experimental.require_command_in_path.ignore, or add an allow rule \
                 for it instead. Otherwise, check for a typo."
                    .to_string()
            ),
            matched_rule: String::new(),
        })
    );
}

/// `sudo $TERRAFORM version`: the wrapper's multi-token capture re-quotes
/// the still-unresolved `$TERRAFORM` with single quotes
/// (`shell_quote_join`), so re-parsing the inner command sees a
/// `raw_string` rather than an expansion node. This is the textual
/// fallback (dequoted argv[0] starting with `$`) that catches it anyway.
#[rstest]
fn wrapper_inner_unresolved_variable_is_not_flagged(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
        rules: []
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let result =
        evaluate_command(&config, "sudo $TERRAFORM version", &known_commands_context).unwrap();
    assert_ask(&result.action);
}

/// Same as above, but for backtick command substitution instead of a bare
/// variable -- also re-quoted into a `raw_string` by the wrapper, and also
/// caught by the textual fallback (dequoted argv[0] containing a backtick).
/// `echo` must be a known command here: independently of the wrapper, the
/// backtick's contents are extracted and evaluated as their own nested
/// sub-command (the same mechanism that catches `echo $(rm -rf /)`), so a
/// resolver that didn't know `echo` would deny it through that unrelated
/// path and mask what this test is actually checking.
#[rstest]
fn wrapper_inner_backtick_substitution_is_not_flagged(known_commands_context: EvalContext) {
    let config = parse_config(indoc! {"
        experimental:
          require_command_in_path:
            enabled: true
            action: deny
        rules: []
        definitions:
          wrappers:
            - 'sudo <cmd>'
    "})
    .unwrap();

    let result = evaluate_command(
        &config,
        "sudo `echo terraform` version",
        &known_commands_context,
    )
    .unwrap();
    assert_ask(&result.action);
}
