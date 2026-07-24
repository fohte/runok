use crate::config::{ActionKind, Config, RequireCommandInPathConfig};
use crate::rules::command_parser::{
    FlagSchema, FunctionCallInfo, extract_commands_with_metadata, parse_command,
};

use super::compound::default_action;
use super::{Action, CommandResolution, DenyResponse, EvalContext};

/// Commands whose static analysis is incomplete: a script they load, or a
/// string they evaluate, can define shell functions this check cannot see.
const SOURCE_LIKE_COMMANDS: &[&str] = &["source", ".", "eval"];

/// Resolve the action for a command that matched no rule and unwrapped no
/// wrapper. Applies `experimental.require_command_in_path` when it's
/// enabled and none of the false-deny-avoidance skip conditions apply;
/// falls back to `default_action` in every other case (disabled, a skip
/// condition, or the resolver finding the command or being unable to
/// tell).
///
/// The second tuple element is the unresolved command name, present only
/// when this check itself decided the returned action (deny or ask)
/// rather than deferring to `default_action` -- callers thread it into
/// `EvalResult::require_command_in_path` for audit logging.
pub(super) fn resolve_unmatched(
    config: &Config,
    command: &str,
    context: &EvalContext,
    function_call: Option<&FunctionCallInfo>,
    source_like_present: bool,
) -> (Action, Option<String>) {
    let Some(check) = config
        .experimental
        .as_ref()
        .and_then(|e| e.require_command_in_path.as_ref())
        .filter(|c| c.is_enabled())
    else {
        return (default_action(config), None);
    };

    // A call resolved earlier in the same command string is a defined
    // function by construction. A `source`/`.`/`eval` anywhere in the
    // input may define or invoke functions no static check can see.
    if function_call.is_some() || source_like_present {
        return (default_action(config), None);
    }

    let Ok(parsed) = parse_command(command, &FlagSchema::default()) else {
        return (default_action(config), None);
    };

    // A wrapper's multi-token capture is re-quoted with single quotes
    // (`shell_quote_join`), so a still-unresolved variable reference or
    // backtick command substitution re-parses as a `raw_string`, not an
    // expansion node -- catch it from the dequoted text too instead of
    // relying on `command_is_expansion` alone.
    let looks_like_unresolved_expansion = parsed.command.starts_with('$')
        || parsed.command.contains("$(")
        || parsed.command.contains('`');

    if parsed.command_is_expansion
        || looks_like_unresolved_expansion
        || parsed.command.contains('/')
        || check.resolved_ignore().contains(&parsed.command)
    {
        return (default_action(config), None);
    }

    match context.resolver.resolve(&parsed.command) {
        CommandResolution::Found | CommandResolution::Unknown => (default_action(config), None),
        CommandResolution::NotFound => deny_or_ask(config, check, &parsed.command),
    }
}

fn deny_or_ask(
    config: &Config,
    check: &RequireCommandInPathConfig,
    command_name: &str,
) -> (Action, Option<String>) {
    let message = format!(
        "command '{command_name}' not found in PATH (experimental.require_command_in_path)"
    );
    match check.resolved_action() {
        ActionKind::Deny => (
            Action::Deny(DenyResponse {
                message: Some(message),
                fix_suggestion: Some(format!(
                    "if '{command_name}' is a shell function or alias defined in your shell \
                     profile, add it to experimental.require_command_in_path.ignore, or add an \
                     allow rule for it instead. Otherwise, check for a typo."
                )),
                matched_rule: String::new(),
            }),
            Some(command_name.to_owned()),
        ),
        ActionKind::Ask => (Action::Ask(Some(message)), Some(command_name.to_owned())),
        // Rejected by config validation; treated as absent rather than
        // panicking on a config that skipped validation.
        ActionKind::Allow => (default_action(config), None),
    }
}

/// Whether any command in `command`'s split -- including nested command
/// substitutions -- is `source`, `.`, or `eval`. Functions defined by a
/// sourced script, or run dynamically via `eval`, are invisible to static
/// analysis, so this disables the check for the whole input string rather
/// than trying to track control flow past the source/eval point.
pub(super) fn command_contains_source_like(command: &str) -> bool {
    extract_commands_with_metadata(command)
        .map(|extracted| {
            extracted.iter().any(|ec| {
                ec.argv
                    .first()
                    .is_some_and(|name| SOURCE_LIKE_COMMANDS.contains(&name.as_str()))
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use rstest::rstest;

    use crate::config::{ActionKind, Config, ExperimentalConfig, RequireCommandInPathConfig};

    use super::super::{CommandResolver, StubCommandResolver};
    use super::*;

    struct AlwaysNotFoundResolver;

    impl CommandResolver for AlwaysNotFoundResolver {
        fn resolve(&self, _name: &str) -> CommandResolution {
            CommandResolution::NotFound
        }
    }

    struct AlwaysUnknownResolver;

    impl CommandResolver for AlwaysUnknownResolver {
        fn resolve(&self, _name: &str) -> CommandResolution {
            CommandResolution::Unknown
        }
    }

    fn context_with(resolver: Arc<dyn CommandResolver>) -> EvalContext {
        EvalContext {
            env: HashMap::new(),
            cwd: PathBuf::from("/tmp"),
            resolver,
        }
    }

    fn enabled_config(action: ActionKind, ignore: Vec<&str>) -> Config {
        Config {
            experimental: Some(ExperimentalConfig {
                require_command_in_path: Some(RequireCommandInPathConfig {
                    enabled: Some(true),
                    action: Some(action),
                    ignore: (!ignore.is_empty())
                        .then(|| ignore.into_iter().map(String::from).collect()),
                }),
            }),
            ..Default::default()
        }
    }

    // ========================================
    // Disabled / not configured -> default_action
    // ========================================

    #[rstest]
    #[case::not_configured(Config::default())]
    #[case::explicitly_disabled(Config {
        experimental: Some(ExperimentalConfig {
            require_command_in_path: Some(RequireCommandInPathConfig {
                enabled: Some(false),
                action: None,
                ignore: None,
            }),
        }),
        ..Default::default()
    })]
    fn disabled_falls_back_to_default_action(#[case] config: Config) {
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, "tarraform version", &context, None, false);
        assert_eq!(result, (default_action(&config), None));
    }

    // ========================================
    // Enabled: resolver outcome
    // ========================================

    #[rstest]
    #[case::found(Arc::new(StubCommandResolver) as Arc<dyn CommandResolver>, "terraform version")]
    #[case::unknown(Arc::new(AlwaysUnknownResolver) as Arc<dyn CommandResolver>, "tarraform version")]
    fn resolver_result_other_than_not_found_falls_back_to_default_action(
        #[case] resolver: Arc<dyn CommandResolver>,
        #[case] command: &str,
    ) {
        let config = enabled_config(ActionKind::Deny, vec![]);
        let context = context_with(resolver);
        let result = resolve_unmatched(&config, command, &context, None, false);
        assert_eq!(result, (default_action(&config), None));
    }

    #[rstest]
    #[case::deny(
        ActionKind::Deny,
        (
            Action::Deny(DenyResponse {
                message: Some(
                    "command 'tarraform' not found in PATH (experimental.require_command_in_path)"
                        .to_string()
                ),
                fix_suggestion: Some(
                    "if 'tarraform' is a shell function or alias defined in your shell \
                     profile, add it to experimental.require_command_in_path.ignore, or add \
                     an allow rule for it instead. Otherwise, check for a typo."
                        .to_string()
                ),
                matched_rule: String::new(),
            }),
            Some("tarraform".to_string()),
        )
    )]
    #[case::ask(
        ActionKind::Ask,
        (
            Action::Ask(Some(
                "command 'tarraform' not found in PATH (experimental.require_command_in_path)"
                    .to_string()
            )),
            Some("tarraform".to_string()),
        )
    )]
    // `allow` is rejected by config validation, but `resolve_unmatched`
    // doesn't itself call `validate()` -- a config that skipped it (e.g.
    // constructed programmatically) must not panic.
    #[case::allow_falls_back_to_default_action(
        ActionKind::Allow,
        (default_action(&Config::default()), None)
    )]
    fn not_found_resolves_per_configured_action(
        #[case] action_kind: ActionKind,
        #[case] expected: (Action, Option<String>),
    ) {
        let config = enabled_config(action_kind, vec![]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, "tarraform version", &context, None, false);
        assert_eq!(result, expected);
    }

    // ========================================
    // Skip conditions
    // ========================================

    #[rstest]
    #[case::simple_expansion("$TERRAFORM version")]
    #[case::braced_expansion("${TERRAFORM} version")]
    #[case::command_substitution("$(echo terraform) version")]
    fn unresolved_expansion_argv0_skips(#[case] command: &str) {
        let config = enabled_config(ActionKind::Deny, vec![]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, command, &context, None, false);
        assert_eq!(result, (default_action(&config), None));
    }

    #[rstest]
    #[case::single_quoted_simple_expansion("'$TERRAFORM' version")]
    #[case::single_quoted_command_substitution("'$(echo terraform)' version")]
    #[case::single_quoted_backtick_substitution("'`echo terraform`' version")]
    fn dequoted_text_looking_like_expansion_skips(#[case] command: &str) {
        let config = enabled_config(ActionKind::Deny, vec![]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, command, &context, None, false);
        assert_eq!(result, (default_action(&config), None));
    }

    #[rstest]
    #[case::relative_path("./tarraform version")]
    #[case::absolute_path("/usr/local/bin/tarraform version")]
    fn argv0_with_slash_skips(#[case] command: &str) {
        let config = enabled_config(ActionKind::Deny, vec![]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, command, &context, None, false);
        assert_eq!(result, (default_action(&config), None));
    }

    #[rstest]
    fn ignored_command_skips() {
        let config = enabled_config(ActionKind::Deny, vec!["tarraform"]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, "tarraform version", &context, None, false);
        assert_eq!(result, (default_action(&config), None));
    }

    #[rstest]
    fn function_call_present_skips() {
        let config = enabled_config(ActionKind::Deny, vec![]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let extracted = extract_commands_with_metadata("f() { true; }; f").unwrap();
        let call = extracted
            .iter()
            .find_map(|ec| ec.function_call.as_ref())
            .expect("f() {..}; f should produce a resolved function call");
        let result = resolve_unmatched(&config, "f", &context, Some(call), false);
        assert_eq!(result, (default_action(&config), None));
    }

    #[rstest]
    fn source_like_present_skips() {
        let config = enabled_config(ActionKind::Deny, vec![]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, "tarraform version", &context, None, true);
        assert_eq!(result, (default_action(&config), None));
    }

    #[rstest]
    fn unparsable_command_skips() {
        let config = enabled_config(ActionKind::Deny, vec![]);
        let context = context_with(Arc::new(AlwaysNotFoundResolver));
        let result = resolve_unmatched(&config, "", &context, None, false);
        assert_eq!(result, (default_action(&config), None));
    }

    // ========================================
    // command_contains_source_like
    // ========================================

    #[rstest]
    #[case::source_argv0("source ~/.bashrc", true)]
    #[case::dot_argv0(". ~/.bashrc", true)]
    #[case::eval_argv0("eval \"echo hi\"", true)]
    #[case::source_before_other("source ~/.bashrc; foo", true)]
    #[case::source_in_command_substitution("echo $(source ~/.bashrc)", true)]
    #[case::source_as_argument("echo source", false)]
    #[case::no_source("terraform version", false)]
    fn detects_source_like_commands(#[case] command: &str, #[case] expected: bool) {
        assert_eq!(command_contains_source_like(command), expected);
    }
}
