#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;

use super::ActionKind;

/// Experimental features. Each feature is disabled by default and has no
/// effect until explicitly enabled.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct ExperimentalConfig {
    /// Deny (or ask, per `action`) commands whose argv[0] cannot be resolved
    /// via `PATH`.
    pub require_command_in_path: Option<RequireCommandInPathConfig>,
}

/// Configuration for the `require_command_in_path` experimental check.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct RequireCommandInPathConfig {
    /// Whether this check is enabled (default: false).
    pub enabled: Option<bool>,
    /// Action to take when a command cannot be resolved via `PATH`: `deny`
    /// or `ask` (default: deny). `allow` is a validation error.
    pub action: Option<ActionKind>,
    /// Command names exempt from this check (literal exact match).
    pub ignore: Option<Vec<String>>,
}

impl RequireCommandInPathConfig {
    /// Returns whether this check is enabled, defaulting to false.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    /// Returns the configured action, defaulting to deny.
    pub fn resolved_action(&self) -> ActionKind {
        self.action.unwrap_or(ActionKind::Deny)
    }

    /// Returns the list of command names exempt from this check, defaulting
    /// to empty.
    pub fn resolved_ignore(&self) -> &[String] {
        self.ignore.as_deref().unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    // === RequireCommandInPathConfig ===

    #[test]
    fn require_command_in_path_config_default() {
        assert_eq!(
            RequireCommandInPathConfig::default(),
            RequireCommandInPathConfig {
                enabled: None,
                action: None,
                ignore: None,
            }
        );
    }

    #[rstest]
    #[case::enabled(Some(true), true)]
    #[case::disabled(Some(false), false)]
    #[case::default_when_none(None, false)]
    fn require_command_in_path_config_is_enabled(
        #[case] enabled: Option<bool>,
        #[case] expected: bool,
    ) {
        let config = RequireCommandInPathConfig {
            enabled,
            action: None,
            ignore: None,
        };
        assert_eq!(config.is_enabled(), expected);
    }

    #[rstest]
    #[case::deny(Some(ActionKind::Deny), ActionKind::Deny)]
    #[case::ask(Some(ActionKind::Ask), ActionKind::Ask)]
    #[case::default_when_none(None, ActionKind::Deny)]
    fn require_command_in_path_config_resolved_action(
        #[case] action: Option<ActionKind>,
        #[case] expected: ActionKind,
    ) {
        let config = RequireCommandInPathConfig {
            enabled: None,
            action,
            ignore: None,
        };
        assert_eq!(config.resolved_action(), expected);
    }

    #[rstest]
    #[case::some(Some(vec!["my-func".to_string()]), vec!["my-func"])]
    #[case::default_when_none(None, Vec::<&str>::new())]
    fn require_command_in_path_config_resolved_ignore(
        #[case] ignore: Option<Vec<String>>,
        #[case] expected: Vec<&str>,
    ) {
        let config = RequireCommandInPathConfig {
            enabled: None,
            action: None,
            ignore,
        };
        assert_eq!(config.resolved_ignore(), expected.as_slice());
    }
}
