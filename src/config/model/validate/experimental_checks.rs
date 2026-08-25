use crate::config::{ActionKind, Config};

impl Config {
    /// Validate that `experimental.require_command_in_path.action`, if set,
    /// is `deny` or `ask`. `allow` would defeat the purpose of the check,
    /// and `passthrough` would silently hand the decision to Claude Code's
    /// classifier instead of enforcing it, so both are rejected regardless
    /// of whether the check is currently enabled.
    pub(super) fn validate_experimental(&self, errors: &mut Vec<String>) {
        let action = self
            .experimental
            .as_ref()
            .and_then(|e| e.require_command_in_path.as_ref())
            .and_then(|r| r.action);

        if let Some(invalid) =
            action.filter(|a| matches!(a, ActionKind::Allow | ActionKind::Passthrough))
        {
            let label = match invalid {
                ActionKind::Allow => "allow",
                ActionKind::Passthrough => "passthrough",
                ActionKind::Ask | ActionKind::Deny => {
                    unreachable!("filtered to Allow | Passthrough above")
                }
            };
            errors.push(format!(
                "experimental.require_command_in_path.action: '{label}' is not a valid action \
                 for this check (must be 'deny' or 'ask')"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use crate::config::parse_config;

    // === experimental.require_command_in_path.action ===

    #[test]
    fn validate_errors_on_require_command_in_path_action_allow() {
        let mut config = parse_config(indoc! {"
            experimental:
              require_command_in_path:
                enabled: true
                action: allow
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "validation errors:\n  - experimental.require_command_in_path.action: 'allow' is \
             not a valid action for this check (must be 'deny' or 'ask')"
        );
    }

    #[test]
    fn validate_errors_on_require_command_in_path_action_passthrough() {
        let mut config = parse_config(indoc! {"
            experimental:
              require_command_in_path:
                enabled: true
                action: passthrough
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "validation errors:\n  - experimental.require_command_in_path.action: 'passthrough' \
             is not a valid action for this check (must be 'deny' or 'ask')"
        );
    }

    #[test]
    fn validate_errors_on_require_command_in_path_action_allow_even_when_disabled() {
        let mut config = parse_config(indoc! {"
            experimental:
              require_command_in_path:
                enabled: false
                action: allow
        "})
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_ok_with_require_command_in_path_action_deny() {
        let mut config = parse_config(indoc! {"
            experimental:
              require_command_in_path:
                enabled: true
                action: deny
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_ok_with_require_command_in_path_action_ask() {
        let mut config = parse_config(indoc! {"
            experimental:
              require_command_in_path:
                enabled: true
                action: ask
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_ok_without_experimental_section() {
        let mut config = parse_config("{}").unwrap();
        assert!(config.validate().is_ok());
    }
}
