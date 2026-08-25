use crate::config::{ActionKind, Config};

impl Config {
    /// Validate that a `pass`-resolving `defaults.action` is not combined
    /// with `defaults.sandbox`. `pass` -- including the unset default -- means
    /// the hook writes no output at all, so `updatedInput` (how
    /// `defaults.sandbox` wraps the command in `runok exec --sandbox`) can
    /// never be applied -- the sandbox would be silently dropped.
    pub(super) fn validate_defaults(&self, errors: &mut Vec<String>) {
        let Some(defaults) = &self.defaults else {
            return;
        };
        if defaults.resolved_action() == ActionKind::Pass && defaults.sandbox.is_some() {
            errors.push(
                "defaults: 'pass' action (the default when defaults.action is unset) \
                 cannot be combined with 'sandbox' (a pass decision produces no hook \
                 output, so the sandbox would be silently dropped; remove defaults.sandbox \
                 or set defaults.action to 'allow', 'ask', or 'deny')"
                    .to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use crate::config::parse_config;

    const EXPECTED_ERROR: &str = "validation errors:\n  - defaults: 'pass' action (the default \
         when defaults.action is unset) cannot be combined with 'sandbox' (a pass decision \
         produces no hook output, so the sandbox would be silently dropped; remove \
         defaults.sandbox or set defaults.action to 'allow', 'ask', or 'deny')";

    #[test]
    fn validate_errors_on_pass_with_sandbox() {
        let mut config = parse_config(indoc! {"
            defaults:
              action: pass
              sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert_eq!(err.to_string(), EXPECTED_ERROR);
    }

    #[test]
    fn validate_errors_on_unset_action_with_sandbox() {
        let mut config = parse_config(indoc! {"
            defaults:
              sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert_eq!(err.to_string(), EXPECTED_ERROR);
    }

    #[test]
    fn validate_ok_with_pass_without_sandbox() {
        let mut config = parse_config(indoc! {"
            defaults:
              action: pass
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_ok_with_sandbox_without_pass() {
        let mut config = parse_config(indoc! {"
            defaults:
              action: ask
              sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }
}
