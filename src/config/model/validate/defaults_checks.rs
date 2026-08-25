use crate::config::{ActionKind, Config};

impl Config {
    /// Validate that `defaults.action: pass` is not combined with
    /// `defaults.sandbox`. A pass decision means the hook writes no
    /// output at all, so `updatedInput` (how `defaults.sandbox` wraps the
    /// command in `runok exec --sandbox`) can never be applied -- the
    /// sandbox would be silently dropped.
    pub(super) fn validate_defaults(&self, errors: &mut Vec<String>) {
        let Some(defaults) = &self.defaults else {
            return;
        };
        if defaults.action == Some(ActionKind::Pass) && defaults.sandbox.is_some() {
            errors.push(
                "defaults: 'pass' action cannot be combined with 'sandbox' (a \
                 pass decision produces no hook output, so the sandbox would be \
                 silently dropped; remove defaults.sandbox or use a different defaults.action)"
                    .to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use crate::config::parse_config;

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
        assert!(err.to_string().contains("pass"));
        assert!(err.to_string().contains("sandbox"));
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
