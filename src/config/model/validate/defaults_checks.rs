use crate::config::{ActionKind, Config};

impl Config {
    /// Validate that `defaults.action: passthrough` is not combined with
    /// `defaults.sandbox`. A passthrough decision means the hook writes no
    /// output at all, so `updatedInput` (how `defaults.sandbox` wraps the
    /// command in `runok exec --sandbox`) can never be applied -- the
    /// sandbox would be silently dropped.
    pub(super) fn validate_defaults(&self, errors: &mut Vec<String>) {
        let Some(defaults) = &self.defaults else {
            return;
        };
        if defaults.action == Some(ActionKind::Passthrough) && defaults.sandbox.is_some() {
            errors.push(
                "defaults: 'passthrough' action cannot be combined with 'sandbox' (a \
                 passthrough decision produces no hook output, so the sandbox would be \
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
    fn validate_errors_on_passthrough_with_sandbox() {
        let mut config = parse_config(indoc! {"
            defaults:
              action: passthrough
              sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("passthrough"));
        assert!(err.to_string().contains("sandbox"));
    }

    #[test]
    fn validate_ok_with_passthrough_without_sandbox() {
        let mut config = parse_config(indoc! {"
            defaults:
              action: passthrough
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_ok_with_sandbox_without_passthrough() {
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
