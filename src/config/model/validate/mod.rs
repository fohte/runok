mod definitions_checks;
mod pattern_refs;
mod rule_checks;

use super::Config;

impl Config {
    /// Expand `<path:name>` references in sandbox preset `fs.deny` lists.
    ///
    /// Replaces each `<path:name>` entry with the corresponding path list
    /// from `definitions.paths`. Returns a validation error if a referenced
    /// path name is not defined.
    /// Expand `<path:name>` references in sandbox preset `fs.deny` lists,
    /// collecting all errors so they can be reported together with other
    /// validation errors.
    fn expand_sandbox_path_refs(&mut self, errors: &mut Vec<String>) {
        // Clone paths to avoid borrowing self.definitions both immutably and mutably.
        let paths = self.definitions.as_ref().and_then(|d| d.paths.clone());

        let sandbox = self.definitions.as_mut().and_then(|d| d.sandbox.as_mut());

        let Some(sandbox) = sandbox else {
            return;
        };

        for (preset_name, preset) in sandbox.iter_mut() {
            let Some(fs) = preset.fs.as_mut() else {
                continue;
            };

            // Expand <path:name> references in all deny lists
            let deny_fields: Vec<(&str, Option<&mut Vec<String>>)> = vec![
                (
                    "fs.write.deny",
                    fs.write.as_mut().and_then(|w| w.deny.as_mut()),
                ),
                (
                    "fs.read.deny",
                    fs.read.as_mut().and_then(|r| r.deny.as_mut()),
                ),
            ];

            for (field_name, deny_opt) in deny_fields {
                let Some(deny) = deny_opt else {
                    continue;
                };

                let mut expanded = Vec::new();
                for entry in std::mem::take(deny) {
                    if let Some(name) = entry
                        .strip_prefix("<path:")
                        .and_then(|s| s.strip_suffix('>'))
                    {
                        match paths.as_ref().and_then(|p| p.get(name)) {
                            Some(path_list) => expanded.extend(path_list.iter().cloned()),
                            None => errors.push(format!(
                                "sandbox preset '{}': {} references undefined path '{}'. \
                                 Define it in definitions.paths.{}",
                                preset_name, field_name, name, name
                            )),
                        }
                    } else {
                        expanded.push(entry);
                    }
                }
                *deny = expanded;
            }
        }
    }

    /// Validate the config structure.
    ///
    /// Collects all validation errors and returns them at once so that users
    /// can fix every issue in a single pass.
    ///
    /// Checks:
    /// - Sandbox preset `<path:name>` references resolve to `definitions.paths`
    /// - Each rule entry has exactly one of deny/allow/ask set
    /// - deny rules must not have a sandbox attribute
    /// - sandbox values must reference names defined in definitions.sandbox
    pub fn validate(&mut self) -> Result<(), crate::config::ConfigError> {
        let mut errors = Vec::new();

        self.expand_sandbox_path_refs(&mut errors);
        self.validate_fs_read_allow(&mut errors);
        self.validate_definitions_paths_refs(&mut errors);
        self.validate_definitions_vars(&mut errors);
        self.validate_flag_groups(&mut errors);
        self.validate_rule_pattern_refs(&mut errors);

        if self.rules.is_none() {
            return if errors.is_empty() {
                Ok(())
            } else {
                Err(crate::config::ConfigError::Validation(errors))
            };
        }

        self.validate_rule_actions_and_sandboxes(&mut errors);

        if errors.is_empty() {
            // Pre-parse flag group definitions and pattern-typed variable
            // values so pattern matching never has to re-parse them on every
            // `<flag:name>` / `<var:name>` encounter.
            if let Some(defs) = &mut self.definitions {
                defs.resolve_flag_groups();
                defs.resolve_pattern_vars();
            }
            Ok(())
        } else {
            Err(crate::config::ConfigError::Validation(errors))
        }
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::super::{RuleEntry, parse_config};
    use super::*;

    // === Config::validate ===

    #[test]
    fn validate_valid_config() {
        let mut config = parse_config(indoc! {"
            rules:
              - deny: 'rm -rf /'
              - allow: 'git status'
              - ask: 'git push *'
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_config_without_rules() {
        let mut config = parse_config("{}").unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_collects_all_errors() {
        let mut config = Config {
            required_runok_version: None,
            extends: None,
            defaults: None,
            audit: None,
            rules: Some(vec![
                // Error 1: no action set
                RuleEntry {
                    deny: None,
                    allow: None,
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: None,
                    tests: None,
                },
                // Valid rule (should not appear in errors)
                RuleEntry {
                    deny: Some("rm -rf /".to_string()),
                    allow: None,
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: None,
                    tests: None,
                },
                // Error 2: deny with sandbox
                RuleEntry {
                    deny: Some("curl *".to_string()),
                    allow: None,
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: Some("restricted".to_string()),
                    tests: None,
                },
                // Error 3: undefined sandbox
                RuleEntry {
                    deny: None,
                    allow: Some("python3 *".to_string()),
                    ask: None,
                    when: None,
                    message: None,
                    fix_suggestion: None,
                    sandbox: Some("nonexistent".to_string()),
                    tests: None,
                },
            ]),
            definitions: None,
            tests: None,
        };
        let err = config.validate().unwrap_err();
        let expected = indoc! {"
            validation errors:
              - rules[0]: must have exactly one of 'deny', 'allow', or 'ask'
              - rules[2]: deny rule cannot have a sandbox attribute (sandbox: 'restricted')
              - rules[2]: sandbox 'restricted' is not defined in definitions.sandbox
              - rules[3]: sandbox 'nonexistent' is not defined in definitions.sandbox"}
        .trim_start();
        assert_eq!(err.to_string(), expected);
    }

    // === expand_sandbox_path_refs ===

    #[rstest]
    #[case::single_path_ref(
        indoc! {"
            definitions:
              paths:
                sensitive:
                  - /etc/passwd
                  - /etc/shadow
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - '<path:sensitive>'
        "},
        vec!["/etc/passwd", "/etc/shadow"],
    )]
    #[case::mixed_concrete_and_ref(
        indoc! {"
            definitions:
              paths:
                sensitive:
                  - /etc/passwd
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - /root/.ssh
                      - '<path:sensitive>'
                      - /var/log
        "},
        vec!["/root/.ssh", "/etc/passwd", "/var/log"],
    )]
    fn expand_sandbox_path_refs_success(#[case] yaml: &str, #[case] expected_deny: Vec<&str>) {
        let mut config = parse_config(yaml).unwrap();
        config.validate().unwrap();

        let deny = config
            .definitions
            .as_ref()
            .and_then(|d| d.sandbox.as_ref())
            .and_then(|s| s.get("restricted"))
            .and_then(|p| p.fs.as_ref())
            .and_then(|f| f.write_deny())
            .unwrap();
        assert_eq!(deny, &expected_deny);
    }

    #[rstest]
    #[case::undefined_name(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - '<path:nonexistent>'
        "},
        "nonexistent",
    )]
    #[case::no_paths_defined(
        indoc! {"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
                    deny:
                      - '<path:sensitive>'
        "},
        "sensitive",
    )]
    fn expand_sandbox_path_refs_errors(#[case] yaml: &str, #[case] expected_name: &str) {
        let mut config = parse_config(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains(expected_name));
        assert!(err.to_string().contains("undefined path"));
    }
}
