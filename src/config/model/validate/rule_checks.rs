use crate::config::{ActionKind, Config, VarType};

use super::pattern_refs::{collect_flag_group_refs, collect_var_refs_inside_optional};

impl Config {
    /// Validate that every `<flag:name>` reference in a rule pattern resolves
    /// to a group defined in `definitions.flag_groups`, and that no
    /// pattern-typed `<var:name>` reference is nested inside an optional
    /// group `[...]`.
    pub(super) fn validate_rule_pattern_refs(&self, errors: &mut Vec<String>) {
        let defined_flag_groups: std::collections::HashSet<&str> = self
            .definitions
            .as_ref()
            .and_then(|d| d.flag_groups.as_ref())
            .map(|g| g.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();

        // Set of variable names whose effective definition-level type is
        // `pattern`. Used to reject `[<var:name>]` (pattern-typed var inside
        // an optional group) for the same reason `<flag:name>` is rejected
        // there: pattern-var expansion may itself contain optional groups
        // and value-flags, so wrapping it in another optional layer would
        // break the outer matcher's `optional_flags_absent` accounting.
        let pattern_typed_vars: std::collections::HashSet<&str> = self
            .definitions
            .as_ref()
            .and_then(|d| d.vars.as_ref())
            .map(|vars| {
                vars.iter()
                    .filter(|(_, def)| def.var_type == VarType::Pattern)
                    .map(|(k, _)| k.as_str())
                    .collect()
            })
            .unwrap_or_default();

        if let Some(rules) = &self.rules {
            for (i, rule) in rules.iter().enumerate() {
                let Some((_, pattern_str)) = rule.action_and_pattern() else {
                    continue;
                };
                let parsed = match crate::rules::pattern_parser::parse_multi(pattern_str) {
                    Ok(patterns) => patterns,
                    Err(_) => continue, // Pattern parse errors are surfaced at evaluation time.
                };
                for pattern in &parsed {
                    collect_flag_group_refs(&pattern.tokens, &mut |name| {
                        if !defined_flag_groups.contains(name) {
                            errors.push(format!(
                                "rules[{i}]: pattern references undefined flag group \
                                 '<flag:{name}>'. Define it in definitions.flag_groups."
                            ));
                        }
                    });
                    collect_var_refs_inside_optional(&pattern.tokens, &mut |name| {
                        if pattern_typed_vars.contains(name) {
                            errors.push(format!(
                                "rules[{i}]: pattern places <var:{name}> inside an optional \
                                 group `[...]`. Pattern-typed variables cannot be nested in \
                                 optional groups."
                            ));
                        }
                    });
                }
            }
        }
    }

    pub(super) fn validate_rule_actions_and_sandboxes(&self, errors: &mut Vec<String>) {
        let Some(rules) = &self.rules else {
            return;
        };

        let defined_sandboxes: std::collections::HashSet<&str> = self
            .definitions
            .as_ref()
            .and_then(|d| d.sandbox.as_ref())
            .map(|s| s.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();

        for (i, rule) in rules.iter().enumerate() {
            let action = match rule.action_and_pattern() {
                Some((action, _)) => action,
                None => {
                    errors.push(format!(
                        "rules[{i}]: must have exactly one of 'deny', 'allow', or 'ask'"
                    ));
                    continue;
                }
            };

            if let Some(sandbox_name) = &rule.sandbox {
                if action == ActionKind::Deny {
                    errors.push(format!(
                        "rules[{i}]: deny rule cannot have a sandbox attribute (sandbox: '{sandbox_name}')"
                    ));
                }

                if !defined_sandboxes.contains(sandbox_name.as_str()) {
                    errors.push(format!(
                        "rules[{i}]: sandbox '{sandbox_name}' is not defined in definitions.sandbox"
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use crate::config::{RuleEntry, parse_config};

    use super::*;

    // === rule action / no action set ===

    #[test]
    fn validate_errors_on_rule_with_no_action() {
        let mut config = Config {
            required_runok_version: None,
            extends: None,
            defaults: None,
            rules: Some(vec![RuleEntry {
                deny: None,
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
                tests: None,
            }]),
            definitions: None,
            audit: None,
            tests: None,
            experimental: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn validate_errors_on_rule_with_multiple_actions() {
        let mut config = Config {
            required_runok_version: None,
            extends: None,
            defaults: None,
            rules: Some(vec![RuleEntry {
                deny: Some("rm -rf /".to_string()),
                allow: Some("git status".to_string()),
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
                tests: None,
            }]),
            definitions: None,
            audit: None,
            tests: None,
            experimental: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    // === rule sandbox attribute ===

    #[test]
    fn validate_errors_on_deny_with_sandbox() {
        let mut config = parse_config(indoc! {"
            rules:
              - deny: 'rm -rf /'
                sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("deny"));
        assert!(err.to_string().contains("sandbox"));
    }

    #[test]
    fn validate_errors_on_undefined_sandbox_name() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'python3 *'
                sandbox: nonexistent
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
        assert!(err.to_string().contains("not defined"));
    }

    #[test]
    fn validate_errors_on_undefined_sandbox_name_with_empty_definitions() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'python3 *'
                sandbox: restricted
            definitions:
              paths:
                sensitive:
                  - '.env*'
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("restricted"));
        assert!(err.to_string().contains("not defined"));
    }

    #[test]
    fn validate_allow_with_valid_sandbox() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'python3 *'
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

    #[test]
    fn validate_ask_with_valid_sandbox() {
        let mut config = parse_config(indoc! {"
            rules:
              - ask: 'npm run *'
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

    #[test]
    fn validate_includes_rule_index_in_error() {
        let mut config = parse_config(indoc! {"
            rules:
              - allow: 'git status'
              - deny: 'rm -rf /'
                sandbox: restricted
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp]
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        let expected = indoc! {"
            validation errors:
              - rules[1]: deny rule cannot have a sandbox attribute (sandbox: 'restricted')"}
        .trim_start();
        assert_eq!(err.to_string(), expected);
    }
}
