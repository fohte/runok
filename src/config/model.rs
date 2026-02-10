use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
pub struct Config {
    pub extends: Option<Vec<String>>,
    pub defaults: Option<Defaults>,
    pub rules: Option<Vec<RuleEntry>>,
    pub definitions: Option<Definitions>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Defaults {
    pub action: Option<ActionKind>,
    pub sandbox: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Allow,
    #[default]
    Ask,
    Deny,
}

/// Each entry in the `rules` list. Exactly one of `deny`, `allow`, or `ask` must be set.
#[derive(Debug, Deserialize, PartialEq)]
pub struct RuleEntry {
    pub deny: Option<String>,
    pub allow: Option<String>,
    pub ask: Option<String>,
    pub when: Option<String>,
    pub message: Option<String>,
    pub fix_suggestion: Option<String>,
    pub sandbox: Option<String>,
}

impl RuleEntry {
    /// Extract the action kind and pattern string from this rule entry.
    /// Returns None if not exactly one of deny/allow/ask is set.
    pub fn action_and_pattern(&self) -> Option<(ActionKind, &str)> {
        match (&self.deny, &self.allow, &self.ask) {
            (Some(pattern), None, None) => Some((ActionKind::Deny, pattern)),
            (None, Some(pattern), None) => Some((ActionKind::Allow, pattern)),
            (None, None, Some(pattern)) => Some((ActionKind::Ask, pattern)),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Definitions {
    pub paths: Option<HashMap<String, Vec<String>>>,
    pub sandbox: Option<HashMap<String, SandboxPreset>>,
    pub wrappers: Option<Vec<String>>,
    pub commands: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct SandboxPreset {
    pub fs: Option<FsPolicy>,
    pub network: Option<NetworkPolicy>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct FsPolicy {
    pub writable: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct NetworkPolicy {
    pub allow: Option<Vec<String>>,
}

impl Config {
    /// Validate the config structure.
    ///
    /// Collects all validation errors and returns them at once so that users
    /// can fix every issue in a single pass.
    ///
    /// Checks:
    /// - Each rule entry has exactly one of deny/allow/ask set
    /// - deny rules must not have a sandbox attribute
    /// - sandbox values must reference names defined in definitions.sandbox
    pub fn validate(&self) -> Result<(), crate::config::ConfigError> {
        let rules = match &self.rules {
            Some(rules) => rules,
            None => return Ok(()),
        };

        let defined_sandboxes: std::collections::HashSet<&str> = self
            .definitions
            .as_ref()
            .and_then(|d| d.sandbox.as_ref())
            .map(|s| s.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default();

        let mut errors = Vec::new();

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

        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::config::ConfigError::Validation(errors))
        }
    }
}

/// Parse a YAML string into a `Config`.
pub fn parse_config(yaml: &str) -> Result<Config, crate::config::ConfigError> {
    let config: Config = serde_saphyr::from_str(yaml)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    // === Basic parsing ===

    #[test]
    fn parse_empty_config() {
        let config = parse_config("{}").unwrap();
        assert_eq!(config.extends, None);
        assert_eq!(config.defaults, None);
        assert_eq!(config.rules, None);
        assert_eq!(config.definitions, None);
    }

    #[test]
    fn parse_extends() {
        let config = parse_config(indoc! {"
            extends:
              - ./local-rules.yaml
              - 'github:runok/presets@v1.0.0'
              - 'https://example.com/preset.yaml'
        "})
        .unwrap();
        assert_eq!(
            config.extends.unwrap(),
            vec![
                "./local-rules.yaml",
                "github:runok/presets@v1.0.0",
                "https://example.com/preset.yaml",
            ]
        );
    }

    // === Defaults ===

    #[rstest]
    #[case("allow", ActionKind::Allow)]
    #[case("deny", ActionKind::Deny)]
    #[case("ask", ActionKind::Ask)]
    fn parse_defaults_action(#[case] action_str: &str, #[case] expected: ActionKind) {
        let yaml = format!("defaults:\n  action: {action_str}");
        let config = parse_config(&yaml).unwrap();
        assert_eq!(config.defaults.unwrap().action, Some(expected));
    }

    #[test]
    fn parse_defaults_with_sandbox() {
        let config = parse_config(indoc! {"
            defaults:
              action: ask
              sandbox: workspace-write
        "})
        .unwrap();
        let defaults = config.defaults.unwrap();
        assert_eq!(defaults.action, Some(ActionKind::Ask));
        assert_eq!(defaults.sandbox.as_deref(), Some("workspace-write"));
    }

    // === Rules: single action key ===

    #[rstest]
    #[case::deny("deny", "rm -rf /")]
    #[case::allow("allow", "git status")]
    #[case::ask("ask", "curl -X|--request !GET *")]
    fn parse_single_rule(#[case] action: &str, #[case] pattern: &str) {
        let yaml = format!("rules:\n  - {action}: '{pattern}'");
        let config = parse_config(&yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        let (deny, allow, ask) = (&rule.deny, &rule.allow, &rule.ask);
        match action {
            "deny" => {
                assert_eq!(deny.as_deref(), Some(pattern));
                assert_eq!(allow.as_deref(), None);
                assert_eq!(ask.as_deref(), None);
            }
            "allow" => {
                assert_eq!(deny.as_deref(), None);
                assert_eq!(allow.as_deref(), Some(pattern));
                assert_eq!(ask.as_deref(), None);
            }
            "ask" => {
                assert_eq!(deny.as_deref(), None);
                assert_eq!(allow.as_deref(), None);
                assert_eq!(ask.as_deref(), Some(pattern));
            }
            _ => unreachable!(),
        }
    }

    // === Rules: optional attributes ===

    #[rstest]
    #[case::when(
        indoc! {"
            deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
        "},
        None, Some("env.AWS_PROFILE == 'prod'"), None, None,
    )]
    #[case::message(
        indoc! {"
            deny: 'git push -f|--force *'
            message: 'Force push is not allowed'
        "},
        Some("Force push is not allowed"), None, None, None,
    )]
    #[case::fix_suggestion(
        indoc! {"
            deny: 'git push -f|--force *'
            fix_suggestion: 'git push --force-with-lease'
        "},
        None, None, Some("git push --force-with-lease"), None,
    )]
    #[case::sandbox(
        indoc! {"
            allow: 'python3 *'
            sandbox: restricted
        "},
        None, None, None, Some("restricted"),
    )]
    #[case::message_and_fix(
        indoc! {"
            deny: 'git push -f|--force *'
            message: 'Force push is not allowed'
            fix_suggestion: 'git push --force-with-lease'
        "},
        Some("Force push is not allowed"), None, Some("git push --force-with-lease"), None,
    )]
    #[case::when_and_message(
        indoc! {"
            deny: 'aws *'
            when: \"env.AWS_PROFILE == 'prod'\"
            message: 'Production AWS operations are not allowed'
        "},
        Some("Production AWS operations are not allowed"), Some("env.AWS_PROFILE == 'prod'"), None, None,
    )]
    fn parse_rule_attributes(
        #[case] rule_yaml: &str,
        #[case] expected_message: Option<&str>,
        #[case] expected_when: Option<&str>,
        #[case] expected_fix: Option<&str>,
        #[case] expected_sandbox: Option<&str>,
    ) {
        let yaml = format!("rules:\n  - {}", rule_yaml.replace('\n', "\n    "));
        let config = parse_config(&yaml).unwrap();
        let rule = &config.rules.unwrap()[0];
        assert_eq!(rule.message.as_deref(), expected_message);
        assert_eq!(rule.when.as_deref(), expected_when);
        assert_eq!(rule.fix_suggestion.as_deref(), expected_fix);
        assert_eq!(rule.sandbox.as_deref(), expected_sandbox);
    }

    #[test]
    fn parse_rule_all_optional_fields_none_by_default() {
        let rule = &parse_config("rules:\n  - deny: 'test'")
            .unwrap()
            .rules
            .unwrap()[0];
        assert_eq!(rule.deny.as_deref(), Some("test"));
        assert_eq!(rule.allow, None);
        assert_eq!(rule.ask, None);
        assert_eq!(rule.when, None);
        assert_eq!(rule.message, None);
        assert_eq!(rule.fix_suggestion, None);
        assert_eq!(rule.sandbox, None);
    }

    #[test]
    fn parse_multiple_rules() {
        let config = parse_config(indoc! {"
            rules:
              - deny: 'rm -rf /'
              - allow: 'git status'
              - ask: 'git push *'
              - deny: 'git push -f|--force *'
                message: 'Force push is not allowed'
        "})
        .unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status"));
        assert_eq!(rules[2].ask.as_deref(), Some("git push *"));
        assert_eq!(rules[3].deny.as_deref(), Some("git push -f|--force *"));
        assert_eq!(
            rules[3].message.as_deref(),
            Some("Force push is not allowed")
        );
    }

    // === Definitions ===

    #[test]
    fn parse_definitions_paths() {
        let paths = parse_config(indoc! {r#"
            definitions:
              paths:
                sensitive:
                  - ".env*"
                  - ".envrc"
                  - "~/.ssh/**"
                  - "/etc/**"
        "#})
        .unwrap()
        .definitions
        .unwrap()
        .paths
        .unwrap();
        assert_eq!(
            paths["sensitive"],
            vec![".env*", ".envrc", "~/.ssh/**", "/etc/**"]
        );
    }

    #[test]
    fn parse_definitions_sandbox() {
        let sandbox = parse_config(indoc! {r#"
            definitions:
              sandbox:
                restricted:
                  fs:
                    writable: [./tmp, /tmp]
                    deny:
                      - "<path:sensitive>"
                  network:
                    allow: [github.com, "*.github.com", pypi.org]
        "#})
        .unwrap()
        .definitions
        .unwrap()
        .sandbox
        .unwrap();
        let restricted = &sandbox["restricted"];

        let fs = restricted.fs.as_ref().unwrap();
        assert_eq!(
            fs.writable,
            Some(vec!["./tmp".to_string(), "/tmp".to_string()])
        );
        assert_eq!(fs.deny, Some(vec!["<path:sensitive>".to_string()]));

        let network = restricted.network.as_ref().unwrap();
        assert_eq!(
            network.allow,
            Some(vec![
                "github.com".to_string(),
                "*.github.com".to_string(),
                "pypi.org".to_string(),
            ])
        );
    }

    #[rstest]
    #[case::wrappers(
        indoc! {"
            definitions:
              wrappers:
                - 'sudo <cmd>'
                - 'bash -c <cmd>'
                - 'xargs <cmd>'
        "},
        vec!["sudo <cmd>", "bash -c <cmd>", "xargs <cmd>"],
    )]
    #[case::commands(
        indoc! {"
            definitions:
              commands:
                - 'git commit'
                - 'git push'
        "},
        vec!["git commit", "git push"],
    )]
    fn parse_definitions_string_lists(#[case] yaml: &str, #[case] expected: Vec<&str>) {
        let defs = parse_config(yaml).unwrap().definitions.unwrap();
        let actual = defs.wrappers.or(defs.commands).unwrap();
        let actual_refs: Vec<&str> = actual.iter().map(|s| s.as_str()).collect();
        assert_eq!(actual_refs, expected);
    }

    // === Full config ===

    #[test]
    fn parse_full_config() {
        let config = parse_config(indoc! {r#"
            extends:
              - ./local-rules.yaml
              - "github:runok/presets@v1.0.0"

            defaults:
              action: ask
              sandbox: workspace-write

            rules:
              - deny: 'rm -rf /'
              - deny: 'git push -f|--force *'
                message: 'Force push is not allowed'
                fix_suggestion: 'git push --force-with-lease'
              - deny: 'aws *'
                when: "env.AWS_PROFILE == 'prod'"
                message: 'Production AWS operations are not allowed'
              - allow: 'git status'
              - allow: 'git [-C *] status'
              - allow: 'curl [-X|--request GET] *'
              - allow: 'python3 *'
                sandbox: restricted
              - ask: 'curl -X|--request !GET *'
              - ask: 'git push *'

            definitions:
              paths:
                sensitive:
                  - ".env*"
                  - ".envrc"
                  - "~/.ssh/**"
                  - "/etc/**"

              sandbox:
                restricted:
                  fs:
                    writable: [./tmp, /tmp]
                    deny:
                      - "<path:sensitive>"
                  network:
                    allow: [github.com, "*.github.com", pypi.org]

              wrappers:
                - 'sudo <cmd>'
                - 'bash -c <cmd>'
                - 'sh -c <cmd>'
                - 'xargs <cmd>'
                - "find * -exec <cmd> \\;"
                - 'env * <cmd>'
        "#})
        .unwrap();

        assert_eq!(config.extends.as_ref().unwrap().len(), 2);

        let defaults = config.defaults.as_ref().unwrap();
        assert_eq!(defaults.action, Some(ActionKind::Ask));
        assert_eq!(defaults.sandbox.as_deref(), Some("workspace-write"));

        assert_eq!(config.rules.as_ref().unwrap().len(), 9);

        let defs = config.definitions.as_ref().unwrap();
        assert!(defs.paths.is_some());
        assert!(defs.sandbox.is_some());
        assert_eq!(defs.wrappers.as_ref().unwrap().len(), 6);
    }

    // === Error cases ===

    #[rstest]
    #[case::invalid_yaml("rules: [invalid yaml\n  broken:")]
    #[case::wrong_type("rules: 'not a list'")]
    #[case::invalid_action("defaults:\n  action: invalid_action")]
    fn parse_error(#[case] yaml: &str) {
        assert!(parse_config(yaml).is_err());
    }

    #[test]
    fn parse_empty_string_returns_empty_config() {
        let config = parse_config("").unwrap();
        assert_eq!(config.extends, None);
        assert_eq!(config.defaults, None);
        assert_eq!(config.rules, None);
        assert_eq!(config.definitions, None);
    }

    // === ActionKind ===

    #[test]
    fn action_kind_default_is_ask() {
        assert_eq!(ActionKind::default(), ActionKind::Ask);
    }

    #[test]
    fn action_kind_ordering() {
        assert!(ActionKind::Allow < ActionKind::Ask);
        assert!(ActionKind::Ask < ActionKind::Deny);
    }

    // === RuleEntry::action_and_pattern ===

    #[rstest]
    #[case::deny("deny", "rm -rf /", ActionKind::Deny)]
    #[case::allow("allow", "git status", ActionKind::Allow)]
    #[case::ask("ask", "git push *", ActionKind::Ask)]
    fn action_and_pattern_returns_correct_action(
        #[case] key: &str,
        #[case] pattern: &str,
        #[case] expected_action: ActionKind,
    ) {
        let yaml = format!("rules:\n  - {key}: '{pattern}'");
        let config = parse_config(&yaml).unwrap();
        let rule = &config.rules.unwrap()[0];
        let (action, pat) = rule.action_and_pattern().unwrap();
        assert_eq!(action, expected_action);
        assert_eq!(pat, pattern);
    }

    #[test]
    fn action_and_pattern_returns_none_when_none_set() {
        let rule = RuleEntry {
            deny: None,
            allow: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
        };
        assert!(rule.action_and_pattern().is_none());
    }

    #[test]
    fn action_and_pattern_returns_none_when_multiple_set() {
        let rule = RuleEntry {
            deny: Some("rm -rf /".to_string()),
            allow: Some("git status".to_string()),
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
        };
        assert!(rule.action_and_pattern().is_none());
    }

    #[test]
    fn action_and_pattern_returns_none_when_all_three_set() {
        let rule = RuleEntry {
            deny: Some("rm -rf /".to_string()),
            allow: Some("git status".to_string()),
            ask: Some("git push *".to_string()),
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
        };
        assert!(rule.action_and_pattern().is_none());
    }

    // === Config::validate ===

    #[test]
    fn validate_valid_config() {
        let config = parse_config(indoc! {"
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
        let config = parse_config("{}").unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_errors_on_rule_with_no_action() {
        let config = Config {
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
            }]),
            definitions: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn validate_errors_on_rule_with_multiple_actions() {
        let config = Config {
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
            }]),
            definitions: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn validate_errors_on_deny_with_sandbox() {
        let config = parse_config(indoc! {"
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
        let config = parse_config(indoc! {"
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
        let config = parse_config(indoc! {"
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
        let config = parse_config(indoc! {"
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
        let config = parse_config(indoc! {"
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
    fn validate_collects_all_errors() {
        let config = Config {
            extends: None,
            defaults: None,
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
                },
            ]),
            definitions: None,
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

    #[test]
    fn validate_includes_rule_index_in_error() {
        let config = parse_config(indoc! {"
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
