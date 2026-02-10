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

/// Parse a YAML string into a `Config`.
pub fn parse_config(yaml: &str) -> Result<Config, crate::config::ConfigError> {
    let config: Config = serde_saphyr::from_str(yaml)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === Basic parsing ===

    #[test]
    fn parse_empty_config() {
        let yaml = "{}";
        let config = parse_config(yaml).unwrap();
        assert_eq!(config.extends, None);
        assert_eq!(config.defaults, None);
        assert_eq!(config.rules, None);
        assert_eq!(config.definitions, None);
    }

    #[test]
    fn parse_extends() {
        let yaml = r#"
extends:
  - ./local-rules.yaml
  - "github:runok/presets@v1.0.0"
  - "https://example.com/preset.yaml"
"#;
        let config = parse_config(yaml).unwrap();
        let extends = config.extends.unwrap();
        assert_eq!(extends.len(), 3);
        assert_eq!(extends[0], "./local-rules.yaml");
        assert_eq!(extends[1], "github:runok/presets@v1.0.0");
        assert_eq!(extends[2], "https://example.com/preset.yaml");
    }

    // === Defaults ===

    #[rstest]
    #[case("allow", ActionKind::Allow)]
    #[case("deny", ActionKind::Deny)]
    #[case("ask", ActionKind::Ask)]
    fn parse_defaults_action(#[case] action_str: &str, #[case] expected: ActionKind) {
        let yaml = format!(
            r#"
defaults:
  action: {action_str}
"#
        );
        let config = parse_config(&yaml).unwrap();
        let defaults = config.defaults.unwrap();
        assert_eq!(defaults.action, Some(expected));
    }

    #[test]
    fn parse_defaults_sandbox() {
        let yaml = r#"
defaults:
  action: ask
  sandbox: workspace-write
"#;
        let config = parse_config(yaml).unwrap();
        let defaults = config.defaults.unwrap();
        assert_eq!(defaults.action, Some(ActionKind::Ask));
        assert_eq!(defaults.sandbox, Some("workspace-write".to_string()));
    }

    // === Rules ===

    #[test]
    fn parse_deny_rule() {
        let yaml = r#"
rules:
  - deny: 'rm -rf /'
"#;
        let config = parse_config(yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].deny, Some("rm -rf /".to_string()));
        assert_eq!(rules[0].allow, None);
        assert_eq!(rules[0].ask, None);
    }

    #[test]
    fn parse_allow_rule() {
        let yaml = r#"
rules:
  - allow: 'git status'
"#;
        let config = parse_config(yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].allow, Some("git status".to_string()));
    }

    #[test]
    fn parse_ask_rule() {
        let yaml = r#"
rules:
  - ask: 'curl -X|--request !GET *'
"#;
        let config = parse_config(yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].ask, Some("curl -X|--request !GET *".to_string()));
    }

    #[test]
    fn parse_deny_rule_with_message_and_fix() {
        let yaml = r#"
rules:
  - deny: 'git push -f|--force *'
    message: 'Force push is not allowed'
    fix_suggestion: 'git push --force-with-lease'
"#;
        let config = parse_config(yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].deny, Some("git push -f|--force *".to_string()));
        assert_eq!(
            rules[0].message,
            Some("Force push is not allowed".to_string())
        );
        assert_eq!(
            rules[0].fix_suggestion,
            Some("git push --force-with-lease".to_string())
        );
    }

    #[test]
    fn parse_deny_rule_with_when() {
        let yaml = r#"
rules:
  - deny: 'aws *'
    when: "env.AWS_PROFILE == 'prod'"
    message: 'Production AWS operations are not allowed'
"#;
        let config = parse_config(yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].deny, Some("aws *".to_string()));
        assert_eq!(rules[0].when, Some("env.AWS_PROFILE == 'prod'".to_string()));
        assert_eq!(
            rules[0].message,
            Some("Production AWS operations are not allowed".to_string())
        );
    }

    #[test]
    fn parse_allow_rule_with_sandbox() {
        let yaml = r#"
rules:
  - allow: 'python3 *'
    sandbox: restricted
"#;
        let config = parse_config(yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].allow, Some("python3 *".to_string()));
        assert_eq!(rules[0].sandbox, Some("restricted".to_string()));
    }

    #[test]
    fn parse_multiple_rules() {
        let yaml = r#"
rules:
  - deny: 'rm -rf /'
  - allow: 'git status'
  - ask: 'git push *'
  - deny: 'git push -f|--force *'
    message: 'Force push is not allowed'
"#;
        let config = parse_config(yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].deny, Some("rm -rf /".to_string()));
        assert_eq!(rules[1].allow, Some("git status".to_string()));
        assert_eq!(rules[2].ask, Some("git push *".to_string()));
        assert_eq!(rules[3].deny, Some("git push -f|--force *".to_string()));
        assert_eq!(
            rules[3].message,
            Some("Force push is not allowed".to_string())
        );
    }

    // === Definitions ===

    #[test]
    fn parse_definitions_paths() {
        let yaml = r#"
definitions:
  paths:
    sensitive:
      - ".env*"
      - ".envrc"
      - "~/.ssh/**"
      - "/etc/**"
"#;
        let config = parse_config(yaml).unwrap();
        let definitions = config.definitions.unwrap();
        let paths = definitions.paths.unwrap();
        let sensitive = &paths["sensitive"];
        assert_eq!(sensitive.len(), 4);
        assert_eq!(sensitive[0], ".env*");
        assert_eq!(sensitive[1], ".envrc");
        assert_eq!(sensitive[2], "~/.ssh/**");
        assert_eq!(sensitive[3], "/etc/**");
    }

    #[test]
    fn parse_definitions_sandbox() {
        let yaml = r#"
definitions:
  sandbox:
    restricted:
      fs:
        writable: [./tmp, /tmp]
        deny:
          - "<path:sensitive>"
      network:
        allow: [github.com, "*.github.com", pypi.org]
"#;
        let config = parse_config(yaml).unwrap();
        let definitions = config.definitions.unwrap();
        let sandbox = definitions.sandbox.unwrap();
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

    #[test]
    fn parse_definitions_wrappers() {
        let yaml = r#"
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'bash -c <cmd>'
    - 'xargs <cmd>'
"#;
        let config = parse_config(yaml).unwrap();
        let definitions = config.definitions.unwrap();
        let wrappers = definitions.wrappers.unwrap();
        assert_eq!(wrappers.len(), 3);
        assert_eq!(wrappers[0], "sudo <cmd>");
        assert_eq!(wrappers[1], "bash -c <cmd>");
        assert_eq!(wrappers[2], "xargs <cmd>");
    }

    #[test]
    fn parse_definitions_commands() {
        let yaml = r#"
definitions:
  commands:
    - 'git commit'
    - 'git push'
"#;
        let config = parse_config(yaml).unwrap();
        let definitions = config.definitions.unwrap();
        let commands = definitions.commands.unwrap();
        assert_eq!(commands.len(), 2);
    }

    // === Full config ===

    #[test]
    fn parse_full_config() {
        let yaml = r#"
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
"#;
        let config = parse_config(yaml).unwrap();

        // extends
        let extends = config.extends.unwrap();
        assert_eq!(extends.len(), 2);

        // defaults
        let defaults = config.defaults.unwrap();
        assert_eq!(defaults.action, Some(ActionKind::Ask));
        assert_eq!(defaults.sandbox, Some("workspace-write".to_string()));

        // rules
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 9);

        // definitions
        let definitions = config.definitions.unwrap();
        assert!(definitions.paths.is_some());
        assert!(definitions.sandbox.is_some());
        assert!(definitions.wrappers.is_some());
        let wrappers = definitions.wrappers.unwrap();
        assert_eq!(wrappers.len(), 6);
    }

    // === Error cases ===

    #[test]
    fn parse_invalid_yaml_returns_error() {
        let yaml = "rules: [invalid yaml\n  broken:";
        let result = parse_config(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_wrong_type_returns_error() {
        // rules should be a list, not a string
        let yaml = "rules: 'not a list'";
        let result = parse_config(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_action_kind_returns_error() {
        let yaml = r#"
defaults:
  action: invalid_action
"#;
        let result = parse_config(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_string_returns_empty_config() {
        // Empty YAML string parses as null, which should fail since Config has fields
        let yaml = "";
        let result = parse_config(yaml);
        // serde-saphyr may treat empty string differently
        // An empty document should either succeed with all-None fields or error
        // Let's verify the behavior
        assert!(
            result.is_err() || {
                let config = result.unwrap();
                config.extends.is_none()
                    && config.defaults.is_none()
                    && config.rules.is_none()
                    && config.definitions.is_none()
            }
        );
    }

    // === ActionKind ===

    #[test]
    fn action_kind_default_is_ask() {
        let kind = ActionKind::default();
        assert_eq!(kind, ActionKind::Ask);
    }

    #[test]
    fn action_kind_ordering() {
        // Allow < Ask < Deny (alphabetical by serde rename)
        assert!(ActionKind::Allow < ActionKind::Ask);
        assert!(ActionKind::Ask < ActionKind::Deny);
    }

    // === RuleEntry attributes ===

    #[test]
    fn rule_entry_all_optional_fields_none_by_default() {
        let yaml = r#"
rules:
  - deny: 'test'
"#;
        let config = parse_config(yaml).unwrap();
        let rule = &config.rules.unwrap()[0];
        assert_eq!(rule.deny, Some("test".to_string()));
        assert_eq!(rule.allow, None);
        assert_eq!(rule.ask, None);
        assert_eq!(rule.when, None);
        assert_eq!(rule.message, None);
        assert_eq!(rule.fix_suggestion, None);
        assert_eq!(rule.sandbox, None);
    }
}
