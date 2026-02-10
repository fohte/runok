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
        let config = parse_config("{}").unwrap();
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
        assert_eq!(
            extends,
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
        let yaml = "defaults:\n  action: ask\n  sandbox: workspace-write";
        let config = parse_config(yaml).unwrap();
        let defaults = config.defaults.unwrap();
        assert_eq!(defaults.action, Some(ActionKind::Ask));
        assert_eq!(defaults.sandbox, Some("workspace-write".to_string()));
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
        "deny: 'aws *'\n    when: \"env.AWS_PROFILE == 'prod'\"",
        None,
        Some("env.AWS_PROFILE == 'prod'"),
        None,
        None
    )]
    #[case::message(
        "deny: 'git push -f|--force *'\n    message: 'Force push is not allowed'",
        Some("Force push is not allowed"),
        None,
        None,
        None
    )]
    #[case::fix_suggestion(
        "deny: 'git push -f|--force *'\n    fix_suggestion: 'git push --force-with-lease'",
        None,
        None,
        Some("git push --force-with-lease"),
        None
    )]
    #[case::sandbox(
        "allow: 'python3 *'\n    sandbox: restricted",
        None,
        None,
        None,
        Some("restricted")
    )]
    #[case::message_and_fix(
        "deny: 'git push -f|--force *'\n    message: 'Force push is not allowed'\n    fix_suggestion: 'git push --force-with-lease'",
        Some("Force push is not allowed"),
        None,
        Some("git push --force-with-lease"),
        None
    )]
    #[case::when_and_message(
        "deny: 'aws *'\n    when: \"env.AWS_PROFILE == 'prod'\"\n    message: 'Production AWS operations are not allowed'",
        Some("Production AWS operations are not allowed"),
        Some("env.AWS_PROFILE == 'prod'"),
        None,
        None
    )]
    fn parse_rule_attributes(
        #[case] rule_yaml: &str,
        #[case] expected_message: Option<&str>,
        #[case] expected_when: Option<&str>,
        #[case] expected_fix: Option<&str>,
        #[case] expected_sandbox: Option<&str>,
    ) {
        let yaml = format!("rules:\n  - {rule_yaml}");
        let config = parse_config(&yaml).unwrap();
        let rule = &config.rules.unwrap()[0];
        assert_eq!(rule.message.as_deref(), expected_message);
        assert_eq!(rule.when.as_deref(), expected_when);
        assert_eq!(rule.fix_suggestion.as_deref(), expected_fix);
        assert_eq!(rule.sandbox.as_deref(), expected_sandbox);
    }

    #[test]
    fn parse_rule_all_optional_fields_none_by_default() {
        let yaml = "rules:\n  - deny: 'test'";
        let rule = &parse_config(yaml).unwrap().rules.unwrap()[0];
        assert_eq!(rule.deny, Some("test".to_string()));
        assert_eq!(rule.allow, None);
        assert_eq!(rule.ask, None);
        assert_eq!(rule.when, None);
        assert_eq!(rule.message, None);
        assert_eq!(rule.fix_suggestion, None);
        assert_eq!(rule.sandbox, None);
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
        let yaml = r#"
definitions:
  paths:
    sensitive:
      - ".env*"
      - ".envrc"
      - "~/.ssh/**"
      - "/etc/**"
"#;
        let paths = parse_config(yaml)
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
        let sandbox = parse_config(yaml)
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
        "definitions:\n  wrappers:\n    - 'sudo <cmd>'\n    - 'bash -c <cmd>'\n    - 'xargs <cmd>'",
        vec!["sudo <cmd>", "bash -c <cmd>", "xargs <cmd>"],
    )]
    #[case::commands(
        "definitions:\n  commands:\n    - 'git commit'\n    - 'git push'",
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
}
