use std::cell::RefCell;

use super::Config;

thread_local! {
    static PARSE_WARNINGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Collect warnings emitted during config parsing (e.g. deprecated fields).
fn take_parse_warnings() -> Vec<String> {
    PARSE_WARNINGS.with(|w| w.borrow_mut().drain(..).collect())
}

pub(super) fn push_parse_warning(msg: String) {
    PARSE_WARNINGS.with(|w| w.borrow_mut().push(msg));
}

/// Result of parsing a config, including any warnings.
pub struct ParsedConfig {
    pub config: Config,
    pub warnings: Vec<String>,
}

/// Parse a YAML string into a `Config`.
pub fn parse_config(yaml: &str) -> Result<Config, crate::config::ConfigError> {
    // Discard any warnings; callers that need warnings should use
    // `parse_config_with_warnings` instead.
    take_parse_warnings();
    let mut config: Config = serde_saphyr::from_str(yaml)?;
    take_parse_warnings();
    // Eagerly populate the parsed flag group / pattern-var cache so callers
    // that skip `validate()` (e.g. tests) still get cached lookups.
    if let Some(defs) = &mut config.definitions {
        defs.resolve_flag_groups();
        defs.resolve_pattern_vars();
    }
    Ok(config)
}

/// Parse a YAML string into a `Config`, collecting deprecation warnings.
pub fn parse_config_with_warnings(yaml: &str) -> Result<ParsedConfig, crate::config::ConfigError> {
    take_parse_warnings();
    let mut config: Config = serde_saphyr::from_str(yaml)?;
    let warnings = take_parse_warnings();
    // Eagerly populate the parsed flag group / pattern-var cache so callers
    // that skip `validate()` still get cached lookups.
    if let Some(defs) = &mut config.definitions {
        defs.resolve_flag_groups();
        defs.resolve_pattern_vars();
    }
    Ok(ParsedConfig { config, warnings })
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::super::{ActionKind, VarType};
    use super::*;

    // === Basic parsing ===

    #[test]
    fn parse_empty_config() {
        let config = parse_config("{}").unwrap();
        assert_eq!(config.extends, None);
        assert_eq!(config.defaults, None);
        assert_eq!(config.rules, None);
        assert_eq!(config.definitions, None);
        assert_eq!(config.audit, None);
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
                    allow: true
        "#})
        .unwrap()
        .definitions
        .unwrap()
        .sandbox
        .unwrap();
        let restricted = &sandbox["restricted"];

        let fs = restricted.fs.as_ref().unwrap();
        assert_eq!(
            fs.write_allow(),
            Some(&vec!["./tmp".to_string(), "/tmp".to_string()])
        );
        assert_eq!(fs.write_deny(), Some(&vec!["<path:sensitive>".to_string()]));

        let network = restricted.network.as_ref().unwrap();
        assert_eq!(network.allow, Some(true));
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
    fn parse_definitions_string_lists(#[case] yaml: &str, #[case] expected: Vec<&str>) {
        let defs = parse_config(yaml).unwrap().definitions.unwrap();
        let actual = defs.wrappers.unwrap();
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
                    allow: true

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

    // === AuditConfig parsing ===

    #[test]
    fn parse_audit_full() {
        let config = parse_config(indoc! {"
            audit:
              enabled: false
              path: /tmp/audit/
              rotation:
                retention_days: 30
        "})
        .unwrap();
        let audit = config.audit.unwrap();
        assert_eq!(audit.enabled, Some(false));
        assert_eq!(audit.path.as_deref(), Some("/tmp/audit/"));
        let rotation = audit.rotation.unwrap();
        assert_eq!(rotation.retention_days, Some(30));
    }

    #[test]
    fn parse_audit_partial() {
        let config = parse_config(indoc! {"
            audit:
              enabled: true
        "})
        .unwrap();
        let audit = config.audit.unwrap();
        assert_eq!(audit.enabled, Some(true));
        assert_eq!(audit.path, None);
        assert_eq!(audit.rotation, None);
    }

    #[test]
    fn parse_audit_absent_returns_none() {
        let config = parse_config(indoc! {"
            defaults:
              action: allow
        "})
        .unwrap();
        assert_eq!(config.audit, None);
    }

    // === definitions.vars ===

    #[test]
    fn parse_definitions_vars_literal() {
        let config = parse_config(indoc! {"
            definitions:
              vars:
                instance-ids:
                  type: literal
                  values:
                    - i-abc123
                    - i-def456
        "})
        .unwrap();
        let vars = config.definitions.unwrap().vars.unwrap();
        let var_def = &vars["instance-ids"];
        assert_eq!(var_def.var_type, VarType::Literal);
        assert_eq!(var_def.values, vec!["i-abc123", "i-def456"]);
    }

    #[test]
    fn parse_definitions_vars_path() {
        let config = parse_config(indoc! {"
            definitions:
              vars:
                test-scripts:
                  type: path
                  values:
                    - ./tests/run
                    - ./scripts/test.sh
        "})
        .unwrap();
        let vars = config.definitions.unwrap().vars.unwrap();
        let var_def = &vars["test-scripts"];
        assert_eq!(var_def.var_type, VarType::Path);
        assert_eq!(var_def.values, vec!["./tests/run", "./scripts/test.sh"]);
    }

    #[test]
    fn parse_definitions_vars_default_type_is_literal() {
        let config = parse_config(indoc! {"
            definitions:
              vars:
                regions:
                  values:
                    - us-east-1
                    - eu-west-1
        "})
        .unwrap();
        let vars = config.definitions.unwrap().vars.unwrap();
        let var_def = &vars["regions"];
        assert_eq!(var_def.var_type, VarType::Literal);
        assert_eq!(var_def.values, vec!["us-east-1", "eu-west-1"]);
    }

    #[test]
    fn parse_definitions_vars_multiple_vars() {
        let config = parse_config(indoc! {"
            definitions:
              vars:
                regions:
                  values: [us-east-1]
                instance-ids:
                  type: literal
                  values: [i-abc123]
        "})
        .unwrap();
        let vars = config.definitions.unwrap().vars.unwrap();
        assert!(vars.contains_key("regions"));
        assert!(vars.contains_key("instance-ids"));
    }
}
