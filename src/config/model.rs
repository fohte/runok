use std::collections::{HashMap, HashSet};

use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct Config {
    pub extends: Option<Vec<String>>,
    pub defaults: Option<Defaults>,
    pub rules: Option<Vec<RuleEntry>>,
    pub definitions: Option<Definitions>,
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
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
#[derive(Debug, Deserialize, Clone, PartialEq)]
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

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
pub struct Definitions {
    pub paths: Option<HashMap<String, Vec<String>>>,
    pub sandbox: Option<HashMap<String, SandboxPreset>>,
    pub wrappers: Option<Vec<String>>,
    pub commands: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SandboxPreset {
    pub fs: Option<FsPolicy>,
    pub network: Option<NetworkPolicy>,
}

/// Merged sandbox policy produced by aggregating multiple `SandboxPreset`s.
///
/// Unlike `SandboxPreset` which uses `Option` fields (unset = inherit from
/// defaults), `MergedSandboxPolicy` has concrete resolved values ready for
/// enforcement.
#[derive(Debug, Clone, PartialEq)]
pub struct MergedSandboxPolicy {
    pub writable: Vec<String>,
    pub deny: Vec<String>,
    pub network_allowed: bool,
}

impl SandboxPreset {
    /// Merge multiple sandbox presets using Strictest Wins policy.
    ///
    /// - `writable` (writable roots): intersection across all presets
    /// - `deny` (read-only subpaths): union across all presets
    /// - `network_allowed`: AND; if any preset denies network, the result denies it.
    ///   Presets without a `network` section default to allowed.
    ///
    /// Returns `None` if the input slice is empty.
    pub fn merge_strictest(presets: &[&SandboxPreset]) -> Option<MergedSandboxPolicy> {
        if presets.is_empty() {
            return None;
        }

        let mut writable: Option<HashSet<String>> = None;
        let mut deny: HashSet<String> = HashSet::new();
        // Default to allowed; any explicit deny overrides.
        let mut network_allowed = true;

        for preset in presets {
            // writable: intersection
            if let Some(fs) = &preset.fs {
                if let Some(w) = &fs.writable {
                    let w_set: HashSet<String> = w.iter().cloned().collect();
                    writable = Some(match writable {
                        Some(existing) => existing.intersection(&w_set).cloned().collect(),
                        None => w_set,
                    });
                }

                // deny: union
                if let Some(d) = &fs.deny {
                    deny.extend(d.iter().cloned());
                }
            }

            // network: AND (if any preset explicitly sets allow: false, deny all)
            if let Some(net) = &preset.network
                && let Some(false) = net.allow
            {
                network_allowed = false;
            }
        }

        let mut writable_vec: Vec<String> = writable.unwrap_or_default().into_iter().collect();
        writable_vec.sort();

        let mut deny_vec: Vec<String> = deny.into_iter().collect();
        deny_vec.sort();

        Some(MergedSandboxPolicy {
            writable: writable_vec,
            deny: deny_vec,
            network_allowed,
        })
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct FsPolicy {
    pub writable: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct NetworkPolicy {
    pub allow: Option<bool>,
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

    /// Merge two configs. `self` is the base (e.g. global), `other` is the override (e.g. local).
    ///
    /// - extends / rules / definitions.wrappers / definitions.commands: append
    /// - defaults.action / defaults.sandbox: override (local wins)
    /// - definitions.paths: per-key append (values concatenated, duplicates removed)
    /// - definitions.sandbox: per-key override
    ///   (sandbox presets have interdependent fields like fs.writable and
    ///   fs.deny that must stay consistent; partial merging could create
    ///   contradictory constraints.)
    pub fn merge(self, other: Config) -> Config {
        Config {
            extends: Self::merge_vecs(self.extends, other.extends),
            defaults: Self::merge_defaults(self.defaults, other.defaults),
            rules: Self::merge_vecs(self.rules, other.rules),
            definitions: Self::merge_definitions(self.definitions, other.definitions),
        }
    }

    fn merge_defaults(base: Option<Defaults>, over: Option<Defaults>) -> Option<Defaults> {
        match (base, over) {
            (None, None) => None,
            (Some(b), None) => Some(b),
            (None, Some(o)) => Some(o),
            (Some(b), Some(o)) => Some(Defaults {
                action: o.action.or(b.action),
                sandbox: o.sandbox.or(b.sandbox),
            }),
        }
    }

    fn merge_definitions(
        base: Option<Definitions>,
        over: Option<Definitions>,
    ) -> Option<Definitions> {
        match (base, over) {
            (None, None) => None,
            (Some(b), None) => Some(b),
            (None, Some(o)) => Some(o),
            (Some(b), Some(o)) => Some(Definitions {
                paths: Self::merge_paths(b.paths, o.paths),
                sandbox: Self::merge_hashmaps(b.sandbox, o.sandbox),
                wrappers: Self::merge_vecs(b.wrappers, o.wrappers),
                commands: Self::merge_vecs(b.commands, o.commands),
            }),
        }
    }

    /// Merge paths with per-key append strategy: values are concatenated and deduplicated.
    fn merge_paths(
        base: Option<HashMap<String, Vec<String>>>,
        over: Option<HashMap<String, Vec<String>>>,
    ) -> Option<HashMap<String, Vec<String>>> {
        match (base, over) {
            (Some(mut b), Some(o)) => {
                for (key, over_values) in o {
                    let entry = b.entry(key).or_default();
                    let existing: HashSet<String> = entry.iter().cloned().collect();
                    entry.extend(over_values.into_iter().filter(|v| !existing.contains(v)));
                }
                Some(b)
            }
            (b, o) => b.or(o),
        }
    }

    fn merge_hashmaps<K: Eq + std::hash::Hash, V>(
        base: Option<HashMap<K, V>>,
        over: Option<HashMap<K, V>>,
    ) -> Option<HashMap<K, V>> {
        match (base, over) {
            (Some(mut b), Some(o)) => {
                b.extend(o);
                Some(b)
            }
            (b, o) => b.or(o),
        }
    }

    fn merge_vecs<T>(base: Option<Vec<T>>, over: Option<Vec<T>>) -> Option<Vec<T>> {
        match (base, over) {
            (Some(mut b), Some(o)) => {
                b.extend(o);
                Some(b)
            }
            (b, o) => b.or(o),
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
            fs.writable,
            Some(vec!["./tmp".to_string(), "/tmp".to_string()])
        );
        assert_eq!(fs.deny, Some(vec!["<path:sensitive>".to_string()]));

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

    // === Config::merge ===

    #[test]
    fn merge_both_default() {
        let result = Config::default().merge(Config::default());
        assert_eq!(result, Config::default());
    }

    #[test]
    fn merge_base_only() {
        let base = Config {
            rules: Some(vec![RuleEntry {
                deny: Some("rm -rf /".to_string()),
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
            }]),
            ..Config::default()
        };
        let result = base.clone().merge(Config::default());
        assert_eq!(result, base);
    }

    #[test]
    fn merge_override_only() {
        let over = Config {
            rules: Some(vec![RuleEntry {
                allow: Some("git status".to_string()),
                deny: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
            }]),
            ..Config::default()
        };
        let result = Config::default().merge(over.clone());
        assert_eq!(result, over);
    }

    #[test]
    fn merge_defaults_action_overridden() {
        let base = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Deny),
                sandbox: None,
            }),
            ..Config::default()
        };
        let over = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Allow),
                sandbox: None,
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        assert_eq!(result.defaults.unwrap().action, Some(ActionKind::Allow));
    }

    #[test]
    fn merge_defaults_sandbox_overridden() {
        let base = Config {
            defaults: Some(Defaults {
                action: None,
                sandbox: Some("global-sandbox".to_string()),
            }),
            ..Config::default()
        };
        let over = Config {
            defaults: Some(Defaults {
                action: None,
                sandbox: Some("local-sandbox".to_string()),
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        assert_eq!(
            result.defaults.unwrap().sandbox.as_deref(),
            Some("local-sandbox")
        );
    }

    #[test]
    fn merge_defaults_partial_override() {
        let base = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Deny),
                sandbox: Some("global-sandbox".to_string()),
            }),
            ..Config::default()
        };
        let over = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Allow),
                sandbox: None,
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let defaults = result.defaults.unwrap();
        assert_eq!(defaults.action, Some(ActionKind::Allow));
        assert_eq!(defaults.sandbox.as_deref(), Some("global-sandbox"));
    }

    #[test]
    fn merge_rules_appended() {
        let base = Config {
            rules: Some(vec![RuleEntry {
                deny: Some("rm -rf /".to_string()),
                allow: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
            }]),
            ..Config::default()
        };
        let over = Config {
            rules: Some(vec![RuleEntry {
                allow: Some("git status".to_string()),
                deny: None,
                ask: None,
                when: None,
                message: None,
                fix_suggestion: None,
                sandbox: None,
            }]),
            ..Config::default()
        };
        let result = base.merge(over);
        let rules = result.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status"));
    }

    #[test]
    fn merge_definitions_paths_appended_per_key() {
        let base = Config {
            definitions: Some(Definitions {
                paths: Some(HashMap::from([
                    (
                        "sensitive".to_string(),
                        vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()],
                    ),
                    ("logs".to_string(), vec!["/var/log/**".to_string()]),
                ])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let over = Config {
            definitions: Some(Definitions {
                paths: Some(HashMap::from([(
                    "sensitive".to_string(),
                    vec![".env".to_string(), "/etc/passwd".to_string()],
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let paths = result.definitions.unwrap().paths.unwrap();
        // "sensitive" values are appended with deduplication:
        // base order preserved, then new override values appended
        let mut sensitive = paths["sensitive"].clone();
        sensitive.sort();
        assert_eq!(sensitive, vec![".env", "/etc/passwd", "/etc/shadow"]);
        // "logs" is preserved from base
        assert_eq!(paths["logs"], vec!["/var/log/**"]);
    }

    #[test]
    fn merge_definitions_paths_deduplicates() {
        let base = Config {
            definitions: Some(Definitions {
                paths: Some(HashMap::from([(
                    "sensitive".to_string(),
                    vec![
                        "/etc/passwd".to_string(),
                        ".env".to_string(),
                        "~/.ssh/**".to_string(),
                    ],
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let over = Config {
            definitions: Some(Definitions {
                paths: Some(HashMap::from([(
                    "sensitive".to_string(),
                    vec![
                        ".env".to_string(),
                        "/etc/passwd".to_string(),
                        "/secrets/**".to_string(),
                    ],
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let mut sensitive = result.definitions.unwrap().paths.unwrap()["sensitive"].clone();
        // base has 3, override has 3, but 2 are duplicates -> 4 unique
        sensitive.sort();
        assert_eq!(
            sensitive,
            vec![".env", "/etc/passwd", "/secrets/**", "~/.ssh/**"]
        );
    }

    #[test]
    fn merge_definitions_sandbox_per_key() {
        let base = Config {
            definitions: Some(Definitions {
                sandbox: Some(HashMap::from([(
                    "restricted".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["./tmp".to_string()]),
                            deny: None,
                        }),
                        network: None,
                    },
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let over = Config {
            definitions: Some(Definitions {
                sandbox: Some(HashMap::from([(
                    "restricted".to_string(),
                    SandboxPreset {
                        fs: None,
                        network: Some(NetworkPolicy { allow: Some(true) }),
                    },
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let sandbox = result.definitions.unwrap().sandbox.unwrap();
        // local completely replaces the key
        let restricted = &sandbox["restricted"];
        assert_eq!(restricted.fs, None);
        assert!(restricted.network.is_some());
    }

    #[test]
    fn merge_definitions_wrappers_appended() {
        let base = Config {
            definitions: Some(Definitions {
                wrappers: Some(vec!["sudo <cmd>".to_string()]),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let over = Config {
            definitions: Some(Definitions {
                wrappers: Some(vec!["bash -c <cmd>".to_string()]),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let wrappers = result.definitions.unwrap().wrappers.unwrap();
        assert_eq!(wrappers, vec!["sudo <cmd>", "bash -c <cmd>"]);
    }

    #[test]
    fn merge_definitions_commands_appended() {
        let base = Config {
            definitions: Some(Definitions {
                commands: Some(vec!["git commit".to_string()]),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let over = Config {
            definitions: Some(Definitions {
                commands: Some(vec!["git push".to_string()]),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let commands = result.definitions.unwrap().commands.unwrap();
        assert_eq!(commands, vec!["git commit", "git push"]);
    }

    #[test]
    fn merge_extends_appended() {
        let base = Config {
            extends: Some(vec!["./base.yml".to_string()]),
            ..Config::default()
        };
        let over = Config {
            extends: Some(vec!["./local.yml".to_string()]),
            ..Config::default()
        };
        let result = base.merge(over);
        assert_eq!(result.extends.unwrap(), vec!["./base.yml", "./local.yml"]);
    }

    // === Config::validate ===

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

    // === SandboxPreset::merge_strictest ===

    #[test]
    fn merge_strictest_empty_returns_none() {
        assert_eq!(SandboxPreset::merge_strictest(&[]), None);
    }

    #[test]
    fn merge_strictest_single_preset() {
        let preset = SandboxPreset {
            fs: Some(FsPolicy {
                writable: Some(vec!["/tmp".to_string(), "/home".to_string()]),
                deny: Some(vec!["/etc".to_string()]),
            }),
            network: Some(NetworkPolicy { allow: Some(true) }),
        };
        let result = SandboxPreset::merge_strictest(&[&preset]).unwrap();
        assert_eq!(result.writable, vec!["/home", "/tmp"]);
        assert_eq!(result.deny, vec!["/etc"]);
        assert!(result.network_allowed);
    }

    #[rstest]
    #[case::non_empty_intersection(
        vec!["/tmp".to_string(), "/home".to_string(), "/var".to_string()],
        vec!["/tmp".to_string(), "/var".to_string()],
        vec!["/tmp", "/var"],
    )]
    #[case::empty_intersection(
        vec!["/tmp".to_string()],
        vec!["/home".to_string()],
        vec![],
    )]
    fn merge_strictest_writable_intersection(
        #[case] writable_a: Vec<String>,
        #[case] writable_b: Vec<String>,
        #[case] expected: Vec<&str>,
    ) {
        let a = SandboxPreset {
            fs: Some(FsPolicy {
                writable: Some(writable_a),
                deny: None,
            }),
            network: None,
        };
        let b = SandboxPreset {
            fs: Some(FsPolicy {
                writable: Some(writable_b),
                deny: None,
            }),
            network: None,
        };
        let result = SandboxPreset::merge_strictest(&[&a, &b]).unwrap();
        assert_eq!(result.writable, expected);
    }

    #[test]
    fn merge_strictest_deny_union() {
        let a = SandboxPreset {
            fs: Some(FsPolicy {
                writable: Some(vec!["/tmp".to_string()]),
                deny: Some(vec!["/etc/passwd".to_string()]),
            }),
            network: None,
        };
        let b = SandboxPreset {
            fs: Some(FsPolicy {
                writable: Some(vec!["/tmp".to_string()]),
                deny: Some(vec!["/etc/shadow".to_string()]),
            }),
            network: None,
        };
        let result = SandboxPreset::merge_strictest(&[&a, &b]).unwrap();
        assert_eq!(result.deny, vec!["/etc/passwd", "/etc/shadow"]);
    }

    #[rstest]
    #[case::both_allowed(
        Some(NetworkPolicy { allow: Some(true) }),
        Some(NetworkPolicy { allow: Some(true) }),
        true,
    )]
    #[case::one_denied(
        Some(NetworkPolicy { allow: Some(true) }),
        Some(NetworkPolicy { allow: Some(false) }),
        false,
    )]
    #[case::both_denied(
        Some(NetworkPolicy { allow: Some(false) }),
        Some(NetworkPolicy { allow: Some(false) }),
        false,
    )]
    #[case::none_defaults_to_allowed(
        Some(NetworkPolicy { allow: Some(true) }),
        None,
        true,
    )]
    fn merge_strictest_network(
        #[case] network_a: Option<NetworkPolicy>,
        #[case] network_b: Option<NetworkPolicy>,
        #[case] expected: bool,
    ) {
        let a = SandboxPreset {
            fs: None,
            network: network_a,
        };
        let b = SandboxPreset {
            fs: None,
            network: network_b,
        };
        let result = SandboxPreset::merge_strictest(&[&a, &b]).unwrap();
        assert_eq!(result.network_allowed, expected);
    }

    #[test]
    fn merge_strictest_no_fs_preserves_other() {
        let a = SandboxPreset {
            fs: Some(FsPolicy {
                writable: Some(vec!["/tmp".to_string()]),
                deny: Some(vec!["/etc".to_string()]),
            }),
            network: None,
        };
        let b = SandboxPreset {
            fs: None,
            network: Some(NetworkPolicy { allow: Some(true) }),
        };
        let result = SandboxPreset::merge_strictest(&[&a, &b]).unwrap();
        assert_eq!(result.writable, vec!["/tmp"]);
        assert_eq!(result.deny, vec!["/etc"]);
        assert!(result.network_allowed);
    }
}
