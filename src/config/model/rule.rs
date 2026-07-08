#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;

/// Definition of a single alias entry. Accepts either a single pattern
/// string or a list of pattern strings in YAML.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
#[serde(untagged)]
pub enum AliasDefinition {
    /// A single pattern string.
    Single(String),
    /// A list of pattern strings.
    Many(Vec<String>),
}

impl AliasDefinition {
    /// Return all patterns for this alias entry as a slice-like iterator.
    pub fn patterns(&self) -> Vec<&str> {
        match self {
            AliasDefinition::Single(s) => vec![s.as_str()],
            AliasDefinition::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// Default settings applied when no rule matches a command.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct Defaults {
    /// Default action when no rule matches: `allow`, `deny`, or `ask`.
    pub action: Option<ActionKind>,
    /// Default sandbox preset name to apply.
    pub sandbox: Option<String>,
}

/// Permission action kind.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Allow,
    #[default]
    Ask,
    Deny,
}

/// A permission rule entry. Exactly one of `deny`, `allow`, or `ask` must be set.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
#[cfg_attr(any(feature = "config-schema", test), schemars(transform = super::schema_gen::rule_entry_one_of_transform))]
pub struct RuleEntry {
    /// Command pattern to deny. Matched commands are rejected.
    pub deny: Option<String>,
    /// Command pattern to allow. Matched commands are permitted.
    pub allow: Option<String>,
    /// Command pattern to ask about. Matched commands prompt for confirmation.
    pub ask: Option<String>,
    /// CEL expression that must evaluate to true for this rule to apply.
    pub when: Option<String>,
    /// Message shown when the rule matches (primarily for deny rules).
    pub message: Option<String>,
    /// Suggested fix command shown when a deny rule matches.
    pub fix_suggestion: Option<String>,
    /// Sandbox preset name to apply when this rule matches (not allowed for deny rules).
    pub sandbox: Option<String>,
    /// Inline test cases for this rule.
    pub tests: Option<Vec<InlineTestEntry>>,
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

/// A test case entry used in both inline rule tests and top-level test cases.
/// Exactly one of `allow`, `ask`, or `deny` must be set. The key determines
/// the expected decision, the value is the command to evaluate.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
#[cfg_attr(any(feature = "config-schema", test), schemars(transform = super::schema_gen::inline_test_entry_one_of_transform))]
pub struct InlineTestEntry {
    /// Command expected to be allowed.
    pub allow: Option<String>,
    /// Command expected to trigger an ask prompt.
    pub ask: Option<String>,
    /// Command expected to be denied.
    pub deny: Option<String>,
}

/// Top-level test section for cross-rule tests and test-only extends.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct TestSection {
    /// Additional config files to merge only during test execution.
    pub extends: Option<Vec<String>>,
    /// Test cases to evaluate.
    pub cases: Option<Vec<InlineTestEntry>>,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::config::parse_config;

    use super::*;

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
            tests: None,
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
            tests: None,
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
            tests: None,
        };
        assert!(rule.action_and_pattern().is_none());
    }
}
