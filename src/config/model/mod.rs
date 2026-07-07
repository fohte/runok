mod audit_config;
mod merge;
mod parse;
mod schema_gen;
mod validate;

pub use audit_config::{AuditConfig, RotationConfig};
pub use parse::{ParsedConfig, parse_config, parse_config_with_warnings};
#[cfg(feature = "config-schema")]
pub use schema_gen::print_config_schema;

use std::collections::{HashMap, HashSet};

#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::Deserializer;

/// Top-level runok configuration.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct Config {
    /// Minimum runok version required to load this file. Semver requirement
    /// expression (e.g. `">=0.3.0"`, `">=0.3, <0.5"`). When set, loading the
    /// file with an older runok fails with a clear error, so preset authors
    /// can guard files that depend on newer schema or features.
    pub required_runok_version: Option<String>,
    /// List of configuration files to inherit from. Supports local paths and
    /// remote Git repositories (`github:<owner>/<repo>[/<path>][@<ref>]`).
    pub extends: Option<Vec<String>>,
    /// Default settings applied when no rule matches.
    pub defaults: Option<Defaults>,
    /// Ordered list of permission rules evaluated against each command.
    pub rules: Option<Vec<RuleEntry>>,
    /// Reusable definitions for paths, sandbox presets, wrappers, and variables.
    pub definitions: Option<Definitions>,
    /// Audit log settings.
    pub audit: Option<AuditConfig>,
    /// Test section for rule verification.
    pub tests: Option<TestSection>,
}

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
#[cfg_attr(any(feature = "config-schema", test), schemars(transform = schema_gen::rule_entry_one_of_transform))]
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
#[cfg_attr(any(feature = "config-schema", test), schemars(transform = schema_gen::inline_test_entry_one_of_transform))]
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

/// Reusable definitions for paths, sandbox presets, wrappers, variables, and flag groups.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct Definitions {
    /// Named path lists referenced by `<path:name>` in sandbox deny rules.
    pub paths: Option<HashMap<String, Vec<String>>>,
    /// Named sandbox presets that can be referenced by rules.
    pub sandbox: Option<HashMap<String, SandboxPreset>>,
    /// Wrapper command patterns for recursive evaluation (e.g., `sudo <cmd>`).
    pub wrappers: Option<Vec<String>>,
    /// Typed variable definitions referenced by `<var:name>` in rule patterns.
    pub vars: Option<HashMap<String, VarDefinition>>,
    /// Named flag alias groups referenced by `<flag:name>` in rule patterns.
    /// Each value is a pattern string using the same syntax as rule patterns:
    /// alternation for aliases, with an optional value pattern suffix.
    ///
    /// Examples:
    /// - `"-f|-F|--field|--raw-field *"` — value flag (captures flag + value)
    /// - `"-v|--verbose"` — bool flag (captures flag presence only)
    /// - `"-X|--method GET|HEAD|OPTIONS"` — value flag with restricted values
    pub flag_groups: Option<HashMap<String, String>>,

    /// Rule-pattern aliases. Each entry maps an alias name to one or more
    /// pattern strings. At rule-load time, any rule whose leading command
    /// token equals an alias name is expanded once per alias pattern by
    /// string-substituting the alias pattern in for the alias name. This
    /// lets you factor out a repeated prefix (e.g. shared optional flags)
    /// from many rules.
    pub aliases: Option<HashMap<String, AliasDefinition>>,

    /// Pre-parsed flag group definitions, populated by `resolve_flag_groups()`.
    /// Avoids re-parsing the same definition string on every `<flag:name>` match.
    #[serde(skip)]
    #[cfg_attr(any(feature = "config-schema", test), schemars(skip))]
    pub parsed_flag_groups: Option<HashMap<String, crate::rules::pattern_parser::ParsedFlagGroup>>,

    /// Pre-parsed pattern-typed variable values, populated by `resolve_pattern_vars()`.
    /// Keyed by variable name; each entry stores the parsed `Pattern` for every
    /// value of that variable that has effective type `pattern`.
    #[serde(skip)]
    #[cfg_attr(any(feature = "config-schema", test), schemars(skip))]
    pub parsed_pattern_vars: Option<HashMap<String, Vec<crate::rules::pattern_parser::Pattern>>>,
}

impl Definitions {
    /// Parse all `flag_groups` definition strings and cache the results in
    /// `parsed_flag_groups`. Call this once after deserialization / merging
    /// so that `<flag:name>` lookups during pattern matching never re-parse.
    pub fn resolve_flag_groups(&mut self) {
        let Some(groups) = &self.flag_groups else {
            self.parsed_flag_groups = None;
            return;
        };

        let mut parsed = HashMap::with_capacity(groups.len());
        for (name, definition) in groups {
            if let Ok(pg) = crate::rules::pattern_parser::parse_flag_group_definition(definition) {
                parsed.insert(name.clone(), pg);
            }
            // Invalid definitions are silently skipped here; validation
            // already reports errors for them separately.
        }
        self.parsed_flag_groups = Some(parsed);
    }

    /// Parse every `pattern`-typed variable value into a `Pattern` AST and
    /// cache the result in `parsed_pattern_vars`. Call this once after
    /// deserialization / merging so that `<var:name>` lookups for pattern-typed
    /// variables never re-parse during matching.
    pub fn resolve_pattern_vars(&mut self) {
        let Some(vars) = &self.vars else {
            self.parsed_pattern_vars = None;
            return;
        };

        let mut parsed: HashMap<String, Vec<crate::rules::pattern_parser::Pattern>> =
            HashMap::new();
        for (name, var_def) in vars {
            let mut entries = Vec::new();
            for var_value in &var_def.values {
                let effective_type = var_value.effective_type(var_def.var_type);
                if effective_type != VarType::Pattern {
                    continue;
                }
                if let Ok(p) = crate::rules::pattern_parser::parse(var_value.value()) {
                    entries.push(p);
                }
                // Parse errors are reported by `validate()`; skip silently here.
            }
            if !entries.is_empty() {
                parsed.insert(name.clone(), entries);
            }
        }
        self.parsed_pattern_vars = Some(parsed);
    }
}

/// Type of a variable definition, controlling how values are matched.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum VarType {
    /// Exact string match (default).
    #[default]
    Literal,
    /// Path match: canonicalize both sides before comparison,
    /// falling back to `normalize_path` when the file does not exist.
    Path,
    /// Pattern match: each value is parsed as a rule-pattern fragment and
    /// expanded inline at the `<var:name>` placeholder's position. Useful
    /// for naming a reusable command-prefix pattern such as
    /// `"kubectl [-n|--namespace *] [--context *] [--cluster *]"`.
    Pattern,
}

/// A single value in a variable definition, optionally carrying its own type.
#[derive(Debug, Clone, PartialEq)]
pub enum VarValue {
    /// A plain string that inherits the definition-level type.
    Plain(String),
    /// A value with an explicit per-value type override.
    Typed { var_type: VarType, value: String },
}

impl VarValue {
    /// Return the string value.
    pub fn value(&self) -> &str {
        match self {
            VarValue::Plain(s) => s,
            VarValue::Typed { value, .. } => value,
        }
    }

    /// Return the effective type, falling back to the given definition-level type.
    pub fn effective_type(&self, definition_type: VarType) -> VarType {
        match self {
            VarValue::Plain(_) => definition_type,
            VarValue::Typed { var_type, .. } => *var_type,
        }
    }
}

#[cfg(any(feature = "config-schema", test))]
impl JsonSchema for VarValue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "VarValue".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        use schemars::json_schema;

        // A VarValue is either a plain string or a { type, value } mapping.
        json_schema!({
            "description": "A variable value: either a plain string (inherits definition-level type) \
                or an object with explicit `type` and `value` fields.",
            "oneOf": [
                { "type": "string" },
                {
                    "type": "object",
                    "properties": {
                        "type": generator.subschema_for::<VarType>(),
                        "value": { "type": "string" }
                    },
                    "required": ["type", "value"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

impl From<&str> for VarValue {
    fn from(s: &str) -> Self {
        VarValue::Plain(s.to_string())
    }
}

impl From<String> for VarValue {
    fn from(s: String) -> Self {
        VarValue::Plain(s)
    }
}

impl PartialEq<&str> for VarValue {
    fn eq(&self, other: &&str) -> bool {
        match self {
            VarValue::Plain(s) => s == *other,
            VarValue::Typed { value, .. } => value == *other,
        }
    }
}

impl<'de> Deserialize<'de> for VarValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Helper struct for deserializing `{ type: ..., value: ... }` form.
        #[derive(Deserialize)]
        struct TypedForm {
            #[serde(rename = "type")]
            var_type: VarType,
            value: String,
        }

        /// Internal untagged enum to handle both string and mapping forms.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawVarValue {
            Plain(String),
            Typed(TypedForm),
        }

        match RawVarValue::deserialize(deserializer)? {
            RawVarValue::Plain(s) => Ok(VarValue::Plain(s)),
            RawVarValue::Typed(t) => Ok(VarValue::Typed {
                var_type: t.var_type,
                value: t.value,
            }),
        }
    }
}

/// A typed variable definition with a list of allowed values.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct VarDefinition {
    /// The type of this variable (default: `literal`).
    #[serde(default, rename = "type")]
    pub var_type: VarType,
    /// Allowed values for this variable.
    pub values: Vec<VarValue>,
}

/// Sandbox preset defining filesystem and network restrictions.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct SandboxPreset {
    /// Filesystem access policy.
    pub fs: Option<FsPolicy>,
    /// Network access policy.
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
    /// Paths denied for reading. When non-empty, these paths are blocked from
    /// both read and write access in the sandbox.
    pub read_deny: Vec<String>,
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
        let mut read_deny: HashSet<String> = HashSet::new();
        // Default to allowed; any explicit deny overrides.
        let mut network_allowed = true;

        for preset in presets {
            // writable (write.allow): intersection
            if let Some(fs) = &preset.fs {
                if let Some(w) = fs.write_allow() {
                    let w_set: HashSet<String> = w.iter().cloned().collect();
                    writable = Some(match writable {
                        Some(existing) => existing.intersection(&w_set).cloned().collect(),
                        None => w_set,
                    });
                }

                // write deny: union
                if let Some(d) = fs.write_deny() {
                    deny.extend(d.iter().cloned());
                }

                // read deny: union
                if let Some(rd) = fs.read_deny() {
                    read_deny.extend(rd.iter().cloned());
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

        let mut read_deny_vec: Vec<String> = read_deny.into_iter().collect();
        read_deny_vec.sort();

        Some(MergedSandboxPolicy {
            writable: writable_vec,
            deny: deny_vec,
            read_deny: read_deny_vec,
            network_allowed,
        })
    }
}

/// Filesystem access policy within a sandbox preset.
///
/// Supports a new `read`/`write` format and a deprecated legacy `writable`/`deny` format
/// (the latter emits a warning at parse time).
#[derive(Debug, Clone, PartialEq)]
pub struct FsPolicy {
    /// Read access policy.
    pub read: Option<FsAccessPolicy>,
    /// Write access policy.
    pub write: Option<FsAccessPolicy>,
}

/// Access policy for a single operation (read or write).
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct FsAccessPolicy {
    /// Paths that are allowed for this operation.
    pub allow: Option<Vec<String>>,
    /// Paths that are denied for this operation. Supports `<path:name>` references.
    pub deny: Option<Vec<String>>,
}

impl FsPolicy {
    /// Returns write-allow paths (equivalent to legacy `writable`).
    pub fn write_allow(&self) -> Option<&Vec<String>> {
        self.write.as_ref().and_then(|w| w.allow.as_ref())
    }

    /// Returns write-deny paths (equivalent to legacy `deny`).
    pub fn write_deny(&self) -> Option<&Vec<String>> {
        self.write.as_ref().and_then(|w| w.deny.as_ref())
    }

    /// Returns read-deny paths.
    pub fn read_deny(&self) -> Option<&Vec<String>> {
        self.read.as_ref().and_then(|r| r.deny.as_ref())
    }

    /// Returns read-allow paths.
    pub fn read_allow(&self) -> Option<&Vec<String>> {
        self.read.as_ref().and_then(|r| r.allow.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for FsPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NewFormat {
            read: Option<FsAccessPolicy>,
            write: Option<FsAccessPolicy>,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyFormat {
            writable: Option<Vec<String>>,
            deny: Option<Vec<String>>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum FsPolicyFormat {
            New(NewFormat),
            Legacy(LegacyFormat),
        }

        match FsPolicyFormat::deserialize(deserializer)? {
            FsPolicyFormat::New(new) => Ok(FsPolicy {
                read: new.read,
                write: new.write,
            }),
            FsPolicyFormat::Legacy(legacy) => {
                parse::push_parse_warning(
                    "sandbox fs 'writable'/'deny' fields are deprecated, \
                     use 'write: { allow: [...], deny: [...] }' instead. \
                     Run `runok migrate` to update automatically"
                        .to_string(),
                );
                Ok(FsPolicy {
                    read: None,
                    write: if legacy.writable.is_some() || legacy.deny.is_some() {
                        Some(FsAccessPolicy {
                            allow: legacy.writable,
                            deny: legacy.deny,
                        })
                    } else {
                        None
                    },
                })
            }
        }
    }
}

#[cfg(any(feature = "config-schema", test))]
impl JsonSchema for FsPolicy {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "FsPolicy".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        use schemars::json_schema;

        json_schema!({
            "anyOf": [
                {
                    "type": "object",
                    "description": "New format with read/write sub-sections",
                    "additionalProperties": false,
                    "properties": {
                        "read": generator.subschema_for::<FsAccessPolicy>(),
                        "write": generator.subschema_for::<FsAccessPolicy>()
                    }
                },
                {
                    "type": "object",
                    "description": "Legacy format (deprecated)",
                    "additionalProperties": false,
                    "properties": {
                        "writable": {
                            "type": ["array", "null"],
                            "items": { "type": "string" }
                        },
                        "deny": {
                            "type": ["array", "null"],
                            "items": { "type": "string" }
                        }
                    }
                }
            ]
        })
    }
}

/// Network access policy within a sandbox preset.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct NetworkPolicy {
    /// Whether network access is allowed.
    pub allow: Option<bool>,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

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

    // === SandboxPreset::merge_strictest ===

    #[test]
    fn merge_strictest_empty_returns_none() {
        assert_eq!(SandboxPreset::merge_strictest(&[]), None);
    }

    #[test]
    fn merge_strictest_single_preset() {
        let preset = SandboxPreset {
            fs: Some(FsPolicy {
                read: None,
                write: Some(FsAccessPolicy {
                    allow: Some(vec!["/tmp".to_string(), "/home".to_string()]),
                    deny: Some(vec!["/etc".to_string()]),
                }),
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
                read: None,
                write: Some(FsAccessPolicy {
                    allow: Some(writable_a),
                    deny: None,
                }),
            }),
            network: None,
        };
        let b = SandboxPreset {
            fs: Some(FsPolicy {
                read: None,
                write: Some(FsAccessPolicy {
                    allow: Some(writable_b),
                    deny: None,
                }),
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
                read: None,
                write: Some(FsAccessPolicy {
                    allow: Some(vec!["/tmp".to_string()]),
                    deny: Some(vec!["/etc/passwd".to_string()]),
                }),
            }),
            network: None,
        };
        let b = SandboxPreset {
            fs: Some(FsPolicy {
                read: None,
                write: Some(FsAccessPolicy {
                    allow: Some(vec!["/tmp".to_string()]),
                    deny: Some(vec!["/etc/shadow".to_string()]),
                }),
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
                read: None,
                write: Some(FsAccessPolicy {
                    allow: Some(vec!["/tmp".to_string()]),
                    deny: Some(vec!["/etc".to_string()]),
                }),
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
