use std::collections::{HashMap, HashSet};

#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;

/// Top-level runok configuration.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct Config {
    /// List of configuration files to inherit from. Supports local paths and
    /// remote Git repositories (`github:<owner>/<repo>[/<path>][@<ref>]`).
    pub extends: Option<Vec<String>>,
    /// Default settings applied when no rule matches.
    pub defaults: Option<Defaults>,
    /// Ordered list of permission rules evaluated against each command.
    pub rules: Option<Vec<RuleEntry>>,
    /// Reusable definitions for paths, sandbox presets, wrappers, and commands.
    pub definitions: Option<Definitions>,
    /// Audit log settings.
    pub audit: Option<AuditConfig>,
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
#[cfg_attr(any(feature = "config-schema", test), schemars(transform = rule_entry_one_of_transform))]
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

/// Reusable definitions for paths, sandbox presets, wrappers, and commands.
#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct Definitions {
    /// Named path lists referenced by `<path:name>` in sandbox deny rules.
    pub paths: Option<HashMap<String, Vec<String>>>,
    /// Named sandbox presets that can be referenced by rules.
    pub sandbox: Option<HashMap<String, SandboxPreset>>,
    /// Wrapper command patterns for recursive evaluation (e.g., `sudo <cmd>`).
    pub wrappers: Option<Vec<String>>,
    /// Additional command patterns to recognize.
    pub commands: Option<Vec<String>>,
    /// Typed variable definitions referenced by `<var:name>` in rule patterns.
    pub vars: Option<HashMap<String, VarDefinition>>,
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
}

/// A typed variable definition with a list of allowed values.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct VarDefinition {
    /// The type of this variable (default: `literal`).
    #[serde(default, rename = "type")]
    pub var_type: VarType,
    /// Allowed values for this variable.
    pub values: Vec<String>,
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

/// Filesystem access policy within a sandbox preset.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct FsPolicy {
    /// Directories the sandboxed process is allowed to write to.
    pub writable: Option<Vec<String>>,
    /// Paths the sandboxed process is denied access to. Supports `<path:name>` references.
    pub deny: Option<Vec<String>>,
}

/// Network access policy within a sandbox preset.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct NetworkPolicy {
    /// Whether network access is allowed.
    pub allow: Option<bool>,
}

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
            let Some(deny) = fs.deny.as_mut() else {
                continue;
            };

            let mut expanded = Vec::new();
            for entry in deny.iter() {
                if let Some(name) = entry
                    .strip_prefix("<path:")
                    .and_then(|s| s.strip_suffix('>'))
                {
                    match paths.as_ref().and_then(|p| p.get(name)) {
                        Some(path_list) => expanded.extend(path_list.iter().cloned()),
                        None => errors.push(format!(
                            "sandbox preset '{}': fs.deny references undefined path '{}'. \
                             Define it in definitions.paths.{}",
                            preset_name, name, name
                        )),
                    }
                } else {
                    expanded.push(entry.clone());
                }
            }
            *deny = expanded;
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

        // Reject <path:name> references inside definitions.paths values.
        // The <path:name> syntax is only valid in pattern contexts (rule
        // patterns, fs.deny), not inside path definitions themselves.
        if let Some(defs) = &self.definitions
            && let Some(paths) = &defs.paths
        {
            for (key, values) in paths {
                for value in values {
                    if value.starts_with("<path:") && value.ends_with('>') {
                        errors.push(format!(
                            "definitions.paths.{key}: value '{value}' contains a <path:name> \
                             reference. Path definitions must contain concrete paths, not references"
                        ));
                    }
                }
            }
        }

        // Reject <var:name> and <path:name> references inside definitions.vars values.
        if let Some(defs) = &self.definitions
            && let Some(vars) = &defs.vars
        {
            for (key, var_def) in vars {
                for value in &var_def.values {
                    if (value.starts_with("<var:") || value.starts_with("<path:"))
                        && value.ends_with('>')
                    {
                        errors.push(format!(
                            "definitions.vars.{key}: value '{value}' contains a placeholder \
                             reference. Variable definitions must contain concrete values, not references"
                        ));
                    }
                }
            }
        }

        let rules = match &self.rules {
            Some(rules) => rules,
            None => {
                return if errors.is_empty() {
                    Ok(())
                } else {
                    Err(crate::config::ConfigError::Validation(errors))
                };
            }
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
    /// - audit: override (local wins at merge level; loader enforces
    ///   global-only by stripping audit from project/local layers)
    pub fn merge(self, other: Config) -> Config {
        Config {
            extends: Self::merge_vecs(self.extends, other.extends),
            defaults: Self::merge_defaults(self.defaults, other.defaults),
            rules: Self::merge_vecs(self.rules, other.rules),
            definitions: Self::merge_definitions(self.definitions, other.definitions),
            audit: Self::merge_audit(self.audit, other.audit),
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
                vars: Self::merge_vars(b.vars, o.vars),
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

    /// Merge vars with per-key override strategy: the override wins for each key.
    fn merge_vars(
        base: Option<HashMap<String, VarDefinition>>,
        over: Option<HashMap<String, VarDefinition>>,
    ) -> Option<HashMap<String, VarDefinition>> {
        match (base, over) {
            (Some(mut b), Some(o)) => {
                b.extend(o);
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

    fn merge_audit(base: Option<AuditConfig>, over: Option<AuditConfig>) -> Option<AuditConfig> {
        match (base, over) {
            (None, None) => None,
            (Some(b), None) => Some(b),
            (None, Some(o)) => Some(o),
            (Some(b), Some(o)) => Some(AuditConfig {
                enabled: o.enabled.or(b.enabled),
                path: o.path.or(b.path),
                rotation: Self::merge_rotation(b.rotation, o.rotation),
            }),
        }
    }

    fn merge_rotation(
        base: Option<RotationConfig>,
        over: Option<RotationConfig>,
    ) -> Option<RotationConfig> {
        match (base, over) {
            (None, None) => None,
            (Some(b), None) => Some(b),
            (None, Some(o)) => Some(o),
            (Some(b), Some(o)) => Some(RotationConfig {
                retention_days: o.retention_days.or(b.retention_days),
            }),
        }
    }
}

/// Transform the generated `RuleEntry` schema into a `oneOf` with three variants:
/// - `deny`: requires `deny`, forbids `allow`/`ask`/`sandbox`
/// - `allow`: requires `allow`, forbids `deny`/`ask`
/// - `ask`: requires `ask`, forbids `deny`/`allow`
#[cfg(any(feature = "config-schema", test))]
fn rule_entry_one_of_transform(schema: &mut schemars::Schema) {
    let common_optional = ["when", "message", "fix_suggestion"];

    let make_variant = |action: &str, extra_optional: &[&str]| -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let required = vec![serde_json::Value::String(action.to_string())];

        // Action field (required)
        properties.insert(
            action.to_string(),
            serde_json::json!({ "type": "string", "description": schema.get("properties").and_then(|p| p.get(action)).and_then(|a| a.get("description")).cloned().unwrap_or(serde_json::Value::Null) }),
        );

        // Common optional fields
        for field in &common_optional {
            if let Some(prop) = schema
                .get("properties")
                .and_then(|p| p.get(*field))
                .cloned()
            {
                properties.insert(field.to_string(), prop);
            }
        }

        // Extra optional fields (e.g., sandbox)
        for field in extra_optional {
            if let Some(prop) = schema
                .get("properties")
                .and_then(|p| p.get(*field))
                .cloned()
            {
                properties.insert(field.to_string(), prop);
            }
        }

        serde_json::json!({
            "type": "object",
            "properties": serde_json::Value::Object(properties),
            "required": serde_json::Value::Array(required),
            "additionalProperties": false
        })
    };

    let deny_variant = make_variant("deny", &[]);
    let allow_variant = make_variant("allow", &["sandbox"]);
    let ask_variant = make_variant("ask", &["sandbox"]);

    // Replace the schema with oneOf
    let description = schema.get("description").cloned();

    // Remove all existing keys
    if let Some(obj) = schema.as_object_mut() {
        obj.clear();
    }

    // Set oneOf
    schema.insert(
        "oneOf".to_owned(),
        serde_json::Value::Array(vec![deny_variant, allow_variant, ask_variant]),
    );

    if let Some(desc) = description {
        schema.insert("description".to_owned(), desc);
    }
}

/// Print the JSON Schema for the runok configuration to stdout.
#[cfg(feature = "config-schema")]
pub fn print_config_schema() -> Result<(), serde_json::Error> {
    let schema = schemars::schema_for!(Config);
    let json = serde_json::to_string_pretty(&schema)?;
    println!("{json}");
    Ok(())
}

/// Audit log configuration.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct AuditConfig {
    /// Whether audit logging is enabled (default: true).
    pub enabled: Option<bool>,
    /// Directory path for audit log files (default: ~/.local/share/runok/).
    pub path: Option<String>,
    /// Log rotation settings.
    pub rotation: Option<RotationConfig>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: Some(true),
            path: None,
            rotation: None,
        }
    }
}

impl AuditConfig {
    /// Returns whether audit logging is enabled, defaulting to true.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Returns the audit log directory path, defaulting to the XDG data
    /// directory.
    pub fn resolved_path(&self) -> String {
        self.path.clone().unwrap_or_else(|| {
            if let Ok(data_home) = std::env::var("XDG_DATA_HOME")
                && !data_home.is_empty()
            {
                return format!("{data_home}/runok/");
            }
            std::env::var("HOME")
                .map(|h| format!("{h}/.local/share/runok/"))
                .unwrap_or_else(|_| ".local/share/runok/".to_string())
        })
    }

    /// Returns the audit log directory as a `PathBuf`, expanding `~/` prefixes
    /// and falling back to a safe default when `HOME` is unavailable.
    pub fn base_dir(&self) -> std::path::PathBuf {
        match &self.path {
            Some(p) => {
                // Bare "~" would resolve to $HOME itself, causing
                // set_permissions(0o700) to restrict the home directory.
                // Treat it the same as "~/" by appending the default subpath.
                if p == "~" || p == "~/" {
                    match home_dir() {
                        Some(home) => home.join(".local/share/runok"),
                        None => default_audit_dir(),
                    }
                } else if let Some(rest) = p.strip_prefix("~/") {
                    if let Some(home) = home_dir() {
                        home.join(rest)
                    } else {
                        // Using the path literally would create a directory
                        // named `~`, which is not intended. Fall back to the
                        // default audit directory as a safe alternative.
                        default_audit_dir()
                    }
                } else {
                    std::path::PathBuf::from(p)
                }
            }
            None => default_audit_dir(),
        }
    }

    /// Returns the rotation config, using defaults for any unset fields.
    pub fn resolved_rotation(&self) -> RotationConfig {
        self.rotation.clone().unwrap_or_default()
    }
}

/// Log rotation configuration.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[cfg_attr(any(feature = "config-schema", test), derive(JsonSchema))]
pub struct RotationConfig {
    /// Number of days to retain log files (default: 7).
    pub retention_days: Option<u32>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            retention_days: Some(7),
        }
    }
}

impl RotationConfig {
    /// Returns the retention period in days, defaulting to 7.
    pub fn resolved_retention_days(&self) -> u32 {
        self.retention_days.unwrap_or(7)
    }
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

fn default_audit_dir() -> std::path::PathBuf {
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        let data_home = std::path::PathBuf::from(data_home);
        if !data_home.as_os_str().is_empty() {
            return data_home.join("runok");
        }
    }
    match home_dir() {
        Some(home) => home.join(".local/share/runok"),
        // Writing to a relative path could be surprising for the user.
        // Fall back to a temporary directory if HOME is not set.
        None => std::env::temp_dir().join("runok/audit"),
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
    fn validate_errors_on_rule_with_no_action() {
        let mut config = Config {
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
            audit: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn validate_errors_on_rule_with_multiple_actions() {
        let mut config = Config {
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
            audit: None,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

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
            .and_then(|f| f.deny.as_ref())
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

    #[test]
    fn validate_rejects_path_ref_in_definitions_paths() {
        let mut config = parse_config(indoc! {"
            definitions:
              paths:
                sensitive:
                  - /etc/passwd
                  - '<path:more_sensitive>'
                more_sensitive:
                  - /etc/shadow
        "})
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("definitions.paths.sensitive"),
            "error should mention the path key: {}",
            err
        );
        assert!(
            err.to_string().contains("concrete paths, not references"),
            "error should explain the constraint: {}",
            err
        );
    }

    #[test]
    fn validate_collects_all_errors() {
        let mut config = Config {
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

    // === AuditConfig ===

    #[test]
    fn audit_config_default() {
        let config = AuditConfig::default();
        assert_eq!(config.enabled, Some(true));
        assert_eq!(config.path, None);
        assert_eq!(config.rotation, None);
    }

    #[rstest]
    #[case::enabled(Some(true), true)]
    #[case::disabled(Some(false), false)]
    #[case::default_when_none(None, true)]
    fn audit_config_is_enabled(#[case] enabled: Option<bool>, #[case] expected: bool) {
        let config = AuditConfig {
            enabled,
            path: None,
            rotation: None,
        };
        assert_eq!(config.is_enabled(), expected);
    }

    #[test]
    fn audit_config_resolved_path_custom() {
        let config = AuditConfig {
            enabled: None,
            path: Some("/custom/path/".to_string()),
            rotation: None,
        };
        assert_eq!(config.resolved_path(), "/custom/path/");
    }

    #[test]
    fn rotation_config_default() {
        let config = RotationConfig::default();
        assert_eq!(config.retention_days, Some(7));
    }

    #[rstest]
    #[case::custom(Some(30), 30)]
    #[case::default_when_none(None, 7)]
    fn rotation_config_resolved_retention_days(
        #[case] retention_days: Option<u32>,
        #[case] expected: u32,
    ) {
        let config = RotationConfig { retention_days };
        assert_eq!(config.resolved_retention_days(), expected);
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

    // === Merge: audit ===

    #[test]
    fn merge_audit_both_none() {
        let base = Config::default();
        let over = Config::default();
        let result = base.merge(over);
        assert_eq!(result.audit, None);
    }

    #[test]
    fn merge_audit_base_preserved() {
        let base = Config {
            audit: Some(AuditConfig {
                enabled: Some(false),
                path: Some("/base/".to_string()),
                rotation: Some(RotationConfig {
                    retention_days: Some(14),
                }),
            }),
            ..Config::default()
        };
        let over = Config::default();
        let result = base.merge(over);
        let audit = result.audit.unwrap();
        assert_eq!(audit.enabled, Some(false));
        assert_eq!(audit.path.as_deref(), Some("/base/"));
        assert_eq!(audit.rotation.unwrap().retention_days, Some(14));
    }

    #[test]
    fn merge_audit_override_only() {
        let base = Config::default();
        let over = Config {
            audit: Some(AuditConfig {
                enabled: Some(true),
                path: Some("/over/".to_string()),
                rotation: None,
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let audit = result.audit.unwrap();
        assert_eq!(audit.enabled, Some(true));
        assert_eq!(audit.path.as_deref(), Some("/over/"));
        assert_eq!(audit.rotation, None);
    }

    #[test]
    fn merge_audit_override_wins() {
        let base = Config {
            audit: Some(AuditConfig {
                enabled: Some(true),
                path: Some("/base/".to_string()),
                rotation: Some(RotationConfig {
                    retention_days: Some(7),
                }),
            }),
            ..Config::default()
        };
        let over = Config {
            audit: Some(AuditConfig {
                enabled: Some(false),
                path: None,
                rotation: Some(RotationConfig {
                    retention_days: Some(30),
                }),
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let audit = result.audit.unwrap();
        assert_eq!(audit.enabled, Some(false));
        assert_eq!(audit.path.as_deref(), Some("/base/"));
        assert_eq!(audit.rotation.unwrap().retention_days, Some(30));
    }

    #[test]
    fn merge_audit_partial_override_preserves_base_fields() {
        let base = Config {
            audit: Some(AuditConfig {
                enabled: Some(true),
                path: Some("/base/".to_string()),
                rotation: Some(RotationConfig {
                    retention_days: Some(14),
                }),
            }),
            ..Config::default()
        };
        let over = Config {
            audit: Some(AuditConfig {
                enabled: None,
                path: None,
                rotation: None,
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let audit = result.audit.unwrap();
        assert_eq!(audit.enabled, Some(true));
        assert_eq!(audit.path.as_deref(), Some("/base/"));
        assert_eq!(audit.rotation.unwrap().retention_days, Some(14));
    }

    // === Config::validate ===

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

    #[rstest]
    #[case::var_ref(
        indoc! {"
            definitions:
              vars:
                ids:
                  values:
                    - i-abc123
                    - '<var:other-ids>'
                other-ids:
                  values:
                    - i-xyz999
        "},
        "definitions.vars.ids",
    )]
    #[case::path_ref(
        indoc! {"
            definitions:
              vars:
                scripts:
                  type: path
                  values:
                    - ./run.sh
                    - '<path:sensitive>'
              paths:
                sensitive:
                  - /etc/passwd
        "},
        "definitions.vars.scripts",
    )]
    fn validate_rejects_placeholder_in_definitions_vars(
        #[case] yaml: &str,
        #[case] expected_key_msg: &str,
    ) {
        let mut config = parse_config(yaml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains(expected_key_msg),
            "error should mention the var key: {}",
            err
        );
        assert!(
            err.to_string().contains("concrete values, not references"),
            "error should explain the constraint: {}",
            err
        );
    }

    #[test]
    fn validate_accepts_valid_vars() {
        let mut config = parse_config(indoc! {"
            definitions:
              vars:
                ids:
                  values:
                    - i-abc123
                    - i-def456
        "})
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn merge_definitions_vars_override_per_key() {
        let base = Config {
            definitions: Some(Definitions {
                vars: Some(HashMap::from([
                    (
                        "ids".to_string(),
                        VarDefinition {
                            var_type: VarType::Literal,
                            values: vec!["i-abc123".to_string()],
                        },
                    ),
                    (
                        "regions".to_string(),
                        VarDefinition {
                            var_type: VarType::Literal,
                            values: vec!["us-east-1".to_string()],
                        },
                    ),
                ])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let over = Config {
            definitions: Some(Definitions {
                vars: Some(HashMap::from([(
                    "ids".to_string(),
                    VarDefinition {
                        var_type: VarType::Literal,
                        values: vec!["i-xyz999".to_string()],
                    },
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = base.merge(over);
        let vars = result.definitions.unwrap().vars.unwrap();
        // "ids" is overridden by the override config
        assert_eq!(vars["ids"].values, vec!["i-xyz999"]);
        // "regions" is preserved from base
        assert_eq!(vars["regions"].values, vec!["us-east-1"]);
    }

    #[test]
    fn merge_definitions_vars_base_only() {
        let base = Config {
            definitions: Some(Definitions {
                vars: Some(HashMap::from([(
                    "ids".to_string(),
                    VarDefinition {
                        var_type: VarType::Literal,
                        values: vec!["i-abc123".to_string()],
                    },
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = base.merge(Config::default());
        let vars = result.definitions.unwrap().vars.unwrap();
        assert_eq!(vars["ids"].values, vec!["i-abc123"]);
    }

    #[test]
    fn merge_definitions_vars_override_only() {
        let over = Config {
            definitions: Some(Definitions {
                vars: Some(HashMap::from([(
                    "ids".to_string(),
                    VarDefinition {
                        var_type: VarType::Path,
                        values: vec!["./run.sh".to_string()],
                    },
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };
        let result = Config::default().merge(over);
        let vars = result.definitions.unwrap().vars.unwrap();
        assert_eq!(vars["ids"].var_type, VarType::Path);
        assert_eq!(vars["ids"].values, vec!["./run.sh"]);
    }

    // === JSON Schema ===

    const SCHEMA_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/schema/runok.schema.json");

    fn generate_schema_value() -> serde_json::Value {
        let schema = schemars::schema_for!(Config);
        serde_json::to_value(schema).unwrap()
    }

    #[test]
    fn schema_is_up_to_date() {
        let expected = generate_schema_value();
        let actual_str = std::fs::read_to_string(SCHEMA_PATH).unwrap_or_else(|e| {
            panic!(
                "Failed to read schema file at {SCHEMA_PATH}: {e}. \
                 Run `cargo run --features config-schema -- config-schema > schema/runok.schema.json` to generate it."
            )
        });
        let actual: serde_json::Value = serde_json::from_str(&actual_str)
            .unwrap_or_else(|e| panic!("Schema file is not valid JSON: {e}"));
        assert_eq!(
            actual, expected,
            "Schema file is out of date. \
             Run `cargo run --features config-schema -- config-schema > schema/runok.schema.json` to regenerate."
        );
    }
}
