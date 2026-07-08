use std::collections::HashMap;

#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::Deserializer;

use super::{AliasDefinition, SandboxPreset};

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
