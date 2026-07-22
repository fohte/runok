mod audit_config;
mod definitions;
mod experimental_config;
mod merge;
mod parse;
mod rule;
mod sandbox;
mod schema_gen;
mod validate;

pub use audit_config::{AuditConfig, RotationConfig};
pub use definitions::{Definitions, VarDefinition, VarType, VarValue};
pub use experimental_config::{ExperimentalConfig, RequireCommandInPathConfig};
pub use parse::{ParsedConfig, parse_config, parse_config_with_warnings};
pub use rule::{ActionKind, AliasDefinition, Defaults, InlineTestEntry, RuleEntry, TestSection};
pub use sandbox::{FsAccessPolicy, FsPolicy, MergedSandboxPolicy, NetworkPolicy, SandboxPreset};
#[cfg(feature = "config-schema")]
pub use schema_gen::print_config_schema;

#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;

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
    /// Experimental features, disabled by default.
    pub experimental: Option<ExperimentalConfig>,
}
