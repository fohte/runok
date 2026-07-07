use std::collections::{HashMap, HashSet};

use super::{AuditConfig, Config, Defaults, Definitions, RotationConfig, VarDefinition};

impl Config {
    /// Merge two configs. `self` is the base (e.g. global), `other` is the override (e.g. local).
    ///
    /// - extends / rules / definitions.wrappers: append
    /// - defaults.action / defaults.sandbox: override (local wins)
    /// - definitions.paths: per-key append (values concatenated, duplicates removed)
    /// - definitions.sandbox: per-key override
    ///   (sandbox presets have interdependent fields like fs.writable and
    ///   fs.deny that must stay consistent; partial merging could create
    ///   contradictory constraints.)
    /// - audit: override (local wins at merge level; loader enforces
    ///   global-only by stripping audit from project/local layers)
    /// - tests: override (local wins; test definitions are not merged across layers)
    pub fn merge(self, other: Config) -> Config {
        Config {
            // required_runok_version is enforced at load time per file, so
            // the merged value is informational only. Prefer the override
            // (most specific layer) to match the rest of the merge policy.
            required_runok_version: other.required_runok_version.or(self.required_runok_version),
            extends: Self::merge_vecs(self.extends, other.extends),
            defaults: Self::merge_defaults(self.defaults, other.defaults),
            rules: Self::merge_vecs(self.rules, other.rules),
            definitions: Self::merge_definitions(self.definitions, other.definitions),
            audit: Self::merge_audit(self.audit, other.audit),
            tests: other.tests.or(self.tests),
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
            (Some(b), Some(o)) => {
                let mut merged = Definitions {
                    paths: Self::merge_paths(b.paths, o.paths),
                    sandbox: Self::merge_hashmaps(b.sandbox, o.sandbox),
                    wrappers: Self::merge_vecs(b.wrappers, o.wrappers),
                    vars: Self::merge_vars(b.vars, o.vars),
                    flag_groups: Self::merge_hashmaps(b.flag_groups, o.flag_groups),
                    aliases: Self::merge_hashmaps(b.aliases, o.aliases),
                    parsed_flag_groups: None,
                    parsed_pattern_vars: None,
                };
                merged.resolve_flag_groups();
                merged.resolve_pattern_vars();
                Some(merged)
            }
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

#[cfg(test)]
mod tests {
    use super::super::{
        ActionKind, FsAccessPolicy, FsPolicy, NetworkPolicy, RuleEntry, SandboxPreset, VarType,
    };
    use super::*;

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
                tests: None,
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
                tests: None,
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
                tests: None,
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
                tests: None,
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
                            read: None,
                            write: Some(FsAccessPolicy {
                                allow: Some(vec!["./tmp".to_string()]),
                                deny: None,
                            }),
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

    // === definitions.vars ===

    #[test]
    fn merge_definitions_vars_override_per_key() {
        let base = Config {
            definitions: Some(Definitions {
                vars: Some(HashMap::from([
                    (
                        "ids".to_string(),
                        VarDefinition {
                            var_type: VarType::Literal,
                            values: vec!["i-abc123".into()],
                        },
                    ),
                    (
                        "regions".to_string(),
                        VarDefinition {
                            var_type: VarType::Literal,
                            values: vec!["us-east-1".into()],
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
                        values: vec!["i-xyz999".into()],
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
                        values: vec!["i-abc123".into()],
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
                        values: vec!["./run.sh".into()],
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
}
