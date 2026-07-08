use std::collections::HashSet;

#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::Deserializer;

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
                super::parse::push_parse_warning(
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
