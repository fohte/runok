#[cfg(any(feature = "config-schema", test))]
use schemars::JsonSchema;
use serde::Deserialize;

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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

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
}
