use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_saphyr::Error),
    #[error("preset error: {0}")]
    Preset(#[from] PresetError),
    #[error("validation errors:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    Validation(Vec<String>),
}

#[derive(Debug, thiserror::Error)]
pub enum PresetError {
    #[error("local file not found: {0}")]
    LocalNotFound(PathBuf),
    #[error("fetch error: {url}: {message}")]
    Fetch { url: String, message: String },
    #[error("invalid reference: {0}")]
    InvalidReference(String),
    #[error("circular reference detected: {}", .cycle.join(" → "))]
    CircularReference { cycle: Vec<String> },
    #[error("maximum extends depth ({max_depth}) exceeded: {}", .chain.join(" → "))]
    MaxExtendsDepthExceeded {
        chain: Vec<String>,
        max_depth: usize,
    },
    #[error("cache error: {0}")]
    Cache(String),
    #[error("git clone failed for '{reference}': {message}")]
    GitClone { reference: String, message: String },
    #[error("git clone failed, using cached version: {message}")]
    GitCloneWithCache { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === ConfigError ===

    #[test]
    fn config_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let config_err: ConfigError = io_err.into();
        assert_eq!(config_err.to_string(), "io error: file not found");
    }

    #[test]
    fn config_error_from_preset_error() {
        let preset_err = PresetError::InvalidReference("bad ref".to_string());
        let config_err: ConfigError = preset_err.into();
        assert_eq!(
            config_err.to_string(),
            "preset error: invalid reference: bad ref"
        );
    }

    #[test]
    fn config_error_validation_single() {
        let error = ConfigError::Validation(vec!["rule must have exactly one action".to_string()]);
        assert_eq!(
            error.to_string(),
            "validation errors:\n  - rule must have exactly one action"
        );
    }

    #[test]
    fn config_error_validation_multiple() {
        let error = ConfigError::Validation(vec![
            "rule must have exactly one action".to_string(),
            "deny rule cannot have sandbox".to_string(),
        ]);
        assert_eq!(
            error.to_string(),
            "validation errors:\n  - rule must have exactly one action\n  - deny rule cannot have sandbox"
        );
    }

    #[test]
    fn config_error_from_yaml_error() {
        let result: Result<String, serde_saphyr::Error> = serde_saphyr::from_str("[invalid");
        let yaml_err = result.unwrap_err();
        let config_err: ConfigError = yaml_err.into();
        assert!(config_err.to_string().starts_with("yaml parse error:"));
    }

    #[test]
    fn config_error_yaml_has_source() {
        let result: Result<String, serde_saphyr::Error> = serde_saphyr::from_str("[invalid");
        let yaml_err = result.unwrap_err();
        let config_err = ConfigError::Yaml(yaml_err);
        let source = std::error::Error::source(&config_err);
        assert!(source.is_some());
    }

    #[test]
    fn config_error_io_has_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let config_err = ConfigError::Io(io_err);
        let source = std::error::Error::source(&config_err);
        assert!(source.is_some());
    }

    #[test]
    fn config_error_preset_has_source() {
        let preset_err = PresetError::InvalidReference("bad ref".to_string());
        let config_err = ConfigError::Preset(preset_err);
        let source = std::error::Error::source(&config_err);
        assert!(source.is_some());
    }

    // === PresetError ===

    #[test]
    fn preset_error_local_not_found() {
        let error = PresetError::LocalNotFound(std::path::PathBuf::from("/missing/file.yml"));
        assert_eq!(error.to_string(), "local file not found: /missing/file.yml");
    }

    #[rstest]
    #[case(
        PresetError::Fetch {
            url: "https://example.com/preset.yml".to_string(),
            message: "404 Not Found".to_string(),
        },
        "fetch error: https://example.com/preset.yml: 404 Not Found"
    )]
    #[case(
        PresetError::InvalidReference("github:invalid".to_string()),
        "invalid reference: github:invalid"
    )]
    #[case(
        PresetError::Cache("write failed".to_string()),
        "cache error: write failed"
    )]
    #[case(
        PresetError::GitClone {
            reference: "github:org/repo@v1".to_string(),
            message: "authentication failed".to_string(),
        },
        "git clone failed for 'github:org/repo@v1': authentication failed"
    )]
    #[case(
        PresetError::GitCloneWithCache {
            message: "network unreachable".to_string(),
        },
        "git clone failed, using cached version: network unreachable"
    )]
    fn preset_error_display(#[case] error: PresetError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn preset_error_max_extends_depth_exceeded() {
        let error = PresetError::MaxExtendsDepthExceeded {
            chain: vec![
                "a.yml".to_string(),
                "b.yml".to_string(),
                "c.yml".to_string(),
            ],
            max_depth: 10,
        };
        assert_eq!(
            error.to_string(),
            "maximum extends depth (10) exceeded: a.yml → b.yml → c.yml"
        );
    }

    #[test]
    fn preset_error_circular_reference() {
        let error = PresetError::CircularReference {
            cycle: vec![
                "a.yml".to_string(),
                "b.yml".to_string(),
                "a.yml".to_string(),
            ],
        };
        assert_eq!(
            error.to_string(),
            "circular reference detected: a.yml → b.yml → a.yml"
        );
    }

    #[test]
    fn preset_error_implements_std_error() {
        let error: &dyn std::error::Error = &PresetError::InvalidReference("test".to_string());
        assert!(error.source().is_none());
    }

    // === anyhow integration ===

    #[test]
    fn config_error_into_anyhow() {
        let error = ConfigError::Validation(vec!["invalid config".to_string()]);
        let anyhow_err: anyhow::Error = error.into();
        assert_eq!(
            anyhow_err.to_string(),
            "validation errors:\n  - invalid config"
        );
    }

    #[test]
    fn preset_error_into_anyhow() {
        let error = PresetError::InvalidReference("bad".to_string());
        let anyhow_err: anyhow::Error = error.into();
        assert_eq!(anyhow_err.to_string(), "invalid reference: bad");
    }

    #[test]
    fn anyhow_error_chain_config_to_preset() {
        let preset_err = PresetError::InvalidReference("bad".to_string());
        let config_err = ConfigError::Preset(preset_err);
        let anyhow_err: anyhow::Error = config_err.into();

        let chain: Vec<String> = anyhow_err.chain().map(|e| e.to_string()).collect();
        assert_eq!(chain[0], "preset error: invalid reference: bad");
        assert_eq!(chain[1], "invalid reference: bad");
    }
}
