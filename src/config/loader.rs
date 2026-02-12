use std::path::{Path, PathBuf};

use super::{Config, ConfigError, parse_config};

/// Trait for loading and merging configuration files.
pub trait ConfigLoader {
    fn load(&self, cwd: &Path) -> Result<Config, ConfigError>;
}

/// Default implementation that reads from the filesystem.
pub struct DefaultConfigLoader {
    global_config_path: Option<PathBuf>,
}

impl Default for DefaultConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultConfigLoader {
    pub fn new() -> Self {
        let global_config_path = std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .map(|h| {
                PathBuf::from(h)
                    .join(".config")
                    .join("runok")
                    .join("runok.yml")
            });
        Self { global_config_path }
    }

    /// Create a loader with an explicit global config path (for testing).
    pub fn with_global_path(path: PathBuf) -> Self {
        Self {
            global_config_path: Some(path),
        }
    }

    /// Determine which local config file to use.
    /// `runok.yml` is preferred; `runok.yaml` is a fallback.
    fn local_config_path(cwd: &Path) -> Option<PathBuf> {
        let yml = cwd.join("runok.yml");
        if yml.exists() {
            return Some(yml);
        }
        let yaml = cwd.join("runok.yaml");
        if yaml.exists() {
            return Some(yaml);
        }
        None
    }

    fn read_and_parse(path: &Path) -> Result<Config, ConfigError> {
        let yaml = std::fs::read_to_string(path)?;
        parse_config(&yaml)
    }
}

impl ConfigLoader for DefaultConfigLoader {
    fn load(&self, cwd: &Path) -> Result<Config, ConfigError> {
        let global = self
            .global_config_path
            .as_ref()
            .filter(|p| p.exists())
            .map(|p| Self::read_and_parse(p))
            .transpose()?;

        let local = Self::local_config_path(cwd)
            .map(|p| Self::read_and_parse(&p))
            .transpose()?;

        let config = global.unwrap_or_default().merge(local.unwrap_or_default());

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;
    use std::fs;
    use tempfile::TempDir;

    /// Test environment with temp directories and a loader.
    /// Global config defaults to a nonexistent path (no global config).
    struct TestEnv {
        _tmp: TempDir,
        global_dir: PathBuf,
        cwd: PathBuf,
        global_path: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let global_dir = tmp.path().join("global");
            let cwd = tmp.path().join("project");
            fs::create_dir_all(&global_dir).unwrap();
            fs::create_dir_all(&cwd).unwrap();
            let global_path = global_dir.join("runok.yml");
            Self {
                _tmp: tmp,
                global_dir,
                cwd,
                global_path,
            }
        }

        fn write_global(&self, yaml: &str) {
            fs::write(&self.global_path, yaml).unwrap();
        }

        fn write_local(&self, filename: &str, yaml: &str) {
            fs::write(self.cwd.join(filename), yaml).unwrap();
        }

        fn loader(&self) -> DefaultConfigLoader {
            DefaultConfigLoader::with_global_path(self.global_path.clone())
        }

        fn load(&self) -> Result<Config, ConfigError> {
            self.loader().load(&self.cwd)
        }

        /// Create a loader whose global path points to a nonexistent file.
        fn loader_without_global(&self) -> DefaultConfigLoader {
            DefaultConfigLoader::with_global_path(
                self.global_dir.join("nonexistent").join("runok.yml"),
            )
        }

        fn load_without_global(&self) -> Result<Config, ConfigError> {
            self.loader_without_global().load(&self.cwd)
        }
    }

    #[test]
    fn load_no_config_files_returns_default() {
        let env = TestEnv::new();
        assert_eq!(env.load_without_global().unwrap(), Config::default());
    }

    #[test]
    fn load_global_only() {
        let env = TestEnv::new();
        env.write_global(indoc! {"
            defaults:
              action: deny
        "});

        let config = env.load().unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
    }

    #[rstest]
    #[case::yml("runok.yml", crate::config::ActionKind::Allow)]
    #[case::yaml_fallback("runok.yaml", crate::config::ActionKind::Ask)]
    fn load_local_only(#[case] filename: &str, #[case] expected_action: crate::config::ActionKind) {
        let env = TestEnv::new();
        let action_str = match expected_action {
            crate::config::ActionKind::Allow => "allow",
            crate::config::ActionKind::Ask => "ask",
            crate::config::ActionKind::Deny => "deny",
        };
        env.write_local(filename, &format!("defaults:\n  action: {action_str}"));

        let config = env.load_without_global().unwrap();
        assert_eq!(config.defaults.unwrap().action, Some(expected_action));
    }

    #[test]
    fn load_yml_takes_priority_over_yaml() {
        let env = TestEnv::new();
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_local(
            "runok.yaml",
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let config = env.load_without_global().unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
    }

    #[test]
    fn load_merges_global_and_local() {
        let env = TestEnv::new();
        env.write_global(indoc! {"
            defaults:
              action: deny
              sandbox: global-sandbox
            rules:
              - deny: 'rm -rf /'
        "});
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: allow
                rules:
                  - allow: 'git status'
            "},
        );

        let config = env.load().unwrap();

        let defaults = config.defaults.unwrap();
        assert_eq!(defaults.action, Some(crate::config::ActionKind::Allow));
        assert_eq!(defaults.sandbox.as_deref(), Some("global-sandbox"));

        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status"));
    }

    #[test]
    fn load_merges_definitions() {
        let env = TestEnv::new();
        env.write_global(indoc! {r#"
            definitions:
              paths:
                sensitive:
                  - ".env*"
                logs:
                  - "/var/log/**"
              wrappers:
                - "sudo <cmd>"
              commands:
                - "git commit"
        "#});
        env.write_local(
            "runok.yml",
            indoc! {r#"
                definitions:
                  paths:
                    sensitive:
                      - "~/.ssh/**"
                  wrappers:
                    - "bash -c <cmd>"
                  commands:
                    - "git push"
            "#},
        );

        let config = env.load().unwrap();
        let defs = config.definitions.unwrap();

        let paths = defs.paths.unwrap();
        assert_eq!(paths["sensitive"], vec!["~/.ssh/**"]);
        assert_eq!(paths["logs"], vec!["/var/log/**"]);

        assert_eq!(defs.wrappers.unwrap(), vec!["sudo <cmd>", "bash -c <cmd>"]);
        assert_eq!(defs.commands.unwrap(), vec!["git commit", "git push"]);
    }

    #[test]
    fn load_validation_error_propagated() {
        let env = TestEnv::new();
        env.write_global(indoc! {"
            rules:
              - deny: 'rm -rf /'
                sandbox: restricted
        "});

        let err = env.load().unwrap_err();
        assert!(err.to_string().contains("deny"));
        assert!(err.to_string().contains("sandbox"));
    }

    #[rstest]
    #[case::global_parse_error(true, false)]
    #[case::local_parse_error(false, true)]
    fn load_yaml_parse_error(#[case] global_invalid: bool, #[case] local_invalid: bool) {
        let env = TestEnv::new();
        if global_invalid {
            env.write_global("rules: [invalid yaml\n  broken:");
        }
        if local_invalid {
            env.write_local("runok.yml", "rules: [invalid yaml\n  broken:");
        }

        let result = if global_invalid {
            env.load()
        } else {
            env.load_without_global()
        };
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn new_uses_home_env() {
        let loader = DefaultConfigLoader::new();
        if let Ok(home) = std::env::var("HOME")
            && !home.is_empty()
        {
            let expected = PathBuf::from(home)
                .join(".config")
                .join("runok")
                .join("runok.yml");
            assert_eq!(loader.global_config_path, Some(expected));
        }
    }
}
