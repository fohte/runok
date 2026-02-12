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

    /// Helper to set up a global config file inside a temp directory.
    fn write_global_config(dir: &Path, yaml: &str) -> PathBuf {
        let path = dir.join("runok.yml");
        fs::write(&path, yaml).unwrap();
        path
    }

    /// Helper to set up a local config (runok.yml).
    fn write_local_config(cwd: &Path, yaml: &str) {
        fs::write(cwd.join("runok.yml"), yaml).unwrap();
    }

    /// Helper to set up a local config with .yaml extension (fallback).
    fn write_local_config_yaml(cwd: &Path, yaml: &str) {
        fs::write(cwd.join("runok.yaml"), yaml).unwrap();
    }

    #[test]
    fn load_no_config_files_returns_default() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("runok.yml");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn load_global_only() {
        let tmp = TempDir::new().unwrap();
        let global_path = write_global_config(
            tmp.path(),
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
    }

    #[test]
    fn load_local_yml_only() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("runok.yml");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_config(
            &cwd,
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[test]
    fn load_local_yaml_fallback() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("runok.yml");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_config_yaml(
            &cwd,
            indoc! {"
                defaults:
                  action: ask
            "},
        );

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Ask)
        );
    }

    #[test]
    fn load_yml_takes_priority_over_yaml() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("runok.yml");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_config(
            &cwd,
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        write_local_config_yaml(
            &cwd,
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();
        // runok.yml wins over runok.yaml
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
    }

    #[test]
    fn load_merges_global_and_local() {
        let tmp = TempDir::new().unwrap();
        let global_path = write_global_config(
            tmp.path(),
            indoc! {"
                defaults:
                  action: deny
                  sandbox: global-sandbox
                rules:
                  - deny: 'rm -rf /'
            "},
        );
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_config(
            &cwd,
            indoc! {"
                defaults:
                  action: allow
                rules:
                  - allow: 'git status'
            "},
        );

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();

        // defaults.action is overridden by local
        let defaults = config.defaults.unwrap();
        assert_eq!(defaults.action, Some(crate::config::ActionKind::Allow));
        // defaults.sandbox is inherited from global
        assert_eq!(defaults.sandbox.as_deref(), Some("global-sandbox"));

        // rules are appended (global + local)
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status"));
    }

    #[test]
    fn load_merges_definitions() {
        let tmp = TempDir::new().unwrap();
        let global_path = write_global_config(
            tmp.path(),
            indoc! {r#"
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
            "#},
        );
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_config(
            &cwd,
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

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();
        let defs = config.definitions.unwrap();

        // paths: "sensitive" overridden, "logs" preserved
        let paths = defs.paths.unwrap();
        assert_eq!(paths["sensitive"], vec!["~/.ssh/**"]);
        assert_eq!(paths["logs"], vec!["/var/log/**"]);

        // wrappers: appended
        let wrappers = defs.wrappers.unwrap();
        assert_eq!(wrappers, vec!["sudo <cmd>", "bash -c <cmd>"]);

        // commands: appended
        let commands = defs.commands.unwrap();
        assert_eq!(commands, vec!["git commit", "git push"]);
    }

    #[test]
    fn load_validation_error_propagated() {
        let tmp = TempDir::new().unwrap();
        let global_path = write_global_config(
            tmp.path(),
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
                    sandbox: restricted
            "},
        );
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let err = loader.load(&cwd).unwrap_err();
        assert!(err.to_string().contains("deny"));
        assert!(err.to_string().contains("sandbox"));
    }

    #[rstest]
    #[case::global_parse_error(true, false)]
    #[case::local_parse_error(false, true)]
    fn load_yaml_parse_error(#[case] global_invalid: bool, #[case] local_invalid: bool) {
        let tmp = TempDir::new().unwrap();
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        let global_path = if global_invalid {
            write_global_config(tmp.path(), "rules: [invalid yaml\n  broken:")
        } else {
            tmp.path().join("nonexistent").join("runok.yml")
        };

        if local_invalid {
            write_local_config(&cwd, "rules: [invalid yaml\n  broken:");
        }

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let err = loader.load(&cwd).unwrap_err();
        assert!(matches!(err, ConfigError::Yaml(_)));
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
