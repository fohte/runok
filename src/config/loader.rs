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
                    .join("config.yml")
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
    /// `.runok/config.yml` takes priority over `runok.yml`.
    fn local_config_path(cwd: &Path) -> Option<PathBuf> {
        let dir_config = cwd.join(".runok").join("config.yml");
        if dir_config.exists() {
            return Some(dir_config);
        }
        let file_config = cwd.join("runok.yml");
        if file_config.exists() {
            return Some(file_config);
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
        let global = match &self.global_config_path {
            Some(path) if path.exists() => Some(Self::read_and_parse(path)?),
            _ => None,
        };

        let local = match Self::local_config_path(cwd) {
            Some(path) => Some(Self::read_and_parse(&path)?),
            None => None,
        };

        let config = match (global, local) {
            (None, None) => Config::default(),
            (Some(g), None) => g,
            (None, Some(l)) => l,
            (Some(g), Some(l)) => g.merge(l),
        };

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
        let path = dir.join("config.yml");
        fs::write(&path, yaml).unwrap();
        path
    }

    /// Helper to set up a local directory-style config (.runok/config.yml).
    fn write_local_dir_config(cwd: &Path, yaml: &str) {
        let dir = cwd.join(".runok");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.yml"), yaml).unwrap();
    }

    /// Helper to set up a local single-file config (runok.yml).
    fn write_local_file_config(cwd: &Path, yaml: &str) {
        fs::write(cwd.join("runok.yml"), yaml).unwrap();
    }

    #[test]
    fn load_no_config_files_returns_default() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("config.yml");
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
    fn load_local_dir_config_only() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("config.yml");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_dir_config(
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
    fn load_local_file_config_only() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("config.yml");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_file_config(
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
    fn load_dir_config_takes_priority_over_file_config() {
        let tmp = TempDir::new().unwrap();
        let global_path = tmp.path().join("nonexistent").join("config.yml");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        write_local_dir_config(
            &cwd,
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        write_local_file_config(
            &cwd,
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let loader = DefaultConfigLoader::with_global_path(global_path);
        let config = loader.load(&cwd).unwrap();
        // .runok/config.yml wins over runok.yml
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

        write_local_dir_config(
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

        write_local_dir_config(
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
    #[case::global_io_error(true, false)]
    #[case::local_io_error(false, true)]
    fn load_yaml_parse_error(#[case] global_invalid: bool, #[case] local_invalid: bool) {
        let tmp = TempDir::new().unwrap();
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        let global_path = if global_invalid {
            write_global_config(tmp.path(), "rules: [invalid yaml\n  broken:")
        } else {
            tmp.path().join("nonexistent").join("config.yml")
        };

        if local_invalid {
            write_local_file_config(&cwd, "rules: [invalid yaml\n  broken:");
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
                .join("config.yml");
            assert_eq!(loader.global_config_path, Some(expected));
        }
    }
}
