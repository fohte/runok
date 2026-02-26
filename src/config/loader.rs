use std::path::{Path, PathBuf};

use super::{Config, ConfigError, parse_config};

/// Trait for loading and merging configuration files.
pub trait ConfigLoader {
    fn load(&self, cwd: &Path) -> Result<Config, ConfigError>;
}

/// Default implementation that reads from the filesystem.
pub struct DefaultConfigLoader {
    global_config_path: Option<PathBuf>,
    global_config_dir: Option<PathBuf>,
}

impl Default for DefaultConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultConfigLoader {
    pub fn new() -> Self {
        let global_config_dir = std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .map(|h| PathBuf::from(h).join(".config").join("runok"));
        let global_config_path = global_config_dir.as_ref().map(|d| d.join("runok.yml"));
        Self {
            global_config_path,
            global_config_dir,
        }
    }

    /// Create a loader with an explicit global config path (for testing).
    pub fn with_global_path(path: PathBuf) -> Self {
        let global_config_dir = path.parent().map(Path::to_path_buf);
        Self {
            global_config_path: Some(path),
            global_config_dir,
        }
    }

    /// Find the first existing file from `filenames` inside `dir`.
    fn find_config(dir: &Path, filenames: &[&str]) -> Option<PathBuf> {
        filenames
            .iter()
            .map(|name| dir.join(name))
            .find(|path| path.exists())
    }

    fn global_local_override_config_path(&self) -> Option<PathBuf> {
        let dir = self.global_config_dir.as_ref()?;
        Self::find_config(dir, &["runok.local.yml", "runok.local.yaml"])
    }

    fn local_config_path(cwd: &Path) -> Option<PathBuf> {
        Self::find_config(cwd, &["runok.yml", "runok.yaml"])
    }

    fn local_override_config_path(cwd: &Path) -> Option<PathBuf> {
        Self::find_config(cwd, &["runok.local.yml", "runok.local.yaml"])
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

        let global_local_override = self
            .global_local_override_config_path()
            .map(|p| Self::read_and_parse(&p))
            .transpose()?;

        let local = Self::local_config_path(cwd)
            .map(|p| Self::read_and_parse(&p))
            .transpose()?;

        let local_override = Self::local_override_config_path(cwd)
            .map(|p| Self::read_and_parse(&p))
            .transpose()?;

        // Merge priority: global < global local override < project < project local override
        let mut config = global
            .unwrap_or_default()
            .merge(global_local_override.unwrap_or_default())
            .merge(local.unwrap_or_default())
            .merge(local_override.unwrap_or_default());

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

        fn write_global_local(&self, filename: &str, yaml: &str) {
            fs::write(self.global_dir.join(filename), yaml).unwrap();
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
        // paths are appended per key (not overridden)
        assert_eq!(paths["sensitive"], vec![".env*", "~/.ssh/**"]);
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

    #[rstest]
    #[case::local_yml("runok.local.yml")]
    #[case::local_yaml_fallback("runok.local.yaml")]
    fn load_local_override(#[case] filename: &str) {
        let env = TestEnv::new();
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_local(
            filename,
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let config = env.load_without_global().unwrap();
        // local override takes priority over project config
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[test]
    fn load_local_override_yml_takes_priority_over_yaml() {
        let env = TestEnv::new();
        env.write_local(
            "runok.local.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_local(
            "runok.local.yaml",
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
    fn load_merges_all_three_layers() {
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
                  action: ask
                rules:
                  - allow: 'git status'
            "},
        );
        env.write_local(
            "runok.local.yml",
            indoc! {"
                defaults:
                  action: allow
                rules:
                  - allow: 'cargo test'
            "},
        );

        let config = env.load().unwrap();

        let defaults = config.defaults.unwrap();
        // local override wins over project and global
        assert_eq!(defaults.action, Some(crate::config::ActionKind::Allow));
        // sandbox from global is preserved (not overridden by layers without it)
        assert_eq!(defaults.sandbox.as_deref(), Some("global-sandbox"));

        // rules are appended: global + project + local override
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status"));
        assert_eq!(rules[2].allow.as_deref(), Some("cargo test"));
    }

    #[rstest]
    #[case::global_local_yml("runok.local.yml")]
    #[case::global_local_yaml_fallback("runok.local.yaml")]
    fn load_global_local_override(#[case] filename: &str) {
        let env = TestEnv::new();
        env.write_global(indoc! {"
            defaults:
              action: deny
        "});
        env.write_global_local(
            filename,
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let config = env.load().unwrap();
        // global local override takes priority over global
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[test]
    fn load_global_local_override_yml_takes_priority_over_yaml() {
        let env = TestEnv::new();
        env.write_global_local(
            "runok.local.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_global_local(
            "runok.local.yaml",
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let config = env.load().unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
    }

    #[test]
    fn load_project_overrides_global_local_override() {
        let env = TestEnv::new();
        env.write_global(indoc! {"
            defaults:
              action: deny
        "});
        env.write_global_local(
            "runok.local.yml",
            indoc! {"
                defaults:
                  action: ask
            "},
        );
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let config = env.load().unwrap();
        // project config takes priority over global local override
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[test]
    fn load_merges_all_four_layers() {
        let env = TestEnv::new();
        env.write_global(indoc! {"
            defaults:
              sandbox: global-sandbox
            rules:
              - deny: 'rm -rf /'
        "});
        env.write_global_local(
            "runok.local.yml",
            indoc! {"
                rules:
                  - allow: 'internal-tool'
            "},
        );
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: ask
                rules:
                  - allow: 'git status'
            "},
        );
        env.write_local(
            "runok.local.yml",
            indoc! {"
                defaults:
                  action: allow
                rules:
                  - allow: 'cargo test'
            "},
        );

        let config = env.load().unwrap();

        let defaults = config.defaults.unwrap();
        // project local override wins
        assert_eq!(defaults.action, Some(crate::config::ActionKind::Allow));
        // sandbox from global is preserved
        assert_eq!(defaults.sandbox.as_deref(), Some("global-sandbox"));

        // rules are appended: global + global local override + project + project local override
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("internal-tool"));
        assert_eq!(rules[2].allow.as_deref(), Some("git status"));
        assert_eq!(rules[3].allow.as_deref(), Some("cargo test"));
    }

    #[test]
    fn load_global_local_override_parse_error() {
        let env = TestEnv::new();
        env.write_global_local("runok.local.yml", "rules: [invalid yaml\n  broken:");

        let result = env.load();
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn load_local_override_parse_error() {
        let env = TestEnv::new();
        env.write_local("runok.local.yml", "rules: [invalid yaml\n  broken:");

        let result = env.load_without_global();
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[test]
    fn load_local_override_only_without_project_config() {
        let env = TestEnv::new();
        // no runok.yml, only runok.local.yml
        env.write_local(
            "runok.local.yml",
            indoc! {"
                rules:
                  - allow: 'echo hello'
            "},
        );

        let config = env.load_without_global().unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].allow.as_deref(), Some("echo hello"));
    }
}
