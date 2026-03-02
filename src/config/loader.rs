use std::path::{Path, PathBuf};

use super::{Config, ConfigError, parse_config};

/// Trait for loading and merging configuration files.
pub trait ConfigLoader {
    fn load(&self, cwd: &Path) -> Result<Config, ConfigError>;
}

/// Default implementation that reads from the filesystem.
pub struct DefaultConfigLoader {
    global_dir: Option<PathBuf>,
}

impl Default for DefaultConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Filenames for the main configuration file, in priority order.
const CONFIG_FILENAMES: &[&str] = &["runok.yml", "runok.yaml"];

/// Filenames for the local override configuration file, in priority order.
const LOCAL_OVERRIDE_FILENAMES: &[&str] = &["runok.local.yml", "runok.local.yaml"];

impl DefaultConfigLoader {
    pub fn new() -> Self {
        let global_dir = super::dirs::config_dir().map(|dir| dir.join("runok"));
        Self { global_dir }
    }

    /// Create a loader with an explicit global config directory (for testing).
    pub fn with_global_dir(dir: PathBuf) -> Self {
        Self {
            global_dir: Some(dir),
        }
    }

    /// Find the first existing file from `filenames` inside `dir`.
    fn find_config(dir: &Path, filenames: &[&str]) -> Option<PathBuf> {
        filenames
            .iter()
            .map(|name| dir.join(name))
            .find(|path| path.exists())
    }

    fn find_and_parse(dir: &Path, filenames: &[&str]) -> Result<Option<Config>, ConfigError> {
        Self::find_config(dir, filenames)
            .map(|p| Self::read_and_parse(&p))
            .transpose()
    }

    fn read_and_parse(path: &Path) -> Result<Config, ConfigError> {
        let yaml = std::fs::read_to_string(path)?;
        parse_config(&yaml)
    }
}

impl ConfigLoader for DefaultConfigLoader {
    fn load(&self, cwd: &Path) -> Result<Config, ConfigError> {
        let (global, global_local_override) = match &self.global_dir {
            Some(dir) => (
                Self::find_and_parse(dir, CONFIG_FILENAMES)?,
                Self::find_and_parse(dir, LOCAL_OVERRIDE_FILENAMES)?,
            ),
            None => (None, None),
        };

        let local = Self::find_and_parse(cwd, CONFIG_FILENAMES)?;
        let local_override = Self::find_and_parse(cwd, LOCAL_OVERRIDE_FILENAMES)?;

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
    struct TestEnv {
        _tmp: TempDir,
        global_dir: PathBuf,
        cwd: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let global_dir = tmp.path().join("global");
            let cwd = tmp.path().join("project");
            fs::create_dir_all(&global_dir).unwrap();
            fs::create_dir_all(&cwd).unwrap();
            Self {
                _tmp: tmp,
                global_dir,
                cwd,
            }
        }

        fn write_global(&self, filename: &str, yaml: &str) {
            fs::write(self.global_dir.join(filename), yaml).unwrap();
        }

        fn write_local(&self, filename: &str, yaml: &str) {
            fs::write(self.cwd.join(filename), yaml).unwrap();
        }

        fn loader(&self) -> DefaultConfigLoader {
            DefaultConfigLoader::with_global_dir(self.global_dir.clone())
        }

        fn load(&self) -> Result<Config, ConfigError> {
            self.loader().load(&self.cwd)
        }

        fn loader_without_global(&self) -> DefaultConfigLoader {
            DefaultConfigLoader { global_dir: None }
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

    // -- Global config: .yml / .yaml support and priority --

    #[rstest]
    #[case::yml("runok.yml")]
    #[case::yaml_fallback("runok.yaml")]
    fn load_global_only(#[case] filename: &str) {
        let env = TestEnv::new();
        env.write_global(
            filename,
            indoc! {"
                defaults:
                  action: deny
            "},
        );

        let config = env.load().unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
    }

    #[test]
    fn load_global_yml_takes_priority_over_yaml() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_global(
            "runok.yaml",
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

    // -- Global local override: .yml / .yaml support and priority --

    #[rstest]
    #[case::global_local_yml("runok.local.yml")]
    #[case::global_local_yaml_fallback("runok.local.yaml")]
    fn load_global_local_override(#[case] filename: &str) {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_global(
            filename,
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let config = env.load().unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[test]
    fn load_global_local_override_yml_takes_priority_over_yaml() {
        let env = TestEnv::new();
        env.write_global(
            "runok.local.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_global(
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

    // -- Project config: .yml / .yaml support and priority --

    #[rstest]
    #[case::yml("runok.yml")]
    #[case::yaml_fallback("runok.yaml")]
    fn load_local_only(#[case] filename: &str) {
        let env = TestEnv::new();
        env.write_local(
            filename,
            indoc! {"
                defaults:
                  action: deny
            "},
        );

        let config = env.load_without_global().unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
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

    // -- Project local override: .yml / .yaml support and priority --

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

    // -- Merge priority tests --

    #[test]
    fn load_merges_global_and_local() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
                  sandbox: global-sandbox
                rules:
                  - deny: 'rm -rf /'
            "},
        );
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
        env.write_global(
            "runok.yml",
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
        assert_eq!(paths["sensitive"], vec![".env*", "~/.ssh/**"]);
        assert_eq!(paths["logs"], vec!["/var/log/**"]);

        assert_eq!(defs.wrappers.unwrap(), vec!["sudo <cmd>", "bash -c <cmd>"]);
        assert_eq!(defs.commands.unwrap(), vec!["git commit", "git push"]);
    }

    #[test]
    fn load_project_overrides_global_local_override() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_global(
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
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[test]
    fn load_merges_all_three_layers() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
                  sandbox: global-sandbox
                rules:
                  - deny: 'rm -rf /'
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
        assert_eq!(defaults.action, Some(crate::config::ActionKind::Allow));
        assert_eq!(defaults.sandbox.as_deref(), Some("global-sandbox"));

        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status"));
        assert_eq!(rules[2].allow.as_deref(), Some("cargo test"));
    }

    #[test]
    fn load_merges_all_four_layers() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                defaults:
                  sandbox: global-sandbox
                rules:
                  - deny: 'rm -rf /'
            "},
        );
        env.write_global(
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
        assert_eq!(defaults.action, Some(crate::config::ActionKind::Allow));
        assert_eq!(defaults.sandbox.as_deref(), Some("global-sandbox"));

        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("internal-tool"));
        assert_eq!(rules[2].allow.as_deref(), Some("git status"));
        assert_eq!(rules[3].allow.as_deref(), Some("cargo test"));
    }

    #[test]
    fn load_local_override_only_without_project_config() {
        let env = TestEnv::new();
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

    // -- Parse error tests --

    #[test]
    fn load_validation_error_propagated() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
                    sandbox: restricted
            "},
        );

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
            env.write_global("runok.yml", "rules: [invalid yaml\n  broken:");
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
    fn load_global_local_override_parse_error() {
        let env = TestEnv::new();
        env.write_global("runok.local.yml", "rules: [invalid yaml\n  broken:");

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
}
