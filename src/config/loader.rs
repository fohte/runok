use std::path::{Path, PathBuf};

use super::{Config, ConfigError, parse_config};

/// Trait for loading and merging configuration files.
pub trait ConfigLoader {
    fn load(&self, cwd: &Path) -> Result<Config, ConfigError>;
}

/// Default implementation that reads from the filesystem.
pub struct DefaultConfigLoader {
    global_dir: Option<PathBuf>,
    home_dir: Option<PathBuf>,
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
        let home_dir = super::dirs::home_dir();
        Self {
            global_dir,
            home_dir,
        }
    }

    /// Create a loader with an explicit global config directory (for testing).
    pub fn with_global_dir(dir: PathBuf) -> Self {
        Self {
            global_dir: Some(dir),
            home_dir: super::dirs::home_dir(),
        }
    }

    /// Create a loader with explicit global and home directories (for testing).
    #[cfg(test)]
    fn with_dirs(global_dir: PathBuf, home_dir: PathBuf) -> Self {
        Self {
            global_dir: Some(global_dir),
            home_dir: Some(home_dir),
        }
    }

    /// Walk up from `start` looking for a directory that contains a config file
    /// (`runok.yml`, `runok.yaml`, `runok.local.yml`, or `runok.local.yaml`).
    /// Stop before reaching `home_dir` (i.e. `~/runok.yml` is ignored).
    fn find_project_dir(&self, start: &Path) -> Option<PathBuf> {
        for ancestor in start.ancestors() {
            if let Some(home) = &self.home_dir
                && ancestor == home
            {
                break;
            }
            let has_config = CONFIG_FILENAMES
                .iter()
                .chain(LOCAL_OVERRIDE_FILENAMES)
                .any(|name| ancestor.join(name).exists());
            if has_config {
                return Some(ancestor.to_path_buf());
            }
        }
        None
    }

    /// Find the first existing file from `filenames` inside `dir`.
    fn find_config(dir: &Path, filenames: &[&str]) -> Option<PathBuf> {
        filenames
            .iter()
            .map(|name| dir.join(name))
            .find(|path| path.exists())
    }

    /// Read, parse, and resolve paths in a config file using its own base_dir.
    /// Resolving paths before merging prevents global config paths from being
    /// incorrectly re-resolved with the local base_dir.
    fn find_parse_and_resolve(
        dir: &Path,
        filenames: &[&str],
    ) -> Result<Option<Config>, ConfigError> {
        Self::find_config(dir, filenames)
            .map(|p| {
                let mut config = Self::read_and_parse(&p)?;
                let base_dir = p.parent().unwrap_or(dir);
                super::path_resolver::resolve_config_paths(&mut config, base_dir)?;
                Ok(config)
            })
            .transpose()
    }

    fn read_and_parse(path: &Path) -> Result<Config, ConfigError> {
        let yaml = std::fs::read_to_string(path)?;
        parse_config(&yaml)
    }
}

impl ConfigLoader for DefaultConfigLoader {
    fn load(&self, cwd: &Path) -> Result<Config, ConfigError> {
        // Resolve paths in each config file with its own base_dir before merging
        let (global, global_local_override) = match &self.global_dir {
            Some(dir) => (
                Self::find_parse_and_resolve(dir, CONFIG_FILENAMES)?,
                Self::find_parse_and_resolve(dir, LOCAL_OVERRIDE_FILENAMES)?,
            ),
            None => (None, None),
        };

        let project_dir = self.find_project_dir(cwd);
        let (local, local_override) = match &project_dir {
            Some(dir) => (
                Self::find_parse_and_resolve(dir, CONFIG_FILENAMES)?,
                Self::find_parse_and_resolve(dir, LOCAL_OVERRIDE_FILENAMES)?,
            ),
            None => (None, None),
        };

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
    use rstest::{fixture, rstest};
    use std::fs;
    use tempfile::TempDir;

    /// Test environment with temp directories and a loader.
    struct TestEnv {
        _tmp: TempDir,
        global_dir: PathBuf,
        home_dir: PathBuf,
        cwd: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let home_dir = tmp.path().join("home");
            let global_dir = tmp.path().join("global");
            let cwd = home_dir.join("project");
            fs::create_dir_all(&home_dir).unwrap();
            fs::create_dir_all(&global_dir).unwrap();
            fs::create_dir_all(&cwd).unwrap();
            Self {
                _tmp: tmp,
                global_dir,
                home_dir,
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
            DefaultConfigLoader::with_dirs(self.global_dir.clone(), self.home_dir.clone())
        }

        fn load(&self) -> Result<Config, ConfigError> {
            self.loader().load(&self.cwd)
        }

        fn loader_without_global(&self) -> DefaultConfigLoader {
            DefaultConfigLoader {
                global_dir: None,
                home_dir: Some(self.home_dir.clone()),
            }
        }

        fn load_without_global(&self) -> Result<Config, ConfigError> {
            self.loader_without_global().load(&self.cwd)
        }
    }

    #[fixture]
    fn env() -> TestEnv {
        TestEnv::new()
    }

    #[rstest]
    fn load_no_config_files_returns_default(env: TestEnv) {
        assert_eq!(env.load_without_global().unwrap(), Config::default());
    }

    // -- Global config: .yml / .yaml support and priority --

    #[rstest]
    #[case::yml("runok.yml")]
    #[case::yaml_fallback("runok.yaml")]
    fn load_global_only(env: TestEnv, #[case] filename: &str) {
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

    #[rstest]
    #[case::global("runok.yml", "runok.yaml")]
    #[case::global_local_override("runok.local.yml", "runok.local.yaml")]
    fn load_global_yml_takes_priority_over_yaml(
        env: TestEnv,
        #[case] yml_file: &str,
        #[case] yaml_file: &str,
    ) {
        env.write_global(
            yml_file,
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_global(
            yaml_file,
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
    fn load_global_local_override(env: TestEnv, #[case] filename: &str) {
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

    // -- Project config: .yml / .yaml support and priority --

    #[rstest]
    #[case::yml("runok.yml")]
    #[case::yaml_fallback("runok.yaml")]
    fn load_local_only(env: TestEnv, #[case] filename: &str) {
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

    #[rstest]
    #[case::project("runok.yml", "runok.yaml")]
    #[case::project_local_override("runok.local.yml", "runok.local.yaml")]
    fn load_project_yml_takes_priority_over_yaml(
        env: TestEnv,
        #[case] yml_file: &str,
        #[case] yaml_file: &str,
    ) {
        env.write_local(
            yml_file,
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_local(
            yaml_file,
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
    fn load_local_override(env: TestEnv, #[case] filename: &str) {
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

    // -- Merge priority tests --

    #[rstest]
    fn load_merges_global_and_local(env: TestEnv) {
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

    #[rstest]
    fn load_merges_definitions(env: TestEnv) {
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
        // .env* is resolved relative to the global config's base_dir
        let global_env = format!("{}/.env*", env.global_dir.display());
        // ~/ is expanded using the HOME environment variable
        let sensitive = &paths["sensitive"];
        assert_eq!(sensitive[0], global_env);
        assert!(
            !sensitive[1].starts_with("~/"),
            "tilde should be expanded: {}",
            sensitive[1]
        );
        assert!(sensitive[1].ends_with("/.ssh/**"));
        // Absolute paths are kept as-is
        assert_eq!(paths["logs"], vec!["/var/log/**"]);

        assert_eq!(defs.wrappers.unwrap(), vec!["sudo <cmd>", "bash -c <cmd>"]);
        assert_eq!(defs.commands.unwrap(), vec!["git commit", "git push"]);
    }

    #[rstest]
    fn load_project_overrides_global_local_override(env: TestEnv) {
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

    #[rstest]
    fn load_merges_all_three_layers(env: TestEnv) {
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

    #[rstest]
    fn load_merges_all_four_layers(env: TestEnv) {
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

    #[rstest]
    fn load_local_override_only_without_project_config(env: TestEnv) {
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

    #[rstest]
    fn load_validation_error_propagated(env: TestEnv) {
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
    fn load_yaml_parse_error(
        env: TestEnv,
        #[case] global_invalid: bool,
        #[case] local_invalid: bool,
    ) {
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

    #[rstest]
    fn load_global_local_override_parse_error(env: TestEnv) {
        env.write_global("runok.local.yml", "rules: [invalid yaml\n  broken:");

        let result = env.load();
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    #[rstest]
    fn load_local_override_parse_error(env: TestEnv) {
        env.write_local("runok.local.yml", "rules: [invalid yaml\n  broken:");

        let result = env.load_without_global();
        assert!(matches!(result.unwrap_err(), ConfigError::Yaml(_)));
    }

    // -- Ancestor directory traversal tests --

    #[rstest]
    fn load_finds_config_in_parent_directory(env: TestEnv) {
        // Config is in the project dir (parent of subdirectory)
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        // cwd is a subdirectory
        let subdir = env.cwd.join("src").join("lib");
        fs::create_dir_all(&subdir).unwrap();

        let config = env.loader_without_global().load(&subdir).unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Deny)
        );
    }

    #[rstest]
    fn load_finds_config_and_local_override_in_parent(env: TestEnv) {
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        env.write_local(
            "runok.local.yml",
            indoc! {"
                defaults:
                  action: allow
            "},
        );
        let subdir = env.cwd.join("src");
        fs::create_dir_all(&subdir).unwrap();

        let config = env.loader_without_global().load(&subdir).unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[rstest]
    fn load_stops_at_home_dir(env: TestEnv) {
        // Place config in home dir — should be ignored
        fs::write(
            env.home_dir.join("runok.yml"),
            indoc! {"
                defaults:
                  action: deny
            "},
        )
        .unwrap();
        let subdir = env.home_dir.join("projects").join("myapp");
        fs::create_dir_all(&subdir).unwrap();

        let config = env.loader_without_global().load(&subdir).unwrap();
        assert_eq!(config, Config::default());
    }

    #[rstest]
    fn load_nearest_config_wins(env: TestEnv) {
        // Outer config at project level
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: deny
            "},
        );
        // Inner config in subproject
        let inner = env.cwd.join("packages").join("sub");
        fs::create_dir_all(&inner).unwrap();
        fs::write(
            inner.join("runok.yml"),
            indoc! {"
                defaults:
                  action: allow
            "},
        )
        .unwrap();

        let config = env.loader_without_global().load(&inner).unwrap();
        assert_eq!(
            config.defaults.unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
    }

    #[rstest]
    fn load_no_config_in_ancestor_returns_default(env: TestEnv) {
        // No config files anywhere
        let subdir = env.cwd.join("deep").join("path");
        fs::create_dir_all(&subdir).unwrap();

        let config = env.loader_without_global().load(&subdir).unwrap();
        assert_eq!(config, Config::default());
    }
}
