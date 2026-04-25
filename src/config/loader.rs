use std::path::{Path, PathBuf};

use super::cache::PresetCache;
use super::preset::resolve_extends;
use super::required_version::{check_required_runok_version, current_runok_version};
use super::{Config, ConfigError, ParsedConfig, parse_config_with_warnings};

/// Describes where the configuration should be loaded from.
///
/// `Default` performs the standard global-plus-project discovery rooted at
/// `cwd`. `Explicit` loads only the given file (used by the global `-c` /
/// `--config` flag), skipping all discovery.
#[derive(Debug, Clone)]
pub enum ConfigSource {
    Default { cwd: PathBuf },
    Explicit { path: PathBuf },
}

impl ConfigSource {
    /// Build a `ConfigSource` from an optional explicit path and a `cwd`
    /// fallback. `Some(path)` becomes `Explicit`; `None` falls back to
    /// default discovery rooted at `cwd`.
    pub fn from_flag(config_flag: Option<&Path>, cwd: &Path) -> Self {
        match config_flag {
            Some(path) => ConfigSource::Explicit {
                path: path.to_path_buf(),
            },
            None => ConfigSource::Default {
                cwd: cwd.to_path_buf(),
            },
        }
    }
}

/// Trait for loading and merging configuration files.
pub trait ConfigLoader {
    /// Load the configuration for the given source. Implementations must
    /// honour both `Default` discovery and `Explicit` single-file loading
    /// so that callers never have to branch on the variant themselves.
    fn load(&self, source: &ConfigSource) -> Result<Config, ConfigError>;
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

    /// Return all config file paths that would be loaded for the given `cwd`.
    ///
    /// The returned list includes global and project config files (both main and
    /// local override variants), in merge-priority order.
    pub fn find_config_paths(&self, cwd: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        let mut collect = |dir: &Path| {
            if let Some(p) = Self::find_config(dir, CONFIG_FILENAMES) {
                paths.push(p);
            }
            if let Some(p) = Self::find_config(dir, LOCAL_OVERRIDE_FILENAMES) {
                paths.push(p);
            }
        };

        if let Some(dir) = &self.global_dir {
            collect(dir);
        }
        if let Some(dir) = self.find_project_dir(cwd) {
            collect(&dir);
        }

        paths
    }

    /// Read, parse, resolve paths, and resolve extends in a config file using its own base_dir.
    /// Resolving paths and extends before merging prevents global config paths from being
    /// incorrectly re-resolved with the local base_dir.
    fn find_parse_and_resolve(
        dir: &Path,
        filenames: &[&str],
    ) -> Result<Option<Config>, ConfigError> {
        Self::find_config(dir, filenames)
            .map(|p| parse_and_resolve(&p))
            .transpose()
    }
}

/// Read, parse, resolve paths, and resolve extends in a config file.
fn parse_and_resolve(path: &Path) -> Result<Config, ConfigError> {
    let mut config = read_and_parse(path)?;
    let base_dir = path.parent().unwrap_or(Path::new("."));
    super::path_resolver::resolve_config_paths(&mut config, base_dir)?;
    if config.extends.as_ref().is_some_and(|e| !e.is_empty()) {
        let source_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("runok.yml");
        let cache = PresetCache::from_env()?;
        config = resolve_extends(config, base_dir, source_name, &cache)?;
    }
    Ok(config)
}

fn read_and_parse(path: &Path) -> Result<Config, ConfigError> {
    let yaml = std::fs::read_to_string(path)?;
    let ParsedConfig { config, warnings } = parse_config_with_warnings(&yaml)?;
    for warning in &warnings {
        eprintln!("runok warning: {warning}\n  --> {}", path.display());
    }
    // Enforce `required_runok_version` as soon as the file is parsed so
    // that the error message points at the exact file that carries the
    // constraint.
    check_required_runok_version(
        config.required_runok_version.as_deref(),
        &current_runok_version(),
        &path.display().to_string(),
    )?;
    Ok(config)
}

/// Load a single config file without the global/project config discovery.
///
/// Parses the file, resolves paths and `extends`, and validates the result.
/// No global or local override files are merged — the returned `Config`
/// reflects only the given file (with extends resolved recursively).
fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
    let mut config = parse_and_resolve(path)?;
    config.validate()?;
    Ok(config)
}

/// Strip audit settings from a config, emitting a warning.
/// Audit settings can only be configured in the global config.
fn strip_audit(mut config: Config, source: &str) -> Config {
    if config.audit.is_some() {
        eprintln!(
            "runok warning: 'audit' section in {source} is ignored \
             (audit settings can only be configured in the global config)"
        );
        config.audit = None;
    }
    config
}

impl ConfigLoader for DefaultConfigLoader {
    fn load(&self, source: &ConfigSource) -> Result<Config, ConfigError> {
        match source {
            ConfigSource::Default { cwd } => self.load_default(cwd),
            ConfigSource::Explicit { path } => load_from_path(path),
        }
    }
}

impl DefaultConfigLoader {
    /// Load using the standard global + project discovery.
    fn load_default(&self, cwd: &Path) -> Result<Config, ConfigError> {
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
                Self::find_parse_and_resolve(dir, CONFIG_FILENAMES)?
                    .map(|c| strip_audit(c, "project config")),
                Self::find_parse_and_resolve(dir, LOCAL_OVERRIDE_FILENAMES)?
                    .map(|c| strip_audit(c, "local override config")),
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
            self.loader().load(&ConfigSource::Default {
                cwd: self.cwd.clone(),
            })
        }

        fn loader_without_global(&self) -> DefaultConfigLoader {
            DefaultConfigLoader {
                global_dir: None,
                home_dir: Some(self.home_dir.clone()),
            }
        }

        fn load_without_global(&self) -> Result<Config, ConfigError> {
            self.loader_without_global().load(&ConfigSource::Default {
                cwd: self.cwd.clone(),
            })
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

    #[test]
    fn load_audit_global_only_ignores_local_overrides() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                audit:
                  enabled: true
                  path: /global/audit/
                  rotation:
                    retention_days: 30
            "},
        );
        env.write_local(
            "runok.yml",
            indoc! {"
                audit:
                  enabled: false
                  path: /local/audit/
            "},
        );
        env.write_local(
            "runok.local.yml",
            indoc! {"
                audit:
                  rotation:
                    retention_days: 7
            "},
        );

        let config = env.load().unwrap();
        let audit = config.audit.unwrap();
        // global values are preserved; local overrides are ignored
        assert_eq!(audit.enabled, Some(true));
        assert_eq!(audit.path.as_deref(), Some("/global/audit/"));
        assert_eq!(audit.rotation.unwrap().retention_days, Some(30));
    }

    #[test]
    fn load_audit_stripped_from_extended_project_config() {
        let env = TestEnv::new();
        env.write_global(
            "runok.yml",
            indoc! {"
                audit:
                  enabled: true
                  path: /global/audit/
            "},
        );
        // Preset file referenced by project config contains audit settings
        fs::write(
            env.cwd.join("preset.yml"),
            indoc! {"
                audit:
                  enabled: false
                  path: /preset/audit/
                rules:
                  - allow: 'echo preset'
            "},
        )
        .unwrap();
        env.write_local(
            "runok.yml",
            indoc! {"
                extends:
                  - ./preset.yml
                rules:
                  - allow: 'echo local'
            "},
        );

        let config = env.load().unwrap();
        let audit = config.audit.unwrap();
        // Audit from the extended preset is stripped; global audit is preserved
        assert_eq!(audit.enabled, Some(true));
        assert_eq!(audit.path.as_deref(), Some("/global/audit/"));
        // Rules from the preset are still merged
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("echo preset"));
        assert_eq!(rules[1].allow.as_deref(), Some("echo local"));
    }

    #[test]
    fn load_audit_absent_returns_none() {
        let env = TestEnv::new();
        env.write_local(
            "runok.yml",
            indoc! {"
                defaults:
                  action: allow
            "},
        );

        let config = env.load_without_global().unwrap();
        assert_eq!(config.audit, None);
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

        let config = env
            .loader_without_global()
            .load(&ConfigSource::Default {
                cwd: subdir.clone(),
            })
            .unwrap();
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

        let config = env
            .loader_without_global()
            .load(&ConfigSource::Default {
                cwd: subdir.clone(),
            })
            .unwrap();
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

        let config = env
            .loader_without_global()
            .load(&ConfigSource::Default {
                cwd: subdir.clone(),
            })
            .unwrap();
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

        let config = env
            .loader_without_global()
            .load(&ConfigSource::Default { cwd: inner.clone() })
            .unwrap();
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

        let config = env
            .loader_without_global()
            .load(&ConfigSource::Default {
                cwd: subdir.clone(),
            })
            .unwrap();
        assert_eq!(config, Config::default());
    }
}
