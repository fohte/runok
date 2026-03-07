//! Resolves path strings in config files against a base directory.
//!
//! Paths are classified into three categories, each resolved differently:
//! - Absolute paths (starting with `/`): returned as-is
//! - Home directory paths (starting with `~/` or bare `~`): expanded with `$HOME`
//! - Relative paths (everything else): joined with base_dir
//!
//! Does not apply `canonicalize()` to paths containing glob patterns.

use std::path::{Component, Path, PathBuf};

use super::ConfigError;

/// Error during path resolution.
#[derive(Debug, thiserror::Error)]
pub enum PathResolveError {
    #[error("cannot expand '~': HOME environment variable is not set")]
    HomeNotSet,
}

impl From<PathResolveError> for ConfigError {
    fn from(e: PathResolveError) -> Self {
        ConfigError::Validation(vec![e.to_string()])
    }
}

/// Resolves a path string against a base directory.
///
/// - Absolute paths are normalized and returned as-is
/// - Paths starting with `~/` are expanded with `$HOME` and normalized
/// - Relative paths are joined with `base_dir` and normalized
///
/// Normalization only resolves `.` and `..` logically without filesystem access.
/// Safe to apply to paths containing glob patterns.
pub fn resolve_path(path: &str, base_dir: &Path) -> Result<PathBuf, PathResolveError> {
    resolve_path_with(path, base_dir, get_home)
}

/// Version that accepts an injectable HOME retrieval function for testing.
fn resolve_path_with(
    path: &str,
    base_dir: &Path,
    home_fn: impl FnOnce() -> Option<String>,
) -> Result<PathBuf, PathResolveError> {
    if path == "~" {
        let home = home_fn().ok_or(PathResolveError::HomeNotSet)?;
        return Ok(normalize_logical(Path::new(&home)));
    }

    if let Some(rest) = path.strip_prefix("~/") {
        let home = home_fn().ok_or(PathResolveError::HomeNotSet)?;
        let joined = PathBuf::from(&home).join(rest);
        return Ok(normalize_logical(&joined));
    }

    let p = Path::new(path);
    if p.is_absolute() {
        Ok(normalize_logical(p))
    } else {
        Ok(normalize_logical(&base_dir.join(path)))
    }
}

/// Logically normalizes `.` and `..` components (filesystem-independent).
fn normalize_logical(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other),
        }
    }
    result
}

/// Resolves all paths in definitions.paths and definitions.sandbox within a Config.
pub fn resolve_config_paths(
    config: &mut super::Config,
    base_dir: &Path,
) -> Result<(), PathResolveError> {
    let Some(defs) = config.definitions.as_mut() else {
        return Ok(());
    };

    // Resolve all paths in definitions.paths
    if let Some(paths) = defs.paths.as_mut() {
        for values in paths.values_mut() {
            for value in values.iter_mut() {
                *value = resolve_path(value, base_dir)?.to_string_lossy().to_string();
            }
        }
    }

    // Resolve all paths in definitions.sandbox fs.writable and fs.deny
    if let Some(sandbox) = defs.sandbox.as_mut() {
        for preset in sandbox.values_mut() {
            if let Some(fs) = preset.fs.as_mut() {
                if let Some(writable) = fs.writable.as_mut() {
                    for path in writable.iter_mut() {
                        *path = resolve_path(path, base_dir)?.to_string_lossy().to_string();
                    }
                }
                if let Some(deny) = fs.deny.as_mut() {
                    for path in deny.iter_mut() {
                        *path = resolve_path(path, base_dir)?.to_string_lossy().to_string();
                    }
                }
            }
        }
    }

    Ok(())
}

fn get_home() -> Option<String> {
    std::env::var("HOME").ok().filter(|h| !h.is_empty())
}

/// Expands paths starting with `~` using `$HOME`.
/// Safe to apply to already-resolved paths (idempotent).
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    } else if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return home;
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::path::Path;

    fn resolve_with_fake_home(
        path: &str,
        base_dir: &Path,
        home: Option<&str>,
    ) -> Result<PathBuf, PathResolveError> {
        let home_owned = home.map(|h| h.to_string());
        resolve_path_with(path, base_dir, move || home_owned)
    }

    // === Path classification and resolution ===

    #[rstest]
    #[case::absolute_simple("/usr/bin", "/project", "/usr/bin")]
    #[case::absolute_with_dot("/usr/./bin", "/project", "/usr/bin")]
    #[case::absolute_with_dotdot("/usr/local/../bin", "/project", "/usr/bin")]
    #[case::relative_simple("src/lib.rs", "/project", "/project/src/lib.rs")]
    #[case::relative_dot("./src/lib.rs", "/project", "/project/src/lib.rs")]
    #[case::relative_dotdot("../other/file", "/project/sub", "/project/other/file")]
    #[case::relative_glob("*.env*", "/project", "/project/*.env*")]
    #[case::relative_glob_nested("**/.git", "/project", "/project/**/.git")]
    #[case::absolute_glob("/var/log/**", "/project", "/var/log/**")]
    fn resolve_path_cases(#[case] input: &str, #[case] base_dir: &str, #[case] expected: &str) {
        let result = resolve_with_fake_home(input, Path::new(base_dir), Some("/home/user"));
        assert_eq!(result.unwrap(), PathBuf::from(expected));
    }

    #[rstest]
    #[case::tilde_subpath("~/projects/app", "/home/user/projects/app")]
    #[case::tilde_only("~", "/home/user")]
    #[case::tilde_with_dotdot("~/projects/../.ssh", "/home/user/.ssh")]
    fn resolve_tilde_cases(#[case] input: &str, #[case] expected: &str) {
        let result = resolve_with_fake_home(input, Path::new("/project"), Some("/home/user"));
        assert_eq!(result.unwrap(), PathBuf::from(expected));
    }

    #[rstest]
    #[case::tilde_prefix("~/foo")]
    #[case::tilde_only("~")]
    fn resolve_tilde_home_not_set(#[case] input: &str) {
        let result = resolve_with_fake_home(input, Path::new("/project"), None);
        assert!(matches!(result, Err(PathResolveError::HomeNotSet)));
    }

    // === normalize_logical ===

    #[rstest]
    #[case::identity("/a/b/c", "/a/b/c")]
    #[case::dot("/a/./b", "/a/b")]
    #[case::dotdot("/a/b/../c", "/a/c")]
    #[case::multiple_dots("/a/./b/./c", "/a/b/c")]
    #[case::multiple_dotdots("/a/b/c/../../d", "/a/d")]
    #[case::dotdot_at_root("/../a", "/a")]
    fn normalize_logical_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(normalize_logical(Path::new(input)), PathBuf::from(expected));
    }

    // === resolve_config_paths ===

    #[test]
    fn resolve_config_paths_resolves_definitions() {
        use crate::config::{Config, Definitions, FsPolicy, SandboxPreset};
        use std::collections::HashMap;

        let mut config = Config {
            definitions: Some(Definitions {
                paths: Some(HashMap::from([(
                    "sensitive".to_string(),
                    vec![".env*".to_string(), "~/.ssh/**".to_string()],
                )])),
                sandbox: Some(HashMap::from([(
                    "restricted".to_string(),
                    SandboxPreset {
                        fs: Some(FsPolicy {
                            writable: Some(vec!["./tmp".to_string()]),
                            deny: Some(vec![".env*".to_string()]),
                        }),
                        network: None,
                    },
                )])),
                ..Definitions::default()
            }),
            ..Config::default()
        };

        let base_dir = Path::new("/project");
        resolve_config_paths(&mut config, base_dir).unwrap();

        let defs = config.definitions.unwrap();
        let paths = defs.paths.unwrap();
        let sensitive = &paths["sensitive"];
        // Relative path is joined with base_dir
        assert_eq!(sensitive[0], "/project/.env*");
        // ~/ is expanded using the HOME environment variable
        assert!(
            !sensitive[1].starts_with("~/"),
            "tilde should be expanded: {}",
            sensitive[1]
        );
        assert!(
            sensitive[1].ends_with("/.ssh/**"),
            "should preserve subpath: {}",
            sensitive[1]
        );

        let sandbox = defs.sandbox.unwrap();
        let restricted = &sandbox["restricted"];
        let fs = restricted.fs.as_ref().unwrap();
        let writable = fs.writable.as_ref().unwrap();
        assert!(
            writable[0].starts_with("/project/"),
            "writable ./tmp should be resolved: {}",
            writable[0]
        );
        let deny = fs.deny.as_ref().unwrap();
        assert!(
            deny[0].starts_with("/project/"),
            "deny .env* should be resolved: {}",
            deny[0]
        );
    }
}
