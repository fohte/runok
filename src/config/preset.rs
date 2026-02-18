use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::cache::PresetCache;
use super::git_client::{GitClient, ProcessGitClient};
use super::preset_remote::{PresetReference, load_remote_preset, parse_preset_reference};
use super::{Config, ConfigError, PresetError, parse_config};

fn home_dir() -> Option<String> {
    std::env::var("HOME").ok().filter(|h| !h.is_empty())
}

/// Resolve a preset reference string into a filesystem path.
///
/// Supports three forms:
/// - Relative path (`./rules/aws.yml`): resolved from `base_dir`
/// - Home directory (`~/presets/git.yml`): `~` expanded via `get_home`
/// - Absolute path (`/etc/runok/global.yml`): used as-is
///
/// Relative and `~/` paths are validated against path traversal:
/// the resolved canonical path must stay within the expected root directory.
fn resolve_local_path(
    reference: &str,
    base_dir: &Path,
    get_home: impl FnOnce() -> Option<String>,
) -> Result<PathBuf, PresetError> {
    if let Some(rest) = reference.strip_prefix("~/") {
        let home = get_home().ok_or_else(|| {
            PresetError::InvalidReference(
                "cannot expand '~': HOME environment variable is not set".to_string(),
            )
        })?;
        let resolved = PathBuf::from(&home).join(rest);
        validate_within(&resolved, Path::new(&home), reference)?;
        Ok(resolved)
    } else {
        let path = Path::new(reference);
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            let resolved = base_dir.join(reference);
            validate_within(&resolved, base_dir, reference)?;
            Ok(resolved)
        }
    }
}

/// Verify that `resolved` stays within `root` after canonicalization.
///
/// Both `resolved` and `root` are canonicalized before comparison so that
/// `../` sequences are collapsed. If `resolved` does not exist yet, only
/// the existing ancestor portion is canonicalized.
fn validate_within(resolved: &Path, root: &Path, reference: &str) -> Result<(), PresetError> {
    let canonical = canonicalize_best_effort(resolved);
    let canonical_root = canonicalize_best_effort(root);

    if !canonical.starts_with(&canonical_root) {
        return Err(PresetError::InvalidReference(format!(
            "path traversal detected: '{reference}' escapes the base directory"
        )));
    }
    Ok(())
}

/// Normalize a path by resolving `.` and `..` logically (without touching the filesystem),
/// then canonicalize the longest existing prefix for symlink resolution.
fn canonicalize_best_effort(path: &Path) -> PathBuf {
    use std::path::Component;

    // First, logically normalize the path to eliminate `.` and `..`.
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other),
        }
    }

    // Try full canonicalization on the normalized path.
    if let Ok(p) = normalized.canonicalize() {
        return p;
    }

    // Walk up to find the longest existing ancestor, canonicalize it,
    // then re-append the non-existent tail.
    let mut existing = normalized.clone();
    let mut tail = Vec::new();
    while !existing.exists() {
        if let Some(name) = existing.file_name() {
            tail.push(name.to_os_string());
        } else {
            break;
        }
        existing = match existing.parent() {
            Some(p) => p.to_path_buf(),
            None => break,
        };
    }

    let mut result = existing.canonicalize().unwrap_or(existing);
    for component in tail.into_iter().rev() {
        result.push(component);
    }
    result
}

/// Load a local preset file and parse it as a `Config`.
///
/// `reference` is a local path string (relative, absolute, or `~/`-prefixed).
/// `base_dir` is the directory of the file that contains the `extends` entry.
pub fn load_local_preset(
    reference: &str,
    base_dir: &Path,
    // Will be used for circular reference detection (planned for a future task).
    _visited: &mut HashSet<String>,
) -> Result<Config, ConfigError> {
    let path = resolve_local_path(reference, base_dir, home_dir)?;

    if !path.exists() {
        return Err(PresetError::LocalNotFound(path).into());
    }

    let yaml = std::fs::read_to_string(&path)?;
    let config = parse_config(&yaml)?;
    Ok(config)
}

/// Load a preset by reference string using the real git client.
///
/// Convenience wrapper around `load_preset_with` that uses `ProcessGitClient`.
pub fn load_preset(
    reference: &str,
    base_dir: &Path,
    cache: &PresetCache,
    visited: &mut HashSet<String>,
) -> Result<Config, ConfigError> {
    load_preset_with(reference, base_dir, &ProcessGitClient, cache, visited)
}

/// Load a preset by reference string, dispatching to local or remote loader.
///
/// Parses the reference to determine its type, then delegates to the appropriate loader:
/// - Local paths → `load_local_preset`
/// - GitHub shorthand / git URLs → `load_remote_preset` (with caching)
pub fn load_preset_with<G: GitClient>(
    reference: &str,
    base_dir: &Path,
    git_client: &G,
    cache: &PresetCache,
    visited: &mut HashSet<String>,
) -> Result<Config, ConfigError> {
    let parsed = parse_preset_reference(reference)?;
    match parsed {
        PresetReference::Local(_) => load_local_preset(reference, base_dir, visited),
        _ => load_remote_preset(&parsed, reference, git_client, cache, visited),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use std::fs;
    use tempfile::TempDir;

    #[fixture]
    fn tmp() -> TempDir {
        TempDir::new().unwrap()
    }

    #[rstest]
    #[case::relative_dot_slash(
        "./rules/aws.yml",
        "rules/aws.yml",
        indoc! {"
            rules:
              - allow: 'aws s3 ls'
        "},
    )]
    #[case::relative_no_dot(
        "presets/base.yml",
        "presets/base.yml",
        indoc! {"
            defaults:
              action: deny
        "},
    )]
    fn resolve_relative_path(
        tmp: TempDir,
        #[case] reference: &str,
        #[case] relative_file_path: &str,
        #[case] yaml_content: &str,
    ) {
        let base_dir = tmp.path().join("project");

        let file_path = base_dir.join(relative_file_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, yaml_content).unwrap();

        let mut visited = HashSet::new();
        let config = load_local_preset(reference, &base_dir, &mut visited).unwrap();
        assert!(
            config.rules.is_some() || config.defaults.is_some(),
            "loaded config should have content"
        );
    }

    #[rstest]
    fn resolve_absolute_path(tmp: TempDir) {
        let preset_path = tmp.path().join("absolute-preset.yml");
        fs::write(
            &preset_path,
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        let other_dir = tmp.path().join("other");
        fs::create_dir_all(&other_dir).unwrap();

        let reference = preset_path.to_str().unwrap();
        let mut visited = HashSet::new();
        let config = load_local_preset(reference, &other_dir, &mut visited).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
    }

    #[rstest]
    fn resolve_home_directory_path(tmp: TempDir) {
        let fake_home = tmp.path().join("fakehome");
        fs::create_dir_all(fake_home.join("presets")).unwrap();
        fs::write(
            fake_home.join("presets/git.yml"),
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        )
        .unwrap();

        let fake_home_str = fake_home.to_str().unwrap().to_string();
        let path =
            resolve_local_path("~/presets/git.yml", tmp.path(), || Some(fake_home_str)).unwrap();

        let yaml = fs::read_to_string(&path).unwrap();
        let config = parse_config(&yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
    }

    #[test]
    fn error_on_home_not_set() {
        let err = resolve_local_path("~/presets/git.yml", Path::new("/tmp"), || None).unwrap_err();
        assert!(matches!(err, PresetError::InvalidReference(_)));
        assert!(err.to_string().contains("HOME"));
    }

    #[rstest]
    fn error_on_nonexistent_file(tmp: TempDir) {
        let base_dir = tmp.path();

        let mut visited = HashSet::new();
        let err = load_local_preset("./nonexistent.yml", base_dir, &mut visited).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::LocalNotFound(path)) => {
                assert!(
                    path.ends_with("nonexistent.yml"),
                    "error path should contain the filename, got: {path:?}"
                );
            }
            other => panic!("expected PresetError::LocalNotFound, got: {other:?}"),
        }
    }

    #[rstest]
    fn error_on_nonexistent_absolute_path(tmp: TempDir) {
        let missing_path = tmp.path().join("does-not-exist.yml");
        let reference = missing_path.to_str().unwrap();

        let mut visited = HashSet::new();
        let err = load_local_preset(reference, tmp.path(), &mut visited).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::LocalNotFound(path)) => {
                assert_eq!(path, missing_path);
            }
            other => panic!("expected PresetError::LocalNotFound, got: {other:?}"),
        }
    }

    #[rstest]
    fn error_on_invalid_yaml_in_preset(tmp: TempDir) {
        let preset_path = tmp.path().join("bad.yml");
        fs::write(&preset_path, "rules: [invalid yaml\n  broken:").unwrap();

        let mut visited = HashSet::new();
        let err = load_local_preset("./bad.yml", tmp.path(), &mut visited).unwrap_err();
        assert!(matches!(err, ConfigError::Yaml(_)));
    }

    #[rstest]
    fn loaded_preset_config_is_valid(tmp: TempDir) {
        let base_dir = tmp.path();
        fs::write(
            base_dir.join("preset.yml"),
            indoc! {"
                defaults:
                  action: allow
                rules:
                  - allow: 'git status'
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        let mut visited = HashSet::new();
        let config = load_local_preset("./preset.yml", base_dir, &mut visited).unwrap();

        assert_eq!(
            config.defaults.as_ref().unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
        assert_eq!(rules[1].deny.as_deref(), Some("rm -rf /"));
    }

    // === Path traversal prevention ===

    #[rstest]
    #[case::dot_dot_relative(
        "../../etc/passwd",
        "path traversal detected: '../../etc/passwd' escapes the base directory"
    )]
    #[case::dot_dot_nested(
        "./rules/../../etc/passwd",
        "path traversal detected: './rules/../../etc/passwd' escapes the base directory"
    )]
    fn error_on_path_traversal_relative(
        tmp: TempDir,
        #[case] reference: &str,
        #[case] expected_msg: &str,
    ) {
        let base_dir = tmp.path().join("project");
        fs::create_dir_all(&base_dir).unwrap();

        let mut visited = HashSet::new();
        let err = load_local_preset(reference, &base_dir, &mut visited).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::InvalidReference(msg)) => {
                assert_eq!(msg, expected_msg);
            }
            other => panic!("expected PresetError::InvalidReference, got: {other:?}"),
        }
    }

    #[rstest]
    fn error_on_path_traversal_home(tmp: TempDir) {
        let fake_home = tmp.path().join("fakehome");
        fs::create_dir_all(&fake_home).unwrap();

        let fake_home_str = fake_home.to_str().unwrap().to_string();
        let err = resolve_local_path("~/../../etc/passwd", tmp.path(), || Some(fake_home_str))
            .unwrap_err();

        match err {
            PresetError::InvalidReference(msg) => {
                assert_eq!(
                    msg,
                    "path traversal detected: '~/../../etc/passwd' escapes the base directory"
                );
            }
            other => panic!("expected PresetError::InvalidReference, got: {other:?}"),
        }
    }
}
