use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::cache::PresetCache;
use super::git_client::{GitClient, ProcessGitClient};
use super::preset_remote::{PresetReference, load_remote_preset, parse_preset_reference};
use super::{Config, ConfigError, PresetError, parse_config};

const MAX_EXTENDS_DEPTH: usize = 10;

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

/// Resolve all `extends` references in a config, recursively loading and merging presets.
///
/// Uses DFS with a `chain` vector to track the current resolution path and detect
/// circular references. When a reference is encountered that already exists in the chain,
/// returns `PresetError::CircularReference` with the full cycle path.
///
/// Convenience wrapper around `resolve_extends_with` that uses `ProcessGitClient`.
pub fn resolve_extends(
    config: Config,
    base_dir: &Path,
    source_name: &str,
    cache: &PresetCache,
) -> Result<Config, ConfigError> {
    resolve_extends_with(config, base_dir, source_name, &ProcessGitClient, cache)
}

/// Resolve all `extends` references in a config with a custom git client.
pub fn resolve_extends_with<G: GitClient>(
    config: Config,
    base_dir: &Path,
    source_name: &str,
    git_client: &G,
    cache: &PresetCache,
) -> Result<Config, ConfigError> {
    let mut chain = vec![source_name.to_string()];
    let mut visited = HashSet::new();
    visited.insert(source_name.to_string());

    resolve_extends_recursive(
        config,
        base_dir,
        git_client,
        cache,
        &mut chain,
        &mut visited,
    )
}

/// Recursive inner function for extends resolution.
///
/// `chain` tracks the current DFS path (ordered) for cycle reporting.
/// `visited` is the set of all references in the current chain for O(1) lookup.
fn resolve_extends_recursive<G: GitClient>(
    config: Config,
    base_dir: &Path,
    git_client: &G,
    cache: &PresetCache,
    chain: &mut Vec<String>,
    visited: &mut HashSet<String>,
) -> Result<Config, ConfigError> {
    let extends = match &config.extends {
        Some(refs) if !refs.is_empty() => refs.clone(),
        _ => return Ok(config),
    };

    // Start with an empty config and merge each resolved preset in order,
    // then merge the current config on top (current config takes priority).
    let mut merged = Config::default();

    for reference in &extends {
        if visited.contains(reference.as_str()) {
            // Build the cycle chain: from the first occurrence of `reference` to the end
            let cycle_start = chain.iter().position(|r| r == reference).unwrap_or(0);
            let mut cycle: Vec<String> = chain[cycle_start..].to_vec();
            cycle.push(reference.clone());
            return Err(PresetError::CircularReference { cycle }.into());
        }

        if chain.len() >= MAX_EXTENDS_DEPTH {
            let mut cycle = chain.clone();
            cycle.push(reference.clone());
            return Err(PresetError::CircularReference { cycle }.into());
        }

        chain.push(reference.clone());
        visited.insert(reference.clone());

        // Load the preset config (without resolving its extends yet)
        let mut load_visited = HashSet::new();
        let preset_config =
            load_preset_with(reference, base_dir, git_client, cache, &mut load_visited)?;

        // Determine the base_dir for the loaded preset's own extends
        let preset_base_dir = determine_preset_base_dir(reference, base_dir);

        // Recursively resolve the preset's own extends
        let resolved = resolve_extends_recursive(
            preset_config,
            &preset_base_dir,
            git_client,
            cache,
            chain,
            visited,
        )?;

        merged = merged.merge(resolved);

        visited.remove(reference.as_str());
        chain.pop();
    }

    // Strip extends from the current config before merging (already resolved)
    let current = Config {
        extends: None,
        ..config
    };

    Ok(merged.merge(current))
}

/// Determine the base directory for a preset's own extends resolution.
fn determine_preset_base_dir(reference: &str, parent_base_dir: &Path) -> PathBuf {
    let parsed = parse_preset_reference(reference);
    match parsed {
        Ok(PresetReference::Local(_)) => {
            // For local presets, resolve relative to the preset file's directory
            let path = parent_base_dir.join(reference);
            path.parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| parent_base_dir.to_path_buf())
        }
        _ => {
            // For remote presets, the base_dir stays the same
            // (remote presets' relative extends are resolved relative to the repo root,
            // which is handled by the cache directory)
            parent_base_dir.to_path_buf()
        }
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

    // === Circular reference detection ===

    #[rstest]
    fn circular_reference_direct(tmp: TempDir) {
        let base_dir = tmp.path();

        // a.yml extends b.yml, b.yml extends a.yml
        fs::write(
            base_dir.join("a.yml"),
            indoc! {"
                extends:
                  - ./b.yml
                rules:
                  - allow: 'git status'
            "},
        )
        .unwrap();
        fs::write(
            base_dir.join("b.yml"),
            indoc! {"
                extends:
                  - ./a.yml
                rules:
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        let config = parse_config(indoc! {"
            extends:
              - ./a.yml
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        let err = resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache)
            .unwrap_err();

        match err {
            ConfigError::Preset(PresetError::CircularReference { cycle }) => {
                assert_eq!(cycle, vec!["./a.yml", "./b.yml", "./a.yml"]);
            }
            other => panic!("expected CircularReference, got: {other:?}"),
        }
    }

    #[rstest]
    fn circular_reference_self(tmp: TempDir) {
        let base_dir = tmp.path();

        // a.yml extends itself
        fs::write(
            base_dir.join("a.yml"),
            indoc! {"
                extends:
                  - ./a.yml
                rules:
                  - allow: 'git status'
            "},
        )
        .unwrap();

        let config = parse_config(indoc! {"
            extends:
              - ./a.yml
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        let err = resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache)
            .unwrap_err();

        match err {
            ConfigError::Preset(PresetError::CircularReference { cycle }) => {
                assert_eq!(cycle, vec!["./a.yml", "./a.yml"]);
            }
            other => panic!("expected CircularReference, got: {other:?}"),
        }
    }

    #[rstest]
    fn circular_reference_three_level(tmp: TempDir) {
        let base_dir = tmp.path();

        // a.yml → b.yml → c.yml → a.yml
        fs::write(
            base_dir.join("a.yml"),
            indoc! {"
                extends:
                  - ./b.yml
            "},
        )
        .unwrap();
        fs::write(
            base_dir.join("b.yml"),
            indoc! {"
                extends:
                  - ./c.yml
            "},
        )
        .unwrap();
        fs::write(
            base_dir.join("c.yml"),
            indoc! {"
                extends:
                  - ./a.yml
            "},
        )
        .unwrap();

        let config = parse_config(indoc! {"
            extends:
              - ./a.yml
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        let err = resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache)
            .unwrap_err();

        match err {
            ConfigError::Preset(PresetError::CircularReference { cycle }) => {
                assert_eq!(cycle, vec!["./a.yml", "./b.yml", "./c.yml", "./a.yml"]);
            }
            other => panic!("expected CircularReference, got: {other:?}"),
        }
    }

    #[rstest]
    fn circular_reference_back_to_root(tmp: TempDir) {
        let base_dir = tmp.path();

        // a.yml extends back to runok.yml (the root source)
        fs::write(
            base_dir.join("a.yml"),
            indoc! {"
                extends:
                  - ./runok.yml
            "},
        )
        .unwrap();
        fs::write(
            base_dir.join("runok.yml"),
            indoc! {"
                rules:
                  - allow: 'ls'
            "},
        )
        .unwrap();

        let config = parse_config(indoc! {"
            extends:
              - ./a.yml
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        // "runok.yml" is in the chain as the root, so ./runok.yml would collide
        // if the reference matches. But "./runok.yml" != "runok.yml" as strings.
        // This test verifies that different string representations are treated as
        // different references (no false positive).
        let result = resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache);
        // "./runok.yml" is a different string from "runok.yml", so no circular reference
        assert!(result.is_ok());
    }

    // === Nested extends resolution (no cycles) ===

    #[rstest]
    fn nested_extends_resolved(tmp: TempDir) {
        let base_dir = tmp.path();

        // base.yml has rules
        fs::write(
            base_dir.join("base.yml"),
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        // mid.yml extends base.yml and adds rules
        fs::write(
            base_dir.join("mid.yml"),
            indoc! {"
                extends:
                  - ./base.yml
                rules:
                  - allow: 'cargo test'
            "},
        )
        .unwrap();

        // root config extends mid.yml
        let config = parse_config(indoc! {"
            extends:
              - ./mid.yml
            rules:
              - allow: 'git status'
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        let resolved =
            resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache).unwrap();

        let rules = resolved.rules.unwrap();
        assert_eq!(rules.len(), 3);
        // base.yml rules first, then mid.yml, then root
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
        assert_eq!(rules[1].allow.as_deref(), Some("cargo test"));
        assert_eq!(rules[2].allow.as_deref(), Some("git status"));
    }

    #[rstest]
    fn diamond_extends_resolved(tmp: TempDir) {
        let base_dir = tmp.path();

        // common.yml is shared
        fs::write(
            base_dir.join("common.yml"),
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        // a.yml extends common.yml
        fs::write(
            base_dir.join("a.yml"),
            indoc! {"
                extends:
                  - ./common.yml
                rules:
                  - allow: 'git status'
            "},
        )
        .unwrap();

        // b.yml extends common.yml
        fs::write(
            base_dir.join("b.yml"),
            indoc! {"
                extends:
                  - ./common.yml
                rules:
                  - allow: 'cargo test'
            "},
        )
        .unwrap();

        // root extends both a.yml and b.yml (diamond shape)
        let config = parse_config(indoc! {"
            extends:
              - ./a.yml
              - ./b.yml
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        // Diamond is not a circular reference, so this should succeed.
        // common.yml is loaded twice but that's expected (no cycle).
        let resolved =
            resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache).unwrap();

        let rules = resolved.rules.unwrap();
        // common.yml (from a.yml) + a.yml + common.yml (from b.yml) + b.yml
        assert_eq!(rules.len(), 4);
    }

    #[rstest]
    fn no_extends_returns_config_as_is(tmp: TempDir) {
        let base_dir = tmp.path();
        let config = parse_config(indoc! {"
            rules:
              - allow: 'git status'
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        let resolved = resolve_extends_with(
            config.clone(),
            base_dir,
            "runok.yml",
            &ProcessGitClient,
            &cache,
        )
        .unwrap();

        assert_eq!(resolved.rules, config.rules);
    }

    #[rstest]
    fn extends_stripped_from_resolved_config(tmp: TempDir) {
        let base_dir = tmp.path();

        fs::write(
            base_dir.join("base.yml"),
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        let config = parse_config(indoc! {"
            extends:
              - ./base.yml
            rules:
              - allow: 'git status'
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        let resolved =
            resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache).unwrap();

        // extends should be stripped from the resolved config
        assert!(resolved.extends.is_none());
    }

    #[rstest]
    fn error_message_contains_cycle_chain(tmp: TempDir) {
        let base_dir = tmp.path();

        fs::write(
            base_dir.join("a.yml"),
            indoc! {"
                extends:
                  - ./b.yml
            "},
        )
        .unwrap();
        fs::write(
            base_dir.join("b.yml"),
            indoc! {"
                extends:
                  - ./a.yml
            "},
        )
        .unwrap();

        let config = parse_config(indoc! {"
            extends:
              - ./a.yml
        "})
        .unwrap();

        let cache = PresetCache::with_config(
            base_dir.join(".cache"),
            std::time::Duration::from_secs(3600),
        );
        let err = resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache)
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "preset error: circular reference detected: ./a.yml \u{2192} ./b.yml \u{2192} ./a.yml"
        );
    }
}
