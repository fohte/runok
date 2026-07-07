use std::path::{Path, PathBuf};

use super::cache::PresetCache;
use super::git_client::{GitClient, ProcessGitClient};
use super::preset_remote::{PresetReference, load_remote_preset, parse_preset_reference};
use super::required_version::{check_required_runok_version, current_runok_version};
use super::{Config, ConfigError, PresetError, parse_config_with_warnings};

mod extends;

pub use extends::{resolve_extends, resolve_extends_with};

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
/// Relative and `~/` references are checked for `..`-based escape: a
/// reference like `../../etc/passwd` is rejected even when `base_dir` /
/// `$HOME` happens to make it resolve to a real file. The check is purely
/// lexical on the reference string — a symlink at the resolved path is
/// followed normally even when its target lives outside `base_dir` /
/// `$HOME`.
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

/// Verify that `reference` does not lexically escape `root` via `..` segments.
///
/// Both `resolved` and `root` are normalized lexically (`.` / `..` collapsed
/// without touching the filesystem), so a symlink at the resolved path whose
/// target lives outside `root` is allowed as long as the reference itself
/// stays inside `root`. Examples that fail: `../../etc/passwd` (relative),
/// `~/../../etc/passwd` (home).
fn validate_within(resolved: &Path, root: &Path, reference: &str) -> Result<(), PresetError> {
    // `root` is expected to be non-empty: `Path::starts_with` returns true
    // for an empty prefix, which would let `..` references through. All
    // callers (`resolve_local_path`) satisfy this — `base_dir` is supplied
    // by the loader from an existing directory, and `home_dir()` filters
    // out empty `$HOME`.
    let normalized = lexically_normalize(resolved);
    let normalized_root = lexically_normalize(root);

    if !normalized.starts_with(&normalized_root) {
        return Err(PresetError::InvalidReference(format!(
            "path traversal detected: '{reference}' escapes the base directory"
        )));
    }
    Ok(())
}

/// Collapse `.` and `..` in `path` purely lexically, without touching the
/// filesystem. Symlinks are not followed.
fn lexically_normalize(path: &Path) -> PathBuf {
    use std::path::Component;

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
    normalized
}

/// Lexically normalize a path and then canonicalize the longest existing
/// prefix so that distinct references to the same file (`./runok.yml` vs.
/// `runok.yml`, or different symlinks pointing at the same target) hash to
/// the same key. Used for cycle detection in extends resolution.
fn canonicalize_best_effort(path: &Path) -> PathBuf {
    let normalized = lexically_normalize(path);

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
pub fn load_local_preset(reference: &str, base_dir: &Path) -> Result<Config, ConfigError> {
    let path = resolve_local_path(reference, base_dir, home_dir)?;

    if !path.exists() {
        return Err(PresetError::LocalNotFound(path).into());
    }

    let yaml = std::fs::read_to_string(&path)?;
    let parsed = parse_config_with_warnings(&yaml)?;
    for warning in &parsed.warnings {
        eprintln!("runok warning: {warning}\n  --> {}", path.display());
    }
    let mut config = parsed.config;

    // Enforce `required_runok_version` per file so that violations are
    // attributed to the preset that declares the constraint.
    check_required_runok_version(
        config.required_runok_version.as_deref(),
        &current_runok_version(),
        &path.display().to_string(),
    )?;

    // Resolve paths in the preset relative to the preset file's parent directory
    let preset_base_dir = path.parent().unwrap_or(base_dir);
    super::path_resolver::resolve_config_paths(&mut config, preset_base_dir)?;

    Ok(config)
}

/// Load a preset by reference string using the real git client.
///
/// Convenience wrapper around `load_preset_with` that uses `ProcessGitClient`.
pub fn load_preset(
    reference: &str,
    base_dir: &Path,
    cache: &PresetCache,
) -> Result<Config, ConfigError> {
    load_preset_with(reference, base_dir, &ProcessGitClient, cache)
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
) -> Result<Config, ConfigError> {
    let parsed = parse_preset_reference(reference)?;
    match parsed {
        PresetReference::Local(_) => load_local_preset(reference, base_dir),
        _ => {
            let mut config = load_remote_preset(&parsed, reference, git_client, cache)?;

            // Enforce `required_runok_version` per file. For remote presets
            // the source label is the reference string so users can trace
            // the failure back to the exact preset entry they wrote.
            check_required_runok_version(
                config.required_runok_version.as_deref(),
                &current_runok_version(),
                reference,
            )?;

            // Resolve paths in the remote preset relative to the cache directory
            let cache_dir = cache.cache_dir(reference);
            super::path_resolver::resolve_config_paths(&mut config, &cache_dir)?;

            // Strip test definitions from remote presets.  Tests are authored
            // for the preset itself and should not be evaluated by downstream
            // consumers — local overrides would cause them to fail.
            //
            // Invariant: any new strip target added here must also be cleared
            // by `strip_preset_tests`, because `resolve_extends_recursive`
            // re-applies the same strip to nested children reached via local
            // paths under a remote ancestor.
            strip_preset_tests(&mut config);

            Ok(config)
        }
    }
}

/// Strip inline `tests` on each rule and the top-level `tests` from `config`.
///
/// Used for any preset reached via a remote ancestor in the extends chain so
/// that preset-authored tests are not evaluated under downstream overrides.
fn strip_preset_tests(config: &mut Config) {
    if let Some(rules) = &mut config.rules {
        for rule in rules.iter_mut() {
            rule.tests = None;
        }
    }
    config.tests = None;
}

/// Returns `true` when `reference` is a remote preset (GitHub shorthand or git URL).
fn is_remote_reference(reference: &str) -> bool {
    !matches!(
        parse_preset_reference(reference),
        Ok(PresetReference::Local(_))
    )
}

/// Fully load a preset by reference and recursively resolve its `extends`.
///
/// This is a convenience helper for callers that need to materialize the
/// entire preset tree at a given reference — for example `update-presets`,
/// which must probe every file under a candidate tag to verify that all of
/// them satisfy the current `required_runok_version`.
///
/// The returned `Config` contains the merged result of the preset and every
/// file it transitively extends. Any `ConfigError` raised while loading or
/// checking a child file (including `UnsupportedRunokVersion`) is propagated
/// unchanged so the caller can inspect the reason.
pub fn load_and_resolve_preset_with<G: GitClient>(
    reference: &str,
    base_dir: &Path,
    git_client: &G,
    cache: &PresetCache,
) -> Result<Config, ConfigError> {
    let config = load_preset_with(reference, base_dir, git_client, cache)?;
    let preset_base_dir = extends::determine_preset_base_dir(reference, base_dir, cache);
    resolve_extends_with(config, &preset_base_dir, reference, git_client, cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cache::CacheMetadata;
    use crate::config::git_client::mock::MockGitClient;
    use crate::config::parse_config;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
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

        let config = load_local_preset(reference, &base_dir).unwrap();
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
        let config = load_local_preset(reference, &other_dir).unwrap();
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

        let err = load_local_preset("./nonexistent.yml", base_dir).unwrap_err();

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

        let err = load_local_preset(reference, tmp.path()).unwrap_err();

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

        let err = load_local_preset("./bad.yml", tmp.path()).unwrap_err();
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

        let config = load_local_preset("./preset.yml", base_dir).unwrap();

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

        let err = load_local_preset(reference, &base_dir).unwrap_err();

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

    /// Overlay-style configurations drop a symlink whose target lives
    /// outside `base_dir` into the config directory. The reference text
    /// itself (`./work.yml`) stays inside `base_dir`, so the load must
    /// succeed even though the symlink target is elsewhere on the
    /// filesystem.
    #[cfg(unix)]
    #[rstest]
    fn relative_extends_follows_symlink_outside_base_dir(tmp: TempDir) {
        let base_dir = tmp.path().join("config");
        fs::create_dir_all(&base_dir).unwrap();
        let overlay_dir = tmp.path().join("overlay");
        fs::create_dir_all(&overlay_dir).unwrap();

        let overlay_target = overlay_dir.join("work.yml");
        fs::write(
            &overlay_target,
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        )
        .unwrap();

        std::os::unix::fs::symlink(&overlay_target, base_dir.join("work.yml")).unwrap();

        let config = load_local_preset("./work.yml", &base_dir).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
    }

    // === Remote preset inline tests are stripped ===

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build a `PresetCache` rooted at `root` with a one-hour TTL.
    fn make_cache(root: &Path) -> PresetCache {
        PresetCache::with_config(root.to_path_buf(), std::time::Duration::from_secs(3600))
    }

    /// Seed `cache` with a remote preset at `reference`: write each
    /// `(file_name, yaml)` entry into the cache dir and persist its metadata.
    /// Returns the cache dir for callers that need it directly.
    fn seed_remote_preset(cache: &PresetCache, reference: &str, files: &[(&str, &str)]) -> PathBuf {
        let cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&cache_dir).unwrap();
        for (name, body) in files {
            fs::write(cache_dir.join(name), body).unwrap();
        }
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();
        cache_dir
    }

    #[rstest]
    fn remote_preset_inline_tests_stripped(tmp: TempDir) {
        let reference_str = "github:org/preset@v1";
        let cache = make_cache(tmp.path());
        seed_remote_preset(
            &cache,
            reference_str,
            &[(
                "runok.yml",
                indoc! {"
                    rules:
                      - ask: 'gh api *'
                        tests:
                          - ask: 'gh api /repos'
                      - allow: 'git status'
                        tests:
                          - allow: 'git status --short'
                    tests:
                      cases:
                        - ask: 'gh api /users'
                "},
            )],
        );

        let mock = MockGitClient::new();
        let config = load_preset_with(reference_str, tmp.path(), &mock, &cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        // Rules should be preserved
        assert_eq!(rules[0].ask.as_deref(), Some("gh api *"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status"));
        // Inline tests should be stripped
        assert!(
            rules.iter().all(|r| r.tests.is_none()),
            "all inline tests should be stripped from remote preset"
        );
        // Top-level tests should be stripped
        assert!(
            config.tests.is_none(),
            "top-level tests should be stripped from remote preset"
        );
    }

    #[rstest]
    fn local_preset_inline_tests_preserved(tmp: TempDir) {
        let base_dir = tmp.path();
        fs::write(
            base_dir.join("local.yml"),
            indoc! {"
                rules:
                  - ask: 'gh api *'
                    tests:
                      - ask: 'gh api /repos'
            "},
        )
        .unwrap();

        let config = load_local_preset("./local.yml", base_dir).unwrap();
        let rules = config.rules.unwrap();
        assert!(
            rules[0].tests.is_some(),
            "inline tests should be preserved in local preset"
        );
    }

    /// A remote preset that internally extends another preset via a local
    /// path (the layout used by `runok-presets/base`) must have inline tests
    /// and top-level tests stripped from every nested file, not just the
    /// outermost remote entry point.
    #[rstest]
    fn remote_preset_with_local_extends_strips_nested_tests(tmp: TempDir) {
        let reference_str = "github:org/preset/base@v1";
        let cache = make_cache(tmp.path());
        // Top-level remote preset extends a sibling via a local path, mirroring
        // the structure used by published preset bundles such as runok-presets/base.
        seed_remote_preset(
            &cache,
            reference_str,
            &[
                (
                    "base.yml",
                    indoc! {"
                        extends:
                          - ./readonly.yml
                        rules:
                          - ask: 'gh api *'
                            tests:
                              - ask: 'gh api /repos'
                        tests:
                          cases:
                            - ask: 'gh api /users'
                    "},
                ),
                (
                    "readonly.yml",
                    indoc! {"
                        rules:
                          - allow: 'find *'
                            tests:
                              - allow: 'find . -name *.txt'
                          - allow: 'sed -n *'
                            tests:
                              - allow: 'sed -n 1,10p file'
                        tests:
                          cases:
                            - allow: 'find . -type f'
                    "},
                ),
            ],
        );

        let mock = MockGitClient::new();
        let resolved =
            load_and_resolve_preset_with(reference_str, tmp.path(), &mock, &cache).unwrap();

        let rules = resolved.rules.expect("merged rules should be present");
        assert!(
            rules.iter().all(|r| r.tests.is_none()),
            "inline tests must be stripped from every preset reached via the remote ancestor",
        );
        assert!(
            resolved.tests.is_none(),
            "top-level tests must be stripped from every preset reached via the remote ancestor",
        );
    }
}
