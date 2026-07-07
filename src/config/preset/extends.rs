use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::cache::PresetCache;
use crate::config::git_client::{GitClient, ProcessGitClient};
use crate::config::preset_remote::{PresetReference, parse_preset_reference};
use crate::config::{Config, ConfigError, PresetError};

const MAX_EXTENDS_DEPTH: usize = 10;

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
    let canonical_source = normalize_reference_key(source_name, base_dir);
    let mut chain = vec![canonical_source.clone()];
    let mut visited = HashSet::new();
    visited.insert(canonical_source);

    // Once an extends chain crosses into a remote preset, every preset reached
    // from it (including locally-referenced children inside the cloned repo)
    // is preset-authored and must have its tests stripped.
    let under_remote = super::is_remote_reference(source_name);

    resolve_extends_recursive(
        config,
        base_dir,
        git_client,
        cache,
        &mut chain,
        &mut visited,
        under_remote,
    )
}

/// Recursive inner function for extends resolution.
///
/// `chain` tracks the current DFS path (ordered) for cycle reporting.
/// `visited` is the set of all references in the current chain for O(1) lookup.
/// `under_remote` is true when the current config was reached via a remote
/// preset; child presets loaded from this point must have their preset-authored
/// tests stripped, even when referenced via local paths inside the cloned repo.
fn resolve_extends_recursive<G: GitClient>(
    config: Config,
    base_dir: &Path,
    git_client: &G,
    cache: &PresetCache,
    chain: &mut Vec<String>,
    visited: &mut HashSet<String>,
    under_remote: bool,
) -> Result<Config, ConfigError> {
    let extends = match &config.extends {
        Some(refs) if !refs.is_empty() => refs.clone(),
        _ => return Ok(config),
    };

    // Start with an empty config and merge each resolved preset in order,
    // then merge the current config on top (current config takes priority).
    let mut merged = Config::default();

    for reference in &extends {
        // Normalize local references to canonical keys for cycle detection.
        // Without this, "./runok.yml" and "runok.yml" would be treated as
        // different references even though they resolve to the same file.
        let canonical_key = normalize_reference_key(reference, base_dir);

        if visited.contains(&canonical_key) {
            // Build the cycle chain: from the first occurrence to the end
            let cycle_start = chain.iter().position(|r| r == &canonical_key).unwrap_or(0);
            let mut cycle: Vec<String> = chain[cycle_start..].to_vec();
            cycle.push(canonical_key);
            return Err(PresetError::CircularReference { cycle }.into());
        }

        if chain.len() > MAX_EXTENDS_DEPTH {
            let mut depth_chain = chain.clone();
            depth_chain.push(canonical_key);
            return Err(PresetError::MaxExtendsDepthExceeded {
                chain: depth_chain,
                max_depth: MAX_EXTENDS_DEPTH,
            }
            .into());
        }

        chain.push(canonical_key.clone());
        visited.insert(canonical_key.clone());

        // Load the preset config (without resolving its extends yet)
        let mut preset_config = super::load_preset_with(reference, base_dir, git_client, cache)?;

        // Once anything in the chain is remote, every transitively-loaded
        // preset must have its tests stripped. `load_preset_with` already
        // strips for direct-remote references, but local references reached
        // via a remote ancestor also need stripping here.
        let child_under_remote = under_remote || super::is_remote_reference(reference);
        if child_under_remote {
            super::strip_preset_tests(&mut preset_config);
        }

        // Determine the base_dir for the loaded preset's own extends
        let preset_base_dir = determine_preset_base_dir(reference, base_dir, cache);

        // Recursively resolve the preset's own extends
        let resolved = resolve_extends_recursive(
            preset_config,
            &preset_base_dir,
            git_client,
            cache,
            chain,
            visited,
            child_under_remote,
        )?;

        merged = merged.merge(resolved);

        visited.remove(&canonical_key);
        chain.pop();
    }

    // Strip extends from the current config before merging (already resolved)
    let current = Config {
        extends: None,
        ..config
    };

    Ok(merged.merge(current))
}

/// Normalize a reference string into a canonical key for cycle detection.
///
/// For local references, resolves the path against `base_dir` and canonicalizes
/// it so that `./runok.yml` and `runok.yml` are treated as the same file.
/// For remote references, the original string is used as-is.
fn normalize_reference_key(reference: &str, base_dir: &Path) -> String {
    let parsed = parse_preset_reference(reference);
    match parsed {
        Ok(PresetReference::Local(_)) => {
            // Resolve with ~/expansion, fall back to simple join if resolution fails
            let resolved = super::resolve_local_path(reference, base_dir, super::home_dir)
                .unwrap_or_else(|_| base_dir.join(reference));
            let path = super::canonicalize_best_effort(&resolved);
            path.to_string_lossy().to_string()
        }
        _ => reference.to_string(),
    }
}

/// Determine the base directory for a preset's own extends resolution.
///
/// For local presets, resolves the reference (including `~/` expansion) and
/// returns the parent directory of the resolved path. For remote presets,
/// returns the cache directory where the repo was cloned, so that the
/// preset's own relative extends are resolved within the cloned repo.
pub(super) fn determine_preset_base_dir(
    reference: &str,
    parent_base_dir: &Path,
    cache: &PresetCache,
) -> PathBuf {
    let parsed = parse_preset_reference(reference);
    match parsed {
        Ok(PresetReference::Local(_)) => {
            // Resolve the full path using the same logic as load_local_preset
            // so that ~/presets/base.yml is correctly expanded.
            let resolved = super::resolve_local_path(reference, parent_base_dir, super::home_dir)
                .unwrap_or_else(|_| parent_base_dir.join(reference));
            resolved
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| parent_base_dir.to_path_buf())
        }
        Ok(PresetReference::GitHub {
            path: Some(preset_path),
            ..
        }) => {
            // For GitHub shorthand with a path (e.g., github:org/repo/presets/readonly@v1),
            // the base directory must be the parent of the preset file within the cloned repo
            // so that relative extends resolve correctly from the preset's location.
            let cache_dir = cache.cache_dir(reference);
            let preset_file = Path::new(&preset_path);
            match preset_file.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => cache_dir.join(parent),
                _ => cache_dir,
            }
        }
        _ => {
            // For remote presets without a path, use the cache directory (repo root).
            cache.cache_dir(reference)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::git_client::mock::MockGitClient;
    use crate::config::parse_config;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use std::fs;
    use tempfile::TempDir;

    use super::super::test_support::{make_cache, seed_remote_preset};

    #[fixture]
    fn tmp() -> TempDir {
        TempDir::new().unwrap()
    }

    /// Extract file names from canonical paths in a cycle chain for assertion.
    fn cycle_filenames(cycle: &[String]) -> Vec<String> {
        cycle
            .iter()
            .map(|p| {
                Path::new(p)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect()
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
                assert_eq!(cycle_filenames(&cycle), vec!["a.yml", "b.yml", "a.yml"]);
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
                assert_eq!(cycle_filenames(&cycle), vec!["a.yml", "a.yml"]);
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
                assert_eq!(
                    cycle_filenames(&cycle),
                    vec!["a.yml", "b.yml", "c.yml", "a.yml"]
                );
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
        // "./runok.yml" and "runok.yml" resolve to the same file.
        // After path normalization, this is correctly detected as circular.
        let err = resolve_extends_with(config, base_dir, "runok.yml", &ProcessGitClient, &cache)
            .unwrap_err();

        match err {
            ConfigError::Preset(PresetError::CircularReference { cycle }) => {
                // runok.yml → a.yml → runok.yml (back to root)
                assert_eq!(
                    cycle_filenames(&cycle),
                    vec!["runok.yml", "a.yml", "runok.yml"]
                );
                // First and last should be the same canonical path
                assert_eq!(cycle[0], cycle[2]);
            }
            other => panic!("expected CircularReference, got: {other:?}"),
        }
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

        match err {
            ConfigError::Preset(PresetError::CircularReference { cycle }) => {
                assert_eq!(cycle_filenames(&cycle), vec!["a.yml", "b.yml", "a.yml"]);
                // Verify Display format uses " → " separator
                let error = PresetError::CircularReference { cycle };
                let msg = error.to_string();
                // The canonical paths are joined with " → "
                let parts: Vec<&str> = msg
                    .strip_prefix("circular reference detected: ")
                    .unwrap()
                    .split(" \u{2192} ")
                    .collect();
                assert_eq!(parts.len(), 3);
            }
            other => panic!("expected CircularReference, got: {other:?}"),
        }
    }

    // === determine_preset_base_dir tests ===

    #[rstest]
    #[case::github_no_path("github:org/repo@v1", None)]
    #[case::github_simple_path("github:org/repo/readonly@v1", None)]
    #[case::github_nested_path("github:org/repo/presets/readonly@v1", Some("presets"))]
    fn preset_base_dir_for_github_shorthand(
        tmp: TempDir,
        #[case] ref_str: &str,
        #[case] expected_suffix: Option<&str>,
    ) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
        let expected = match expected_suffix {
            Some(suffix) => cache.cache_dir(ref_str).join(suffix),
            None => cache.cache_dir(ref_str),
        };
        assert_eq!(
            determine_preset_base_dir(ref_str, tmp.path(), &cache),
            expected,
        );
    }

    // === Remote preset inline tests are stripped ===

    /// User config that locally extends a remote preset must keep its own
    /// tests, but every preset reached through the remote (including its
    /// local-path children) must be stripped.
    #[rstest]
    fn user_config_keeps_tests_when_remote_extends_chain_is_stripped(tmp: TempDir) {
        let reference_str = "github:org/preset@v1";
        let cache = make_cache(tmp.path());
        seed_remote_preset(
            &cache,
            reference_str,
            &[
                (
                    "runok.yml",
                    indoc! {"
                        extends:
                          - ./child.yml
                        rules:
                          - ask: 'gh api *'
                            tests:
                              - ask: 'gh api /repos'
                    "},
                ),
                (
                    "child.yml",
                    indoc! {"
                        rules:
                          - allow: 'find *'
                            tests:
                              - allow: 'find . -name *.txt'
                    "},
                ),
            ],
        );

        let user_dir = tmp.path().join("user");
        fs::create_dir_all(&user_dir).unwrap();
        let user_config: Config = parse_config(indoc! {"
            extends:
              - github:org/preset@v1
            rules:
              - allow: 'echo hello'
                tests:
                  - allow: 'echo hello world'
            tests:
              cases:
                - allow: 'echo greetings'
        "})
        .unwrap();

        let mock = MockGitClient::new();
        let resolved =
            resolve_extends_with(user_config, &user_dir, "user-config", &mock, &cache).unwrap();

        let rules = resolved.rules.expect("merged rules should be present");
        let user_rule = rules
            .iter()
            .find(|r| r.allow.as_deref() == Some("echo hello"))
            .expect("user rule should be merged in");
        assert!(
            user_rule.tests.is_some(),
            "user-defined inline tests must be preserved",
        );
        assert!(
            resolved.tests.is_some(),
            "user-defined top-level tests must be preserved",
        );
        assert!(
            rules
                .iter()
                .filter(|r| r.allow.as_deref() != Some("echo hello"))
                .all(|r| r.tests.is_none()),
            "tests on rules contributed by the remote chain must be stripped",
        );
    }

    /// A config that locally extends another local preset (no remote in the
    /// chain) must retain inline and top-level tests on both files.
    #[rstest]
    fn local_only_extends_chain_preserves_tests(tmp: TempDir) {
        let base_dir = tmp.path();
        fs::write(
            base_dir.join("child.yml"),
            indoc! {"
                rules:
                  - allow: 'echo child'
                    tests:
                      - allow: 'echo child detail'
                tests:
                  cases:
                    - allow: 'echo child top-level'
            "},
        )
        .unwrap();

        let parent_config: Config = parse_config(indoc! {"
            extends:
              - ./child.yml
            rules:
              - allow: 'echo parent'
                tests:
                  - allow: 'echo parent detail'
        "})
        .unwrap();

        let cache = make_cache(&tmp.path().join("cache"));
        let mock = MockGitClient::new();
        let resolved =
            resolve_extends_with(parent_config, base_dir, "parent.yml", &mock, &cache).unwrap();

        let rules = resolved.rules.expect("merged rules should be present");
        assert!(
            rules.iter().all(|r| r.tests.is_some()),
            "inline tests on local-only chains must be preserved",
        );
        assert!(
            resolved.tests.is_some(),
            "top-level tests on local-only chains must be preserved",
        );
    }

    /// A chain user → local intermediate → remote → local-under-remote child:
    /// the intermediate keeps its tests (no remote ancestor yet), but every
    /// preset reached after crossing the remote boundary is stripped.
    #[rstest]
    fn local_intermediate_then_remote_strips_only_remote_descendants(tmp: TempDir) {
        let reference_str = "github:org/preset@v1";
        let cache = make_cache(&tmp.path().join("cache"));
        seed_remote_preset(
            &cache,
            reference_str,
            &[
                (
                    "runok.yml",
                    indoc! {"
                        extends:
                          - ./remote-child.yml
                        rules:
                          - allow: 'remote-rule'
                            tests:
                              - allow: 'remote-rule arg'
                    "},
                ),
                (
                    "remote-child.yml",
                    indoc! {"
                        rules:
                          - allow: 'remote-grandchild'
                            tests:
                              - allow: 'remote-grandchild arg'
                    "},
                ),
            ],
        );

        let user_dir = tmp.path().join("user");
        fs::create_dir_all(&user_dir).unwrap();
        fs::write(
            user_dir.join("mid.yml"),
            indoc! {"
                extends:
                  - github:org/preset@v1
                rules:
                  - allow: 'mid-rule'
                    tests:
                      - allow: 'mid-rule arg'
            "},
        )
        .unwrap();

        let user_config: Config = parse_config(indoc! {"
            extends:
              - ./mid.yml
            rules:
              - allow: 'user-rule'
                tests:
                  - allow: 'user-rule arg'
        "})
        .unwrap();

        let mock = MockGitClient::new();
        let resolved =
            resolve_extends_with(user_config, &user_dir, "user-config", &mock, &cache).unwrap();

        let rules = resolved.rules.expect("merged rules should be present");
        let assert_tests = |needle: &str, expected_tests: bool| {
            let rule = rules
                .iter()
                .find(|r| r.allow.as_deref() == Some(needle))
                .unwrap_or_else(|| panic!("missing rule {needle}"));
            assert_eq!(
                rule.tests.is_some(),
                expected_tests,
                "rule '{needle}' tests presence mismatch",
            );
        };
        // User and local intermediate are above the remote boundary.
        assert_tests("user-rule", true);
        assert_tests("mid-rule", true);
        // Everything from the remote subtree is stripped, including its
        // local-under-remote child.
        assert_tests("remote-rule", false);
        assert_tests("remote-grandchild", false);
    }
}
