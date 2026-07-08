use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::cache::{CacheMetadata, CacheStatus, PresetCache};
use super::git_client::GitClient;
use super::{Config, ConfigError, ParsedConfig, PresetError, parse_config_with_warnings};

mod candidate_inspection;
mod reference;

pub use candidate_inspection::{CandidateInspection, inspect_candidate_required_versions};
use reference::is_commit_sha;
pub use reference::{GitHubVersion, PresetReference, parse_preset_reference};

/// Resolve git parameters from a `PresetReference`.
pub struct GitParams {
    pub url: String,
    pub git_ref: Option<String>,
    pub is_immutable: bool,
}

pub fn resolve_git_params(reference: &PresetReference) -> GitParams {
    match reference {
        PresetReference::GitHub {
            owner,
            repo,
            version,
            ..
        } => {
            let url = format!("https://github.com/{owner}/{repo}.git");
            let git_ref = version.as_git_ref().map(String::from);
            let is_immutable = version.is_immutable();
            GitParams {
                url,
                git_ref,
                is_immutable,
            }
        }
        PresetReference::GitUrl { url, git_ref } => {
            let is_immutable = git_ref.as_deref().is_some_and(is_commit_sha);
            GitParams {
                url: url.clone(),
                git_ref: git_ref.clone(),
                is_immutable,
            }
        }
        PresetReference::Local(_) => {
            // Should not be called for local references
            GitParams {
                url: String::new(),
                git_ref: None,
                is_immutable: false,
            }
        }
    }
}

/// Resolve the preset file path within a directory.
///
/// When `preset_path` is `None`, looks for `runok.yml` (or `runok.yaml`) from the root.
/// When `preset_path` is `Some("foo/bar")`, looks for `foo/bar.yml` (or `foo/bar.yaml`).
pub fn resolve_preset_file_path(
    dir: &Path,
    preset_path: Option<&str>,
) -> Result<PathBuf, ConfigError> {
    let (yml, yaml, not_found_msg) = match preset_path {
        Some(p) => (
            dir.join(format!("{p}.yml")),
            dir.join(format!("{p}.yaml")),
            format!("preset file '{p}.yml' (or '{p}.yaml') not found in preset repository"),
        ),
        None => (
            dir.join("runok.yml"),
            dir.join("runok.yaml"),
            "runok.yml not found in preset repository".to_string(),
        ),
    };

    if yml.exists() {
        Ok(yml)
    } else if yaml.exists() {
        Ok(yaml)
    } else {
        Err(PresetError::GitClone {
            reference: dir.display().to_string(),
            message: not_found_msg,
        }
        .into())
    }
}

/// Read a preset config file from a directory.
///
/// When `preset_path` is `None`, reads `runok.yml` (or `runok.yaml`) from the root.
/// When `preset_path` is `Some("foo/bar")`, reads `foo/bar.yml` (or `foo/bar.yaml`).
pub fn read_preset_from_dir(dir: &Path, preset_path: Option<&str>) -> Result<Config, ConfigError> {
    let path = resolve_preset_file_path(dir, preset_path)?;
    let content = std::fs::read_to_string(&path)?;
    let ParsedConfig { config, warnings } = parse_config_with_warnings(&content)?;
    for warning in &warnings {
        eprintln!("runok warning: {warning}\n  --> {}", path.display());
    }
    Ok(config)
}

/// Re-wrap a `PresetError` with a different reference, extracting the inner
/// message to avoid double-nesting the Display format.
fn rewrap_git_error(error: PresetError, reference: &str) -> PresetError {
    let message = match error {
        PresetError::GitClone { message, .. } => message,
        other => other.to_string(),
    };
    PresetError::GitClone {
        reference: reference.to_string(),
        message,
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Extract the preset path from a reference (only GitHub shorthand supports this).
pub fn preset_path_from_reference(reference: &PresetReference) -> Option<&str> {
    match reference {
        PresetReference::GitHub { path, .. } => path.as_deref(),
        _ => None,
    }
}

/// Load a remote preset (GitHub shorthand or git URL) with caching.
///
/// Flow:
/// 1. Check cache status
/// 2. Hit → read from cache
/// 3. Stale → try `git fetch` to update; fallback to old cache on error
/// 4. Miss → `git clone --depth 1`; error if clone fails
pub fn load_remote_preset<G: GitClient>(
    reference: &PresetReference,
    original_reference: &str,
    git_client: &G,
    cache: &PresetCache,
) -> Result<Config, ConfigError> {
    let params = resolve_git_params(reference);
    let cache_dir = cache.cache_dir(original_reference);
    let preset_path = preset_path_from_reference(reference);

    match cache.check(original_reference, params.is_immutable) {
        // Cache hits read without locking. A concurrent checkout could cause
        // a parse error, but not silent corruption — acceptable trade-off to
        // avoid lock contention on the common path.
        CacheStatus::Hit(dir) => read_preset_from_dir(&dir, preset_path),
        CacheStatus::Stale(_) | CacheStatus::Miss => {
            // Acquire an exclusive lock to prevent concurrent git operations
            // on the same cache directory.
            let _lock = cache.acquire_lock(original_reference)?;

            // Re-check cache status after acquiring the lock, because another
            // process may have updated it while we were waiting.
            match cache.check(original_reference, params.is_immutable) {
                CacheStatus::Hit(dir) => read_preset_from_dir(&dir, preset_path),
                CacheStatus::Stale(dir) => {
                    handle_stale_cache(git_client, &dir, &params, original_reference, preset_path)
                }
                CacheStatus::Miss => handle_cache_miss(
                    git_client,
                    &cache_dir,
                    &params,
                    original_reference,
                    preset_path,
                ),
            }
            // _lock is dropped here, releasing the file lock
        }
    }
}

/// Handle a stale cache entry during automatic refresh.
///
/// Flow (level A: never touch the working tree with an unvalidated revision):
/// 1. `git fetch` (working tree unchanged)
/// 2. Inspect the fetched commit via `git show FETCH_HEAD:<path>` and verify
///    that every `required_runok_version` constraint in the new preset and its
///    same-repo `extends` chain is satisfied by the current runok build.
/// 3. All constraints satisfied → `git checkout FETCH_HEAD` (only now the
///    working tree is updated) and return the new content.
/// 4. Any constraint violated (or inspection failed) → leave the working tree
///    untouched and return the old cached content silently. The metadata
///    `fetched_at` is still bumped so we do not retry on every subsequent
///    load until the TTL expires again.
fn handle_stale_cache<G: GitClient>(
    git_client: &G,
    dir: &Path,
    params: &GitParams,
    original_reference: &str,
    preset_path: Option<&str>,
) -> Result<Config, ConfigError> {
    match git_client.fetch(dir, params.git_ref.as_deref()) {
        Ok(()) => {
            let required_ok =
                inspect_candidate_required_versions(git_client, dir, "FETCH_HEAD", preset_path);

            // Regardless of the outcome below, remember that we successfully
            // fetched so we do not loop on TTL failures for the whole TTL
            // window.
            let touch_metadata = |resolved_sha: Option<String>| {
                let metadata = CacheMetadata {
                    fetched_at: current_timestamp(),
                    is_immutable: params.is_immutable,
                    reference: original_reference.to_string(),
                    resolved_sha,
                };
                let _ = PresetCache::write_metadata(dir, &metadata);
            };

            match required_ok {
                CandidateInspection::Compatible => {
                    // All constraints satisfied: commit the new revision to the
                    // working tree.
                    if let Err(e) = git_client.checkout(dir, "FETCH_HEAD") {
                        eprintln!(
                            "warning: checkout failed for '{original_reference}': {e}, \
                             using cached version"
                        );
                        touch_metadata(None);
                        return read_preset_from_dir(dir, preset_path);
                    }
                    let resolved_sha = git_client.rev_parse_head(dir).ok();
                    touch_metadata(resolved_sha);
                    read_preset_from_dir(dir, preset_path)
                }
                CandidateInspection::Incompatible { .. } => {
                    // New revision violates `required_runok_version`. Keep the
                    // old working tree in place; no warning, no error, because
                    // automatic refresh must not break normal operations.
                    touch_metadata(None);
                    read_preset_from_dir(dir, preset_path)
                }
                CandidateInspection::InspectionFailed => {
                    // We could not read / parse the candidate. Fall back to the
                    // old working tree (same behaviour as before the refresh
                    // started). This is intentional: safer to keep working than
                    // to propagate an internal git-show error.
                    touch_metadata(None);
                    read_preset_from_dir(dir, preset_path)
                }
            }
        }
        Err(_) => {
            // Fetch failed: use stale cache with a warning
            eprintln!(
                "warning: Failed to update preset '{original_reference}', using cached version"
            );
            read_preset_from_dir(dir, preset_path)
        }
    }
}

fn handle_cache_miss<G: GitClient>(
    git_client: &G,
    cache_dir: &Path,
    params: &GitParams,
    original_reference: &str,
    preset_path: Option<&str>,
) -> Result<Config, ConfigError> {
    // Create parent directory only; let git clone create the target directory itself.
    // Creating cache_dir first would cause `git clone` to fail with
    // "destination path already exists and is not an empty directory".
    if let Some(parent) = cache_dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            PresetError::Cache(format!("failed to create cache parent directory: {e}"))
        })?;
    }

    // Determine if git_ref is a commit SHA. `git clone --branch` only accepts
    // branch/tag names, not commit SHAs, so SHA refs must clone without --branch
    // then checkout the SHA separately.
    let ref_is_sha = params.git_ref.as_deref().is_some_and(is_commit_sha);

    let clone_branch = if ref_is_sha {
        None
    } else {
        params.git_ref.as_deref()
    };

    git_client
        .clone_shallow(&params.url, cache_dir, clone_branch)
        .map_err(|e| rewrap_git_error(e, original_reference))?;

    // For commit SHA, the shallow clone only has the default branch tip.
    // Fetch the specific commit then checkout FETCH_HEAD.
    if let Some(sha) = params.git_ref.as_deref().filter(|r| is_commit_sha(r)) {
        git_client
            .fetch(cache_dir, Some(sha))
            .map_err(|e| rewrap_git_error(e, original_reference))?;
        git_client
            .checkout(cache_dir, "FETCH_HEAD")
            .map_err(|e| rewrap_git_error(e, original_reference))?;
    }

    // Write cache metadata
    let resolved_sha = git_client.rev_parse_head(cache_dir).ok();
    let metadata = CacheMetadata {
        fetched_at: current_timestamp(),
        is_immutable: params.is_immutable,
        reference: original_reference.to_string(),
        resolved_sha,
    };
    let _ = PresetCache::write_metadata(cache_dir, &metadata);

    read_preset_from_dir(cache_dir, preset_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::git_client::mock::MockGitClient;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    // === GitHub shorthand → git URL conversion ===

    #[rstest]
    #[case::basic("org", "repo", "https://github.com/org/repo.git")]
    #[case::with_dash("my-org", "my-repo", "https://github.com/my-org/my-repo.git")]
    fn github_to_url(#[case] owner: &str, #[case] repo: &str, #[case] expected: &str) {
        let reference = PresetReference::GitHub {
            owner: owner.to_string(),
            repo: repo.to_string(),
            path: None,
            version: GitHubVersion::Latest,
        };
        let params = resolve_git_params(&reference);
        assert_eq!(params.url, expected);
    }

    // === load_remote_preset tests ===

    /// Bundles a `TempDir` with a `PresetCache` so the temporary directory
    /// lives as long as the cache (preventing premature cleanup).
    struct CacheFixture {
        cache: PresetCache,
        // Held to keep the temporary directory alive for the test's lifetime.
        _tmp: TempDir,
    }

    #[fixture]
    fn cache_fixture() -> CacheFixture {
        let tmp = TempDir::new().unwrap();
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
        CacheFixture { cache, _tmp: tmp }
    }

    #[fixture]
    fn tmp() -> TempDir {
        TempDir::new().unwrap()
    }

    fn write_runok_yml(dir: &Path, content: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("runok.yml"), content).unwrap();
    }

    #[rstest]
    fn clone_miss_calls_clone_with_branch(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        mock.on_clone(Ok(()));
        mock.on_rev_parse(Ok("abc123".to_string()));

        // Mock clone doesn't create files, so read_preset_from_dir will fail.
        // We verify clone was called with correct --branch.
        let _result = load_remote_preset(&parsed, reference_str, &mock, cache);

        let calls = mock.calls.borrow();
        let has_clone_with_branch = calls.iter().any(|c| {
            matches!(c, crate::config::git_client::mock::GitCall::CloneShallow { branch, .. } if branch.as_deref() == Some("v1.0.0"))
        });
        assert!(has_clone_with_branch, "expected clone with --branch v1.0.0");
    }

    #[rstest]
    fn read_preset_from_dir_reads_yml(tmp: TempDir) {
        write_runok_yml(
            tmp.path(),
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        );

        let config = read_preset_from_dir(tmp.path(), None).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
    }

    #[rstest]
    fn read_preset_from_dir_reads_yaml(tmp: TempDir) {
        std::fs::write(
            tmp.path().join("runok.yaml"),
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        let config = read_preset_from_dir(tmp.path(), None).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
    }

    #[rstest]
    #[case::yml("presets/readonly.yml", "presets/readonly", "allow", "cat *")]
    #[case::yaml("my-preset.yaml", "my-preset", "deny", "rm *")]
    fn read_preset_from_dir_with_path(
        tmp: TempDir,
        #[case] file_path: &str,
        #[case] preset_path: &str,
        #[case] rule_kind: &str,
        #[case] rule_value: &str,
    ) {
        let full_path = tmp.path().join(file_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let yaml = format!(
            indoc! {"
                rules:
                  - {kind}: '{value}'
            "},
            kind = rule_kind,
            value = rule_value,
        );
        std::fs::write(&full_path, yaml).unwrap();

        let config = read_preset_from_dir(tmp.path(), Some(preset_path)).unwrap();
        let rules = config.rules.unwrap();
        let actual = match rule_kind {
            "allow" => rules[0].allow.as_deref(),
            "deny" => rules[0].deny.as_deref(),
            _ => panic!("unexpected rule kind: {rule_kind}"),
        };
        assert_eq!(actual, Some(rule_value));
    }

    #[rstest]
    fn read_preset_from_dir_with_path_not_found(tmp: TempDir) {
        let err = read_preset_from_dir(tmp.path(), Some("nonexistent")).unwrap_err();
        match err {
            ConfigError::Preset(PresetError::GitClone { message, .. }) => {
                assert_eq!(
                    message,
                    "preset file 'nonexistent.yml' (or 'nonexistent.yaml') not found in preset repository"
                );
            }
            other => panic!("expected GitClone error, got: {other:?}"),
        }
    }

    #[rstest]
    fn cache_hit_skips_clone(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Write a fresh cache
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        // No clone/fetch results queued — should not be called

        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));

        // Verify no git calls were made
        assert!(mock.calls.borrow().is_empty());
    }

    #[rstest]
    fn stale_cache_fetch_success(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Write a stale cache (fetched_at = 0)
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - allow: 'cargo test'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok("def456".to_string()));

        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("cargo test"));
    }

    #[rstest]
    fn stale_cache_fetch_failure_uses_old_cache(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Write a stale cache (fetched_at = 0)
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - allow: 'old cached rule'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Err(PresetError::GitClone {
            reference: reference_str.to_string(),
            message: "network error".to_string(),
        }));

        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("old cached rule"));
    }

    #[rstest]
    fn clone_failure_no_cache_returns_error(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        mock.on_clone(Err(PresetError::GitClone {
            reference: reference_str.to_string(),
            message: "authentication failed".to_string(),
        }));

        let err = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::GitClone { reference, .. }) => {
                assert_eq!(reference, reference_str);
            }
            other => panic!("expected GitClone error, got: {other:?}"),
        }
    }

    #[rstest]
    fn commit_sha_triggers_fetch_and_checkout_after_clone(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let sha = "abc1234def567890abc1234def567890abc12345";
        let reference_str = &format!("github:org/repo@{sha}");
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        // clone (no --branch) → fetch SHA → checkout FETCH_HEAD → rev_parse
        mock.on_clone(Ok(()));
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok(sha.to_string()));

        let _result = load_remote_preset(&parsed, reference_str, &mock, cache);

        let calls = mock.calls.borrow();
        let has_clone_without_branch = calls.iter().any(|c| {
            matches!(c, crate::config::git_client::mock::GitCall::CloneShallow { branch, .. } if branch.is_none())
        });
        assert!(
            has_clone_without_branch,
            "expected clone without --branch for CommitSha"
        );

        // After clone, fetch the SHA then checkout FETCH_HEAD
        let has_fetch = calls
            .iter()
            .any(|c| matches!(c, crate::config::git_client::mock::GitCall::Fetch));
        assert!(has_fetch, "expected fetch after clone for CommitSha");

        let has_checkout_fetch_head = calls.iter().any(|c| {
            matches!(c, crate::config::git_client::mock::GitCall::Checkout { git_ref, .. } if git_ref == "FETCH_HEAD")
        });
        assert!(
            has_checkout_fetch_head,
            "expected checkout FETCH_HEAD after fetch"
        );
    }

    #[rstest]
    fn git_url_commit_sha_fetches_then_checkouts(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let sha = "abc1234def567890abc1234def567890abc12345";
        let reference_str = &format!("https://github.com/org/repo.git@{sha}");
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        mock.on_clone(Ok(()));
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok(sha.to_string()));

        let _result = load_remote_preset(&parsed, reference_str, &mock, cache);

        let calls = mock.calls.borrow();
        let has_clone_without_branch = calls.iter().any(|c| {
            matches!(c, crate::config::git_client::mock::GitCall::CloneShallow { branch, .. } if branch.is_none())
        });
        assert!(
            has_clone_without_branch,
            "expected clone without --branch for GitUrl with commit SHA"
        );

        let has_checkout_fetch_head = calls.iter().any(|c| {
            matches!(c, crate::config::git_client::mock::GitCall::Checkout { git_ref, .. } if git_ref == "FETCH_HEAD")
        });
        assert!(
            has_checkout_fetch_head,
            "expected checkout FETCH_HEAD for GitUrl with SHA"
        );
    }

    #[rstest]
    fn stale_cache_latest_checkouts_fetch_head(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Write a stale cache (fetched_at = 0)
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - allow: 'cargo test'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok("def456".to_string()));
        // The refresh path inspects the candidate with `git show` before
        // touching the working tree. Return a permissive preset (no
        // `required_runok_version`) so the inspection is Compatible and
        // the working tree is updated.
        mock.on_show_file(
            "FETCH_HEAD",
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'cargo test'
            "},
        );

        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("cargo test"));

        // Verify checkout was called with FETCH_HEAD (since Latest has no git_ref)
        let calls = mock.calls.borrow();
        let has_checkout_fetch_head = calls.iter().any(|c| {
            matches!(c, crate::config::git_client::mock::GitCall::Checkout { git_ref, .. } if git_ref == "FETCH_HEAD")
        });
        assert!(
            has_checkout_fetch_head,
            "expected checkout with FETCH_HEAD for Latest reference"
        );
    }

    // === stale refresh + required_runok_version (level A) ===

    /// When the fetched revision satisfies the current runok version, the
    /// working tree is updated via `git checkout FETCH_HEAD` and the refresh
    /// returns the new content.
    #[rstest]
    fn stale_refresh_compatible_candidate_updates_working_tree(cache_fixture: CacheFixture) {
        use crate::config::required_version::VersionOverrideGuard;
        let _guard = VersionOverrideGuard::set(semver::Version::new(0, 3, 0));

        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Existing (stale) working tree has the "old" preset that we should
        // read if the refresh bails out.
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - allow: 'old rule'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Ok(()));
        // The candidate revision's preset is compatible with current runok.
        mock.on_show_file(
            "FETCH_HEAD",
            "runok.yml",
            indoc! {"
                required_runok_version: '>=0.2'
                rules:
                  - allow: 'new rule'
            "},
        );
        // After inspection succeeds, the refresh path should checkout
        // FETCH_HEAD to materialize the new revision, and then re-read the
        // file from disk. Simulate that by also updating the working tree
        // through a checkout hook: the mock does not actually run git, so
        // we emulate the checkout side-effect by rewriting the file just
        // before calling `load_remote_preset` below is not possible — we
        // instead assert the call sequence rather than the returned content.
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok("deadbeef".to_string()));

        let _config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let calls = mock.calls.borrow();
        // Must have inspected the candidate via show_file before touching
        // the working tree.
        let show_pos = calls.iter().position(|c| {
            matches!(
                c,
                crate::config::git_client::mock::GitCall::ShowFile { git_ref, path }
                if git_ref == "FETCH_HEAD" && path == "runok.yml"
            )
        });
        let checkout_pos = calls.iter().position(|c| {
            matches!(
                c,
                crate::config::git_client::mock::GitCall::Checkout { git_ref, .. }
                if git_ref == "FETCH_HEAD"
            )
        });
        assert!(show_pos.is_some(), "expected show_file to be called");
        assert!(
            checkout_pos.is_some(),
            "expected checkout FETCH_HEAD when compatible"
        );
        assert!(
            show_pos.unwrap() < checkout_pos.unwrap(),
            "inspection must precede checkout (level A)"
        );
    }

    /// When the fetched revision declares a `required_runok_version` that
    /// current runok does not satisfy, the working tree must NOT be touched
    /// by `git checkout`. The refresh silently falls back to the old cached
    /// content so that normal operations keep working.
    #[rstest]
    fn stale_refresh_incompatible_candidate_keeps_working_tree(cache_fixture: CacheFixture) {
        use crate::config::required_version::VersionOverrideGuard;
        let _guard = VersionOverrideGuard::set(semver::Version::new(0, 2, 0));

        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@main";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - allow: 'still valid'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Ok(()));
        // The new revision requires runok 0.3+, but the override pins the
        // current binary to 0.2.0.
        mock.on_show_file(
            "FETCH_HEAD",
            "runok.yml",
            indoc! {"
                required_runok_version: '>=0.3'
                rules:
                  - allow: 'needs newer runok'
            "},
        );

        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        // The returned content should come from the existing working tree,
        // not the new (rejected) revision.
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("still valid"));

        // Most importantly, there must have been NO checkout call: the
        // working tree stays exactly as it was so concurrent runok processes
        // never observe a preset that is too new for them.
        let calls = mock.calls.borrow();
        let had_checkout = calls
            .iter()
            .any(|c| matches!(c, crate::config::git_client::mock::GitCall::Checkout { .. }));
        assert!(
            !had_checkout,
            "checkout must not be called when the candidate is incompatible (level A)"
        );
    }

    /// If a child file reachable via `extends` declares a
    /// `required_runok_version` that current runok does not satisfy, the
    /// parent revision is treated as incompatible as a whole. The working
    /// tree is left unchanged just like the single-file case.
    #[rstest]
    fn stale_refresh_incompatible_extends_child_rejects_parent(cache_fixture: CacheFixture) {
        use crate::config::required_version::VersionOverrideGuard;
        let _guard = VersionOverrideGuard::set(semver::Version::new(0, 2, 0));

        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@main";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - allow: 'existing'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Ok(()));
        // Parent preset itself is compatible.
        mock.on_show_file(
            "FETCH_HEAD",
            "runok.yml",
            indoc! {"
                extends:
                  - ./rules/aws.yml
                rules:
                  - allow: 'parent ok'
            "},
        );
        // Child preset requires a newer runok than the override provides.
        mock.on_show_file(
            "FETCH_HEAD",
            "rules/aws.yml",
            indoc! {"
                required_runok_version: '>=0.9'
                rules:
                  - allow: 'aws'
            "},
        );

        let _config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let calls = mock.calls.borrow();
        let had_checkout = calls
            .iter()
            .any(|c| matches!(c, crate::config::git_client::mock::GitCall::Checkout { .. }));
        assert!(
            !had_checkout,
            "checkout must not be called when an extends child is incompatible"
        );
    }

    #[rstest]
    fn lock_acquired_for_cache_miss(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        mock.on_clone(Ok(()));
        mock.on_rev_parse(Ok("abc123".to_string()));

        // Cache miss triggers clone (which won't create runok.yml, so it errors).
        // The important thing: the lock file should exist after the call.
        let _result = load_remote_preset(&parsed, reference_str, &mock, cache);

        let lock_path = cache.lock_path(reference_str);
        assert!(lock_path.exists(), "lock file should be created");
    }

    #[rstest]
    fn lock_acquired_for_stale_cache(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Write a stale cache (fetched_at = 0)
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - allow: 'cargo test'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok("def456".to_string()));

        let _config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let lock_path = cache.lock_path(reference_str);
        assert!(lock_path.exists(), "lock file should be created");
    }

    #[rstest]
    fn cache_hit_skips_lock(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Write a fresh cache
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();

        let _config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let lock_path = cache.lock_path(reference_str);
        assert!(
            !lock_path.exists(),
            "lock file should not be created for cache hit"
        );
    }

    // === Path-based remote preset tests ===

    fn write_preset_file(dir: &Path, path: &str, content: &str) {
        let full_path = dir.join(format!("{path}.yml"));
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(full_path, content).unwrap();
    }

    #[rstest]
    fn path_based_preset_loads_correct_file(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:fohte/runok-presets/readonly-unix@v1";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Simulate a cloned repo with path-based preset file
        std::fs::create_dir_all(&cache_dir).unwrap();
        write_preset_file(
            &cache_dir,
            "readonly-unix",
            indoc! {"
                rules:
                  - allow: 'cat *'
                  - allow: 'ls *'
            "},
        );
        // Also write runok.yml to verify it is NOT loaded
        write_runok_yml(
            &cache_dir,
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        // Should load readonly-unix.yml, not runok.yml
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("cat *"));
        assert_eq!(rules[1].allow.as_deref(), Some("ls *"));
    }

    #[rstest]
    fn path_based_preset_with_version(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:fohte/runok-presets/readonly-git@v2.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        std::fs::create_dir_all(&cache_dir).unwrap();
        write_preset_file(
            &cache_dir,
            "readonly-git",
            indoc! {"
                rules:
                  - allow: 'git status *'
                  - allow: 'git log *'
                  - allow: 'git diff *'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].allow.as_deref(), Some("git status *"));
    }

    #[rstest]
    fn multiple_path_presets_from_same_repo(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;

        // First preset: readonly-unix
        let ref1 = "github:fohte/runok-presets/readonly-unix@v1";
        let parsed1 = parse_preset_reference(ref1).unwrap();
        let cache_dir1 = cache.cache_dir(ref1);
        std::fs::create_dir_all(&cache_dir1).unwrap();
        write_preset_file(
            &cache_dir1,
            "readonly-unix",
            indoc! {"
                rules:
                  - allow: 'cat *'
            "},
        );
        let metadata1 = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: ref1.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir1, &metadata1).unwrap();

        // Second preset: readonly-git
        let ref2 = "github:fohte/runok-presets/readonly-git@v1";
        let parsed2 = parse_preset_reference(ref2).unwrap();
        let cache_dir2 = cache.cache_dir(ref2);
        std::fs::create_dir_all(&cache_dir2).unwrap();
        write_preset_file(
            &cache_dir2,
            "readonly-git",
            indoc! {"
                rules:
                  - allow: 'git status *'
            "},
        );
        let metadata2 = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: ref2.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir2, &metadata2).unwrap();

        let mock = MockGitClient::new();
        let config1 = load_remote_preset(&parsed1, ref1, &mock, cache).unwrap();
        let config2 = load_remote_preset(&parsed2, ref2, &mock, cache).unwrap();
        let merged = config1.merge(config2);

        let rules = merged.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("cat *"));
        assert_eq!(rules[1].allow.as_deref(), Some("git status *"));
    }

    #[rstest]
    fn nonexistent_path_preset_returns_descriptive_error(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:fohte/runok-presets/nonexistent@v1";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Create cache dir but without the expected preset file
        std::fs::create_dir_all(&cache_dir).unwrap();
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        let err = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::GitClone { message, .. }) => {
                assert_eq!(
                    message,
                    "preset file 'nonexistent.yml' (or 'nonexistent.yaml') not found in preset repository"
                );
            }
            other => panic!("expected GitClone error, got: {other:?}"),
        }
    }

    #[rstest]
    fn path_based_preset_stale_cache_fetches_then_reads_path(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:fohte/runok-presets/readonly-unix@v1";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        // Create a stale cache with the preset file
        std::fs::create_dir_all(&cache_dir).unwrap();
        write_preset_file(
            &cache_dir,
            "readonly-unix",
            indoc! {"
                rules:
                  - allow: 'head *'
            "},
        );
        let metadata = CacheMetadata {
            fetched_at: 0,
            is_immutable: false,
            reference: reference_str.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let mock = MockGitClient::new();
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok("abc123".to_string()));

        let config = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap();

        // Verify fetch was called (stale cache update)
        let calls = mock.calls.borrow();
        let has_fetch = calls
            .iter()
            .any(|c| matches!(c, crate::config::git_client::mock::GitCall::Fetch));
        assert!(has_fetch, "expected fetch for stale cache");

        // Verify the path-based file was loaded
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("head *"));
    }

    #[rstest]
    fn missing_runok_yml_returns_error(cache_fixture: CacheFixture) {
        let cache = &cache_fixture.cache;
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        // Cache miss path: clone succeeds but no runok.yml in the cloned dir
        mock.on_clone(Ok(()));
        mock.on_rev_parse(Ok("abc123".to_string()));

        let err = load_remote_preset(&parsed, reference_str, &mock, cache).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::GitClone { message, .. }) => {
                assert_eq!(message, "runok.yml not found in preset repository");
            }
            other => panic!("expected GitClone error, got: {other:?}"),
        }
    }
}
