mod semver_utils;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use similar::ChangeTag;

use crate::config::cache::{CacheMetadata, CacheStatus, PresetCache};
use crate::config::git_client::{GitClient, ProcessGitClient};
use crate::config::preset_remote::{
    PresetReference, parse_preset_reference, preset_path_from_reference, resolve_git_params,
    resolve_preset_file_path,
};
use crate::config::{Config, parse_config};

use semver_utils::{find_latest_upgrade, parse_version_spec};

/// A remote preset reference paired with the config file it came from.
struct TrackedReference {
    reference: String,
    source_file: PathBuf,
}

/// Collect all `extends` references from a parsed config, returning only remote ones.
fn collect_remote_references(config: &Config) -> Vec<String> {
    config
        .extends
        .as_ref()
        .map(|refs| {
            refs.iter()
                .filter(|r| {
                    parse_preset_reference(r)
                        .map(|p| !matches!(p, PresetReference::Local(_)))
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Read raw YAML content from a preset cache directory, returning empty string if not found.
fn read_preset_content(cache_dir: &Path, preset_path: Option<&str>) -> String {
    resolve_preset_file_path(cache_dir, preset_path)
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default()
}

/// Print a colored unified-style diff between two strings.
fn print_diff(old_label: &str, new_label: &str, before: &str, after: &str) {
    let diff = similar::TextDiff::from_lines(before, after);

    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    eprintln!("{RED}--- a/{old_label}{RESET}");
    eprintln!("{GREEN}+++ b/{new_label}{RESET}");

    for group in diff.grouped_ops(3) {
        let first = &group[0];
        let last = &group[group.len() - 1];
        let old_start = first.old_range().start + 1;
        let old_len = last.old_range().end - first.old_range().start;
        let new_start = first.new_range().start + 1;
        let new_len = last.new_range().end - first.new_range().start;
        eprintln!("{CYAN}@@ -{old_start},{old_len} +{new_start},{new_len} @@{RESET}");
        for op in &group {
            for change in diff.iter_changes(op) {
                let (sign, color) = match change.tag() {
                    ChangeTag::Delete => ("-", RED),
                    ChangeTag::Insert => ("+", GREEN),
                    ChangeTag::Equal => (" ", ""),
                };
                eprint!("{color}{sign}{change}{RESET}");
                if change.missing_newline() {
                    eprintln!();
                }
            }
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Result of updating a single preset.
enum UpdateResult {
    /// Preset content was refreshed with changes (branch/Latest).
    Updated { before: String, after: String },
    /// Preset was already up to date (no changes).
    UpToDate,
    /// Preset is immutable (commit SHA), skipped.
    Skipped,
    /// A newer semver tag was found and the preset was upgraded.
    Upgraded {
        before: String,
        after: String,
        old_reference: String,
        new_reference: String,
    },
    /// Error occurred during update.
    Error(String),
}

/// Extract the current tag from a parsed reference, if it has a version-parseable tag.
///
/// Recognizes full semver (`v1.0.0`), partial major (`v1`), and partial major.minor (`v1.0`).
fn extract_version_tag(parsed: &PresetReference) -> Option<&str> {
    let tag = match parsed {
        PresetReference::GitHub {
            version: crate::config::preset_remote::GitHubVersion::Tag(t),
            ..
        } => t.as_str(),
        PresetReference::GitUrl {
            git_ref: Some(r), ..
        } => r.as_str(),
        _ => return None,
    };
    // Only return if it's parseable as a version spec
    parse_version_spec(tag).map(|_| tag)
}

/// Build a new reference string by replacing the old tag with the new one.
fn build_updated_reference(original: &str, old_tag: &str, new_tag: &str) -> String {
    original.replacen(&format!("@{old_tag}"), &format!("@{new_tag}"), 1)
}

/// Force-fetch a single remote preset and return the update result.
fn update_single_preset<G: GitClient>(
    reference: &str,
    cache: &PresetCache,
    git_client: &G,
    tags_cache: &mut HashMap<String, Vec<String>>,
) -> UpdateResult {
    let parsed = match parse_preset_reference(reference) {
        Ok(p) => p,
        Err(e) => return UpdateResult::Error(e.to_string()),
    };

    let params = resolve_git_params(&parsed);

    // Skip immutable references (commit SHA)
    if params.is_immutable {
        return UpdateResult::Skipped;
    }

    // Check if this is a version tag that can be upgraded
    if let Some(current_tag) = extract_version_tag(&parsed) {
        let result = try_tag_upgrade(
            reference,
            current_tag,
            &params.url,
            &parsed,
            cache,
            git_client,
            tags_cache,
        );
        // If no upgrade was found, the tag might actually be a branch (e.g., `v1` in
        // GitHub Actions style). Fall through to force_refetch so it still gets updated.
        if !matches!(result, UpdateResult::UpToDate) {
            return result;
        }
    }

    // Branch/Latest (or version tag with no upgrade): force re-fetch and show diff
    force_refetch(reference, &parsed, &params, cache, git_client)
}

/// Try to upgrade a semver-tagged preset to the latest compatible version.
fn try_tag_upgrade<G: GitClient>(
    reference: &str,
    current_tag: &str,
    url: &str,
    parsed: &PresetReference,
    cache: &PresetCache,
    git_client: &G,
    tags_cache: &mut HashMap<String, Vec<String>>,
) -> UpdateResult {
    // Fetch remote tags (cached per URL to avoid redundant network calls)
    let remote_tags = match tags_cache.entry(url.to_string()) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(e) => match git_client.ls_remote_tags(url) {
            Ok(tags) => e.insert(tags),
            Err(err) => return UpdateResult::Error(format!("ls-remote failed: {err}")),
        },
    };

    let new_tag = match find_latest_upgrade(current_tag, remote_tags) {
        Some(t) => t,
        None => return UpdateResult::UpToDate,
    };

    let new_reference = build_updated_reference(reference, current_tag, &new_tag);
    let preset_path = preset_path_from_reference(parsed);

    // Read old content from current cache
    let old_cache_dir = cache.cache_dir(reference);
    let before = read_preset_content(&old_cache_dir, preset_path);

    // Fetch the new version into its own cache slot
    let new_cache_dir = cache.cache_dir(&new_reference);
    let new_parsed = match parse_preset_reference(&new_reference) {
        Ok(p) => p,
        Err(e) => return UpdateResult::Error(format!("invalid new reference: {e}")),
    };
    let new_params = resolve_git_params(&new_parsed);

    let _lock = match cache.acquire_lock(&new_reference) {
        Ok(l) => l,
        Err(e) => return UpdateResult::Error(e.to_string()),
    };

    // Check if already cached
    match cache.check(&new_reference, new_params.is_immutable) {
        CacheStatus::Hit(_) => {}
        CacheStatus::Stale(_) | CacheStatus::Miss => {
            if !new_cache_dir.exists() {
                if let Some(parent) = new_cache_dir.parent()
                    && let Err(e) = std::fs::create_dir_all(parent)
                {
                    return UpdateResult::Error(format!("failed to create cache directory: {e}"));
                }
                if let Err(e) = git_client.clone_shallow(
                    &new_params.url,
                    &new_cache_dir,
                    new_params.git_ref.as_deref(),
                ) {
                    return UpdateResult::Error(format!("clone failed: {e}"));
                }
            } else {
                if let Err(e) = git_client.fetch(&new_cache_dir, new_params.git_ref.as_deref()) {
                    return UpdateResult::Error(format!("fetch failed: {e}"));
                }
                if let Err(e) = git_client.checkout(&new_cache_dir, "FETCH_HEAD") {
                    return UpdateResult::Error(format!("checkout failed: {e}"));
                }
            }
            let resolved_sha = git_client.rev_parse_head(&new_cache_dir).ok();
            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: new_params.is_immutable,
                reference: new_reference.clone(),
                resolved_sha,
            };
            let _ = PresetCache::write_metadata(&new_cache_dir, &metadata);
        }
    }

    let after = read_preset_content(&new_cache_dir, preset_path);

    UpdateResult::Upgraded {
        before,
        after,
        old_reference: reference.to_string(),
        new_reference,
    }
}

/// Force re-fetch a branch/Latest preset and return diff result.
fn force_refetch<G: GitClient>(
    reference: &str,
    parsed: &PresetReference,
    params: &crate::config::preset_remote::GitParams,
    cache: &PresetCache,
    git_client: &G,
) -> UpdateResult {
    let cache_dir = cache.cache_dir(reference);
    let preset_path = preset_path_from_reference(parsed);

    // Read old content before fetching
    let before = read_preset_content(&cache_dir, preset_path);

    match cache.check(reference, false) {
        CacheStatus::Hit(_) | CacheStatus::Stale(_) => {
            let _lock = match cache.acquire_lock(reference) {
                Ok(l) => l,
                Err(e) => return UpdateResult::Error(e.to_string()),
            };

            if let Err(e) = git_client.fetch(&cache_dir, params.git_ref.as_deref()) {
                return UpdateResult::Error(format!("fetch failed: {e}"));
            }

            if let Err(e) = git_client.checkout(&cache_dir, "FETCH_HEAD") {
                return UpdateResult::Error(format!("checkout failed: {e}"));
            }

            let resolved_sha = git_client.rev_parse_head(&cache_dir).ok();
            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: false,
                reference: reference.to_string(),
                resolved_sha,
            };
            let _ = PresetCache::write_metadata(&cache_dir, &metadata);
        }
        CacheStatus::Miss => {
            let _lock = match cache.acquire_lock(reference) {
                Ok(l) => l,
                Err(e) => return UpdateResult::Error(e.to_string()),
            };

            if let Some(parent) = cache_dir.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return UpdateResult::Error(format!("failed to create cache directory: {e}"));
            }

            if let Err(e) =
                git_client.clone_shallow(&params.url, &cache_dir, params.git_ref.as_deref())
            {
                return UpdateResult::Error(format!("clone failed: {e}"));
            }

            let resolved_sha = git_client.rev_parse_head(&cache_dir).ok();
            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: false,
                reference: reference.to_string(),
                resolved_sha,
            };
            let _ = PresetCache::write_metadata(&cache_dir, &metadata);
        }
    }

    let after = read_preset_content(&cache_dir, preset_path);

    if before == after {
        UpdateResult::UpToDate
    } else {
        UpdateResult::Updated { before, after }
    }
}

/// Replace a preset reference in a config file, preserving formatting.
fn update_config_file(
    source_file: &Path,
    old_reference: &str,
    new_reference: &str,
) -> Result<(), anyhow::Error> {
    let content = std::fs::read_to_string(source_file)?;
    let updated = content.replace(old_reference, new_reference);
    std::fs::write(source_file, updated)?;
    Ok(())
}

/// Run the update-presets command.
///
/// Finds all config files, collects remote preset references, and force-fetches each one.
/// For semver-tagged presets, checks for newer compatible versions and updates config files.
/// Displays a diff for presets that changed.
pub fn run(cwd: &Path) -> Result<(), anyhow::Error> {
    let tracked_refs = collect_all_tracked_references(cwd)?;

    if tracked_refs.is_empty() {
        eprintln!("No remote presets found in configuration.");
        return Ok(());
    }

    let cache = PresetCache::from_env()?;
    let git_client = ProcessGitClient;

    run_with(tracked_refs, &cache, &git_client)
}

/// Inner implementation that accepts injected dependencies for testing.
fn run_with<G: GitClient>(
    tracked_refs: Vec<TrackedReference>,
    cache: &PresetCache,
    git_client: &G,
) -> Result<(), anyhow::Error> {
    let mut updated_count = 0;
    let mut up_to_date_count = 0;
    let mut skipped_count = 0;
    let mut upgraded_count = 0;
    let mut error_count = 0;

    // Cache ls-remote results per URL to avoid redundant network calls
    let mut tags_cache: HashMap<String, Vec<String>> = HashMap::new();

    for tracked in &tracked_refs {
        let reference = &tracked.reference;
        match update_single_preset(reference, cache, git_client, &mut tags_cache) {
            UpdateResult::Updated { before, after } => {
                eprintln!("\x1b[1mUpdated:\x1b[0m {reference}");
                print_diff(reference, reference, &before, &after);
                eprintln!();
                updated_count += 1;
            }
            UpdateResult::UpToDate => {
                eprintln!("Already up to date: {reference}");
                up_to_date_count += 1;
            }
            UpdateResult::Skipped => {
                eprintln!("Skipped (immutable): {reference}");
                skipped_count += 1;
            }
            UpdateResult::Upgraded {
                before,
                after,
                old_reference,
                new_reference,
            } => {
                eprintln!("\x1b[1mUpgraded:\x1b[0m {old_reference} \u{2192} {new_reference}");
                print_diff(&old_reference, &new_reference, &before, &after);

                match update_config_file(&tracked.source_file, &old_reference, &new_reference) {
                    Ok(()) => {
                        eprintln!(
                            "  Updated {}: {old_reference} \u{2192} {new_reference}",
                            tracked.source_file.display()
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "  \x1b[31mFailed to update {}:\x1b[0m {e}",
                            tracked.source_file.display()
                        );
                        error_count += 1;
                    }
                }
                eprintln!();
                upgraded_count += 1;
            }
            UpdateResult::Error(msg) => {
                eprintln!("\x1b[31mError:\x1b[0m {reference}: {msg}");
                error_count += 1;
            }
        }
    }

    eprintln!();
    eprintln!(
        "Summary: {} updated, {} upgraded, {} already up to date, {} skipped, {} errors",
        updated_count, upgraded_count, up_to_date_count, skipped_count, error_count
    );

    if error_count > 0 {
        Err(anyhow::anyhow!("{error_count} preset(s) failed to update"))
    } else {
        Ok(())
    }
}

/// Collect all remote preset references from all config layers, tracking source files.
fn collect_all_tracked_references(cwd: &Path) -> Result<Vec<TrackedReference>, anyhow::Error> {
    let mut tracked = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let config_filenames = &["runok.yml", "runok.yaml"];
    let local_override_filenames = &["runok.local.yml", "runok.local.yaml"];

    // Global config directory
    if let Some(global_dir) = crate::config::dirs::config_dir().map(|d| d.join("runok")) {
        collect_tracked_from_dir(&global_dir, config_filenames, &mut tracked, &mut seen);
        collect_tracked_from_dir(
            &global_dir,
            local_override_filenames,
            &mut tracked,
            &mut seen,
        );
    }

    // Project config directory (walk up from cwd)
    if let Some(project_dir) = find_project_dir(cwd) {
        collect_tracked_from_dir(&project_dir, config_filenames, &mut tracked, &mut seen);
        collect_tracked_from_dir(
            &project_dir,
            local_override_filenames,
            &mut tracked,
            &mut seen,
        );
    }

    Ok(tracked)
}

/// Find project directory by walking up from `start` looking for config files.
fn find_project_dir(start: &Path) -> Option<PathBuf> {
    let home_dir = crate::config::dirs::home_dir();
    let config_files = [
        "runok.yml",
        "runok.yaml",
        "runok.local.yml",
        "runok.local.yaml",
    ];

    for ancestor in start.ancestors() {
        if let Some(ref home) = home_dir
            && ancestor == home.as_path()
        {
            break;
        }
        if config_files.iter().any(|name| ancestor.join(name).exists()) {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// Read a config file and collect remote references with source file tracking.
fn collect_tracked_from_dir(
    dir: &Path,
    filenames: &[&str],
    tracked: &mut Vec<TrackedReference>,
    seen: &mut std::collections::HashSet<String>,
) {
    let path = filenames
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists());

    let Some(path) = path else { return };

    let yaml = match std::fs::read_to_string(&path) {
        Ok(y) => y,
        Err(_) => return,
    };

    let config = match parse_config(&yaml) {
        Ok(c) => c,
        Err(_) => return,
    };

    for r in collect_remote_references(&config) {
        if seen.insert(r.clone()) {
            tracked.push(TrackedReference {
                reference: r,
                source_file: path.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cache::PresetCache;
    use crate::config::git_client::mock::MockGitClient;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    #[fixture]
    fn tmp() -> TempDir {
        TempDir::new().unwrap()
    }

    // === collect_remote_references ===

    #[rstest]
    #[case::github_shorthand("github:org/repo@v1", true)]
    #[case::git_url("https://github.com/org/repo.git@main", true)]
    #[case::local_path("./local.yml", false)]
    fn collect_remote_references_filters_local(
        #[case] reference: &str,
        #[case] expected_included: bool,
    ) {
        let config = Config {
            extends: Some(vec![reference.to_string()]),
            ..Config::default()
        };
        let refs = collect_remote_references(&config);
        assert_eq!(refs.contains(&reference.to_string()), expected_included);
    }

    #[rstest]
    fn collect_remote_references_empty_extends() {
        let config = Config::default();
        assert!(collect_remote_references(&config).is_empty());
    }

    // === update_single_preset ===

    #[rstest]
    fn update_skips_immutable_preset(tmp: TempDir) {
        let sha = "a".repeat(40);
        let reference = format!("github:org/repo@{sha}");
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let git_client = MockGitClient::new();
        let mut tags_cache = HashMap::new();

        let result = update_single_preset(&reference, &cache, &git_client, &mut tags_cache);
        assert!(matches!(result, UpdateResult::Skipped));
    }

    #[rstest]
    fn update_branch_reports_up_to_date_when_no_changes(tmp: TempDir) {
        // "main" is not semver, so it goes through the branch/force-refetch path
        let reference = "github:org/repo@main";
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&cache_dir).unwrap();

        let content = indoc! {"
            rules:
              - allow: 'git status'
        "};
        fs::write(cache_dir.join("runok.yml"), content).unwrap();

        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference.to_string(),
            resolved_sha: Some("abc123".to_string()),
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let git_client = MockGitClient::new();
        git_client.on_fetch(Ok(()));
        git_client.on_checkout(Ok(()));
        git_client.on_rev_parse(Ok("abc123".to_string()));

        let mut tags_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut tags_cache);
        assert!(matches!(result, UpdateResult::UpToDate));
    }

    #[rstest]
    fn update_handles_fetch_error(tmp: TempDir) {
        let reference = "github:org/repo@main";
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("runok.yml"), "rules: []").unwrap();

        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference.to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let git_client = MockGitClient::new();
        git_client.on_fetch(Err(crate::config::PresetError::GitClone {
            reference: "mock".to_string(),
            message: "network error".to_string(),
        }));

        let mut tags_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut tags_cache);
        match result {
            UpdateResult::Error(msg) => {
                assert_eq!(
                    msg,
                    "fetch failed: git clone failed for 'mock': network error"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // === semver tag upgrade ===

    #[rstest]
    fn update_upgrades_semver_tag(tmp: TempDir) {
        let reference = "github:org/repo@v1.0.0";
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));

        // Set up old cache for v1.0.0
        let old_cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&old_cache_dir).unwrap();
        fs::write(
            old_cache_dir.join("runok.yml"),
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        )
        .unwrap();

        let new_reference = "github:org/repo@v1.2.0";
        let new_cache_dir = cache.cache_dir(new_reference);

        let git_client = MockGitClient::new();
        git_client.on_ls_remote_tags(Ok(vec![
            "v0.9.0".to_string(),
            "v1.0.0".to_string(),
            "v1.1.0".to_string(),
            "v1.2.0".to_string(),
            "v2.0.0".to_string(),
        ]));
        // new_cache_dir doesn't exist yet, so it takes the clone path.
        // Mock clone succeeds, and we pre-create the directory/file to simulate what
        // a real git clone would produce.
        git_client.on_clone(Ok(()));
        git_client.on_rev_parse(Ok("def456".to_string()));

        // Pre-create the new cache directory with the new preset content.
        // In production, git clone creates this. The mock doesn't, so we do it manually.
        // However, the code checks `!new_cache_dir.exists()` AFTER acquiring the lock,
        // so we must create it *after* on_clone is "called" — but since MockGitClient
        // doesn't actually do anything, we create it before and the code will see it exists
        // and go to the fetch+checkout path instead. So don't pre-create it; instead,
        // set up a directory that will be checked after clone.
        //
        // The flow: lock -> check cache (Miss) -> !exists -> clone_shallow -> write_metadata
        //   -> read_preset_content. Since mock clone doesn't create files, we need to
        //   create the directory after the test starts but the mock is synchronous...
        //
        // Simplest fix: pre-create the parent so clone doesn't fail, and create the
        // preset file in a separate step. Actually, let's just pre-create the cache dir
        // with content and queue fetch+checkout mocks for the existing-dir path.
        fs::create_dir_all(&new_cache_dir).unwrap();
        fs::write(
            new_cache_dir.join("runok.yml"),
            indoc! {"
                rules:
                  - allow: 'git status'
                  - allow: 'git log'
            "},
        )
        .unwrap();

        // Since new_cache_dir already exists, code takes the fetch+checkout path.
        // We need to replace clone mock with fetch+checkout mocks.
        // Clear the clone mock and set up fetch+checkout instead.
        // Actually, MockGitClient queues are already set with on_clone above.
        // The code checks `!new_cache_dir.exists()` — since we created it, it goes
        // to the else branch (fetch+checkout). So on_clone won't be consumed, and
        // fetch+checkout will pop from empty queues.
        // Fix: don't call on_clone, call on_fetch + on_checkout instead.
        drop(git_client);

        let git_client = MockGitClient::new();
        git_client.on_ls_remote_tags(Ok(vec![
            "v0.9.0".to_string(),
            "v1.0.0".to_string(),
            "v1.1.0".to_string(),
            "v1.2.0".to_string(),
            "v2.0.0".to_string(),
        ]));
        git_client.on_fetch(Ok(()));
        git_client.on_checkout(Ok(()));
        git_client.on_rev_parse(Ok("def456".to_string()));

        let mut tags_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut tags_cache);
        match result {
            UpdateResult::Upgraded {
                old_reference,
                new_reference: new_ref,
                ..
            } => {
                assert_eq!(old_reference, "github:org/repo@v1.0.0");
                assert_eq!(new_ref, "github:org/repo@v1.2.0");
            }
            other => panic!("expected Upgraded, got {other:?}"),
        }
    }

    #[rstest]
    fn update_semver_tag_no_newer_version_falls_through_to_refetch(tmp: TempDir) {
        // When no upgrade is found, falls through to force_refetch (branch-like behavior).
        // This handles cases like GitHub Actions where `v1` is a branch, not a semver tag.
        let reference = "github:org/repo@v1.2.0";
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&cache_dir).unwrap();

        let content = indoc! {"
            rules:
              - allow: 'git status'
        "};
        fs::write(cache_dir.join("runok.yml"), content).unwrap();

        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference.to_string(),
            resolved_sha: Some("abc123".to_string()),
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let git_client = MockGitClient::new();
        git_client.on_ls_remote_tags(Ok(vec![
            "v1.0.0".to_string(),
            "v1.1.0".to_string(),
            "v1.2.0".to_string(),
        ]));
        // force_refetch path: fetch + checkout + rev_parse
        git_client.on_fetch(Ok(()));
        git_client.on_checkout(Ok(()));
        git_client.on_rev_parse(Ok("abc123".to_string()));

        let mut tags_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut tags_cache);
        // Content unchanged, so UpToDate after re-fetch
        assert!(matches!(result, UpdateResult::UpToDate));
    }

    #[rstest]
    fn update_full_semver_tag_respects_major_boundary(tmp: TempDir) {
        // v1.0.0 should NOT upgrade to v2.0.0, and then falls through to re-fetch
        let reference = "github:org/repo@v1.0.0";
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&cache_dir).unwrap();

        let content = indoc! {"
            rules:
              - allow: 'git status'
        "};
        fs::write(cache_dir.join("runok.yml"), content).unwrap();

        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference.to_string(),
            resolved_sha: Some("abc123".to_string()),
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();

        let git_client = MockGitClient::new();
        git_client.on_ls_remote_tags(Ok(vec!["v1.0.0".to_string(), "v2.0.0".to_string()]));
        git_client.on_fetch(Ok(()));
        git_client.on_checkout(Ok(()));
        git_client.on_rev_parse(Ok("abc123".to_string()));

        let mut tags_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut tags_cache);
        assert!(matches!(result, UpdateResult::UpToDate));
    }

    // === collect_tracked_from_dir ===

    #[rstest]
    fn collect_references_deduplicates(tmp: TempDir) {
        let dir = tmp.path();
        fs::write(
            dir.join("runok.yml"),
            indoc! {"
                extends:
                  - github:org/repo@v1
                  - github:org/repo@v1
                  - github:org/other@v2
            "},
        )
        .unwrap();

        let mut tracked = Vec::new();
        let mut seen = std::collections::HashSet::new();
        collect_tracked_from_dir(dir, &["runok.yml"], &mut tracked, &mut seen);

        let refs: Vec<&str> = tracked.iter().map(|t| t.reference.as_str()).collect();
        assert_eq!(refs, vec!["github:org/repo@v1", "github:org/other@v2"]);
    }

    #[rstest]
    fn collect_references_tracks_source_file(tmp: TempDir) {
        let dir = tmp.path();
        fs::write(
            dir.join("runok.yml"),
            indoc! {"
                extends:
                  - github:org/repo@v1
            "},
        )
        .unwrap();

        let mut tracked = Vec::new();
        let mut seen = std::collections::HashSet::new();
        collect_tracked_from_dir(dir, &["runok.yml"], &mut tracked, &mut seen);

        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].source_file, dir.join("runok.yml"));
    }

    #[rstest]
    fn collect_references_skips_missing_files(tmp: TempDir) {
        let dir = tmp.path();
        let mut tracked = Vec::new();
        let mut seen = std::collections::HashSet::new();
        collect_tracked_from_dir(dir, &["nonexistent.yml"], &mut tracked, &mut seen);
        assert!(tracked.is_empty());
    }

    // === update_config_file ===

    #[rstest]
    fn update_config_file_replaces_reference(tmp: TempDir) {
        let config_path = tmp.path().join("runok.yml");
        let content = indoc! {"
            extends:
              - github:org/repo@v1.0.0
            rules:
              - allow: 'git status'
        "};
        fs::write(&config_path, content).unwrap();

        update_config_file(
            &config_path,
            "github:org/repo@v1.0.0",
            "github:org/repo@v1.2.0",
        )
        .unwrap();

        let updated = fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            updated,
            indoc! {"
                extends:
                  - github:org/repo@v1.2.0
                rules:
                  - allow: 'git status'
            "}
        );
    }

    #[rstest]
    fn update_config_file_preserves_comments(tmp: TempDir) {
        let config_path = tmp.path().join("runok.yml");
        let content = indoc! {"
            # Shared rules
            extends:
              - github:org/repo@v1.0.0  # pinned
            rules:
              - allow: 'git status'
        "};
        fs::write(&config_path, content).unwrap();

        update_config_file(
            &config_path,
            "github:org/repo@v1.0.0",
            "github:org/repo@v1.2.0",
        )
        .unwrap();

        let updated = fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            updated,
            indoc! {"
                # Shared rules
                extends:
                  - github:org/repo@v1.2.0  # pinned
                rules:
                  - allow: 'git status'
            "}
        );
    }

    // === build_updated_reference ===

    #[rstest]
    #[case::github("github:org/repo@v1.0.0", "v1.0.0", "v1.2.0", "github:org/repo@v1.2.0")]
    #[case::git_url(
        "https://github.com/org/repo.git@v1.0.0",
        "v1.0.0",
        "v1.2.0",
        "https://github.com/org/repo.git@v1.2.0"
    )]
    fn build_updated_reference_test(
        #[case] original: &str,
        #[case] old_tag: &str,
        #[case] new_tag: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            build_updated_reference(original, old_tag, new_tag),
            expected
        );
    }

    impl std::fmt::Debug for UpdateResult {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                UpdateResult::Updated { .. } => write!(f, "Updated"),
                UpdateResult::UpToDate => write!(f, "UpToDate"),
                UpdateResult::Skipped => write!(f, "Skipped"),
                UpdateResult::Upgraded { .. } => write!(f, "Upgraded"),
                UpdateResult::Error(msg) => write!(f, "Error({msg})"),
            }
        }
    }
}
