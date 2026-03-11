use std::path::Path;

use similar::ChangeTag;

use crate::config::cache::{CacheMetadata, CacheStatus, PresetCache};
use crate::config::git_client::{GitClient, ProcessGitClient};
use crate::config::preset_remote::{
    PresetReference, parse_preset_reference, preset_path_from_reference, resolve_git_params,
    resolve_preset_file_path,
};
use crate::config::{Config, parse_config};

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
fn print_diff(reference: &str, before: &str, after: &str) {
    let diff = similar::TextDiff::from_lines(before, after);

    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    eprintln!("{RED}--- a/{reference}{RESET}");
    eprintln!("{GREEN}+++ b/{reference}{RESET}");

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
    /// Preset was updated with changes.
    Updated { before: String, after: String },
    /// Preset was already up to date (no changes).
    UpToDate,
    /// Preset is immutable (commit SHA), skipped.
    Skipped,
    /// Error occurred during update.
    Error(String),
}

/// Force-fetch a single remote preset and return the update result.
fn update_single_preset<G: GitClient>(
    reference: &str,
    cache: &PresetCache,
    git_client: &G,
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

    let cache_dir = cache.cache_dir(reference);
    let preset_path = preset_path_from_reference(&parsed);

    // Read old content before fetching
    let before = read_preset_content(&cache_dir, preset_path);

    match cache.check(reference, false) {
        CacheStatus::Hit(_) | CacheStatus::Stale(_) => {
            // Cache exists: fetch and update
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

            // Update metadata
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
            // No cache: clone fresh
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

            // Write metadata
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

    // Read new content after fetching
    let after = read_preset_content(&cache_dir, preset_path);

    if before == after {
        UpdateResult::UpToDate
    } else {
        UpdateResult::Updated { before, after }
    }
}

/// Run the update-presets command.
///
/// Finds all config files, collects remote preset references, and force-fetches each one.
/// Displays a diff for presets that changed.
pub fn run(cwd: &Path) -> Result<(), anyhow::Error> {
    let references = collect_all_remote_references(cwd)?;

    if references.is_empty() {
        eprintln!("No remote presets found in configuration.");
        return Ok(());
    }

    let cache = PresetCache::from_env()?;
    let git_client = ProcessGitClient;

    let mut updated_count = 0;
    let mut up_to_date_count = 0;
    let mut skipped_count = 0;
    let mut error_count = 0;

    for reference in &references {
        match update_single_preset(reference, &cache, &git_client) {
            UpdateResult::Updated { before, after } => {
                eprintln!("\x1b[1mUpdated:\x1b[0m {reference}");
                print_diff(reference, &before, &after);
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
            UpdateResult::Error(msg) => {
                eprintln!("\x1b[31mError:\x1b[0m {reference}: {msg}");
                error_count += 1;
            }
        }
    }

    eprintln!();
    eprintln!(
        "Summary: {} updated, {} already up to date, {} skipped, {} errors",
        updated_count, up_to_date_count, skipped_count, error_count
    );

    if error_count > 0 {
        Err(anyhow::anyhow!("{error_count} preset(s) failed to update"))
    } else {
        Ok(())
    }
}

/// Collect all remote preset references from all config layers.
///
/// Reads global and project config files (without resolving extends) to extract
/// the raw `extends` lists.
fn collect_all_remote_references(cwd: &Path) -> Result<Vec<String>, anyhow::Error> {
    let mut references = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let config_filenames = &["runok.yml", "runok.yaml"];
    let local_override_filenames = &["runok.local.yml", "runok.local.yaml"];

    // Global config directory
    if let Some(global_dir) = crate::config::dirs::config_dir().map(|d| d.join("runok")) {
        collect_from_dir(&global_dir, config_filenames, &mut references, &mut seen);
        collect_from_dir(
            &global_dir,
            local_override_filenames,
            &mut references,
            &mut seen,
        );
    }

    // Project config directory (walk up from cwd)
    if let Some(project_dir) = find_project_dir(cwd) {
        collect_from_dir(&project_dir, config_filenames, &mut references, &mut seen);
        collect_from_dir(
            &project_dir,
            local_override_filenames,
            &mut references,
            &mut seen,
        );
    }

    Ok(references)
}

/// Find project directory by walking up from `start` looking for config files.
fn find_project_dir(start: &Path) -> Option<std::path::PathBuf> {
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

/// Read a config file directory and collect remote references from `extends`.
fn collect_from_dir(
    dir: &Path,
    filenames: &[&str],
    references: &mut Vec<String>,
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
            references.push(r);
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

    #[rstest]
    fn update_skips_immutable_preset(tmp: TempDir) {
        let sha = "a".repeat(40);
        let reference = format!("github:org/repo@{sha}");
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let git_client = MockGitClient::new();

        let result = update_single_preset(&reference, &cache, &git_client);
        assert!(matches!(result, UpdateResult::Skipped));
    }

    #[rstest]
    fn update_reports_up_to_date_when_no_changes(tmp: TempDir) {
        let reference = "github:org/repo@v1";
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

        let result = update_single_preset(reference, &cache, &git_client);
        assert!(matches!(result, UpdateResult::UpToDate));
    }

    #[rstest]
    fn update_handles_fetch_error(tmp: TempDir) {
        let reference = "github:org/repo@v1";
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

        let result = update_single_preset(reference, &cache, &git_client);
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

        let mut refs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        collect_from_dir(dir, &["runok.yml"], &mut refs, &mut seen);

        assert_eq!(refs, vec!["github:org/repo@v1", "github:org/other@v2"]);
    }

    #[rstest]
    fn collect_references_skips_missing_files(tmp: TempDir) {
        let dir = tmp.path();
        let mut refs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        collect_from_dir(dir, &["nonexistent.yml"], &mut refs, &mut seen);
        assert!(refs.is_empty());
    }

    impl std::fmt::Debug for UpdateResult {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                UpdateResult::Updated { .. } => write!(f, "Updated"),
                UpdateResult::UpToDate => write!(f, "UpToDate"),
                UpdateResult::Skipped => write!(f, "Skipped"),
                UpdateResult::Error(msg) => write!(f, "Error({msg})"),
            }
        }
    }
}
