mod semver_utils;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use similar::ChangeTag;

use crate::config::cache::{CacheMetadata, CacheStatus, PresetCache};
use crate::config::git_client::{GitClient, ProcessGitClient, RemoteRef};
use crate::config::preset_remote::{
    CandidateInspection, PresetReference, inspect_candidate_required_versions,
    parse_preset_reference, preset_path_from_reference, resolve_git_params,
};
use crate::config::{Config, ConfigError, load_and_resolve_preset_with, parse_config};

use semver_utils::{find_upgrade_candidates, parse_version_spec};

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

/// Print a colored unified-style diff between two strings.
fn print_diff(old_label: &str, new_label: &str, before: &str, after: &str) {
    let diff = similar::TextDiff::from_lines(before, after);

    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    eprintln!("{RED}--- {old_label}{RESET}");
    eprintln!("{GREEN}+++ {new_label}{RESET}");

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

/// A candidate tag that was rejected because of a `required_runok_version`
/// constraint the current runok build does not satisfy. Surfaced so that the
/// `update-presets` command can emit a single consolidated warning.
#[derive(Debug, Clone)]
struct SkippedCandidate {
    tag: String,
    source_label: String,
    requirement: String,
    current: String,
}

/// Result of updating a single preset.
enum UpdateResult {
    /// Preset content was refreshed with changes (branch/Latest).
    Updated {
        old_sha: Option<String>,
        new_sha: Option<String>,
        /// Candidates that were inspected but skipped because they required a
        /// newer runok version. Populated only when there were candidates to
        /// skip; empty otherwise.
        skipped_candidates: Vec<SkippedCandidate>,
    },
    /// Preset was already up to date (no changes).
    UpToDate {
        skipped_candidates: Vec<SkippedCandidate>,
    },
    /// Preset is immutable (commit SHA), skipped.
    Skipped,
    /// A newer version tag was found and the preset was upgraded.
    Upgraded {
        old_reference: String,
        new_reference: String,
        /// Candidates newer than the adopted one that were skipped because
        /// they required a newer runok version.
        skipped_candidates: Vec<SkippedCandidate>,
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
    refs_cache: &mut HashMap<String, Vec<RemoteRef>>,
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
    let mut skipped_from_upgrade: Vec<SkippedCandidate> = Vec::new();
    if let Some(current_tag) = extract_version_tag(&parsed) {
        let result = try_tag_upgrade(
            reference,
            current_tag,
            &params.url,
            &parsed,
            cache,
            git_client,
            refs_cache,
        );
        // If no upgrade was found, the tag might actually be a branch (e.g., `v1` in
        // GitHub Actions style). Fall through to force_refetch so it still gets updated.
        match result {
            UpdateResult::UpToDate { skipped_candidates } => {
                skipped_from_upgrade = skipped_candidates;
            }
            other => return other,
        }
    }

    // Branch/Latest (or version tag with no upgrade): force re-fetch.
    // Preserve any candidates that were skipped during `try_tag_upgrade` so
    // the final warn report still mentions them.
    let mut refetched = force_refetch(reference, &params, cache, git_client);
    attach_skipped(&mut refetched, skipped_from_upgrade);
    refetched
}

/// Attach a list of skipped candidates to the result returned by
/// `force_refetch`, merging with any pre-existing list.
fn attach_skipped(result: &mut UpdateResult, mut extra: Vec<SkippedCandidate>) {
    if extra.is_empty() {
        return;
    }
    match result {
        UpdateResult::Updated {
            skipped_candidates, ..
        }
        | UpdateResult::UpToDate { skipped_candidates }
        | UpdateResult::Upgraded {
            skipped_candidates, ..
        } => {
            skipped_candidates.append(&mut extra);
        }
        UpdateResult::Skipped | UpdateResult::Error(_) => {}
    }
}

/// Try to upgrade a version-tagged preset to the latest compatible version.
///
/// Candidate tags are tried from newest to oldest. Each candidate is inspected
/// with `git show` against the *existing* cache directory so the working tree
/// is never touched with an unvalidated revision (level A). Only after a
/// candidate is confirmed compatible is the new reference materialized in its
/// own cache directory. If every candidate fails the version check, the
/// preset is reported as up to date and the caller proceeds with
/// `force_refetch` for branches/Latest.
fn try_tag_upgrade<G: GitClient>(
    reference: &str,
    current_tag: &str,
    url: &str,
    parsed_ref: &PresetReference,
    cache: &PresetCache,
    git_client: &G,
    refs_cache: &mut HashMap<String, Vec<RemoteRef>>,
) -> UpdateResult {
    // Fetch remote refs (cached per URL to avoid redundant network calls)
    let remote_refs = match refs_cache.entry(url.to_string()) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(e) => match git_client.ls_remote_refs(url) {
            Ok(refs) => e.insert(refs),
            Err(err) => return UpdateResult::Error(format!("ls-remote failed: {err}")),
        },
    };

    let ref_names: Vec<String> = remote_refs.iter().map(|r| r.name.clone()).collect();
    let candidates = find_upgrade_candidates(current_tag, &ref_names);
    if candidates.is_empty() {
        return UpdateResult::UpToDate {
            skipped_candidates: Vec::new(),
        };
    }

    let preset_path = preset_path_from_reference(parsed_ref).map(|s| s.to_string());
    let old_cache_dir = cache.cache_dir(reference);

    let mut skipped: Vec<SkippedCandidate> = Vec::new();

    for new_tag in candidates {
        let new_reference = build_updated_reference(reference, current_tag, &new_tag);

        // Decide how to inspect the candidate.
        //
        // - If we already have a cache directory for the *current* reference,
        //   use it as a scratch pad: fetch the candidate tag into its existing
        //   clone and run `git show <tag>:<path>` to inspect the revision
        //   without touching the working tree. This preserves level A: no
        //   concurrent runok process ever sees a partially-updated cache.
        //
        // - Otherwise we have no existing clone to inspect. Fall back to the
        //   old behavior of materializing the candidate in a fresh cache
        //   directory; this is still level-A-safe because no concurrent
        //   process is reading that cache (it did not exist before).
        let inspection = if old_cache_dir.exists() {
            // Acquire a lock on the old cache to serialize against concurrent
            // auto-refresh. The fetch-only phase does not modify the working
            // tree, but we still lock to match existing conventions and to
            // prevent the working tree from being pulled out from under us.
            let _lock = match cache.acquire_lock(reference) {
                Ok(l) => l,
                Err(e) => return UpdateResult::Error(format!("lock failed: {e}")),
            };

            if let Err(e) = git_client.fetch(&old_cache_dir, Some(&new_tag)) {
                skipped.push(SkippedCandidate {
                    tag: new_tag.clone(),
                    source_label: format!("fetch failed: {e}"),
                    requirement: String::new(),
                    current: String::new(),
                });
                continue;
            }

            inspect_candidate_required_versions(
                git_client,
                &old_cache_dir,
                "FETCH_HEAD",
                preset_path.as_deref(),
            )
        } else {
            // No existing clone: materialize into the new cache dir so we can
            // inspect it directly. This path is taken only for presets that
            // were never loaded before (`update-presets` is usually run after
            // presets have been used, so this is rare).
            match materialize_candidate(&new_reference, cache, git_client) {
                Ok(()) => {}
                Err(msg) => return UpdateResult::Error(msg),
            }
            let new_cache_dir = cache.cache_dir(&new_reference);
            // Inspect by reading files directly from the working tree via
            // `load_and_resolve_preset_with`, which walks the real extends
            // chain. This matches the previous implementation for first-use.
            match load_and_resolve_preset_with(&new_reference, &new_cache_dir, git_client, cache) {
                Ok(_) => CandidateInspection::Compatible,
                Err(ConfigError::UnsupportedRunokVersion {
                    source_label,
                    requirement,
                    current,
                }) => CandidateInspection::Incompatible {
                    source_label,
                    requirement,
                    current,
                },
                Err(e) => {
                    return UpdateResult::Error(format!(
                        "failed to load candidate tag {new_tag}: {e}"
                    ));
                }
            }
        };

        match inspection {
            CandidateInspection::Compatible => {
                // If we inspected via the old cache dir, the new reference
                // has not yet been materialized; do it now so that subsequent
                // loads can find it in the cache.
                if old_cache_dir.exists()
                    && let Err(msg) = materialize_candidate(&new_reference, cache, git_client)
                {
                    return UpdateResult::Error(msg);
                }
                return UpdateResult::Upgraded {
                    old_reference: reference.to_string(),
                    new_reference,
                    skipped_candidates: skipped,
                };
            }
            CandidateInspection::Incompatible {
                source_label,
                requirement,
                current,
            } => {
                skipped.push(SkippedCandidate {
                    tag: new_tag.clone(),
                    source_label,
                    requirement,
                    current,
                });
                continue;
            }
            CandidateInspection::InspectionFailed => {
                // Could not inspect (missing preset file, parse error, etc.).
                // Treat the same as "not a valid upgrade target" and keep
                // trying older tags. Do not append to `skipped` because we
                // do not know whether this was a version-constraint failure.
                continue;
            }
        }
    }

    UpdateResult::UpToDate {
        skipped_candidates: skipped,
    }
}

/// Ensure a candidate reference is materialized in the preset cache so that
/// it can be loaded by `load_and_resolve_preset_with`. This mirrors the
/// fetch/clone bookkeeping that `try_tag_upgrade` used to inline, extracted
/// so that multiple candidates can reuse it.
fn materialize_candidate<G: GitClient>(
    new_reference: &str,
    cache: &PresetCache,
    git_client: &G,
) -> Result<(), String> {
    let new_cache_dir = cache.cache_dir(new_reference);
    let new_parsed =
        parse_preset_reference(new_reference).map_err(|e| format!("invalid new reference: {e}"))?;
    let new_params = resolve_git_params(&new_parsed);

    let _lock = cache
        .acquire_lock(new_reference)
        .map_err(|e| e.to_string())?;

    match cache.check(new_reference, new_params.is_immutable) {
        CacheStatus::Hit(_) => Ok(()),
        CacheStatus::Stale(_) | CacheStatus::Miss => {
            if !new_cache_dir.exists() {
                if let Some(parent) = new_cache_dir.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create cache directory: {e}"))?;
                }
                git_client
                    .clone_shallow(
                        &new_params.url,
                        &new_cache_dir,
                        new_params.git_ref.as_deref(),
                    )
                    .map_err(|e| format!("clone failed: {e}"))?;
            } else {
                git_client
                    .fetch(&new_cache_dir, new_params.git_ref.as_deref())
                    .map_err(|e| format!("fetch failed: {e}"))?;
                git_client
                    .checkout(&new_cache_dir, "FETCH_HEAD")
                    .map_err(|e| format!("checkout failed: {e}"))?;
            }
            let resolved_sha = git_client.rev_parse_head(&new_cache_dir).ok();
            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: new_params.is_immutable,
                reference: new_reference.to_string(),
                resolved_sha,
            };
            let _ = PresetCache::write_metadata(&new_cache_dir, &metadata);
            Ok(())
        }
    }
}

/// Force re-fetch a branch/Latest preset and return the result.
fn force_refetch<G: GitClient>(
    reference: &str,
    params: &crate::config::preset_remote::GitParams,
    cache: &PresetCache,
    git_client: &G,
) -> UpdateResult {
    let cache_dir = cache.cache_dir(reference);

    // Read old SHA from existing metadata
    let old_sha =
        PresetCache::read_metadata(&cache_dir.join("metadata.json")).and_then(|m| m.resolved_sha);

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

            let new_sha = git_client.rev_parse_head(&cache_dir).ok();
            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: false,
                reference: reference.to_string(),
                resolved_sha: new_sha.clone(),
            };
            let _ = PresetCache::write_metadata(&cache_dir, &metadata);

            if old_sha == new_sha {
                UpdateResult::UpToDate {
                    skipped_candidates: Vec::new(),
                }
            } else {
                UpdateResult::Updated {
                    old_sha,
                    new_sha,
                    skipped_candidates: Vec::new(),
                }
            }
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

            let new_sha = git_client.rev_parse_head(&cache_dir).ok();
            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: false,
                reference: reference.to_string(),
                resolved_sha: new_sha.clone(),
            };
            let _ = PresetCache::write_metadata(&cache_dir, &metadata);

            UpdateResult::Updated {
                old_sha: None,
                new_sha,
                skipped_candidates: Vec::new(),
            }
        }
    }
}

/// Emit a warning listing tag candidates that were rejected because of a
/// `required_runok_version` constraint. Called only from the manual
/// `update-presets` path; the automatic stale-refresh path is intentionally
/// silent so that normal operations never surface preset-author messages
/// about the runok binary version.
fn warn_skipped_candidates(reference: &str, skipped: &[SkippedCandidate]) {
    if skipped.is_empty() {
        return;
    }
    eprintln!(
        "\x1b[33mwarning:\x1b[0m {} candidate upgrade(s) for {reference} \
         were skipped because the current runok binary is too old:",
        skipped.len()
    );
    for entry in skipped {
        if entry.requirement.is_empty() {
            // Inspection failure (e.g. fetch error). Surface the raw detail.
            eprintln!("  {}: {}", entry.tag, entry.source_label);
        } else {
            eprintln!(
                "  {}: {} requires runok {} (current: {})",
                entry.tag, entry.source_label, entry.requirement, entry.current
            );
        }
    }
    eprintln!("  Upgrade runok to pick up newer preset versions.");
}

/// Replace a preset reference in a config file, preserving formatting.
fn update_config_file(
    source_file: &Path,
    old_reference: &str,
    new_reference: &str,
) -> Result<(), anyhow::Error> {
    let content = std::fs::read_to_string(source_file)?;
    let updated = content.replacen(old_reference, new_reference, 1);
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
    let mut refs_cache: HashMap<String, Vec<RemoteRef>> = HashMap::new();

    for tracked in &tracked_refs {
        let reference = &tracked.reference;
        match update_single_preset(reference, cache, git_client, &mut refs_cache) {
            UpdateResult::Updated {
                old_sha,
                new_sha,
                skipped_candidates,
            } => {
                let old = old_sha.as_deref().map_or("(none)", |s| s);
                let new = new_sha.as_deref().map_or("(unknown)", |s| s);
                eprintln!("\x1b[1mUpdated:\x1b[0m {reference} ({old} \u{2192} {new})");
                warn_skipped_candidates(reference, &skipped_candidates);
                updated_count += 1;
            }
            UpdateResult::UpToDate { skipped_candidates } => {
                eprintln!("Already up to date: {reference}");
                warn_skipped_candidates(reference, &skipped_candidates);
                up_to_date_count += 1;
            }
            UpdateResult::Skipped => {
                eprintln!("Skipped (immutable): {reference}");
                skipped_count += 1;
            }
            UpdateResult::Upgraded {
                old_reference,
                new_reference,
                skipped_candidates,
            } => {
                eprintln!("\x1b[1mUpgraded:\x1b[0m {old_reference} \u{2192} {new_reference}");
                warn_skipped_candidates(&old_reference, &skipped_candidates);

                // Read config file content before updating
                let config_before =
                    std::fs::read_to_string(&tracked.source_file).unwrap_or_default();

                match update_config_file(&tracked.source_file, &old_reference, &new_reference) {
                    Ok(()) => {
                        let config_after =
                            std::fs::read_to_string(&tracked.source_file).unwrap_or_default();
                        let config_path = tracked.source_file.display();
                        print_diff(
                            &format!("a/{config_path}"),
                            &format!("b/{config_path}"),
                            &config_before,
                            &config_after,
                        );
                        upgraded_count += 1;
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
        // Deduplicate by (reference, source_file) pair. The same reference
        // in different config files must be tracked separately so that all
        // files are updated on upgrade.
        let key = format!("{}:{}", r, path.display());
        if seen.insert(key) {
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
    use crate::config::git_client::RefKind;
    use crate::config::git_client::mock::MockGitClient;
    use indoc::{formatdoc, indoc};
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

    /// Expected outcome of `update_single_preset`.
    #[derive(Debug, PartialEq, Eq)]
    enum Expected {
        /// Upgraded to a new version reference.
        Upgraded(&'static str),
        /// Content re-fetched but unchanged (or no upgrade available, fell through to re-fetch).
        UpToDate,
        /// Immutable reference, skipped entirely.
        Skipped,
    }

    const T: RefKind = RefKind::Tag;
    const B: RefKind = RefKind::Branch;

    /// Build a `Vec<RemoteRef>` from `(name, kind)` pairs.
    fn refs(pairs: &[(&str, RefKind)]) -> Vec<RemoteRef> {
        pairs
            .iter()
            .map(|(name, kind)| RemoteRef {
                name: name.to_string(),
                kind: *kind,
            })
            .collect()
    }

    /// Run `update_single_preset` with the given scenario.
    ///
    /// - Sets up old cache with preset content.
    /// - If `expected` is `Upgraded(new_ref)`, pre-creates the upgrade target cache with
    ///   different content so the diff is non-empty.
    /// - Mocks `ls_remote_refs` with `remote_refs`.
    /// - Mocks fetch/checkout/rev_parse for the force_refetch fallback path
    ///   and for the per-candidate inspection fetches in the upgrade path.
    /// - Mocks `show_file` to return a permissive preset (no
    ///   `required_runok_version`) for every candidate, simulating the case
    ///   where every tag passes the version check.
    fn run_update_scenario(
        tmp: &TempDir,
        reference: &str,
        remote_refs: Vec<RemoteRef>,
        expected: &Expected,
    ) -> UpdateResult {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));

        let old_content = indoc! {"
            rules:
              - allow: 'git status'
        "};

        // Set up old cache (skip for commit SHA which has no prior cache)
        let is_sha = reference
            .split('@')
            .next_back()
            .is_some_and(|s| s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()));

        if !is_sha {
            let cache_dir = cache.cache_dir(reference);
            fs::create_dir_all(&cache_dir).unwrap();
            fs::write(cache_dir.join("runok.yml"), old_content).unwrap();

            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: false,
                reference: reference.to_string(),
                resolved_sha: Some("abc123".to_string()),
            };
            PresetCache::write_metadata(&cache_dir, &metadata).unwrap();
        }

        // If we expect an upgrade, pre-create the target cache with new content
        if let Expected::Upgraded(new_ref) = expected {
            let new_cache_dir = cache.cache_dir(new_ref);
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
        }

        let git_client = MockGitClient::new();

        if !remote_refs.is_empty() {
            git_client.on_ls_remote_refs(Ok(remote_refs));
        }

        // Per-candidate inspection fetches: queue a generous number of Ok
        // results so each `git fetch origin <tag>` the upgrade path issues
        // succeeds. The `force_refetch` fallback also needs one more.
        for _ in 0..32 {
            git_client.on_fetch(Ok(()));
        }
        if !is_sha {
            git_client.on_checkout(Ok(()));
            git_client.on_rev_parse(Ok("abc123".to_string()));
        }
        // Every candidate inspection tries `show_file("FETCH_HEAD", "runok.yml")`.
        // Queue a permissive preset so the compatibility check always passes.
        git_client.on_show_file(
            "FETCH_HEAD",
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        );

        let mut refs_cache = HashMap::new();
        update_single_preset(reference, &cache, &git_client, &mut refs_cache)
    }

    #[rstest]
    // -- commit SHA: always skipped --
    #[case::commit_sha_is_skipped(
        "github:org/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &[],
        Expected::Skipped,
    )]
    // -- branch name: re-fetched, content unchanged → UpToDate --
    #[case::branch_refetched(
        "github:org/repo@main",
        &[],
        Expected::UpToDate,
    )]
    // -- v1 branch with v2 branch available: upgraded --
    #[case::v1_branch_to_v2_branch(
        "github:org/repo@v1",
        &[("v1", B), ("v2", B)],
        Expected::Upgraded("github:org/repo@v2"),
    )]
    // -- v1 tag with v2 tag available: upgraded --
    #[case::v1_tag_to_v2_tag(
        "github:org/repo@v1",
        &[("v1.0.0", T), ("v2.0.0", T)],
        Expected::Upgraded("github:org/repo@v2"),
    )]
    // -- v1 with both v2 branch and v2.x tags: upgraded to v2 --
    #[case::v1_mixed_branches_and_tags(
        "github:org/repo@v1",
        &[("v1", B), ("v1.0.0", T), ("v2", B), ("v2.0.0", T)],
        Expected::Upgraded("github:org/repo@v2"),
    )]
    // -- v1 with no v2 available: no upgrade, re-fetched --
    #[case::v1_no_newer_major(
        "github:org/repo@v1",
        &[("v1", B), ("v1.0.0", T), ("v1.1.0", T)],
        Expected::UpToDate,
    )]
    // -- full semver v1.0.0 with v1.0.1 and v1.2.0: picks v1.2.0 (latest within major) --
    #[case::full_semver_picks_latest_minor(
        "github:org/repo@v1.0.0",
        &[("v1.0.0", T), ("v1.0.1", T), ("v1.2.0", T)],
        Expected::Upgraded("github:org/repo@v1.2.0"),
    )]
    // -- full semver v1.0.0 with v2.0.0 only: no upgrade (major boundary) --
    #[case::full_semver_respects_major_boundary(
        "github:org/repo@v1.0.0",
        &[("v1.0.0", T), ("v2.0.0", T)],
        Expected::UpToDate,
    )]
    // -- full semver v1.0.0 with v1.0.1 available: patch upgrade --
    #[case::full_semver_patch_upgrade(
        "github:org/repo@v1.0.0",
        &[("v1.0.0", T), ("v1.0.1", T)],
        Expected::Upgraded("github:org/repo@v1.0.1"),
    )]
    // -- full semver at latest: no upgrade --
    #[case::full_semver_already_latest(
        "github:org/repo@v1.2.0",
        &[("v1.0.0", T), ("v1.1.0", T), ("v1.2.0", T)],
        Expected::UpToDate,
    )]
    // -- major.minor v1.0 with v1.3 available: upgraded --
    #[case::major_minor_upgrade(
        "github:org/repo@v1.0",
        &[("v1.0.0", T), ("v1.1.0", T), ("v1.3.0", T)],
        Expected::Upgraded("github:org/repo@v1.3"),
    )]
    // -- major.minor v1.2 at latest: no upgrade --
    #[case::major_minor_already_latest(
        "github:org/repo@v1.2",
        &[("v1.0.0", T), ("v1.1.0", T), ("v1.2.0", T)],
        Expected::UpToDate,
    )]
    // -- major.minor respects major boundary --
    #[case::major_minor_respects_major_boundary(
        "github:org/repo@v1.0",
        &[("v1.0.0", T), ("v2.0.0", T)],
        Expected::UpToDate,
    )]
    // -- pre-release tags are excluded from upgrades --
    #[case::pre_release_excluded(
        "github:org/repo@v1.0.0",
        &[("v1.0.0", T), ("v1.1.0-beta.1", T)],
        Expected::UpToDate,
    )]
    // -- v-prefix mismatch: v-prefixed ref ignores non-prefixed tags --
    #[case::v_prefix_mismatch(
        "github:org/repo@v1.0.0",
        &[("1.1.0", T), ("v1.1.0", T)],
        Expected::Upgraded("github:org/repo@v1.1.0"),
    )]
    fn update_single_preset_scenarios(
        tmp: TempDir,
        #[case] reference: &str,
        #[case] remote_refs: &[(&str, RefKind)],
        #[case] expected: Expected,
    ) {
        let result = run_update_scenario(&tmp, reference, refs(remote_refs), &expected);
        match &expected {
            Expected::Upgraded(new_ref) => match result {
                UpdateResult::Upgraded {
                    old_reference,
                    new_reference,
                    ..
                } => {
                    assert_eq!(old_reference, reference);
                    assert_eq!(new_reference, *new_ref);
                }
                other => panic!("expected Upgraded to {new_ref}, got {other:?}"),
            },
            Expected::UpToDate => {
                assert!(
                    matches!(result, UpdateResult::UpToDate { .. }),
                    "expected UpToDate, got {result:?}"
                );
            }
            Expected::Skipped => {
                assert!(
                    matches!(result, UpdateResult::Skipped),
                    "expected Skipped, got {result:?}"
                );
            }
        }
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

        let mut refs_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut refs_cache);
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

    // === required_runok_version fallback ===

    use crate::config::VersionOverrideGuard;
    use semver::Version;

    /// Set up a cache entry for a specific reference with the given preset body.
    /// Mirrors `run_update_scenario` setup but allows each cache dir to hold
    /// distinct content, which is what candidate-fallback tests need.
    fn seed_cache_entry(cache: &PresetCache, reference: &str, body: &str) {
        let cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("runok.yml"), body).unwrap();
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference.to_string(),
            resolved_sha: Some("abc123".to_string()),
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();
    }

    /// Shared preset body used by the candidate-fallback scenarios.
    fn preset_body(required: &str) -> String {
        formatdoc! {"
            required_runok_version: '{required}'
            rules:
              - allow: 'echo *'
        "}
    }

    /// Queue enough `fetch`/`clone`/`checkout`/`rev_parse` outcomes that the
    /// upgrade path can repeatedly probe candidate tags and still materialize
    /// the adopted one afterwards. Tests that exercise the candidate fallback
    /// do not care about the exact call count — only that each subsequent
    /// call has a success available.
    fn stub_upgrade_mocks(mock: &MockGitClient, ok_count: usize) {
        for _ in 0..ok_count {
            mock.on_fetch(Ok(()));
            mock.on_clone(Ok(()));
            mock.on_checkout(Ok(()));
            mock.on_rev_parse(Ok("abc123".to_string()));
        }
    }

    #[rstest]
    fn try_tag_upgrade_adopts_newest_compatible_candidate(tmp: TempDir) {
        // Pretend the runok binary is exactly 0.2.0 so that upper-bounded
        // requirements like `">=0.3, <0.4"` genuinely reject candidates.
        let _guard = VersionOverrideGuard::set(Version::new(0, 2, 0));

        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));

        let reference = "github:org/repo@v1.0.0";
        seed_cache_entry(&cache, reference, "rules: []");

        let git_client = MockGitClient::new();
        git_client.on_ls_remote_refs(Ok(refs(&[
            ("v1.0.0", T),
            ("v1.1.0", T),
            ("v1.2.0", T),
            ("v1.3.0", T),
        ])));
        // Candidate order is newest first: v1.3.0 is inspected first and is
        // compatible, so it is adopted immediately.
        git_client.push_show_file("FETCH_HEAD", "runok.yml", &preset_body(">=0.2, <0.3"));
        stub_upgrade_mocks(&git_client, 4);

        let mut refs_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut refs_cache);
        match result {
            UpdateResult::Upgraded { new_reference, .. } => {
                assert_eq!(new_reference, "github:org/repo@v1.3.0");
            }
            other => panic!("expected Upgraded to v1.3.0, got {other:?}"),
        }
    }

    #[rstest]
    fn try_tag_upgrade_skips_incompatible_newest_and_picks_older(tmp: TempDir) {
        // Current runok simulated as 0.2.0. v1.2.0 requires runok 0.3+ and
        // is skipped; v1.1.0 is compatible and adopted.
        let _guard = VersionOverrideGuard::set(Version::new(0, 2, 0));

        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));

        let reference = "github:org/repo@v1.0.0";
        seed_cache_entry(&cache, reference, "rules: []");

        let git_client = MockGitClient::new();
        git_client.on_ls_remote_refs(Ok(refs(&[("v1.0.0", T), ("v1.1.0", T), ("v1.2.0", T)])));
        // First inspection = v1.2.0 (Unsupported), second = v1.1.0 (Compatible).
        git_client.push_show_file("FETCH_HEAD", "runok.yml", &preset_body(">=0.3.0"));
        git_client.push_show_file("FETCH_HEAD", "runok.yml", &preset_body(">=0.2.0"));
        stub_upgrade_mocks(&git_client, 4);

        let mut refs_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut refs_cache);
        match result {
            UpdateResult::Upgraded {
                new_reference,
                skipped_candidates,
                ..
            } => {
                assert_eq!(new_reference, "github:org/repo@v1.1.0");
                // The skipped newer candidate should be reported so that
                // `update-presets` can warn about it.
                assert_eq!(skipped_candidates.len(), 1);
                assert_eq!(skipped_candidates[0].tag, "v1.2.0");
            }
            other => panic!("expected Upgraded to v1.1.0, got {other:?}"),
        }
    }

    #[rstest]
    fn try_tag_upgrade_reports_up_to_date_when_all_candidates_incompatible(tmp: TempDir) {
        // Every newer tag requires runok 0.3+ but the simulated current is 0.2.0,
        // so try_tag_upgrade yields UpToDate and update_single_preset then
        // falls through to force_refetch (requires fetch/checkout/rev_parse mocks).
        let _guard = VersionOverrideGuard::set(Version::new(0, 2, 0));

        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));

        let reference = "github:org/repo@v1.0.0";
        seed_cache_entry(&cache, reference, "rules: []");

        let git_client = MockGitClient::new();
        git_client.on_ls_remote_refs(Ok(refs(&[("v1.0.0", T), ("v1.1.0", T), ("v1.2.0", T)])));
        // Both candidates are incompatible.
        git_client.push_show_file("FETCH_HEAD", "runok.yml", &preset_body(">=0.3.0"));
        git_client.push_show_file("FETCH_HEAD", "runok.yml", &preset_body(">=0.3.0"));
        stub_upgrade_mocks(&git_client, 4);

        let mut refs_cache = HashMap::new();
        let result = update_single_preset(reference, &cache, &git_client, &mut refs_cache);
        match result {
            UpdateResult::UpToDate { skipped_candidates } => {
                // Both candidates should be reported as skipped so the manual
                // update-presets command can warn about them.
                assert_eq!(skipped_candidates.len(), 2);
            }
            other => panic!("expected UpToDate, got {other:?}"),
        }
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
    fn collect_references_allows_same_ref_from_different_dirs(tmp: TempDir) {
        let dir_a = tmp.path().join("a");
        let dir_b = tmp.path().join("b");
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();

        let content = indoc! {"
            extends:
              - github:org/repo@v1
        "};
        fs::write(dir_a.join("runok.yml"), content).unwrap();
        fs::write(dir_b.join("runok.yml"), content).unwrap();

        let mut tracked = Vec::new();
        let mut seen = std::collections::HashSet::new();
        collect_tracked_from_dir(&dir_a, &["runok.yml"], &mut tracked, &mut seen);
        collect_tracked_from_dir(&dir_b, &["runok.yml"], &mut tracked, &mut seen);

        // Same reference from different files should both be tracked
        assert_eq!(tracked.len(), 2);
        assert_eq!(tracked[0].source_file, dir_a.join("runok.yml"));
        assert_eq!(tracked[1].source_file, dir_b.join("runok.yml"));
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

    // === run_with ===

    /// Set up cache for a reference with a given SHA in metadata.
    fn setup_cache_with_sha(cache: &PresetCache, reference: &str, sha: &str) {
        let cache_dir = cache.cache_dir(reference);
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("runok.yml"), "rules: []").unwrap();
        let metadata = CacheMetadata {
            fetched_at: current_timestamp(),
            is_immutable: false,
            reference: reference.to_string(),
            resolved_sha: Some(sha.to_string()),
        };
        PresetCache::write_metadata(&cache_dir, &metadata).unwrap();
    }

    /// Expected outcome for `run_with` scenario tests.
    #[derive(Debug)]
    enum RunWithExpected {
        /// Config file should be updated to contain `new_content`.
        ConfigUpdated(&'static str),
        /// Config file should remain unchanged.
        ConfigUnchanged,
        /// `run_with` should return an error.
        Error,
    }

    /// Scenario definition for `run_with` tests.
    struct RunWithScenario {
        /// Initial config file content.
        config_content: &'static str,
        /// References to track (reference string, same config file).
        references: Vec<&'static str>,
        /// Cache entries to pre-create: (reference, sha).
        cache_entries: Vec<(&'static str, &'static str)>,
        /// Remote refs for ls-remote mock.
        remote_refs: Vec<(&'static str, RefKind)>,
        /// Mock results for fetch calls (Ok or Err).
        fetch_results: Vec<Result<(), crate::config::PresetError>>,
        /// Mock results for checkout calls.
        checkout_results: Vec<Result<(), crate::config::PresetError>>,
        /// Mock results for rev-parse calls.
        rev_parse_results: Vec<Result<String, crate::config::PresetError>>,
    }

    /// Run a `run_with` scenario and return (result, final config content).
    fn run_run_with_scenario(
        tmp: &TempDir,
        scenario: RunWithScenario,
    ) -> (Result<(), anyhow::Error>, String) {
        let config_path = tmp.path().join("runok.yml");
        fs::write(&config_path, scenario.config_content).unwrap();

        let cache = PresetCache::with_config(tmp.path().join("cache"), Duration::from_secs(3600));

        for (reference, sha) in &scenario.cache_entries {
            setup_cache_with_sha(&cache, reference, sha);
        }

        let git_client = MockGitClient::new();

        if !scenario.remote_refs.is_empty() {
            git_client.on_ls_remote_refs(Ok(refs(&scenario.remote_refs)));
        }

        for r in scenario.fetch_results {
            git_client.on_fetch(r);
        }
        for r in scenario.checkout_results {
            git_client.on_checkout(r);
        }
        for r in scenario.rev_parse_results {
            git_client.on_rev_parse(r);
        }

        // Queue permissive padding for the level-A upgrade path: each
        // candidate tag issues an additional fetch + show_file inspection
        // before materializing. Scenarios that expect upgrades don't bother
        // listing these explicitly, so provide a generous buffer of
        // successful outcomes that will simply be unused by scenarios that
        // don't reach the upgrade path.
        for _ in 0..8 {
            git_client.on_fetch(Ok(()));
            git_client.on_clone(Ok(()));
            git_client.on_checkout(Ok(()));
            git_client.on_rev_parse(Ok("abc123".to_string()));
        }
        git_client.on_show_file(
            "FETCH_HEAD",
            "runok.yml",
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        );

        let tracked: Vec<TrackedReference> = scenario
            .references
            .iter()
            .map(|r| TrackedReference {
                reference: r.to_string(),
                source_file: config_path.clone(),
            })
            .collect();

        let result = run_with(tracked, &cache, &git_client);
        let final_content = fs::read_to_string(&config_path).unwrap();
        (result, final_content)
    }

    #[rstest]
    // -- Upgraded: config file is rewritten with new version --
    #[case::upgraded_updates_config(
        RunWithScenario {
            config_content: indoc! {"
                extends:
                  - github:org/repo@v1.0.0
                rules:
                  - allow: 'git status'
            "},
            references: vec!["github:org/repo@v1.0.0"],
            cache_entries: vec![
                ("github:org/repo@v1.0.0", "aaa111"),
                ("github:org/repo@v1.2.0", "bbb222"),
            ],
            remote_refs: vec![("v1.0.0", T), ("v1.2.0", T)],
            fetch_results: vec![],
            checkout_results: vec![],
            rev_parse_results: vec![],
        },
        RunWithExpected::ConfigUpdated(indoc! {"
            extends:
              - github:org/repo@v1.2.0
            rules:
              - allow: 'git status'
        "}),
    )]
    // -- Updated (SHA changed): config file unchanged --
    #[case::updated_does_not_modify_config(
        RunWithScenario {
            config_content: indoc! {"
                extends:
                  - github:org/repo@main
                rules:
                  - allow: 'git status'
            "},
            references: vec!["github:org/repo@main"],
            cache_entries: vec![("github:org/repo@main", "abc123")],
            remote_refs: vec![],
            fetch_results: vec![Ok(())],
            checkout_results: vec![Ok(())],
            rev_parse_results: vec![Ok("def456".to_string())],
        },
        RunWithExpected::ConfigUnchanged,
    )]
    // -- UpToDate (same SHA): config file unchanged --
    #[case::up_to_date_does_not_modify_config(
        RunWithScenario {
            config_content: indoc! {"
                extends:
                  - github:org/repo@main
            "},
            references: vec!["github:org/repo@main"],
            cache_entries: vec![("github:org/repo@main", "abc123")],
            remote_refs: vec![],
            fetch_results: vec![Ok(())],
            checkout_results: vec![Ok(())],
            rev_parse_results: vec![Ok("abc123".to_string())],
        },
        RunWithExpected::ConfigUnchanged,
    )]
    // -- Skipped (commit SHA): config file unchanged --
    #[case::skipped_does_not_modify_config(
        RunWithScenario {
            config_content: indoc! {"
                extends:
                  - github:org/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            "},
            references: vec!["github:org/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            cache_entries: vec![],
            remote_refs: vec![],
            fetch_results: vec![],
            checkout_results: vec![],
            rev_parse_results: vec![],
        },
        RunWithExpected::ConfigUnchanged,
    )]
    // -- Error (fetch fails): returns Err --
    #[case::error_returns_err(
        RunWithScenario {
            config_content: indoc! {"
                extends:
                  - github:org/repo@main
            "},
            references: vec!["github:org/repo@main"],
            cache_entries: vec![("github:org/repo@main", "abc123")],
            remote_refs: vec![],
            fetch_results: vec![Err(crate::config::PresetError::GitClone {
                reference: "mock".to_string(),
                message: "network error".to_string(),
            })],
            checkout_results: vec![],
            rev_parse_results: vec![],
        },
        RunWithExpected::Error,
    )]
    // -- Mixed: one success + one error → returns Err --
    #[case::mixed_results_counts_errors(
        RunWithScenario {
            config_content: indoc! {"
                extends:
                  - github:org/repo@main
                  - github:org/other@develop
            "},
            references: vec!["github:org/repo@main", "github:org/other@develop"],
            cache_entries: vec![
                ("github:org/repo@main", "abc123"),
                ("github:org/other@develop", "xyz789"),
            ],
            remote_refs: vec![],
            fetch_results: vec![
                Ok(()),
                Err(crate::config::PresetError::GitClone {
                    reference: "mock".to_string(),
                    message: "timeout".to_string(),
                }),
            ],
            checkout_results: vec![Ok(())],
            rev_parse_results: vec![Ok("abc123".to_string())],
        },
        RunWithExpected::Error,
    )]
    fn run_with_scenarios(
        tmp: TempDir,
        #[case] scenario: RunWithScenario,
        #[case] expected: RunWithExpected,
    ) {
        let original_content = scenario.config_content;
        let (result, final_content) = run_run_with_scenario(&tmp, scenario);

        match expected {
            RunWithExpected::ConfigUpdated(new_content) => {
                assert!(result.is_ok(), "expected Ok, got {result:?}");
                assert_eq!(final_content, new_content);
            }
            RunWithExpected::ConfigUnchanged => {
                assert!(result.is_ok(), "expected Ok, got {result:?}");
                assert_eq!(final_content, original_content);
            }
            RunWithExpected::Error => {
                assert!(result.is_err(), "expected Err, got Ok");
            }
        }
    }

    impl std::fmt::Debug for UpdateResult {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                UpdateResult::Updated { .. } => write!(f, "Updated"),
                UpdateResult::UpToDate { .. } => write!(f, "UpToDate"),
                UpdateResult::Skipped => write!(f, "Skipped"),
                UpdateResult::Upgraded { .. } => write!(f, "Upgraded"),
                UpdateResult::Error(msg) => write!(f, "Error({msg})"),
            }
        }
    }
}
