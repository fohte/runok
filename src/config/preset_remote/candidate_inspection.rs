use std::path::Path;

use crate::config::git_client::GitClient;
use crate::config::required_version::{check_required_runok_version, current_runok_version};
use crate::config::{ConfigError, parse_config_with_warnings};

use super::reference::{PresetReference, parse_preset_reference};

/// Outcome of inspecting a candidate revision for `required_runok_version`.
///
/// Exposed at crate level so that both the automatic stale-refresh path
/// (`handle_stale_cache`) and the manual `update-presets` path can share the
/// same level-A inspection logic.
pub enum CandidateInspection {
    /// The candidate revision and every same-repo `extends` child satisfy the
    /// current runok version.
    Compatible,
    /// At least one file under the candidate revision declares a
    /// `required_runok_version` that the current runok build does not meet.
    /// The `source_label` identifies the first offending file.
    Incompatible {
        source_label: String,
        requirement: String,
        current: String,
    },
    /// The candidate revision could not be inspected (missing file, parse
    /// error, unrelated git error). Caller should treat it as "unknown" and
    /// fall back to the old working tree.
    InspectionFailed,
}

/// Inspect the given `git_ref` in `dir` by reading `preset_path` via
/// `git show` and checking its `required_runok_version`. Recurses into
/// `extends` entries that point to files in the same repository, so every
/// transitively referenced file is validated without touching the working
/// tree. Remote (cross-repository) `extends` entries are skipped: they live
/// in their own cache and are validated separately when loaded.
/// Inspect the given `git_ref` in an already-cloned repository by reading
/// files via `git show`. Returns whether the referenced preset (and every
/// same-repo child it `extends`) satisfies the current runok version.
///
/// The working tree of `dir` is not touched at any point, so this can be run
/// safely in parallel with other runok processes that are reading the same
/// cache (level A).
pub fn inspect_candidate_required_versions<G: GitClient>(
    git_client: &G,
    dir: &Path,
    git_ref: &str,
    preset_path: Option<&str>,
) -> CandidateInspection {
    let Some((root_rel, root_content)) = candidate_root_file(git_client, dir, git_ref, preset_path)
    else {
        return CandidateInspection::InspectionFailed;
    };

    let current = current_runok_version();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    visited.insert(root_rel.clone());

    match inspect_candidate_content(
        git_client,
        dir,
        git_ref,
        &root_rel,
        &root_content,
        &current,
        &mut visited,
    ) {
        Ok(()) => CandidateInspection::Compatible,
        Err(CandidateInspectionError::Unsupported {
            source_label,
            requirement,
            current,
        }) => CandidateInspection::Incompatible {
            source_label,
            requirement,
            current,
        },
        Err(CandidateInspectionError::Other) => CandidateInspection::InspectionFailed,
    }
}

/// Internal error kind for `inspect_candidate_recursive`.
enum CandidateInspectionError {
    /// A file declared a `required_runok_version` that current runok does not
    /// satisfy. Carries the details of the first offending file so that the
    /// caller can surface them in a warning.
    Unsupported {
        source_label: String,
        requirement: String,
        current: String,
    },
    /// Parse error, missing file, git error, etc. Treated as "unknown" at the
    /// top level.
    Other,
}

/// Determine the preset file path (relative to the repo root) to inspect and
/// return its contents. The caller may have been loading `runok.yml` or
/// `runok.yaml`, or a preset under a subpath with either extension. We probe
/// the candidate revision in a fixed order so that a preset that changes
/// extensions across versions still works.
///
/// Returns `(relative_path, file_content)`. Keeping the content lets the
/// recursive inspector avoid a second `git show` call for the same file,
/// which matters when mocks are stateful.
fn candidate_root_file<G: GitClient>(
    git_client: &G,
    dir: &Path,
    git_ref: &str,
    preset_path: Option<&str>,
) -> Option<(String, String)> {
    let candidates: Vec<String> = match preset_path {
        Some(p) => vec![format!("{p}.yml"), format!("{p}.yaml")],
        None => vec!["runok.yml".to_string(), "runok.yaml".to_string()],
    };

    for candidate in candidates {
        if let Ok(content) = git_client.show_file(dir, git_ref, &candidate) {
            return Some((candidate, content));
        }
    }
    None
}

fn inspect_candidate_recursive<G: GitClient>(
    git_client: &G,
    dir: &Path,
    git_ref: &str,
    rel_path: &str,
    current: &semver::Version,
    visited: &mut std::collections::HashSet<String>,
) -> Result<(), CandidateInspectionError> {
    if visited.contains(rel_path) {
        // Already inspected (cycle or shared dependency). Do not re-check.
        return Ok(());
    }
    visited.insert(rel_path.to_string());

    let content = git_client
        .show_file(dir, git_ref, rel_path)
        .map_err(|_| CandidateInspectionError::Other)?;

    inspect_candidate_content(
        git_client, dir, git_ref, rel_path, &content, current, visited,
    )
}

/// Like `inspect_candidate_recursive`, but accepts the pre-fetched file
/// content so the caller can avoid an extra `git show` when the root file
/// has already been read (e.g. by `candidate_root_file`).
fn inspect_candidate_content<G: GitClient>(
    git_client: &G,
    dir: &Path,
    git_ref: &str,
    rel_path: &str,
    content: &str,
    current: &semver::Version,
    visited: &mut std::collections::HashSet<String>,
) -> Result<(), CandidateInspectionError> {
    let parsed =
        parse_config_with_warnings(content).map_err(|_| CandidateInspectionError::Other)?;
    let config = parsed.config;

    // Per-file version check. The source label includes the candidate git ref
    // so that, if this ever bubbled up to the user, they could identify the
    // exact offending revision. In automatic refresh the error is silenced
    // before it reaches the user.
    let source_label = format!("{git_ref}:{rel_path}");
    match check_required_runok_version(
        config.required_runok_version.as_deref(),
        current,
        &source_label,
    ) {
        Ok(()) => {}
        Err(ConfigError::UnsupportedRunokVersion {
            source_label,
            requirement,
            current,
        }) => {
            return Err(CandidateInspectionError::Unsupported {
                source_label,
                requirement,
                current,
            });
        }
        Err(_) => return Err(CandidateInspectionError::Other),
    }

    // Recurse into local (same-repo) extends. Remote extends live in their
    // own cache and will be validated independently when they are loaded, so
    // skip them here. Path-based extends are resolved relative to the parent
    // directory of the file that contains the `extends` entry.
    let Some(extends) = config.extends.as_ref() else {
        return Ok(());
    };

    let parent_dir = Path::new(rel_path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();

    for reference in extends {
        let parsed_ref = match parse_preset_reference(reference) {
            Ok(p) => p,
            Err(_) => continue, // ignore unparseable entries, not our problem
        };
        let PresetReference::Local(local_path) = parsed_ref else {
            // Cross-repository reference: validated via its own cache.
            continue;
        };

        // Only plain repo-relative paths are reachable via `git show`. Absolute
        // paths and `~/`-prefixed paths are not in the repository at all, so
        // skip them. Same for paths that walk out of the repo with `..`.
        let rel_str = local_path.to_string_lossy();
        if rel_str.starts_with('/') || rel_str.starts_with("~/") {
            continue;
        }

        let joined = parent_dir.join(&local_path);
        let Some(normalized) = normalize_repo_relative(&joined) else {
            continue;
        };

        let has_extension = Path::new(&normalized)
            .extension()
            .is_some_and(|e| e == "yml" || e == "yaml");
        let paths_to_try: Vec<String> = if has_extension {
            vec![normalized]
        } else {
            vec![format!("{normalized}.yml"), format!("{normalized}.yaml")]
        };

        let mut any_exists = false;
        let mut unsupported_err: Option<CandidateInspectionError> = None;
        let mut last_other = false;
        for candidate in &paths_to_try {
            match inspect_candidate_recursive(git_client, dir, git_ref, candidate, current, visited)
            {
                Ok(()) => {
                    any_exists = true;
                    unsupported_err = None;
                    last_other = false;
                    break;
                }
                Err(e @ CandidateInspectionError::Unsupported { .. }) => {
                    any_exists = true;
                    unsupported_err = Some(e);
                    break;
                }
                Err(CandidateInspectionError::Other) => {
                    last_other = true;
                }
            }
        }

        if let Some(err) = unsupported_err {
            return Err(err);
        }
        if !any_exists && last_other {
            return Err(CandidateInspectionError::Other);
        }
    }

    Ok(())
}

/// Logically normalize a path (resolving `.` / `..`) relative to the repo
/// root. Returns `None` if the path walks out of the repository (e.g. starts
/// with `..`), which would escape the cached clone and cannot be inspected
/// via `git show`.
fn normalize_repo_relative(path: &Path) -> Option<String> {
    use std::path::Component;
    let mut stack: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                stack.pop()?;
            }
            Component::Normal(c) => {
                stack.push(c.to_string_lossy().to_string());
            }
            Component::RootDir | Component::Prefix(_) => {
                // Absolute path: not a repo-relative reference.
                return None;
            }
        }
    }
    Some(stack.join("/"))
}
