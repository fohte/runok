use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::cache::{CacheMetadata, CacheStatus, PresetCache};
use super::git_client::GitClient;
use super::required_version::{check_required_runok_version, current_runok_version};
use super::{Config, ConfigError, ParsedConfig, PresetError, parse_config_with_warnings};

/// Parsed preset reference indicating where to load a preset from.
#[derive(Debug, Clone, PartialEq)]
pub enum PresetReference {
    /// Local file path (relative, absolute, or `~/`-prefixed).
    Local(PathBuf),
    /// GitHub shorthand (`github:owner/repo[/path][@version]`).
    GitHub {
        owner: String,
        repo: String,
        /// Optional path within the repository to a preset file (without extension).
        path: Option<String>,
        version: GitHubVersion,
    },
    /// Generic git URL (HTTPS or SSH), optionally with a ref.
    GitUrl {
        url: String,
        git_ref: Option<String>,
    },
}

/// Version specifier for GitHub shorthand references.
#[derive(Debug, Clone, PartialEq)]
pub enum GitHubVersion {
    /// Commit SHA (40-char hex) — immutable, cached permanently.
    CommitSha(String),
    /// Tag or branch name — cached with TTL.
    Tag(String),
    /// No version specified — uses default branch, cached with TTL.
    Latest,
}

impl GitHubVersion {
    /// Whether this is an immutable reference (only commit SHA).
    pub fn is_immutable(&self) -> bool {
        matches!(self, Self::CommitSha(_))
    }

    /// Convert to a git ref string for `--branch` or `checkout`.
    pub fn as_git_ref(&self) -> Option<&str> {
        match self {
            Self::CommitSha(s) | Self::Tag(s) => Some(s),
            Self::Latest => None,
        }
    }
}

/// Check if a string looks like a full commit SHA (40-char hex).
fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a preset reference string into a `PresetReference`.
///
/// Detection rules:
/// 1. `github:` prefix → `GitHub` shorthand
/// 2. `https://` prefix → `GitUrl` (HTTPS)
/// 3. `git@` prefix → `GitUrl` (SSH)
/// 4. Otherwise → `Local` path
pub fn parse_preset_reference(reference: &str) -> Result<PresetReference, PresetError> {
    if let Some(rest) = reference.strip_prefix("github:") {
        parse_github_shorthand(rest)
    } else if reference.starts_with("https://")
        || reference.starts_with("http://")
        || reference.starts_with("git@")
    {
        parse_git_url(reference)
    } else {
        Ok(PresetReference::Local(PathBuf::from(reference)))
    }
}

/// Parse `owner/repo[/path][@version]` from a GitHub shorthand.
///
/// The path portion starts after `owner/repo/` and extends until `@` or end of string.
/// GitHub repository names cannot contain `/`, so there is no ambiguity.
fn parse_github_shorthand(rest: &str) -> Result<PresetReference, PresetError> {
    let (path_part, version_part) = match rest.split_once('@') {
        Some((path, version)) => (path, Some(version)),
        None => (rest, None),
    };

    let (owner, after_owner) = path_part.split_once('/').ok_or_else(|| {
        PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: expected 'github:owner/repo', got 'github:{rest}'"
        ))
    })?;

    // Split repo from optional path: "repo/path/to/preset" → ("repo", Some("path/to/preset"))
    let (repo, preset_path) = match after_owner.split_once('/') {
        Some((repo, path)) => (repo, Some(path)),
        None => (after_owner, None),
    };

    if owner.is_empty() || repo.is_empty() {
        return Err(PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: owner and repo must not be empty in 'github:{rest}'"
        )));
    }

    // Validate path: must not be empty, must not contain traversal sequences or absolute paths
    if let Some(p) = preset_path
        && (p.is_empty()
            || p.starts_with('/')
            || p.split('/')
                .any(|seg| seg.is_empty() || seg == ".." || seg == "."))
    {
        return Err(PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: invalid path in 'github:{rest}'"
        )));
    }

    let version = match version_part {
        Some("") => {
            return Err(PresetError::InvalidReference(format!(
                "invalid GitHub shorthand: version must not be empty after '@' in 'github:{rest}'"
            )));
        }
        Some(v) if is_commit_sha(v) => GitHubVersion::CommitSha(v.to_string()),
        Some(v) => GitHubVersion::Tag(v.to_string()),
        None => GitHubVersion::Latest,
    };

    Ok(PresetReference::GitHub {
        owner: owner.to_string(),
        repo: repo.to_string(),
        path: preset_path.map(String::from),
        version,
    })
}

/// Parse a git URL with optional `@ref` suffix.
///
/// The ref separator is `@` after the `.git` extension or at the end.
/// Examples:
/// - `https://github.com/org/repo.git@v1.0` → url=..., ref=v1.0
/// - `git@github.com:org/repo.git@main` → url=..., ref=main
/// - `https://github.com/org/repo.git` → url=..., ref=None
fn parse_git_url(reference: &str) -> Result<PresetReference, PresetError> {
    // For SSH URLs (git@...), the `@` in `git@` is part of the URL itself.
    // We look for `@` after `.git` suffix as the ref separator.
    if let Some(idx) = reference.rfind(".git@") {
        let url = &reference[..idx + 4]; // include ".git"
        let git_ref = &reference[idx + 5..]; // after ".git@"
        if git_ref.is_empty() {
            return Err(PresetError::InvalidReference(format!(
                "invalid git URL: ref must not be empty after '@' in '{reference}'"
            )));
        }
        return Ok(PresetReference::GitUrl {
            url: url.to_string(),
            git_ref: Some(git_ref.to_string()),
        });
    }

    // No .git@ pattern found. Check for trailing @ref (only for URLs without .git suffix).
    // But for git@ SSH URLs, the first @ is part of the URL, so we need to be careful.
    if reference.starts_with("git@") {
        // SSH URL without .git suffix: look for @ after the colon (host:path@ref).
        // The first @ is part of "git@", so we find the colon first, then look for
        // @ in the path portion.
        if let Some(colon_idx) = reference.find(':') {
            let path_part = &reference[colon_idx + 1..];
            if let Some(at_idx) = path_part.rfind('@') {
                let ref_str = &path_part[at_idx + 1..];
                if !ref_str.is_empty() {
                    let url = &reference[..colon_idx + 1 + at_idx];
                    return Ok(PresetReference::GitUrl {
                        url: url.to_string(),
                        git_ref: Some(ref_str.to_string()),
                    });
                }
            }
        }
        Ok(PresetReference::GitUrl {
            url: reference.to_string(),
            git_ref: None,
        })
    } else {
        // HTTPS URL: check for trailing @ref after the path portion.
        // We must not split on the `@` in userinfo (e.g., `https://user@host/...`).
        // Strategy: find the path start (after `://host`) and only look for `@` there.
        let ref_split_start = reference
            .find("://")
            .map(|scheme_end| {
                // Skip past `://host` to the first `/` of the path
                reference[scheme_end + 3..]
                    .find('/')
                    .map(|slash| scheme_end + 3 + slash)
                    .unwrap_or(reference.len())
            })
            .unwrap_or(0);

        if let Some(at_offset) = reference[ref_split_start..].rfind('@') {
            let idx = ref_split_start + at_offset;
            let url = &reference[..idx];
            let git_ref = &reference[idx + 1..];
            if !git_ref.is_empty() && !url.is_empty() {
                return Ok(PresetReference::GitUrl {
                    url: url.to_string(),
                    git_ref: Some(git_ref.to_string()),
                });
            }
        }
        Ok(PresetReference::GitUrl {
            url: reference.to_string(),
            git_ref: None,
        })
    }
}

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
    if !visited.insert(rel_path.to_string()) {
        // Already inspected (cycle or shared dependency). Do not re-check.
        return Ok(());
    }

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
        let rel_str = local_path.to_string_lossy().to_string();
        if rel_str.starts_with('/') || rel_str.starts_with("~/") {
            continue;
        }

        let joined = parent_dir.join(&local_path);
        let Some(normalized) = normalize_repo_relative(&joined) else {
            continue;
        };

        // Try both extensions if the reference does not already include one.
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
                    // keep trying the other extension
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

    // === parse_preset_reference tests ===

    #[rstest]
    #[case::github_latest(
        "github:org/repo",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::Latest,
        }
    )]
    #[case::github_tag(
        "github:org/repo@v1.0.0",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::Tag("v1.0.0".into()),
        }
    )]
    #[case::github_sha(
        "github:org/repo@abc1234def567890abc1234def567890abc12345",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::CommitSha(
                "abc1234def567890abc1234def567890abc12345".into()
            ),
        }
    )]
    #[case::github_branch_name(
        "github:org/repo@main",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: None,
            version: GitHubVersion::Tag("main".into()),
        }
    )]
    #[case::github_with_path(
        "github:org/repo/presets/readonly",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: Some("presets/readonly".into()),
            version: GitHubVersion::Latest,
        }
    )]
    #[case::github_with_path_and_tag(
        "github:fohte/runok-presets/readonly-unix@v1",
        PresetReference::GitHub {
            owner: "fohte".into(),
            repo: "runok-presets".into(),
            path: Some("readonly-unix".into()),
            version: GitHubVersion::Tag("v1".into()),
        }
    )]
    #[case::github_with_nested_path_and_sha(
        "github:org/repo/path/to/preset@abc1234def567890abc1234def567890abc12345",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            path: Some("path/to/preset".into()),
            version: GitHubVersion::CommitSha(
                "abc1234def567890abc1234def567890abc12345".into()
            ),
        }
    )]
    #[case::https_url_no_ref(
        "https://github.com/org/repo.git",
        PresetReference::GitUrl {
            url: "https://github.com/org/repo.git".into(),
            git_ref: None,
        }
    )]
    #[case::https_url_with_ref(
        "https://github.com/org/repo.git@v1.0",
        PresetReference::GitUrl {
            url: "https://github.com/org/repo.git".into(),
            git_ref: Some("v1.0".into()),
        }
    )]
    #[case::ssh_url_no_ref(
        "git@github.com:org/repo.git",
        PresetReference::GitUrl {
            url: "git@github.com:org/repo.git".into(),
            git_ref: None,
        }
    )]
    #[case::ssh_url_with_ref(
        "git@github.com:org/repo.git@main",
        PresetReference::GitUrl {
            url: "git@github.com:org/repo.git".into(),
            git_ref: Some("main".into()),
        }
    )]
    #[case::ssh_url_no_git_suffix_with_ref(
        "git@github.com:org/repo@v2.0",
        PresetReference::GitUrl {
            url: "git@github.com:org/repo".into(),
            git_ref: Some("v2.0".into()),
        }
    )]
    #[case::https_url_with_userinfo(
        "https://user@github.com/org/repo.git",
        PresetReference::GitUrl {
            url: "https://user@github.com/org/repo.git".into(),
            git_ref: None,
        }
    )]
    #[case::https_url_with_userinfo_and_ref(
        "https://user@github.com/org/repo.git@v1.0",
        PresetReference::GitUrl {
            url: "https://user@github.com/org/repo.git".into(),
            git_ref: Some("v1.0".into()),
        }
    )]
    #[case::local_relative(
        "./rules/preset.yml",
        PresetReference::Local(PathBuf::from("./rules/preset.yml"))
    )]
    #[case::local_absolute(
        "/etc/runok/global.yml",
        PresetReference::Local(PathBuf::from("/etc/runok/global.yml"))
    )]
    #[case::local_home(
        "~/presets/base.yml",
        PresetReference::Local(PathBuf::from("~/presets/base.yml"))
    )]
    fn parse_reference(#[case] input: &str, #[case] expected: PresetReference) {
        let result = parse_preset_reference(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::no_slash("github:invalid", "invalid GitHub shorthand")]
    #[case::empty_owner("github:/repo", "owner and repo must not be empty")]
    #[case::empty_repo("github:org/", "owner and repo must not be empty")]
    #[case::empty_version("github:org/repo@", "version must not be empty")]
    #[case::empty_path_with_version("github:org/repo/@v1", "invalid path")]
    #[case::path_traversal("github:org/repo/../../etc/passwd@v1", "invalid path")]
    #[case::path_traversal_no_ref("github:org/repo/../secret", "invalid path")]
    #[case::absolute_path("github:org/repo//etc/passwd@v1", "invalid path")]
    #[case::dot_segment("github:org/repo/./foo@v1", "invalid path")]
    #[case::trailing_slash("github:org/repo/foo/bar/@v1", "invalid path")]
    fn parse_reference_errors(#[case] input: &str, #[case] expected_msg: &str) {
        let err = parse_preset_reference(input).unwrap_err();
        assert!(
            err.to_string().contains(expected_msg),
            "expected error containing '{expected_msg}', got: {err}"
        );
    }

    // === is_commit_sha tests ===

    #[rstest]
    #[case::valid_sha("abc1234def567890abc1234def567890abc12345", true)]
    #[case::all_digits("1234567890123456789012345678901234567890", true)]
    #[case::too_short("abc123", false)]
    #[case::too_long("abc1234def567890abc1234def567890abc123456", false)]
    #[case::non_hex("xyz1234def567890abc1234def567890abc12345", false)]
    #[case::tag("v1.0.0", false)]
    #[case::empty("", false)]
    fn commit_sha_detection(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_commit_sha(input), expected);
    }

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
