use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::cache::{CacheMetadata, CacheStatus, PresetCache};
use super::git_client::GitClient;
use super::{Config, ConfigError, PresetError, parse_config};

/// Parsed preset reference indicating where to load a preset from.
#[derive(Debug, Clone, PartialEq)]
pub enum PresetReference {
    /// Local file path (relative, absolute, or `~/`-prefixed).
    Local(PathBuf),
    /// GitHub shorthand (`github:owner/repo[@version]`).
    GitHub {
        owner: String,
        repo: String,
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

    /// Whether this is a mutable reference that should trigger a warning.
    pub fn is_mutable(&self) -> bool {
        !self.is_immutable()
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

/// Parse `owner/repo[@version]` from a GitHub shorthand.
fn parse_github_shorthand(rest: &str) -> Result<PresetReference, PresetError> {
    let (path_part, version_part) = match rest.split_once('@') {
        Some((path, version)) => (path, Some(version)),
        None => (rest, None),
    };

    let (owner, repo) = path_part.split_once('/').ok_or_else(|| {
        PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: expected 'github:owner/repo', got 'github:{rest}'"
        ))
    })?;

    if owner.is_empty() || repo.is_empty() {
        return Err(PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: owner and repo must not be empty in 'github:{rest}'"
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
struct GitParams {
    url: String,
    git_ref: Option<String>,
    is_immutable: bool,
}

fn resolve_git_params(reference: &PresetReference) -> GitParams {
    match reference {
        PresetReference::GitHub {
            owner,
            repo,
            version,
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

/// Emit a warning to stderr if the reference is mutable.
fn emit_mutable_warning(reference: &PresetReference, original: &str) {
    let is_mutable = match reference {
        PresetReference::GitHub { version, .. } => version.is_mutable(),
        PresetReference::GitUrl { git_ref, .. } => {
            git_ref.as_deref().is_none_or(|r| !is_commit_sha(r))
        }
        PresetReference::Local(_) => false,
    };
    if is_mutable {
        eprintln!(
            "warning: Mutable preset reference '{original}'\n  \
             Consider pinning to a commit SHA for reproducibility"
        );
    }
}

/// Read `runok.yml` (or `runok.yaml`) from a directory and parse it as `Config`.
fn read_preset_from_dir(dir: &Path) -> Result<Config, ConfigError> {
    let yml = dir.join("runok.yml");
    let yaml = dir.join("runok.yaml");

    let path = if yml.exists() {
        yml
    } else if yaml.exists() {
        yaml
    } else {
        return Err(PresetError::GitClone {
            reference: dir.display().to_string(),
            message: "runok.yml not found in preset repository".to_string(),
        }
        .into());
    };

    let content = std::fs::read_to_string(&path)?;
    let config = parse_config(&content)?;
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
    emit_mutable_warning(reference, original_reference);

    let params = resolve_git_params(reference);
    let cache_dir = cache.cache_dir(original_reference);

    match cache.check(original_reference, params.is_immutable) {
        CacheStatus::Hit(dir) => read_preset_from_dir(&dir),
        CacheStatus::Stale(dir) => {
            handle_stale_cache(git_client, &dir, &params, original_reference)
        }
        CacheStatus::Miss => handle_cache_miss(git_client, &cache_dir, &params, original_reference),
    }
}

fn handle_stale_cache<G: GitClient>(
    git_client: &G,
    dir: &Path,
    params: &GitParams,
    original_reference: &str,
) -> Result<Config, ConfigError> {
    match git_client.fetch(dir, params.git_ref.as_deref()) {
        Ok(()) => {
            // Always checkout FETCH_HEAD after fetch to update the working tree.
            // `git fetch` updates remote tracking refs but not the working tree,
            // and `git checkout <branch>` is a no-op if already on that branch.
            // FETCH_HEAD always points to the just-fetched commit.
            let checkout_ref = "FETCH_HEAD";
            if let Err(e) = git_client.checkout(dir, checkout_ref) {
                eprintln!(
                    "warning: checkout failed for '{original_reference}': {e}, \
                     using cached version"
                );
                return read_preset_from_dir(dir);
            }

            // Update metadata only after successful fetch + checkout
            let resolved_sha = git_client.rev_parse_head(dir).ok();
            let metadata = CacheMetadata {
                fetched_at: current_timestamp(),
                is_immutable: params.is_immutable,
                reference: original_reference.to_string(),
                resolved_sha,
            };
            let _ = PresetCache::write_metadata(dir, &metadata);

            read_preset_from_dir(dir)
        }
        Err(_) => {
            // Fetch failed: use stale cache with a warning
            eprintln!(
                "warning: Failed to update preset '{original_reference}', using cached version"
            );
            read_preset_from_dir(dir)
        }
    }
}

fn handle_cache_miss<G: GitClient>(
    git_client: &G,
    cache_dir: &Path,
    params: &GitParams,
    original_reference: &str,
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

    read_preset_from_dir(cache_dir)
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
            version: GitHubVersion::Latest,
        }
    )]
    #[case::github_tag(
        "github:org/repo@v1.0.0",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
            version: GitHubVersion::Tag("v1.0.0".into()),
        }
    )]
    #[case::github_sha(
        "github:org/repo@abc1234def567890abc1234def567890abc12345",
        PresetReference::GitHub {
            owner: "org".into(),
            repo: "repo".into(),
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
            version: GitHubVersion::Tag("main".into()),
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

    // === GitHubVersion mutability ===

    #[rstest]
    #[case::sha_immutable(
        GitHubVersion::CommitSha("abc1234def567890abc1234def567890abc12345".into()),
        false
    )]
    #[case::tag_mutable(GitHubVersion::Tag("v1.0.0".into()), true)]
    #[case::latest_mutable(GitHubVersion::Latest, true)]
    fn version_mutability(#[case] version: GitHubVersion, #[case] expected_mutable: bool) {
        assert_eq!(version.is_mutable(), expected_mutable);
    }

    // === GitHub shorthand → git URL conversion ===

    #[rstest]
    #[case::basic("org", "repo", "https://github.com/org/repo.git")]
    #[case::with_dash("my-org", "my-repo", "https://github.com/my-org/my-repo.git")]
    fn github_to_url(#[case] owner: &str, #[case] repo: &str, #[case] expected: &str) {
        let reference = PresetReference::GitHub {
            owner: owner.to_string(),
            repo: repo.to_string(),
            version: GitHubVersion::Latest,
        };
        let params = resolve_git_params(&reference);
        assert_eq!(params.url, expected);
    }

    // === load_remote_preset tests ===

    #[fixture]
    fn tmp() -> TempDir {
        TempDir::new().unwrap()
    }

    fn write_runok_yml(dir: &Path, content: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("runok.yml"), content).unwrap();
    }

    #[rstest]
    fn clone_miss_calls_clone_with_branch(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        mock.on_clone(Ok(()));
        mock.on_rev_parse(Ok("abc123".to_string()));

        // Mock clone doesn't create files, so read_preset_from_dir will fail.
        // We verify clone was called with correct --branch.
        let _result = load_remote_preset(&parsed, reference_str, &mock, &cache);

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

        let config = read_preset_from_dir(tmp.path()).unwrap();
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

        let config = read_preset_from_dir(tmp.path()).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
    }

    #[rstest]
    fn cache_hit_skips_clone(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
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

        let config = load_remote_preset(&parsed, reference_str, &mock, &cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));

        // Verify no git calls were made
        assert!(mock.calls.borrow().is_empty());
    }

    #[rstest]
    fn stale_cache_fetch_success(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
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

        let config = load_remote_preset(&parsed, reference_str, &mock, &cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("cargo test"));
    }

    #[rstest]
    fn stale_cache_fetch_failure_uses_old_cache(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
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

        let config = load_remote_preset(&parsed, reference_str, &mock, &cache).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("old cached rule"));
    }

    #[rstest]
    fn clone_failure_no_cache_returns_error(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        mock.on_clone(Err(PresetError::GitClone {
            reference: reference_str.to_string(),
            message: "authentication failed".to_string(),
        }));

        let err = load_remote_preset(&parsed, reference_str, &mock, &cache).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::GitClone { reference, .. }) => {
                assert_eq!(reference, reference_str);
            }
            other => panic!("expected GitClone error, got: {other:?}"),
        }
    }

    #[rstest]
    fn commit_sha_triggers_fetch_and_checkout_after_clone(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
        let sha = "abc1234def567890abc1234def567890abc12345";
        let reference_str = &format!("github:org/repo@{sha}");
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        // clone (no --branch) → fetch SHA → checkout FETCH_HEAD → rev_parse
        mock.on_clone(Ok(()));
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok(sha.to_string()));

        let _result = load_remote_preset(&parsed, reference_str, &mock, &cache);

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
    fn git_url_commit_sha_fetches_then_checkouts(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
        let sha = "abc1234def567890abc1234def567890abc12345";
        let reference_str = &format!("https://github.com/org/repo.git@{sha}");
        let parsed = parse_preset_reference(reference_str).unwrap();

        let mock = MockGitClient::new();
        mock.on_clone(Ok(()));
        mock.on_fetch(Ok(()));
        mock.on_checkout(Ok(()));
        mock.on_rev_parse(Ok(sha.to_string()));

        let _result = load_remote_preset(&parsed, reference_str, &mock, &cache);

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
    fn stale_cache_latest_checkouts_fetch_head(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
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

        let config = load_remote_preset(&parsed, reference_str, &mock, &cache).unwrap();

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

    #[rstest]
    fn missing_runok_yml_returns_error(tmp: TempDir) {
        let cache = PresetCache::with_config(
            tmp.path().to_path_buf(),
            std::time::Duration::from_secs(3600),
        );
        let reference_str = "github:org/repo@v1.0.0";
        let parsed = parse_preset_reference(reference_str).unwrap();
        let cache_dir = cache.cache_dir(reference_str);

        let mock = MockGitClient::new();
        mock.on_clone(Ok(()));
        mock.on_rev_parse(Ok("abc123".to_string()));

        // Create cache dir but no runok.yml
        std::fs::create_dir_all(&cache_dir).unwrap();

        let err = load_remote_preset(&parsed, reference_str, &mock, &cache).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::GitClone { message, .. }) => {
                assert_eq!(message, "runok.yml not found in preset repository");
            }
            other => panic!("expected GitClone error, got: {other:?}"),
        }
    }
}
