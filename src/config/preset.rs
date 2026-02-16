use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use super::{Config, ConfigError, PresetError, parse_config};

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
    // Will be used for circular reference detection (planned for a future task).
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

// ── Remote preset types and functions ──

/// Parsed form of a `github:org/repo@version` reference.
#[derive(Debug, Clone, PartialEq)]
pub enum GitHubVersion {
    /// 40-character hex SHA (immutable, cached permanently).
    CommitSha(String),
    /// Semantic version tag (e.g. `v1.0.0`).
    Tag(String),
    /// Branch name (mutable, triggers a warning).
    Branch(String),
    /// No version specified; resolves to default branch.
    Latest,
}

impl GitHubVersion {
    /// Whether this version points at a mutable target (branch or latest).
    pub fn is_mutable(&self) -> bool {
        matches!(self, Self::Branch(_) | Self::Latest)
    }
}

/// Parsed preset reference.
#[derive(Debug, Clone, PartialEq)]
pub enum PresetReference {
    /// Local filesystem path.
    Local(PathBuf),
    /// `github:owner/repo@version` shorthand.
    GitHub {
        owner: String,
        repo: String,
        version: GitHubVersion,
    },
    /// Raw HTTP/HTTPS URL.
    Url(String),
}

/// Parse a preset reference string into a `PresetReference`.
pub fn parse_reference(reference: &str) -> Result<PresetReference, PresetError> {
    if let Some(gh) = reference.strip_prefix("github:") {
        parse_github_shorthand(gh)
    } else if reference.starts_with("https://") || reference.starts_with("http://") {
        Ok(PresetReference::Url(reference.to_string()))
    } else {
        Ok(PresetReference::Local(PathBuf::from(reference)))
    }
}

fn parse_github_shorthand(shorthand: &str) -> Result<PresetReference, PresetError> {
    let (owner_repo, version) = if let Some((left, ver)) = shorthand.split_once('@') {
        (left, Some(ver))
    } else {
        (shorthand, None)
    };

    let (owner, repo) = owner_repo.split_once('/').ok_or_else(|| {
        PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: expected 'github:owner/repo', got 'github:{shorthand}'"
        ))
    })?;

    if owner.is_empty() || repo.is_empty() {
        return Err(PresetError::InvalidReference(format!(
            "invalid GitHub shorthand: owner and repo must not be empty in 'github:{shorthand}'"
        )));
    }

    let github_version = match version {
        None => GitHubVersion::Latest,
        Some(v) if is_commit_sha(v) => GitHubVersion::CommitSha(v.to_string()),
        Some(v) if looks_like_tag(v) => GitHubVersion::Tag(v.to_string()),
        Some(v) => GitHubVersion::Branch(v.to_string()),
    };

    Ok(PresetReference::GitHub {
        owner: owner.to_string(),
        repo: repo.to_string(),
        version: github_version,
    })
}

fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_tag(s: &str) -> bool {
    s.starts_with('v') && s.len() > 1 && s[1..].starts_with(|c: char| c.is_ascii_digit())
}

/// Build the raw.githubusercontent.com URL for the given GitHub reference.
fn github_raw_url(owner: &str, repo: &str, version: &GitHubVersion) -> String {
    let version_part = match version {
        GitHubVersion::CommitSha(sha) => sha.clone(),
        GitHubVersion::Tag(tag) => tag.clone(),
        GitHubVersion::Branch(branch) => branch.clone(),
        GitHubVersion::Latest => "HEAD".to_string(),
    };
    format!("https://raw.githubusercontent.com/{owner}/{repo}/{version_part}/runok.yml")
}

/// Trait to allow injecting a test HTTP client.
pub trait HttpClient {
    fn get(&self, url: &str) -> Result<String, String>;
}

/// Production HTTP client using reqwest blocking.
pub struct ReqwestClient;

impl HttpClient for ReqwestClient {
    fn get(&self, url: &str) -> Result<String, String> {
        let response = reqwest::blocking::get(url).map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status()));
        }
        response.text().map_err(|e| e.to_string())
    }
}

/// Compute cache directory path.
fn default_cache_dir() -> PathBuf {
    if let Some(xdg) = std::env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|v| !v.is_empty())
    {
        PathBuf::from(xdg).join("runok").join("presets")
    } else if let Some(home) = home_dir() {
        PathBuf::from(home)
            .join(".cache")
            .join("runok")
            .join("presets")
    } else {
        PathBuf::from("/tmp/runok/presets")
    }
}

/// Get the default cache TTL (24 hours, overridable by `RUNOK_CACHE_TTL`).
fn cache_ttl() -> Duration {
    if let Some(secs) = std::env::var("RUNOK_CACHE_TTL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        Duration::from_secs(secs)
    } else {
        Duration::from_secs(24 * 60 * 60)
    }
}

/// SHA-256 hash of a string, returned as hex.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the cache file path for a given reference URL.
fn cache_path(cache_dir: &Path, reference_url: &str) -> PathBuf {
    let hash = sha256_hex(reference_url);
    cache_dir.join(format!("{hash}.yml"))
}

/// Metadata stored alongside each cached preset.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheMetadata {
    reference_url: String,
    fetched_at_epoch_secs: u64,
    is_immutable: bool,
}

fn cache_meta_path(cache_dir: &Path, reference_url: &str) -> PathBuf {
    let hash = sha256_hex(reference_url);
    cache_dir.join(format!("{hash}.meta.json"))
}

fn read_cache(cache_dir: &Path, reference_url: &str) -> Option<(String, CacheMetadata)> {
    let content_path = cache_path(cache_dir, reference_url);
    let meta_path = cache_meta_path(cache_dir, reference_url);

    let content = std::fs::read_to_string(&content_path).ok()?;
    let meta_json = std::fs::read_to_string(&meta_path).ok()?;
    let meta: CacheMetadata = serde_json::from_str(&meta_json).ok()?;
    Some((content, meta))
}

fn write_cache(
    cache_dir: &Path,
    reference_url: &str,
    content: &str,
    is_immutable: bool,
) -> Result<(), PresetError> {
    std::fs::create_dir_all(cache_dir)
        .map_err(|e| PresetError::Cache(format!("failed to create cache directory: {e}")))?;

    let epoch_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let meta = CacheMetadata {
        reference_url: reference_url.to_string(),
        fetched_at_epoch_secs: epoch_secs,
        is_immutable,
    };

    std::fs::write(cache_path(cache_dir, reference_url), content)
        .map_err(|e| PresetError::Cache(format!("failed to write cache file: {e}")))?;

    let meta_json = serde_json::to_string(&meta)
        .map_err(|e| PresetError::Cache(format!("failed to serialize cache metadata: {e}")))?;
    std::fs::write(cache_meta_path(cache_dir, reference_url), meta_json)
        .map_err(|e| PresetError::Cache(format!("failed to write cache metadata: {e}")))?;

    Ok(())
}

fn is_cache_valid(meta: &CacheMetadata) -> bool {
    if meta.is_immutable {
        return true;
    }

    let ttl = cache_ttl();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age = now.saturating_sub(meta.fetched_at_epoch_secs);
    age < ttl.as_secs()
}

fn format_epoch(epoch_secs: u64) -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ago = now.saturating_sub(epoch_secs);
    if ago < 60 {
        format!("{ago} seconds ago")
    } else if ago < 3600 {
        format!("{} minutes ago", ago / 60)
    } else if ago < 86400 {
        format!("{} hours ago", ago / 3600)
    } else {
        format!("{} days ago", ago / 86400)
    }
}

/// Emit a warning to stderr for mutable preset references.
fn warn_mutable_reference(reference: &str, version: &GitHubVersion) {
    if version.is_mutable() {
        eprintln!(
            "warning: mutable preset reference '{reference}'\n  \
             Consider pinning to a commit SHA for reproducibility."
        );
    }
}

/// Fetch a remote preset, using cache when available.
///
/// Returns the YAML content as a string. Warnings (mutable reference,
/// stale cache fallback) are emitted to stderr.
pub fn fetch_remote_preset(
    reference: &str,
    preset_ref: &PresetReference,
    http_client: &dyn HttpClient,
    cache_dir: &Path,
) -> Result<String, PresetError> {
    let url = match preset_ref {
        PresetReference::GitHub {
            owner,
            repo,
            version,
        } => {
            warn_mutable_reference(reference, version);
            github_raw_url(owner, repo, version)
        }
        PresetReference::Url(url) => url.clone(),
        PresetReference::Local(_) => {
            return Err(PresetError::InvalidReference(
                "fetch_remote_preset called with a local reference".to_string(),
            ));
        }
    };

    let is_immutable = matches!(
        preset_ref,
        PresetReference::GitHub {
            version: GitHubVersion::CommitSha(_),
            ..
        }
    );

    // Check cache first
    if let Some((content, meta)) = read_cache(cache_dir, &url)
        && is_cache_valid(&meta)
    {
        return Ok(content);
    }

    // Fetch from remote
    match http_client.get(&url) {
        Ok(content) => {
            // Cache is best-effort; ignore write errors
            let _ = write_cache(cache_dir, &url, &content, is_immutable);
            Ok(content)
        }
        Err(err_msg) => {
            // Fall back to stale cache
            if let Some((content, meta)) = read_cache(cache_dir, &url) {
                let cached_at = format_epoch(meta.fetched_at_epoch_secs);
                eprintln!(
                    "warning: network error fetching '{reference}', using cached version from {cached_at}"
                );
                return Ok(content);
            }
            Err(PresetError::Fetch {
                url,
                message: err_msg,
            })
        }
    }
}

/// Load a remote preset reference and parse it as a `Config`.
pub fn load_remote_preset(
    reference: &str,
    preset_ref: &PresetReference,
    http_client: &dyn HttpClient,
    cache_dir: &Path,
) -> Result<Config, ConfigError> {
    let yaml = fetch_remote_preset(reference, preset_ref, http_client, cache_dir)?;
    let config = parse_config(&yaml)?;
    Ok(config)
}

/// Load a remote preset using the default reqwest client and cache directory.
pub fn load_remote_preset_default(reference: &str) -> Result<Config, ConfigError> {
    let preset_ref = parse_reference(reference)?;
    let client = ReqwestClient;
    let cache_dir = default_cache_dir();
    load_remote_preset(reference, &preset_ref, &client, &cache_dir)
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

    // === parse_reference ===

    #[rstest]
    #[case::local_relative(
        "./rules/aws.yml",
        PresetReference::Local(PathBuf::from("./rules/aws.yml"))
    )]
    #[case::local_absolute(
        "/etc/runok/global.yml",
        PresetReference::Local(PathBuf::from("/etc/runok/global.yml"))
    )]
    #[case::local_home(
        "~/presets/git.yml",
        PresetReference::Local(PathBuf::from("~/presets/git.yml"))
    )]
    #[case::https_url(
        "https://example.com/preset.yaml",
        PresetReference::Url("https://example.com/preset.yaml".to_string())
    )]
    #[case::http_url(
        "http://example.com/preset.yaml",
        PresetReference::Url("http://example.com/preset.yaml".to_string())
    )]
    fn parse_reference_non_github(#[case] reference: &str, #[case] expected: PresetReference) {
        assert_eq!(parse_reference(reference).unwrap(), expected);
    }

    #[rstest]
    #[case::commit_sha(
        "github:org/repo@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "org", "repo",
        GitHubVersion::CommitSha("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".to_string()),
    )]
    #[case::tag(
        "github:runok/preset-standard@v1.0.0",
        "runok", "preset-standard",
        GitHubVersion::Tag("v1.0.0".to_string()),
    )]
    #[case::branch(
        "github:org/repo@main",
        "org", "repo",
        GitHubVersion::Branch("main".to_string()),
    )]
    #[case::latest("github:org/repo", "org", "repo", GitHubVersion::Latest)]
    #[case::branch_develop(
        "github:org/repo@develop",
        "org", "repo",
        GitHubVersion::Branch("develop".to_string()),
    )]
    fn parse_reference_github(
        #[case] reference: &str,
        #[case] expected_owner: &str,
        #[case] expected_repo: &str,
        #[case] expected_version: GitHubVersion,
    ) {
        let result = parse_reference(reference).unwrap();
        match result {
            PresetReference::GitHub {
                owner,
                repo,
                version,
            } => {
                assert_eq!(owner, expected_owner);
                assert_eq!(repo, expected_repo);
                assert_eq!(version, expected_version);
            }
            other => panic!("expected PresetReference::GitHub, got: {other:?}"),
        }
    }

    #[rstest]
    #[case::no_slash("github:invalid")]
    #[case::empty_owner("github:/repo")]
    #[case::empty_repo("github:owner/")]
    fn parse_reference_invalid_github(#[case] reference: &str) {
        let err = parse_reference(reference).unwrap_err();
        assert!(matches!(err, PresetError::InvalidReference(_)));
    }

    // === github_raw_url ===

    #[rstest]
    #[case::sha(
        "org", "repo",
        GitHubVersion::CommitSha("abc123def456".to_string()),
        "https://raw.githubusercontent.com/org/repo/abc123def456/runok.yml",
    )]
    #[case::tag(
        "runok", "preset-standard",
        GitHubVersion::Tag("v1.0.0".to_string()),
        "https://raw.githubusercontent.com/runok/preset-standard/v1.0.0/runok.yml",
    )]
    #[case::branch(
        "org", "repo",
        GitHubVersion::Branch("main".to_string()),
        "https://raw.githubusercontent.com/org/repo/main/runok.yml",
    )]
    #[case::latest(
        "org",
        "repo",
        GitHubVersion::Latest,
        "https://raw.githubusercontent.com/org/repo/HEAD/runok.yml"
    )]
    fn github_raw_url_generation(
        #[case] owner: &str,
        #[case] repo: &str,
        #[case] version: GitHubVersion,
        #[case] expected: &str,
    ) {
        assert_eq!(github_raw_url(owner, repo, &version), expected);
    }

    // === GitHubVersion::is_mutable ===

    #[rstest]
    #[case::sha(GitHubVersion::CommitSha("abc".to_string()), false)]
    #[case::tag(GitHubVersion::Tag("v1.0.0".to_string()), false)]
    #[case::branch(GitHubVersion::Branch("main".to_string()), true)]
    #[case::latest(GitHubVersion::Latest, true)]
    fn github_version_is_mutable(#[case] version: GitHubVersion, #[case] expected: bool) {
        assert_eq!(version.is_mutable(), expected);
    }

    // === Mock HTTP client for remote preset tests ===

    struct MockHttpClient {
        responses: std::collections::HashMap<String, Result<String, String>>,
    }

    impl MockHttpClient {
        fn new() -> Self {
            Self {
                responses: std::collections::HashMap::new(),
            }
        }

        fn with_response(mut self, url: &str, response: Result<String, String>) -> Self {
            self.responses.insert(url.to_string(), response);
            self
        }
    }

    impl HttpClient for MockHttpClient {
        fn get(&self, url: &str) -> Result<String, String> {
            self.responses
                .get(url)
                .cloned()
                .unwrap_or_else(|| Err(format!("no mock response for {url}")))
        }
    }

    // === fetch_remote_preset ===

    #[rstest]
    fn fetch_remote_github_sha(tmp: TempDir) {
        let yaml = indoc! {"
            rules:
              - allow: 'git status'
        "};
        let url = "https://raw.githubusercontent.com/org/repo/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0/runok.yml";
        let client = MockHttpClient::new().with_response(url, Ok(yaml.to_string()));
        let preset_ref = PresetReference::GitHub {
            owner: "org".to_string(),
            repo: "repo".to_string(),
            version: GitHubVersion::CommitSha(
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".to_string(),
            ),
        };

        let content = fetch_remote_preset(
            "github:org/repo@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            &preset_ref,
            &client,
            tmp.path(),
        )
        .unwrap();

        assert_eq!(content, yaml);
    }

    #[rstest]
    fn fetch_remote_caches_content(tmp: TempDir) {
        let yaml = indoc! {"
            rules:
              - allow: 'git status'
        "};
        let url = "https://raw.githubusercontent.com/org/repo/v1.0.0/runok.yml";
        let client = MockHttpClient::new().with_response(url, Ok(yaml.to_string()));
        let preset_ref = PresetReference::GitHub {
            owner: "org".to_string(),
            repo: "repo".to_string(),
            version: GitHubVersion::Tag("v1.0.0".to_string()),
        };

        // First fetch
        fetch_remote_preset("github:org/repo@v1.0.0", &preset_ref, &client, tmp.path()).unwrap();

        // Verify cache files exist
        let cache_file = cache_path(tmp.path(), url);
        let meta_file = cache_meta_path(tmp.path(), url);
        assert!(cache_file.exists(), "cache file should be created");
        assert!(meta_file.exists(), "metadata file should be created");

        // Second fetch with a client that would fail — should use cache
        let failing_client =
            MockHttpClient::new().with_response(url, Err("network error".to_string()));
        let content = fetch_remote_preset(
            "github:org/repo@v1.0.0",
            &preset_ref,
            &failing_client,
            tmp.path(),
        )
        .unwrap();
        assert_eq!(content, yaml);
    }

    #[rstest]
    fn fetch_remote_immutable_cache_never_expires(tmp: TempDir) {
        let yaml = "rules:\n  - allow: 'git status'\n";
        let sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
        let url = format!("https://raw.githubusercontent.com/org/repo/{sha}/runok.yml");

        // Write a cache entry with fetched_at far in the past
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(cache_path(tmp.path(), &url), yaml).unwrap();
        let meta = CacheMetadata {
            reference_url: url.clone(),
            fetched_at_epoch_secs: 0, // epoch = very old
            is_immutable: true,
        };
        let meta_json = serde_json::to_string(&meta).unwrap();
        fs::write(cache_meta_path(tmp.path(), &url), meta_json).unwrap();

        let failing_client =
            MockHttpClient::new().with_response(&url, Err("should not be called".to_string()));
        let preset_ref = PresetReference::GitHub {
            owner: "org".to_string(),
            repo: "repo".to_string(),
            version: GitHubVersion::CommitSha(sha.to_string()),
        };

        let content = fetch_remote_preset(
            &format!("github:org/repo@{sha}"),
            &preset_ref,
            &failing_client,
            tmp.path(),
        )
        .unwrap();
        assert_eq!(content, yaml);
    }

    #[rstest]
    fn fetch_remote_stale_cache_fallback(tmp: TempDir) {
        let yaml = "rules:\n  - allow: 'git status'\n";
        let url = "https://raw.githubusercontent.com/org/repo/v1.0.0/runok.yml";

        // Write a cache entry that is expired (fetched_at far in the past, not immutable)
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(cache_path(tmp.path(), url), yaml).unwrap();
        let meta = CacheMetadata {
            reference_url: url.to_string(),
            fetched_at_epoch_secs: 0,
            is_immutable: false,
        };
        let meta_json = serde_json::to_string(&meta).unwrap();
        fs::write(cache_meta_path(tmp.path(), url), meta_json).unwrap();

        let failing_client =
            MockHttpClient::new().with_response(url, Err("connection refused".to_string()));
        let preset_ref = PresetReference::GitHub {
            owner: "org".to_string(),
            repo: "repo".to_string(),
            version: GitHubVersion::Tag("v1.0.0".to_string()),
        };

        // Should fall back to stale cache
        let content = fetch_remote_preset(
            "github:org/repo@v1.0.0",
            &preset_ref,
            &failing_client,
            tmp.path(),
        )
        .unwrap();
        assert_eq!(content, yaml);
    }

    #[rstest]
    fn fetch_remote_network_error_no_cache(tmp: TempDir) {
        let url = "https://raw.githubusercontent.com/org/repo/v1.0.0/runok.yml";
        let failing_client =
            MockHttpClient::new().with_response(url, Err("connection refused".to_string()));
        let preset_ref = PresetReference::GitHub {
            owner: "org".to_string(),
            repo: "repo".to_string(),
            version: GitHubVersion::Tag("v1.0.0".to_string()),
        };

        let err = fetch_remote_preset(
            "github:org/repo@v1.0.0",
            &preset_ref,
            &failing_client,
            tmp.path(),
        )
        .unwrap_err();

        match err {
            PresetError::Fetch { url: u, message } => {
                assert_eq!(
                    u,
                    "https://raw.githubusercontent.com/org/repo/v1.0.0/runok.yml"
                );
                assert_eq!(message, "connection refused");
            }
            other => panic!("expected PresetError::Fetch, got: {other:?}"),
        }
    }

    #[rstest]
    fn fetch_remote_https_url(tmp: TempDir) {
        let yaml = indoc! {"
            rules:
              - deny: 'rm -rf /'
        "};
        let url = "https://example.com/preset.yaml";
        let client = MockHttpClient::new().with_response(url, Ok(yaml.to_string()));
        let preset_ref = PresetReference::Url(url.to_string());

        let content = fetch_remote_preset(url, &preset_ref, &client, tmp.path()).unwrap();
        assert_eq!(content, yaml);
    }

    // === load_remote_preset (end-to-end with mock) ===

    #[rstest]
    fn load_remote_preset_parses_config(tmp: TempDir) {
        let yaml = indoc! {"
            rules:
              - allow: 'git status'
              - deny: 'rm -rf /'
        "};
        let url = "https://raw.githubusercontent.com/org/repo/v1.0.0/runok.yml";
        let client = MockHttpClient::new().with_response(url, Ok(yaml.to_string()));
        let preset_ref = PresetReference::GitHub {
            owner: "org".to_string(),
            repo: "repo".to_string(),
            version: GitHubVersion::Tag("v1.0.0".to_string()),
        };

        let config =
            load_remote_preset("github:org/repo@v1.0.0", &preset_ref, &client, tmp.path()).unwrap();

        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
        assert_eq!(rules[1].deny.as_deref(), Some("rm -rf /"));
    }

    #[rstest]
    fn load_remote_preset_invalid_yaml(tmp: TempDir) {
        let bad_yaml = "rules: [invalid yaml\n  broken:";
        let url = "https://raw.githubusercontent.com/org/repo/v1.0.0/runok.yml";
        let client = MockHttpClient::new().with_response(url, Ok(bad_yaml.to_string()));
        let preset_ref = PresetReference::GitHub {
            owner: "org".to_string(),
            repo: "repo".to_string(),
            version: GitHubVersion::Tag("v1.0.0".to_string()),
        };

        let err = load_remote_preset("github:org/repo@v1.0.0", &preset_ref, &client, tmp.path())
            .unwrap_err();
        assert!(matches!(err, ConfigError::Yaml(_)));
    }
}
