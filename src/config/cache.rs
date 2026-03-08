use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use super::PresetError;

/// Cache metadata stored as `metadata.json` alongside the cloned repository.
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheMetadata {
    /// Unix timestamp (seconds) when the preset was last fetched.
    pub fetched_at: u64,
    /// Whether this reference is immutable (commit SHA).
    pub is_immutable: bool,
    /// The original reference string.
    pub reference: String,
    /// The resolved commit SHA after clone/fetch.
    pub resolved_sha: Option<String>,
}

/// Result of checking cache status for a preset reference.
pub enum CacheStatus {
    /// Valid cache exists within TTL.
    Hit(PathBuf),
    /// Cache exists but TTL has expired.
    Stale(PathBuf),
    /// No cache exists.
    Miss,
}

/// Manages the preset cache directory structure and TTL.
pub struct PresetCache {
    cache_root: PathBuf,
    ttl: Duration,
}

impl PresetCache {
    /// Create a new `PresetCache` resolving the cache directory from environment.
    pub fn from_env() -> Result<Self, PresetError> {
        let cache_root = Self::resolve_cache_dir()?;
        let ttl = Self::resolve_ttl();
        Ok(Self { cache_root, ttl })
    }

    /// Create a `PresetCache` with explicit root and TTL (for testing).
    pub fn with_config(cache_root: PathBuf, ttl: Duration) -> Self {
        Self { cache_root, ttl }
    }

    fn resolve_cache_dir() -> Result<PathBuf, PresetError> {
        let base = super::dirs::cache_dir().ok_or_else(|| {
            PresetError::Cache(
                "cannot determine cache directory: neither XDG_CACHE_HOME nor HOME is set"
                    .to_string(),
            )
        })?;
        Ok(base.join("runok").join("presets"))
    }

    fn resolve_ttl() -> Duration {
        std::env::var("RUNOK_CACHE_TTL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(24 * 60 * 60))
    }

    /// Compute the SHA256-based cache key for a reference string.
    pub fn cache_key(reference: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(reference.as_bytes());
        format!("{hash:x}")
    }

    /// Return the cache directory path for a given reference.
    pub fn cache_dir(&self, reference: &str) -> PathBuf {
        self.cache_root.join(Self::cache_key(reference))
    }

    /// Check the cache status for a reference.
    pub fn check(&self, reference: &str, is_immutable: bool) -> CacheStatus {
        let dir = self.cache_dir(reference);
        if !dir.exists() {
            return CacheStatus::Miss;
        }

        let metadata_path = dir.join("metadata.json");
        let metadata = match Self::read_metadata(&metadata_path) {
            Some(m) => m,
            None => return CacheStatus::Stale(dir),
        };

        if is_immutable || metadata.is_immutable {
            return CacheStatus::Hit(dir);
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now.saturating_sub(metadata.fetched_at) < self.ttl.as_secs() {
            CacheStatus::Hit(dir)
        } else {
            CacheStatus::Stale(dir)
        }
    }

    /// Read metadata from a `metadata.json` file.
    pub fn read_metadata(metadata_path: &Path) -> Option<CacheMetadata> {
        let content = std::fs::read_to_string(metadata_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Return the lock file path for a given reference.
    ///
    /// The lock file is placed alongside the cache directory (not inside it)
    /// so it exists before the cache directory is created by `git clone`.
    pub fn lock_path(&self, reference: &str) -> PathBuf {
        self.cache_root
            .join(format!("{}.lock", Self::cache_key(reference)))
    }

    /// Acquire an exclusive file lock for the given reference.
    ///
    /// Creates the lock file and parent directories if they don't exist.
    /// Blocks until the lock is acquired. The returned `File` holds the lock;
    /// dropping it releases the lock.
    pub fn acquire_lock(&self, reference: &str) -> Result<File, PresetError> {
        let lock_path = self.lock_path(reference);
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PresetError::Cache(format!("failed to create lock directory: {e}")))?;
        }
        let file = File::create(&lock_path)
            .map_err(|e| PresetError::Cache(format!("failed to create lock file: {e}")))?;
        file.lock_exclusive()
            .map_err(|e| PresetError::Cache(format!("failed to acquire lock: {e}")))?;
        Ok(file)
    }

    /// Write metadata to a `metadata.json` file inside `cache_dir`.
    pub fn write_metadata(cache_dir: &Path, metadata: &CacheMetadata) -> Result<(), PresetError> {
        let path = cache_dir.join("metadata.json");
        let json = serde_json::to_string_pretty(metadata)
            .map_err(|e| PresetError::Cache(format!("failed to serialize cache metadata: {e}")))?;
        std::fs::write(&path, json)
            .map_err(|e| PresetError::Cache(format!("failed to write metadata: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    #[fixture]
    fn tmp() -> TempDir {
        TempDir::new().unwrap()
    }

    #[rstest]
    #[case::same_input("github:org/repo@v1", "github:org/repo@v1")]
    fn cache_key_is_deterministic(#[case] ref1: &str, #[case] ref2: &str) {
        assert_eq!(PresetCache::cache_key(ref1), PresetCache::cache_key(ref2));
    }

    #[rstest]
    #[case::different_versions("github:org/repo@v1", "github:org/repo@v2")]
    #[case::different_repos("github:org/a@v1", "github:org/b@v1")]
    fn cache_key_differs_for_different_refs(#[case] ref1: &str, #[case] ref2: &str) {
        assert_ne!(PresetCache::cache_key(ref1), PresetCache::cache_key(ref2));
    }

    #[rstest]
    fn cache_key_is_hex_sha256() {
        let key = PresetCache::cache_key("github:org/repo@v1");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[rstest]
    fn miss_when_no_cache_dir(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        assert!(matches!(
            cache.check("github:org/repo@v1", false),
            CacheStatus::Miss
        ));
    }

    #[rstest]
    fn hit_when_fresh_cache(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let dir = cache.cache_dir("github:org/repo@v1");
        std::fs::create_dir_all(&dir).unwrap();

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let metadata = CacheMetadata {
            fetched_at: now,
            is_immutable: false,
            reference: "github:org/repo@v1".to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&dir, &metadata).unwrap();

        assert!(matches!(
            cache.check("github:org/repo@v1", false),
            CacheStatus::Hit(_)
        ));
    }

    #[rstest]
    fn stale_when_ttl_exceeded(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let dir = cache.cache_dir("github:org/repo@v1");
        std::fs::create_dir_all(&dir).unwrap();

        let metadata = CacheMetadata {
            fetched_at: 0, // epoch = very old
            is_immutable: false,
            reference: "github:org/repo@v1".to_string(),
            resolved_sha: None,
        };
        PresetCache::write_metadata(&dir, &metadata).unwrap();

        assert!(matches!(
            cache.check("github:org/repo@v1", false),
            CacheStatus::Stale(_)
        ));
    }

    #[rstest]
    fn immutable_never_stale(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let dir = cache.cache_dir("github:org/repo@abc123");
        std::fs::create_dir_all(&dir).unwrap();

        let metadata = CacheMetadata {
            fetched_at: 0, // epoch = very old
            is_immutable: true,
            reference: "github:org/repo@abc123".to_string(),
            resolved_sha: Some("abc123".to_string()),
        };
        PresetCache::write_metadata(&dir, &metadata).unwrap();

        assert!(matches!(
            cache.check("github:org/repo@abc123", true),
            CacheStatus::Hit(_)
        ));
    }

    #[rstest]
    fn stale_when_no_metadata(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let dir = cache.cache_dir("github:org/repo@v1");
        std::fs::create_dir_all(&dir).unwrap();
        // No metadata.json written

        assert!(matches!(
            cache.check("github:org/repo@v1", false),
            CacheStatus::Stale(_)
        ));
    }

    #[rstest]
    fn lock_path_is_beside_cache_dir(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let reference = "github:org/repo@v1";
        let cache_dir = cache.cache_dir(reference);
        let lock_path = cache.lock_path(reference);

        // Lock file should be in the same parent as the cache dir
        assert_eq!(lock_path.parent(), cache_dir.parent());
        // Lock file name = cache_key + ".lock"
        assert_eq!(
            lock_path.file_name().unwrap().to_str().unwrap(),
            format!("{}.lock", PresetCache::cache_key(reference))
        );
    }

    #[rstest]
    fn acquire_lock_creates_file(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let reference = "github:org/repo@v1";
        let lock_path = cache.lock_path(reference);

        assert!(!lock_path.exists());
        let _lock = cache.acquire_lock(reference).unwrap();
        assert!(lock_path.exists());
    }

    #[rstest]
    fn lock_is_released_on_drop(tmp: TempDir) {
        let cache = PresetCache::with_config(tmp.path().to_path_buf(), Duration::from_secs(3600));
        let reference = "github:org/repo@v1";

        {
            let _lock = cache.acquire_lock(reference).unwrap();
            // Lock is held here
        }
        // After drop, another lock should be acquirable immediately
        let _lock2 = cache.acquire_lock(reference).unwrap();
    }

    #[rstest]
    fn metadata_roundtrip(tmp: TempDir) {
        let dir = tmp.path();
        let original = CacheMetadata {
            fetched_at: 1700000000,
            is_immutable: true,
            reference: "github:org/repo@abc123".to_string(),
            resolved_sha: Some("abc123def456".to_string()),
        };

        PresetCache::write_metadata(dir, &original).unwrap();

        let path = dir.join("metadata.json");
        let loaded = PresetCache::read_metadata(&path).unwrap();
        assert_eq!(loaded.fetched_at, original.fetched_at);
        assert_eq!(loaded.is_immutable, original.is_immutable);
        assert_eq!(loaded.reference, original.reference);
        assert_eq!(loaded.resolved_sha, original.resolved_sha);
    }
}
