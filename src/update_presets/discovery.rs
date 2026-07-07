use std::path::{Path, PathBuf};

use crate::config::preset_remote::{PresetReference, parse_preset_reference};
use crate::config::{Config, parse_config};

/// A remote preset reference paired with the config file it came from.
pub(super) struct TrackedReference {
    pub(super) reference: String,
    pub(super) source_file: PathBuf,
}

/// Collect all `extends` references from a parsed config, returning only remote ones.
fn collect_remote_references(config: &Config) -> Vec<&str> {
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
                .map(|r| r.as_str())
                .collect()
        })
        .unwrap_or_default()
}

/// Replace a preset reference in a config file, preserving formatting.
pub(super) fn update_config_file(
    source_file: &Path,
    old_reference: &str,
    new_reference: &str,
) -> Result<(), anyhow::Error> {
    let content = std::fs::read_to_string(source_file)?;
    let updated = content.replacen(old_reference, new_reference, 1);
    std::fs::write(source_file, updated)?;
    Ok(())
}

/// Collect all remote preset references from all config layers, tracking source files.
pub(super) fn collect_all_tracked_references(
    source: &crate::config::ConfigSource,
) -> Result<Vec<TrackedReference>, anyhow::Error> {
    let mut tracked = Vec::new();
    let mut seen = std::collections::HashSet::new();

    match source {
        crate::config::ConfigSource::Explicit { path } => {
            collect_tracked_from_file(path, &mut tracked, &mut seen);
        }
        crate::config::ConfigSource::Default { cwd } => {
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
        }
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
    collect_tracked_from_file(&path, tracked, seen);
}

fn collect_tracked_from_file(
    path: &Path,
    tracked: &mut Vec<TrackedReference>,
    seen: &mut std::collections::HashSet<String>,
) {
    let yaml = match std::fs::read_to_string(path) {
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
                reference: r.to_string(),
                source_file: path.to_path_buf(),
            });
        }
    }
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
        assert_eq!(refs.contains(&reference), expected_included);
    }

    #[rstest]
    fn collect_remote_references_empty_extends() {
        let config = Config::default();
        assert!(collect_remote_references(&config).is_empty());
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
}
