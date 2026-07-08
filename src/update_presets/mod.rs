mod discovery;
mod semver_utils;
mod updater;

use std::collections::HashMap;

use similar::ChangeTag;

use crate::config::cache::PresetCache;
use crate::config::git_client::{GitClient, ProcessGitClient, RemoteRef};

use discovery::{TrackedReference, collect_all_tracked_references, update_config_file};
use updater::{UpdateResult, update_single_preset, warn_skipped_candidates};

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

/// Run the update-presets command.
///
/// Finds all config files, collects remote preset references, and force-fetches each one.
/// For semver-tagged presets, checks for newer compatible versions and updates config files.
/// Displays a diff for presets that changed.
pub fn run(source: &crate::config::ConfigSource) -> Result<(), anyhow::Error> {
    let tracked_refs = collect_all_tracked_references(source)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cache::CacheMetadata;
    use crate::config::git_client::RefKind;
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

    const T: RefKind = RefKind::Tag;

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
}
