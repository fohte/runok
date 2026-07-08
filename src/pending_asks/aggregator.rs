use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::audit::{AskResolution, AuditEntry, is_approved};
use crate::config::{ActionKind, Config, ConfigLoader, ConfigSource, DefaultConfigLoader};
use crate::rules::rule_engine::{Action, EvalContext, evaluate_compound};

use super::model::PendingAskGroup;

/// Compute pending-ask groups from ask-decision entries and their
/// resolutions.
///
/// `entries` must already be filtered to ask-decision entries
/// (`SerializableAction::Ask`) and sorted ascending by timestamp (the order
/// `AuditReader::read` returns). Each entry is re-evaluated against the
/// config discovered from its own `metadata.cwd`; only entries still
/// resolved via `defaults.action` fallback (empty `matched_rules`) count as
/// pending. Entries now covered by an explicit `allow`/`deny` rule, or by an
/// explicit `ask` rule the user wrote on purpose, are excluded.
///
/// Entries whose `metadata.cwd` is missing, or whose config fails to load,
/// cannot be re-evaluated; they are kept as pending rather than silently
/// dropped, since hiding a command that may still need attention is worse
/// than showing one that has already been resolved.
///
/// `loader` performs the same global-plus-project discovery as every other
/// runok subcommand, rooted at each entry's own `metadata.cwd`. Callers
/// needing a hermetic loader (tests) can pass one built with
/// `DefaultConfigLoader::with_global_dir`.
///
/// Groups are sorted by `ask_count` descending, then `command` ascending.
pub fn compute_pending_ask_groups(
    entries: &[AuditEntry],
    resolutions: &[AskResolution],
    loader: &DefaultConfigLoader,
) -> Vec<PendingAskGroup> {
    let mut config_cache: HashMap<String, Option<Config>> = HashMap::new();
    let env: HashMap<String, String> = std::env::vars().collect();

    let mut groups: HashMap<String, GroupBuilder> = HashMap::new();

    for entry in entries {
        if !is_pending(entry, loader, &mut config_cache, &env) {
            continue;
        }

        groups
            .entry(entry.command.clone())
            .or_insert_with(|| GroupBuilder::new(&entry.timestamp))
            .record(entry, resolutions);
    }

    let mut result: Vec<PendingAskGroup> = groups
        .into_iter()
        .map(|(command, builder)| builder.build(command))
        .collect();
    result.sort_by(|a, b| {
        b.ask_count
            .cmp(&a.ask_count)
            .then_with(|| a.command.cmp(&b.command))
    });
    result
}

struct GroupBuilder {
    ask_count: usize,
    approved_count: usize,
    first_seen: String,
    last_seen: String,
    cwds: Vec<String>,
}

impl GroupBuilder {
    fn new(first_timestamp: &str) -> Self {
        Self {
            ask_count: 0,
            approved_count: 0,
            first_seen: first_timestamp.to_owned(),
            last_seen: first_timestamp.to_owned(),
            cwds: Vec::new(),
        }
    }

    /// `entries` are processed in ascending timestamp order, so each
    /// recorded entry's timestamp becomes the new `last_seen`.
    fn record(&mut self, entry: &AuditEntry, resolutions: &[AskResolution]) {
        self.ask_count += 1;
        if is_approved(entry, resolutions) {
            self.approved_count += 1;
        }
        self.last_seen = entry.timestamp.clone();
        if let Some(cwd) = &entry.metadata.cwd
            && !self.cwds.contains(cwd)
        {
            self.cwds.push(cwd.clone());
        }
    }

    fn build(self, command: String) -> PendingAskGroup {
        PendingAskGroup {
            command,
            ask_count: self.ask_count,
            approved_count: self.approved_count,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            cwds: self.cwds,
        }
    }
}

/// Whether `entry` is still resolved via `defaults.action` fallback under
/// the config discovered from its `metadata.cwd`.
fn is_pending(
    entry: &AuditEntry,
    loader: &DefaultConfigLoader,
    config_cache: &mut HashMap<String, Option<Config>>,
    env: &HashMap<String, String>,
) -> bool {
    let Some(cwd) = &entry.metadata.cwd else {
        return true;
    };

    let cached = config_cache.entry(cwd.clone()).or_insert_with(|| {
        let source = ConfigSource::from_flag(None, Path::new(cwd));
        match loader.load(&source) {
            Ok(config) => Some(config),
            Err(e) => {
                eprintln!("runok: warning: failed to load config for {cwd}: {e}");
                None
            }
        }
    });
    let Some(config) = cached else {
        return true;
    };

    let context = EvalContext {
        env: env.clone(),
        cwd: PathBuf::from(cwd.as_str()),
    };

    // `evaluate_compound` (not `evaluate_command`) is the same entry point
    // `runok exec`/`check` use, so compound commands (`a && b`) re-evaluate
    // with the same sandbox-contradiction-triggered Ask escalation that
    // produced the original decision.
    match evaluate_compound(config, &entry.command, &context) {
        Ok(result) => match result.action {
            Action::Allow | Action::Deny(_) => false,
            Action::Ask(_) => !result
                .sub_results
                .iter()
                .flat_map(|r| &r.matched_rules)
                .any(|r| r.action_kind == ActionKind::Ask),
        },
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    use super::*;
    use crate::audit::{AskResolutionOutcome, AuditMetadata, SerializableAction};

    #[fixture]
    fn project_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn write_config(dir: &TempDir, yaml: &str) {
        std::fs::write(dir.path().join("runok.yml"), yaml).unwrap();
    }

    /// A loader whose global config directory never exists, so tests are
    /// isolated from whatever global `runok.yml` happens to be present on
    /// the machine running them.
    fn hermetic_loader() -> DefaultConfigLoader {
        DefaultConfigLoader::with_global_dir(PathBuf::from(
            "/nonexistent/runok-pending-asks-test-global",
        ))
    }

    fn ask_entry(timestamp: &str, command: &str, cwd: &str) -> AuditEntry {
        AuditEntry {
            timestamp: timestamp.to_owned(),
            command: command.to_owned(),
            action: SerializableAction::Ask { message: None },
            sandbox_preset: None,
            default_action: Some("ask".to_owned()),
            metadata: AuditMetadata {
                cwd: Some(cwd.to_owned()),
                ..AuditMetadata::default()
            },
            command_evaluations: vec![],
        }
    }

    #[rstest]
    #[case::no_rule("", true)]
    #[case::allow_rule(indoc! {"
        rules:
          - allow: 'terraform apply'
    "}, false)]
    #[case::deny_rule(indoc! {"
        rules:
          - deny: 'terraform apply'
    "}, false)]
    #[case::explicit_ask_rule(indoc! {"
        rules:
          - ask: 'terraform apply'
    "}, false)]
    fn pending_status_depends_on_matching_rule(
        project_dir: TempDir,
        #[case] yaml: &str,
        #[case] expect_pending: bool,
    ) {
        write_config(&project_dir, yaml);
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entries = vec![ask_entry("2026-07-01T10:00:00Z", "terraform apply", &cwd)];

        let groups = compute_pending_ask_groups(&entries, &[], &hermetic_loader());

        let expected = if expect_pending {
            vec![PendingAskGroup {
                command: "terraform apply".to_owned(),
                ask_count: 1,
                approved_count: 0,
                first_seen: "2026-07-01T10:00:00Z".to_owned(),
                last_seen: "2026-07-01T10:00:00Z".to_owned(),
                cwds: vec![cwd],
            }]
        } else {
            vec![]
        };
        assert_eq!(groups, expected);
    }

    // Regression coverage for re-evaluating with `evaluate_compound` (not
    // `evaluate_command`): a compound command's sub-commands must be checked
    // against their own rules independently, not matched as one literal
    // pattern against the whole `a && b` string.
    #[rstest]
    fn compound_command_fully_covered_excludes_from_pending(project_dir: TempDir) {
        write_config(
            &project_dir,
            indoc! {"
                rules:
                  - allow: 'cd *'
                  - allow: 'terraform apply'
            "},
        );
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entries = vec![ask_entry(
            "2026-07-01T10:00:00Z",
            "cd infra && terraform apply",
            &cwd,
        )];

        assert_eq!(
            compute_pending_ask_groups(&entries, &[], &hermetic_loader()),
            vec![],
        );
    }

    #[rstest]
    fn compound_command_partially_covered_stays_pending(project_dir: TempDir) {
        write_config(
            &project_dir,
            indoc! {"
                rules:
                  - allow: 'cd *'
            "},
        );
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entries = vec![ask_entry(
            "2026-07-01T10:00:00Z",
            "cd infra && terraform apply",
            &cwd,
        )];

        let groups = compute_pending_ask_groups(&entries, &[], &hermetic_loader());

        assert_eq!(
            groups,
            vec![PendingAskGroup {
                command: "cd infra && terraform apply".to_owned(),
                ask_count: 1,
                approved_count: 0,
                first_seen: "2026-07-01T10:00:00Z".to_owned(),
                last_seen: "2026-07-01T10:00:00Z".to_owned(),
                cwds: vec![cwd],
            }],
        );
    }

    #[rstest]
    fn missing_cwd_is_kept_pending() {
        let entries = vec![AuditEntry {
            metadata: AuditMetadata::default(),
            ..ask_entry("2026-07-01T10:00:00Z", "terraform apply", "/unused")
        }];

        let groups = compute_pending_ask_groups(&entries, &[], &hermetic_loader());

        assert_eq!(
            groups,
            vec![PendingAskGroup {
                command: "terraform apply".to_owned(),
                ask_count: 1,
                approved_count: 0,
                first_seen: "2026-07-01T10:00:00Z".to_owned(),
                last_seen: "2026-07-01T10:00:00Z".to_owned(),
                cwds: vec![],
            }],
        );
    }

    #[rstest]
    fn config_load_failure_is_kept_pending(project_dir: TempDir) {
        write_config(
            &project_dir,
            indoc! {"
            rules: [invalid yaml
              broken:
        "},
        );
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entries = vec![ask_entry("2026-07-01T10:00:00Z", "terraform apply", &cwd)];

        let groups = compute_pending_ask_groups(&entries, &[], &hermetic_loader());

        assert_eq!(
            groups,
            vec![PendingAskGroup {
                command: "terraform apply".to_owned(),
                ask_count: 1,
                approved_count: 0,
                first_seen: "2026-07-01T10:00:00Z".to_owned(),
                last_seen: "2026-07-01T10:00:00Z".to_owned(),
                cwds: vec![cwd],
            }],
        );
    }

    #[rstest]
    fn approved_entries_are_counted(project_dir: TempDir) {
        write_config(&project_dir, "");
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let entry = AuditEntry {
            metadata: AuditMetadata {
                cwd: Some(cwd.clone()),
                session_id: Some("sess-1".to_owned()),
                tool_use_id: Some("toolu_01".to_owned()),
                ..AuditMetadata::default()
            },
            ..ask_entry("2026-07-01T10:00:00Z", "terraform apply", &cwd)
        };
        let resolution = AskResolution {
            timestamp: "2026-07-01T10:01:00Z".to_owned(),
            outcome: AskResolutionOutcome::Approved,
            tool_use_id: Some("toolu_01".to_owned()),
            session_id: Some("sess-1".to_owned()),
            cwd: Some(cwd.clone()),
            command: "terraform apply".to_owned(),
            executed_command: "terraform apply".to_owned(),
        };

        let groups = compute_pending_ask_groups(&[entry], &[resolution], &hermetic_loader());

        assert_eq!(
            groups,
            vec![PendingAskGroup {
                command: "terraform apply".to_owned(),
                ask_count: 1,
                approved_count: 1,
                first_seen: "2026-07-01T10:00:00Z".to_owned(),
                last_seen: "2026-07-01T10:00:00Z".to_owned(),
                cwds: vec![cwd],
            }],
        );
    }

    #[rstest]
    fn groups_by_command_and_sorts_by_ask_count_desc(project_dir: TempDir) {
        write_config(&project_dir, "");
        let cwd = project_dir.path().to_string_lossy().into_owned();
        let other_dir = TempDir::new().unwrap();
        write_config(&other_dir, "");
        let other_cwd = other_dir.path().to_string_lossy().into_owned();

        let entries = vec![
            ask_entry("2026-07-01T10:00:00Z", "git push", &cwd),
            ask_entry("2026-07-02T10:00:00Z", "terraform apply", &cwd),
            ask_entry("2026-07-03T10:00:00Z", "terraform apply", &other_cwd),
            ask_entry("2026-07-04T10:00:00Z", "terraform apply", &cwd),
        ];

        let groups = compute_pending_ask_groups(&entries, &[], &hermetic_loader());

        assert_eq!(
            groups,
            vec![
                PendingAskGroup {
                    command: "terraform apply".to_owned(),
                    ask_count: 3,
                    approved_count: 0,
                    first_seen: "2026-07-02T10:00:00Z".to_owned(),
                    last_seen: "2026-07-04T10:00:00Z".to_owned(),
                    cwds: vec![cwd.clone(), other_cwd],
                },
                PendingAskGroup {
                    command: "git push".to_owned(),
                    ask_count: 1,
                    approved_count: 0,
                    first_seen: "2026-07-01T10:00:00Z".to_owned(),
                    last_seen: "2026-07-01T10:00:00Z".to_owned(),
                    cwds: vec![cwd],
                },
            ],
        );
    }
}
