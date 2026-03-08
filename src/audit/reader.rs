use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use super::filter::AuditFilter;
use super::log_rotator::parse_log_date;
use super::model::{AuditEntry, SerializableAction};
use crate::config::ActionKind;

/// Reads and filters audit log entries from JSONL date-partitioned files.
pub struct AuditReader {
    log_dir: PathBuf,
}

impl AuditReader {
    pub fn new(log_dir: PathBuf) -> Self {
        Self { log_dir }
    }

    /// Read audit log entries matching the given filter.
    ///
    /// Returns entries sorted by timestamp in descending order (newest first).
    /// Corrupted JSONL lines are skipped with a warning printed to stderr.
    /// If no log files exist, returns an empty list.
    pub fn read(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, anyhow::Error> {
        let now = Utc::now();
        self.read_with_now(filter, now)
    }

    fn read_with_now(
        &self,
        filter: &AuditFilter,
        now: DateTime<Utc>,
    ) -> Result<Vec<AuditEntry>, anyhow::Error> {
        let since = filter.since.as_ref().map(|ts| ts.resolve(now));
        let until = filter.until.as_ref().map(|ts| ts.resolve(now));

        let date_files = self.collect_date_files(since)?;

        let mut entries = Vec::new();

        for path in &date_files {
            self.read_file(
                path,
                &filter.action,
                since,
                until,
                &filter.command_pattern,
                &mut entries,
            )?;
        }

        // Partial sort: find the top `limit` entries without sorting everything
        let cmp = |a: &AuditEntry, b: &AuditEntry| b.timestamp.cmp(&a.timestamp);
        if entries.len() > filter.limit {
            entries.select_nth_unstable_by(filter.limit, cmp);
            entries.truncate(filter.limit);
        }
        entries.sort_by(cmp);

        Ok(entries)
    }

    /// Collect date-partitioned log files, optionally filtering by since date.
    fn collect_date_files(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<PathBuf>, anyhow::Error> {
        if !self.log_dir.exists() {
            return Ok(Vec::new());
        }

        let mut files: Vec<PathBuf> = Vec::new();

        let entries = fs::read_dir(&self.log_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let file_name = match path.file_name().and_then(|s| s.to_str()) {
                Some(name) => name,
                None => continue,
            };

            // Files are named audit-YYYY-MM-DD.jsonl; skip files entirely before the since date
            if let Some(since_dt) = since
                && let Some(file_date) = parse_log_date(file_name)
                && file_date < since_dt.date_naive()
            {
                continue;
            }

            files.push(path);
        }

        files.sort();
        Ok(files)
    }

    /// Read entries from a single JSONL file, applying filters.
    fn read_file(
        &self,
        path: &Path,
        action_filter: &Option<ActionKind>,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        command_pattern: &Option<String>,
        entries: &mut Vec<AuditEntry>,
    ) -> Result<(), anyhow::Error> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "runok: warning: failed to read line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "runok: warning: skipping corrupted entry at line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            if !Self::matches_filter(&entry, action_filter, since, until, command_pattern) {
                continue;
            }

            entries.push(entry);
        }

        Ok(())
    }

    fn matches_filter(
        entry: &AuditEntry,
        action_filter: &Option<ActionKind>,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        command_pattern: &Option<String>,
    ) -> bool {
        // Check timestamp filters; malformed timestamps cannot satisfy time filters
        if since.is_some() || until.is_some() {
            match entry.timestamp.parse::<DateTime<Utc>>() {
                Ok(ts) => {
                    if let Some(since_dt) = since
                        && ts < since_dt
                    {
                        return false;
                    }
                    if let Some(until_dt) = until
                        && ts > until_dt
                    {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }

        // Check action filter
        if let Some(action_kind) = action_filter
            && !Self::action_matches(&entry.action, action_kind)
        {
            return false;
        }

        // Check command pattern (substring match)
        if let Some(pattern) = command_pattern
            && !entry.command.contains(pattern.as_str())
        {
            return false;
        }

        true
    }

    fn action_matches(action: &SerializableAction, kind: &ActionKind) -> bool {
        matches!(
            (action, kind),
            (SerializableAction::Allow, ActionKind::Allow)
                | (SerializableAction::Deny { .. }, ActionKind::Deny)
                | (SerializableAction::Ask { .. }, ActionKind::Ask)
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use chrono::DateTime;
    use indoc::formatdoc;
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    use super::*;
    use crate::audit::filter::TimeSpec;
    use crate::audit::{AuditMetadata, SerializableAction};

    #[fixture]
    fn temp_log_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn make_entry(timestamp: &str, command: &str, action: SerializableAction) -> AuditEntry {
        AuditEntry {
            timestamp: timestamp.to_owned(),
            command: command.to_owned(),
            action,
            matched_rules: vec![],
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata::default(),
            sub_evaluations: None,
        }
    }

    fn write_jsonl(dir: &Path, filename: &str, entries: &[AuditEntry]) {
        let path = dir.join(filename);
        let mut file = fs::File::create(path).unwrap();
        for entry in entries {
            let json = serde_json::to_string(entry).unwrap();
            writeln!(file, "{json}").unwrap();
        }
    }

    #[rstest]
    fn read_empty_dir(temp_log_dir: TempDir) {
        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let filter = AuditFilter::new();
        let entries = reader.read(&filter).unwrap();
        assert!(entries.is_empty());
    }

    #[rstest]
    fn read_nonexistent_dir() {
        let reader = AuditReader::new(PathBuf::from("/nonexistent/path"));
        let filter = AuditFilter::new();
        let entries = reader.read(&filter).unwrap();
        assert!(entries.is_empty());
    }

    #[rstest]
    fn read_entries_sorted_descending(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry(
                "2026-02-25T10:00:00Z",
                "echo first",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T12:00:00Z",
                "echo third",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T11:00:00Z",
                "echo second",
                SerializableAction::Allow,
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let filter = AuditFilter::new();
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].command, "echo third");
        assert_eq!(result[1].command, "echo second");
        assert_eq!(result[2].command, "echo first");
    }

    #[rstest]
    fn filter_by_action(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry(
                "2026-02-25T10:00:00Z",
                "echo hello",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T11:00:00Z",
                "rm -rf /",
                SerializableAction::Deny {
                    message: None,
                    fix_suggestion: None,
                },
            ),
            make_entry(
                "2026-02-25T12:00:00Z",
                "git push",
                SerializableAction::Ask { message: None },
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let mut filter = AuditFilter::new();
        filter.action = Some(ActionKind::Deny);
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "rm -rf /");
    }

    #[rstest]
    fn filter_by_command_pattern(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry(
                "2026-02-25T10:00:00Z",
                "git push origin main",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T11:00:00Z",
                "echo hello",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T12:00:00Z",
                "git pull",
                SerializableAction::Allow,
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let mut filter = AuditFilter::new();
        filter.command_pattern = Some("git".to_owned());
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "git pull");
        assert_eq!(result[1].command, "git push origin main");
    }

    #[rstest]
    fn filter_by_since(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry(
                "2026-02-25T08:00:00Z",
                "echo old",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T12:00:00Z",
                "echo new",
                SerializableAction::Allow,
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let now = "2026-02-25T14:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut filter = AuditFilter::new();
        filter.since = Some(TimeSpec::Absolute("2026-02-25T10:00:00Z".parse().unwrap()));
        let result = reader.read_with_now(&filter, now).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "echo new");
    }

    #[rstest]
    fn filter_by_until(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry(
                "2026-02-25T08:00:00Z",
                "echo old",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T12:00:00Z",
                "echo new",
                SerializableAction::Allow,
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let now = "2026-02-25T14:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut filter = AuditFilter::new();
        filter.until = Some(TimeSpec::Absolute("2026-02-25T10:00:00Z".parse().unwrap()));
        let result = reader.read_with_now(&filter, now).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "echo old");
    }

    #[rstest]
    fn filter_combined(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry(
                "2026-02-25T08:00:00Z",
                "git push",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-02-25T12:00:00Z",
                "git push -f",
                SerializableAction::Deny {
                    message: None,
                    fix_suggestion: None,
                },
            ),
            make_entry(
                "2026-02-25T14:00:00Z",
                "echo hello",
                SerializableAction::Allow,
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let now = "2026-02-25T16:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut filter = AuditFilter::new();
        filter.action = Some(ActionKind::Deny);
        filter.since = Some(TimeSpec::Absolute("2026-02-25T10:00:00Z".parse().unwrap()));
        filter.command_pattern = Some("git".to_owned());
        let result = reader.read_with_now(&filter, now).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "git push -f");
    }

    #[rstest]
    fn limit_entries(temp_log_dir: TempDir) {
        let entries: Vec<AuditEntry> = (0..10)
            .map(|i| {
                make_entry(
                    &format!("2026-02-25T{:02}:00:00Z", i + 1),
                    &format!("echo {i}"),
                    SerializableAction::Allow,
                )
            })
            .collect();
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let mut filter = AuditFilter::new();
        filter.limit = 3;
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 3);
    }

    #[rstest]
    fn skip_corrupted_lines(temp_log_dir: TempDir) {
        let valid_entry = make_entry(
            "2026-02-25T10:00:00Z",
            "echo hello",
            SerializableAction::Allow,
        );
        let valid_json = serde_json::to_string(&valid_entry).unwrap();

        let content = formatdoc! {"
            {valid_json}
            {{invalid json
            {valid_json}
        "};
        let path = temp_log_dir.path().join("audit-2026-02-25.jsonl");
        fs::write(path, content).unwrap();

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let filter = AuditFilter::new();
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 2);
    }

    #[rstest]
    fn read_across_multiple_date_files(temp_log_dir: TempDir) {
        let entries_day1 = vec![make_entry(
            "2026-02-24T10:00:00Z",
            "echo day1",
            SerializableAction::Allow,
        )];
        let entries_day2 = vec![make_entry(
            "2026-02-25T10:00:00Z",
            "echo day2",
            SerializableAction::Allow,
        )];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-24.jsonl", &entries_day1);
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries_day2);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let filter = AuditFilter::new();
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "echo day2");
        assert_eq!(result[1].command, "echo day1");
    }

    #[rstest]
    fn since_filters_date_files(temp_log_dir: TempDir) {
        let entries_old = vec![make_entry(
            "2026-02-20T10:00:00Z",
            "echo old",
            SerializableAction::Allow,
        )];
        let entries_new = vec![make_entry(
            "2026-02-25T10:00:00Z",
            "echo new",
            SerializableAction::Allow,
        )];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-20.jsonl", &entries_old);
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries_new);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let now = "2026-02-25T14:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut filter = AuditFilter::new();
        filter.since = Some(TimeSpec::Absolute("2026-02-24T00:00:00Z".parse().unwrap()));
        let result = reader.read_with_now(&filter, now).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "echo new");
    }

    #[rstest]
    fn malformed_timestamp_excluded_by_time_filter(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry("not-a-timestamp", "echo bad", SerializableAction::Allow),
            make_entry(
                "2026-02-25T12:00:00Z",
                "echo good",
                SerializableAction::Allow,
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let now = "2026-02-25T14:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut filter = AuditFilter::new();
        filter.since = Some(TimeSpec::Absolute("2026-02-25T00:00:00Z".parse().unwrap()));
        let result = reader.read_with_now(&filter, now).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "echo good");
    }

    #[rstest]
    fn skip_empty_lines(temp_log_dir: TempDir) {
        let valid_entry = make_entry(
            "2026-02-25T10:00:00Z",
            "echo hello",
            SerializableAction::Allow,
        );
        let valid_json = serde_json::to_string(&valid_entry).unwrap();

        let content = formatdoc! {"
            {valid_json}

            {valid_json}
        "};
        let path = temp_log_dir.path().join("audit-2026-02-25.jsonl");
        fs::write(path, content).unwrap();

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let filter = AuditFilter::new();
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 2);
    }
}
