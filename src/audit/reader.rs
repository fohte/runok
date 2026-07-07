use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use super::filter::AuditFilter;
use super::log_rotator::parse_log_date;
use super::model::{AskResolution, AuditEntry, SerializableAction};
use crate::config::ActionKind;

/// The `kind` tag value of ask-resolution JSONL lines.
const ASK_RESOLUTION_KIND: &str = "ask_resolution";

/// Extract the top-level `kind` tag from a JSONL line, if any.
///
/// Decision entries have no `kind`; other record types (e.g.
/// `ask_resolution`) carry one so readers can dispatch without fully
/// parsing the line.
fn parse_kind(line: &str) -> Option<String> {
    /// Lightweight view of a record that only captures the `kind` tag.
    #[derive(serde::Deserialize)]
    struct RecordKind {
        kind: Option<String>,
    }
    serde_json::from_str::<RecordKind>(line).ok()?.kind
}

/// Time-resolved filter criteria ready for matching against entries.
struct ResolvedFilter<'a> {
    action: &'a Option<ActionKind>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    command_pattern: &'a Option<String>,
    cwd: &'a Option<String>,
}

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
    /// Returns entries sorted by timestamp in ascending order (oldest first).
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
        let resolved = ResolvedFilter {
            action: &filter.action,
            since: filter.since.as_ref().map(|ts| ts.resolve(now)),
            until: filter.until.as_ref().map(|ts| ts.resolve(now)),
            command_pattern: &filter.command_pattern,
            cwd: &filter.cwd,
        };

        let date_files = self.collect_date_files(resolved.since)?;

        let mut entries = Vec::new();

        for path in &date_files {
            self.read_file(path, &resolved, &mut entries)?;
        }

        // Partial sort: find the newest `limit` entries, then sort ascending (oldest first)
        let newest_first = |a: &AuditEntry, b: &AuditEntry| b.timestamp.cmp(&a.timestamp);
        if entries.len() > filter.limit {
            entries.select_nth_unstable_by(filter.limit, newest_first);
            entries.truncate(filter.limit);
        }
        let oldest_first = |a: &AuditEntry, b: &AuditEntry| a.timestamp.cmp(&b.timestamp);
        entries.sort_by(oldest_first);

        Ok(entries)
    }

    /// Read ask-resolution records matching the given filter.
    ///
    /// Applies the time, command-pattern, and cwd criteria. The action
    /// criterion does not apply (resolutions only exist for asks), and
    /// `limit` is intentionally ignored: resolutions are joined to decision
    /// entries by the caller, and trimming them independently would break
    /// the join.
    ///
    /// Returns records sorted by timestamp in ascending order.
    pub fn read_resolutions(
        &self,
        filter: &AuditFilter,
    ) -> Result<Vec<AskResolution>, anyhow::Error> {
        let now = Utc::now();
        self.read_resolutions_with_now(filter, now)
    }

    fn read_resolutions_with_now(
        &self,
        filter: &AuditFilter,
        now: DateTime<Utc>,
    ) -> Result<Vec<AskResolution>, anyhow::Error> {
        let resolved = ResolvedFilter {
            action: &None,
            since: filter.since.as_ref().map(|ts| ts.resolve(now)),
            until: filter.until.as_ref().map(|ts| ts.resolve(now)),
            command_pattern: &filter.command_pattern,
            cwd: &filter.cwd,
        };

        let date_files = self.collect_date_files(resolved.since)?;

        let mut resolutions = Vec::new();
        for path in &date_files {
            self.read_resolutions_from_file(path, &resolved, &mut resolutions)?;
        }

        resolutions.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(resolutions)
    }

    /// Read ask-resolution records from a single JSONL file, applying filters.
    fn read_resolutions_from_file(
        &self,
        path: &Path,
        resolved: &ResolvedFilter,
        resolutions: &mut Vec<AskResolution>,
    ) -> Result<(), anyhow::Error> {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);

        for (line_num, line_result) in reader.lines().enumerate() {
            let Ok(line) = line_result else { continue };
            // Cheap pre-filter before JSON parsing; false positives (the
            // string appearing inside a command) are rejected by the kind
            // check below.
            if !line.contains(ASK_RESOLUTION_KIND) {
                continue;
            }
            if parse_kind(&line).as_deref() != Some(ASK_RESOLUTION_KIND) {
                continue;
            }

            let resolution: AskResolution = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "runok: warning: skipping corrupted ask_resolution at line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            if !Self::matches_resolution_filter(&resolution, resolved) {
                continue;
            }

            resolutions.push(resolution);
        }

        Ok(())
    }

    fn matches_resolution_filter(resolution: &AskResolution, filter: &ResolvedFilter) -> bool {
        if !Self::within_time_bounds(&resolution.timestamp, filter.since, filter.until) {
            return false;
        }

        if let Some(pattern) = filter.command_pattern
            && !resolution.command.contains(pattern.as_str())
        {
            return false;
        }

        if let Some(filter_cwd) = filter.cwd {
            match &resolution.cwd {
                Some(cwd) => {
                    if !Path::new(cwd).starts_with(filter_cwd) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    /// Check a record timestamp against the resolved time bounds.
    /// Malformed timestamps cannot satisfy time filters.
    fn within_time_bounds(
        timestamp: &str,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
    ) -> bool {
        if since.is_none() && until.is_none() {
            return true;
        }
        match timestamp.parse::<DateTime<Utc>>() {
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
                true
            }
            Err(_) => false,
        }
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
        resolved: &ResolvedFilter,
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
                    // Lines with a `kind` tag are other record types sharing
                    // the file (e.g. ask_resolution), not corrupted entries.
                    if parse_kind(&line).is_some() {
                        continue;
                    }
                    eprintln!(
                        "runok: warning: skipping corrupted entry at line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        e
                    );
                    continue;
                }
            };

            if !Self::matches_filter(&entry, resolved) {
                continue;
            }

            entries.push(entry);
        }

        Ok(())
    }

    fn matches_filter(entry: &AuditEntry, filter: &ResolvedFilter) -> bool {
        if !Self::within_time_bounds(&entry.timestamp, filter.since, filter.until) {
            return false;
        }

        // Check action filter
        if let Some(action_kind) = filter.action
            && !Self::action_matches(&entry.action, action_kind)
        {
            return false;
        }

        // Check command pattern (substring match)
        if let Some(pattern) = filter.command_pattern
            && !entry.command.contains(pattern.as_str())
        {
            return false;
        }

        // Check cwd filter (prefix match, includes subdirectories)
        if let Some(filter_cwd) = filter.cwd {
            match &entry.metadata.cwd {
                Some(entry_cwd) => {
                    if !Path::new(entry_cwd).starts_with(filter_cwd) {
                        return false;
                    }
                }
                None => return false,
            }
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
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata::default(),
            command_evaluations: vec![],
        }
    }

    fn make_entry_with_cwd(
        timestamp: &str,
        command: &str,
        action: SerializableAction,
        cwd: Option<&str>,
    ) -> AuditEntry {
        AuditEntry {
            metadata: AuditMetadata {
                cwd: cwd.map(|s| s.to_owned()),
                ..AuditMetadata::default()
            },
            ..make_entry(timestamp, command, action)
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
    fn read_entries_sorted_ascending(temp_log_dir: TempDir) {
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
        assert_eq!(result[0].command, "echo first");
        assert_eq!(result[1].command, "echo second");
        assert_eq!(result[2].command, "echo third");
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
        assert_eq!(result[0].command, "git push origin main");
        assert_eq!(result[1].command, "git pull");
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
        assert_eq!(result[0].command, "echo day1");
        assert_eq!(result[1].command, "echo day2");
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
    fn filter_by_cwd(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry_with_cwd(
                "2026-02-25T10:00:00Z",
                "echo project",
                SerializableAction::Allow,
                Some("/home/user/project"),
            ),
            make_entry_with_cwd(
                "2026-02-25T11:00:00Z",
                "echo subdir",
                SerializableAction::Allow,
                Some("/home/user/project/src"),
            ),
            make_entry_with_cwd(
                "2026-02-25T12:00:00Z",
                "echo other",
                SerializableAction::Allow,
                Some("/home/user/other"),
            ),
            make_entry_with_cwd(
                "2026-02-25T13:00:00Z",
                "echo no-cwd",
                SerializableAction::Allow,
                None,
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let mut filter = AuditFilter::new();
        filter.cwd = Some("/home/user/project".to_owned());
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "echo project");
        assert_eq!(result[1].command, "echo subdir");
    }

    #[rstest]
    fn filter_by_cwd_root_directory(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry_with_cwd(
                "2026-02-25T10:00:00Z",
                "echo root",
                SerializableAction::Allow,
                Some("/"),
            ),
            make_entry_with_cwd(
                "2026-02-25T11:00:00Z",
                "echo subdir",
                SerializableAction::Allow,
                Some("/home/user"),
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let mut filter = AuditFilter::new();
        filter.cwd = Some("/".to_owned());
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "echo root");
        assert_eq!(result[1].command, "echo subdir");
    }

    #[rstest]
    fn filter_by_cwd_no_false_prefix_match(temp_log_dir: TempDir) {
        let entries = vec![
            make_entry_with_cwd(
                "2026-02-25T10:00:00Z",
                "echo project",
                SerializableAction::Allow,
                Some("/home/user/project"),
            ),
            make_entry_with_cwd(
                "2026-02-25T11:00:00Z",
                "echo project2",
                SerializableAction::Allow,
                Some("/home/user/project2"),
            ),
        ];
        write_jsonl(temp_log_dir.path(), "audit-2026-02-25.jsonl", &entries);

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let mut filter = AuditFilter::new();
        filter.cwd = Some("/home/user/project".to_owned());
        let result = reader.read(&filter).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, "echo project");
    }

    fn make_resolution(timestamp: &str, command: &str, cwd: Option<&str>) -> AskResolution {
        AskResolution {
            timestamp: timestamp.to_owned(),
            outcome: crate::audit::AskResolutionOutcome::Approved,
            tool_use_id: Some("toolu_01".to_owned()),
            session_id: Some("sess-1".to_owned()),
            cwd: cwd.map(str::to_owned),
            command: command.to_owned(),
            executed_command: command.to_owned(),
        }
    }

    fn write_mixed_jsonl(
        dir: &Path,
        filename: &str,
        entries: &[AuditEntry],
        resolutions: &[AskResolution],
    ) {
        let path = dir.join(filename);
        let mut content = String::new();
        for entry in entries {
            content.push_str(&serde_json::to_string(entry).unwrap());
            content.push('\n');
        }
        for resolution in resolutions {
            content.push_str(&serde_json::to_string(resolution).unwrap());
            content.push('\n');
        }
        fs::write(path, content).unwrap();
    }

    #[rstest]
    fn read_skips_ask_resolution_lines(temp_log_dir: TempDir) {
        let entries = vec![make_entry(
            "2026-02-25T10:00:00Z",
            "terraform apply",
            SerializableAction::Ask { message: None },
        )];
        let resolutions = vec![make_resolution(
            "2026-02-25T10:01:00Z",
            "terraform apply",
            Some("/tmp"),
        )];
        write_mixed_jsonl(
            temp_log_dir.path(),
            "audit-2026-02-25.jsonl",
            &entries,
            &resolutions,
        );

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let result = reader.read(&AuditFilter::new()).unwrap();

        assert_eq!(result, entries);
    }

    #[rstest]
    fn read_resolutions_returns_sorted_records(temp_log_dir: TempDir) {
        let entries = vec![make_entry(
            "2026-02-25T10:00:00Z",
            "terraform apply",
            SerializableAction::Ask { message: None },
        )];
        let resolutions = vec![
            make_resolution("2026-02-25T12:00:00Z", "terraform apply", Some("/tmp")),
            make_resolution("2026-02-25T10:01:00Z", "git push", Some("/tmp")),
        ];
        write_mixed_jsonl(
            temp_log_dir.path(),
            "audit-2026-02-25.jsonl",
            &entries,
            &resolutions,
        );

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let result = reader.read_resolutions(&AuditFilter::new()).unwrap();

        assert_eq!(result, vec![resolutions[1].clone(), resolutions[0].clone()]);
    }

    #[rstest]
    #[case::command_pattern(
        AuditFilter {
            command_pattern: Some("terraform".to_owned()),
            ..AuditFilter::new()
        },
        vec![make_resolution("2026-02-25T10:01:00Z", "terraform apply", Some("/tmp"))],
    )]
    #[case::cwd_prefix(
        AuditFilter {
            cwd: Some("/home/user/project".to_owned()),
            ..AuditFilter::new()
        },
        vec![make_resolution("2026-02-25T11:01:00Z", "git push", Some("/home/user/project/src"))],
    )]
    fn read_resolutions_applies_filters(
        temp_log_dir: TempDir,
        #[case] filter: AuditFilter,
        #[case] expected: Vec<AskResolution>,
    ) {
        let resolutions = vec![
            make_resolution("2026-02-25T10:01:00Z", "terraform apply", Some("/tmp")),
            make_resolution(
                "2026-02-25T11:01:00Z",
                "git push",
                Some("/home/user/project/src"),
            ),
        ];
        write_mixed_jsonl(
            temp_log_dir.path(),
            "audit-2026-02-25.jsonl",
            &[],
            &resolutions,
        );

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let result = reader.read_resolutions(&filter).unwrap();

        assert_eq!(result, expected);
    }

    #[rstest]
    fn read_resolutions_applies_time_filter(temp_log_dir: TempDir) {
        let resolutions = vec![
            make_resolution("2026-02-25T08:00:00Z", "echo old", Some("/tmp")),
            make_resolution("2026-02-25T12:00:00Z", "echo new", Some("/tmp")),
        ];
        write_mixed_jsonl(
            temp_log_dir.path(),
            "audit-2026-02-25.jsonl",
            &[],
            &resolutions,
        );

        let reader = AuditReader::new(temp_log_dir.path().to_path_buf());
        let now = "2026-02-25T14:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut filter = AuditFilter::new();
        filter.since = Some(TimeSpec::Absolute("2026-02-25T10:00:00Z".parse().unwrap()));
        let result = reader.read_resolutions_with_now(&filter, now).unwrap();

        assert_eq!(result, vec![resolutions[1].clone()]);
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
