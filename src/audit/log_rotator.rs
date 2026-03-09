use std::path::{Path, PathBuf};

use chrono::{NaiveDate, Utc};

use super::AuditError;

const LOG_FILE_PREFIX: &str = "audit-";
const LOG_FILE_SUFFIX: &str = ".jsonl";

pub struct LogRotator {
    retention_days: u32,
}

impl LogRotator {
    pub fn new(retention_days: u32) -> Self {
        Self { retention_days }
    }

    /// Returns the log file path for today's date.
    pub fn current_log_path(&self, base_dir: &Path) -> PathBuf {
        let today = Utc::now().format("%Y-%m-%d");
        base_dir.join(format!("{LOG_FILE_PREFIX}{today}{LOG_FILE_SUFFIX}"))
    }

    /// Deletes log files older than the retention period.
    pub fn cleanup_old_files(&self, dir: &Path) -> Result<(), AuditError> {
        let cutoff =
            Utc::now().date_naive() - chrono::Duration::days(i64::from(self.retention_days));

        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };

            if let Some(date) = parse_log_date(name)
                && date < cutoff
            {
                std::fs::remove_file(entry.path())?;
            }
        }

        Ok(())
    }
}

/// Extracts the date from a log filename like `audit-2026-02-25.jsonl`.
pub(super) fn parse_log_date(filename: &str) -> Option<NaiveDate> {
    let date_str = filename
        .strip_prefix(LOG_FILE_PREFIX)?
        .strip_suffix(LOG_FILE_SUFFIX)?;
    NaiveDate::parse_from_str(date_str, "%Y-%m-%d").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tempfile::TempDir;

    #[rstest]
    fn current_log_path_contains_today_date() {
        let rotator = LogRotator::new(7);
        let dir = Path::new("/tmp/audit");
        let path = rotator.current_log_path(dir);

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let expected = format!("audit-{today}.jsonl");
        assert_eq!(
            path.file_name().and_then(|f| f.to_str()),
            Some(expected.as_str())
        );
        assert_eq!(path.parent(), Some(dir));
    }

    #[rstest]
    #[case::valid("audit-2026-02-25.jsonl", Some(NaiveDate::from_ymd_opt(2026, 2, 25).unwrap()))]
    #[case::invalid_prefix("log-2026-02-25.jsonl", None)]
    #[case::invalid_suffix("audit-2026-02-25.log", None)]
    #[case::invalid_date("audit-not-a-date.jsonl", None)]
    fn parse_log_date_cases(#[case] filename: &str, #[case] expected: Option<NaiveDate>) {
        assert_eq!(parse_log_date(filename), expected);
    }

    #[rstest]
    fn cleanup_deletes_old_files() {
        let dir = TempDir::new().unwrap();
        let rotator = LogRotator::new(3);

        // Create files with various ages
        let today = Utc::now().date_naive();
        let kept_dates = [
            today,
            today - chrono::Duration::days(1),
            today - chrono::Duration::days(3), // exactly at retention
        ];
        let deleted_dates = [
            today - chrono::Duration::days(4),
            today - chrono::Duration::days(10),
        ];

        for date in kept_dates.iter().chain(deleted_dates.iter()) {
            let name = format!("audit-{}.jsonl", date.format("%Y-%m-%d"));
            std::fs::write(dir.path().join(name), "").unwrap();
        }

        // Also create a non-audit file that should be left alone
        std::fs::write(dir.path().join("other.txt"), "").unwrap();

        rotator.cleanup_old_files(dir.path()).unwrap();

        // Files at or within retention should survive
        for date in &kept_dates {
            let name = format!("audit-{}.jsonl", date.format("%Y-%m-%d"));
            assert!(
                dir.path().join(&name).exists(),
                "expected {name} to be kept"
            );
        }

        // Old files should be deleted
        for date in &deleted_dates {
            let name = format!("audit-{}.jsonl", date.format("%Y-%m-%d"));
            assert!(
                !dir.path().join(&name).exists(),
                "expected {name} to be deleted"
            );
        }

        // Non-audit files should be untouched
        assert!(dir.path().join("other.txt").exists());
    }

    #[rstest]
    fn cleanup_nonexistent_dir_is_ok() {
        let rotator = LogRotator::new(7);
        let result = rotator.cleanup_old_files(Path::new("/nonexistent/path"));
        assert!(result.is_ok());
    }
}
