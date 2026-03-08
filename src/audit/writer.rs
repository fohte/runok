use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use fs2::FileExt;

use super::error::AuditError;
use super::log_rotator::LogRotator;
use super::model::AuditEntry;
use crate::config::AuditConfig;

pub struct AuditWriter {
    config: AuditConfig,
    rotator: LogRotator,
}

impl AuditWriter {
    pub fn new(config: AuditConfig) -> Self {
        let rotator = LogRotator::new(config.retention_days());
        Self { config, rotator }
    }

    /// Writes an audit entry as a single JSONL line.
    /// Uses flock + O_APPEND for concurrent write safety.
    pub fn write(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        if !self.config.is_enabled() {
            return Ok(());
        }

        let base_dir = self.config.base_dir();
        std::fs::create_dir_all(&base_dir)?;
        // Restrict directory to owner-only access since logs may contain
        // sensitive arguments (API keys, tokens passed on command line).
        std::fs::set_permissions(&base_dir, Permissions::from_mode(0o700))?;

        let log_path = self.rotator.current_log_path(&base_dir);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)?;

        file.lock_exclusive()?;
        let result = write_entry(&file, entry);
        // Always unlock, even on write failure
        let _ = file.unlock();

        result?;

        // Cleanup old files; failure here is non-fatal
        if let Err(e) = self.rotator.cleanup_old_files(&base_dir) {
            eprintln!("runok: warning: audit log cleanup failed: {e}");
        }

        Ok(())
    }
}

fn write_entry(mut file: &File, entry: &AuditEntry) -> Result<(), AuditError> {
    serde_json::to_writer(&mut file, entry)?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditMetadata, SerializableAction};
    use crate::config::RotationConfig;
    use chrono::Utc;
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    #[fixture]
    fn audit_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn make_config(dir: &TempDir) -> AuditConfig {
        AuditConfig {
            enabled: Some(true),
            path: Some(dir.path().to_string_lossy().to_string()),
            rotation: Some(RotationConfig {
                retention_days: Some(7),
            }),
        }
    }

    fn make_entry(command: &str, action: SerializableAction) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now(),
            command: command.to_string(),
            action,
            matched_rule: None,
            sub_evaluations: None,
            metadata: AuditMetadata::default(),
        }
    }

    #[rstest]
    fn write_creates_jsonl_file(audit_dir: TempDir) {
        let config = make_config(&audit_dir);
        let writer = AuditWriter::new(config);
        let entry = make_entry("git status", SerializableAction::Allow);

        writer.write(&entry).unwrap();

        let today = Utc::now().format("%Y-%m-%d");
        let log_path = audit_dir.path().join(format!("audit-{today}.jsonl"));
        assert!(log_path.exists());

        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.command, "git status");
        assert_eq!(parsed.action, SerializableAction::Allow);
    }

    #[rstest]
    fn write_appends_multiple_entries(audit_dir: TempDir) {
        let config = make_config(&audit_dir);
        let writer = AuditWriter::new(config);

        writer
            .write(&make_entry("git status", SerializableAction::Allow))
            .unwrap();
        writer
            .write(&make_entry("rm -rf /", SerializableAction::Deny))
            .unwrap();
        writer
            .write(&make_entry("terraform apply", SerializableAction::Ask))
            .unwrap();

        let today = Utc::now().format("%Y-%m-%d");
        let log_path = audit_dir.path().join(format!("audit-{today}.jsonl"));
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);

        let actions: Vec<SerializableAction> = lines
            .iter()
            .map(|line| {
                let entry: AuditEntry = serde_json::from_str(line).unwrap();
                entry.action
            })
            .collect();

        assert_eq!(
            actions,
            vec![
                SerializableAction::Allow,
                SerializableAction::Deny,
                SerializableAction::Ask,
            ]
        );
    }

    #[rstest]
    fn write_skips_when_disabled(audit_dir: TempDir) {
        let config = AuditConfig {
            enabled: Some(false),
            path: Some(audit_dir.path().to_string_lossy().to_string()),
            rotation: None,
        };
        let writer = AuditWriter::new(config);
        let entry = make_entry("git status", SerializableAction::Allow);

        writer.write(&entry).unwrap();

        // No files should be created
        let entries: Vec<_> = std::fs::read_dir(audit_dir.path()).unwrap().collect();
        assert!(entries.is_empty());
    }

    #[rstest]
    fn write_creates_parent_directory(audit_dir: TempDir) {
        let nested_dir = audit_dir.path().join("nested/deep/dir");
        let config = AuditConfig {
            enabled: Some(true),
            path: Some(nested_dir.to_string_lossy().to_string()),
            rotation: Some(RotationConfig {
                retention_days: Some(7),
            }),
        };
        let writer = AuditWriter::new(config);
        let entry = make_entry("git status", SerializableAction::Allow);

        writer.write(&entry).unwrap();
        assert!(nested_dir.exists());
    }

    #[rstest]
    fn write_produces_valid_jsonl(audit_dir: TempDir) {
        let config = make_config(&audit_dir);
        let writer = AuditWriter::new(config);

        let entry = AuditEntry {
            timestamp: Utc::now(),
            command: "git push".to_string(),
            action: SerializableAction::Deny,
            matched_rule: Some(crate::audit::SerializableRuleMatch {
                pattern: "git push -f *".to_string(),
                action: SerializableAction::Deny,
            }),
            sub_evaluations: None,
            metadata: AuditMetadata {
                session_id: Some("sess-123".to_string()),
                tool_name: Some("Bash".to_string()),
                cwd: Some("/home/user".to_string()),
                subcommand: Some("hook".to_string()),
            },
        };

        writer.write(&entry).unwrap();

        let today = Utc::now().format("%Y-%m-%d");
        let log_path = audit_dir.path().join(format!("audit-{today}.jsonl"));
        let content = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

        assert_eq!(parsed["command"], "git push");
        assert_eq!(parsed["action"], "deny");
        assert_eq!(parsed["matched_rule"]["pattern"], "git push -f *");
        assert_eq!(parsed["metadata"]["session_id"], "sess-123");
        assert_eq!(parsed["metadata"]["tool_name"], "Bash");
    }

    #[rstest]
    fn write_rotation_cleans_old_files(audit_dir: TempDir) {
        let config = AuditConfig {
            enabled: Some(true),
            path: Some(audit_dir.path().to_string_lossy().to_string()),
            rotation: Some(RotationConfig {
                retention_days: Some(2),
            }),
        };

        // Create an old log file
        let old_date = (Utc::now() - chrono::Duration::days(5)).format("%Y-%m-%d");
        let old_file = audit_dir.path().join(format!("audit-{old_date}.jsonl"));
        std::fs::write(&old_file, "{}\n").unwrap();

        let writer = AuditWriter::new(config);
        writer
            .write(&make_entry("git status", SerializableAction::Allow))
            .unwrap();

        // Old file should be cleaned up
        assert!(!old_file.exists());
    }

    #[rstest]
    fn write_failure_on_invalid_path() {
        let config = AuditConfig {
            enabled: Some(true),
            path: Some("/proc/nonexistent/impossible/path".to_string()),
            rotation: None,
        };
        let writer = AuditWriter::new(config);
        let entry = make_entry("git status", SerializableAction::Allow);

        let result = writer.write(&entry);
        assert!(result.is_err());
    }

    #[rstest]
    fn metadata_omits_none_fields_in_json(audit_dir: TempDir) {
        let config = make_config(&audit_dir);
        let writer = AuditWriter::new(config);

        let entry = make_entry("ls", SerializableAction::Allow);
        writer.write(&entry).unwrap();

        let today = Utc::now().format("%Y-%m-%d");
        let log_path = audit_dir.path().join(format!("audit-{today}.jsonl"));
        let content = std::fs::read_to_string(&log_path).unwrap();

        // None fields should not appear in output
        assert!(!content.contains("session_id"));
        assert!(!content.contains("tool_name"));
        assert!(!content.contains("cwd"));
        assert!(!content.contains("subcommand"));
    }
}
