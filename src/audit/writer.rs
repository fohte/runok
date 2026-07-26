use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use fs2::FileExt;

use super::error::AuditError;
use super::log_rotator::LogRotator;
use super::model::{AskResolution, AuditEntry};
use crate::config::AuditConfig;

pub struct AuditWriter {
    config: AuditConfig,
    rotator: LogRotator,
}

impl AuditWriter {
    pub fn new(config: AuditConfig) -> Self {
        let retention_days = config.resolved_rotation().resolved_retention_days();
        let rotator = LogRotator::new(retention_days);
        Self { config, rotator }
    }

    /// Writes an audit entry as a single JSONL line.
    /// Uses flock + O_APPEND for concurrent write safety.
    pub fn write(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        self.append_record(entry)
    }

    /// Writes an ask-resolution record as a single JSONL line, into the same
    /// date-partitioned file as decision entries.
    pub fn write_resolution(&self, resolution: &AskResolution) -> Result<(), AuditError> {
        self.append_record(resolution)
    }

    fn append_record<T: serde::Serialize>(&self, record: &T) -> Result<(), AuditError> {
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
        let result = write_record(&file, record);
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

fn write_record<T: serde::Serialize>(mut file: &File, record: &T) -> Result<(), AuditError> {
    serde_json::to_writer(&mut file, record)?;
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
            timestamp: Utc::now().to_rfc3339(),
            command: command.to_string(),
            action,
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata::default(),
            command_evaluations: vec![],
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
            .write(&make_entry(
                "rm -rf /",
                SerializableAction::Deny {
                    message: None,
                    fix_suggestion: None,
                },
            ))
            .unwrap();
        writer
            .write(&make_entry(
                "terraform apply",
                SerializableAction::Ask { message: None },
            ))
            .unwrap();

        let today = Utc::now().format("%Y-%m-%d");
        let log_path = audit_dir.path().join(format!("audit-{today}.jsonl"));
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
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
            timestamp: Utc::now().to_rfc3339(),
            command: "git push".to_string(),
            action: SerializableAction::Deny {
                message: Some("force push is forbidden".to_string()),
                fix_suggestion: Some("git push origin main".to_string()),
            },
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata {
                endpoint_type: "hook".to_string(),
                session_id: Some("sess-123".to_string()),
                cwd: Some("/home/user".to_string()),
                tool_name: Some("Bash".to_string()),
                hook_event_name: Some("PreToolUse".to_string()),
                tool_use_id: Some("toolu_01".to_string()),
            },
            command_evaluations: vec![crate::audit::CommandEvaluation {
                command: "git push".to_string(),
                original_command: None,
                action: SerializableAction::Deny {
                    message: Some("force push is forbidden".to_string()),
                    fix_suggestion: Some("git push origin main".to_string()),
                },
                matched_rules: vec![crate::audit::SerializableRuleMatch {
                    action_kind: "deny".to_string(),
                    pattern: "git push -f *".to_string(),
                    matched_tokens: vec!["origin".to_string(), "main".to_string()],
                }],
                eval_type: crate::audit::EvalType::Primary,
                env: vec![],
                argv: vec!["git".to_string(), "push".to_string()],
                redirects: vec![],
                pipe: crate::audit::SerializablePipe::default(),
                alias_chain: vec![],
                require_command_in_path: None,
            }],
        };

        writer.write(&entry).unwrap();

        let today = Utc::now().format("%Y-%m-%d");
        let log_path = audit_dir.path().join(format!("audit-{today}.jsonl"));
        let content = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

        assert_eq!(parsed["command"], "git push");
        assert_eq!(parsed["action"]["type"], "deny");
        assert_eq!(
            parsed["command_evaluations"][0]["matched_rules"][0]["pattern"],
            "git push -f *"
        );
        assert_eq!(parsed["metadata"]["session_id"], "sess-123");
        assert_eq!(parsed["metadata"]["tool_name"], "Bash");
    }

    #[rstest]
    fn write_resolution_appends_to_same_file_as_entries(audit_dir: TempDir) {
        let config = make_config(&audit_dir);
        let writer = AuditWriter::new(config);

        writer
            .write(&make_entry(
                "terraform apply",
                SerializableAction::Ask { message: None },
            ))
            .unwrap();
        let resolution = crate::audit::AskResolution {
            timestamp: Utc::now().to_rfc3339(),
            outcome: crate::audit::AskResolutionOutcome::Approved,
            tool_use_id: Some("toolu_01".to_string()),
            session_id: Some("sess-123".to_string()),
            cwd: Some("/home/user".to_string()),
            command: "terraform apply".to_string(),
            executed_command: "terraform apply".to_string(),
        };
        writer.write_resolution(&resolution).unwrap();

        let today = Utc::now().format("%Y-%m-%d");
        let log_path = audit_dir.path().join(format!("audit-{today}.jsonl"));
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed: crate::audit::AskResolution = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed, resolution);
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
}
