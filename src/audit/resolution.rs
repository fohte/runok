use std::path::Path;

use chrono::{DateTime, Utc};

use super::error::AuditError;
use super::model::{AskResolution, AskResolutionOutcome, AuditEntry, SerializableAction};
use super::writer::AuditWriter;
use crate::config::AuditConfig;

/// A tool call the user approved, as observed via a PostToolUse hook.
#[derive(Debug)]
pub struct ApprovedToolUse {
    /// Tool use ID from the PostToolUse input. `None` on agent versions
    /// that do not send one; correlation then falls back to session +
    /// command matching.
    pub tool_use_id: Option<String>,
    pub session_id: String,
    pub cwd: String,
    /// The command the agent executed (`tool_input.command`). When the
    /// PreToolUse response rewrote the command via `updatedInput`, this is
    /// the rewritten form, not the original.
    pub executed_command: String,
}

/// Correlate an approved tool call with the ask decision entry runok wrote
/// at PreToolUse time and append an `ask_resolution` record.
///
/// Returns the written record, or `None` when no matching unresolved ask
/// entry was found. `None` is the common case: PostToolUse fires for every
/// Bash call, including allowed ones, and recording those unconditionally
/// would double the log volume.
///
/// Only today's and yesterday's log files are scanned (two files cover an
/// ask spanning midnight); a dialog approved after sitting open longer than
/// that is not worth a full log scan on every Bash call.
pub fn record_approval(
    config: &AuditConfig,
    approval: &ApprovedToolUse,
) -> Result<Option<AskResolution>, AuditError> {
    let base_dir = config.base_dir();
    // Every relevant line carries the correlation key verbatim, so a
    // substring check narrows candidates without parsing each line.
    let needle = approval
        .tool_use_id
        .as_deref()
        .unwrap_or(&approval.session_id);
    let (entries, resolutions) = scan_recent_records(&base_dir, needle);

    let matched = match &approval.tool_use_id {
        Some(id) => find_unresolved_by_tool_use_id(&entries, &resolutions, id),
        None => find_unresolved_by_session(&entries, &resolutions, approval),
    };
    let Some(entry) = matched else {
        return Ok(None);
    };

    let record = AskResolution {
        timestamp: Utc::now().to_rfc3339(),
        outcome: AskResolutionOutcome::Approved,
        tool_use_id: approval
            .tool_use_id
            .clone()
            .or_else(|| entry.metadata.tool_use_id.clone()),
        session_id: Some(approval.session_id.clone()),
        cwd: Some(approval.cwd.clone()),
        command: entry.command.clone(),
        executed_command: approval.executed_command.clone(),
    };
    AuditWriter::new(config.clone()).write_resolution(&record)?;
    Ok(Some(record))
}

/// Whether an ask decision entry has a matching approval record.
///
/// Correlation uses `tool_use_id` when the entry has one; otherwise it falls
/// back to session + command matching, requiring the resolution to be no
/// older than the entry (a resolution cannot precede its ask).
///
/// The fallback is best-effort: when the same command is asked several times
/// in one session, an approval can also match an earlier ask the user
/// denied, because denials leave no record to disambiguate with. Only agents
/// that send no `tool_use_id` are affected.
pub fn is_approved(entry: &AuditEntry, resolutions: &[AskResolution]) -> bool {
    if !is_ask(entry) {
        return false;
    }
    match entry.metadata.tool_use_id.as_deref() {
        Some(id) => resolutions
            .iter()
            .any(|r| r.tool_use_id.as_deref() == Some(id)),
        None => {
            let Some(session) = entry.metadata.session_id.as_deref() else {
                return false;
            };
            resolutions.iter().any(|r| {
                r.session_id.as_deref() == Some(session)
                    && r.command == entry.command
                    && timestamp_ge(&r.timestamp, &entry.timestamp)
            })
        }
    }
}

fn is_ask(entry: &AuditEntry) -> bool {
    matches!(entry.action, SerializableAction::Ask { .. })
}

/// Whether timestamp `a` is at or after timestamp `b`. Falls back to
/// lexicographic comparison when either side is not RFC 3339.
fn timestamp_ge(a: &str, b: &str) -> bool {
    match (a.parse::<DateTime<Utc>>(), b.parse::<DateTime<Utc>>()) {
        (Ok(a), Ok(b)) => a >= b,
        _ => a >= b,
    }
}

/// Scan today's and yesterday's audit files for records whose raw line
/// contains `needle`, split into decision entries and resolutions.
///
/// Unreadable files and unparseable lines are skipped: recording a
/// resolution is best-effort and must never fail the hook.
fn scan_recent_records(base_dir: &Path, needle: &str) -> (Vec<AuditEntry>, Vec<AskResolution>) {
    let today = Utc::now().date_naive();
    let dates = [today - chrono::Duration::days(1), today];

    let mut entries = Vec::new();
    let mut resolutions = Vec::new();
    for date in dates {
        let path = base_dir.join(format!("audit-{}.jsonl", date.format("%Y-%m-%d")));
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            if !line.contains(needle) {
                continue;
            }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            match value.get("kind").and_then(|k| k.as_str()) {
                Some("ask_resolution") => {
                    if let Ok(r) = serde_json::from_value::<AskResolution>(value) {
                        resolutions.push(r);
                    }
                }
                // Unknown record kinds from newer runok versions.
                Some(_) => {}
                None => {
                    if let Ok(e) = serde_json::from_value::<AuditEntry>(value) {
                        entries.push(e);
                    }
                }
            }
        }
    }
    (entries, resolutions)
}

// Both finders reuse `is_approved` as the already-resolved check so the
// display join and the duplicate-write guard cannot silently diverge.

fn find_unresolved_by_tool_use_id<'a>(
    entries: &'a [AuditEntry],
    resolutions: &[AskResolution],
    tool_use_id: &str,
) -> Option<&'a AuditEntry> {
    entries.iter().rev().find(|e| {
        is_ask(e)
            && e.metadata.tool_use_id.as_deref() == Some(tool_use_id)
            && !is_approved(e, resolutions)
    })
}

fn find_unresolved_by_session<'a>(
    entries: &'a [AuditEntry],
    resolutions: &[AskResolution],
    approval: &ApprovedToolUse,
) -> Option<&'a AuditEntry> {
    entries.iter().rev().find(|e| {
        is_ask(e)
            && e.metadata.session_id.as_deref() == Some(approval.session_id.as_str())
            && command_matches(e, &approval.executed_command)
            && !is_approved(e, resolutions)
    })
}

/// The executed command matches the entry either verbatim or after
/// unwrapping the `runok exec --sandbox <preset> -- <command>` rewrite that
/// the PreToolUse hook applies via `updatedInput`.
fn command_matches(entry: &AuditEntry, executed: &str) -> bool {
    if entry.command == executed {
        return true;
    }
    unwrap_sandbox_exec(executed).is_some_and(|inner| inner == entry.command)
}

fn unwrap_sandbox_exec(executed: &str) -> Option<String> {
    let tokens = shlex::split(executed)?;
    match tokens.as_slice() {
        [runok, exec, flag, _preset, sep, command]
            if runok == "runok" && exec == "exec" && flag == "--sandbox" && sep == "--" =>
        {
            Some(command.clone())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    use super::*;
    use crate::audit::AuditMetadata;

    #[fixture]
    fn audit_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    fn make_config(dir: &TempDir) -> AuditConfig {
        AuditConfig {
            enabled: Some(true),
            path: Some(dir.path().to_string_lossy().to_string()),
            rotation: None,
        }
    }

    fn ask_entry(
        timestamp: &str,
        command: &str,
        session_id: &str,
        tool_use_id: Option<&str>,
    ) -> AuditEntry {
        AuditEntry {
            timestamp: timestamp.to_owned(),
            command: command.to_owned(),
            action: SerializableAction::Ask { message: None },
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata {
                endpoint_type: "hook".to_owned(),
                session_id: Some(session_id.to_owned()),
                cwd: Some("/tmp".to_owned()),
                tool_name: Some("Bash".to_owned()),
                hook_event_name: Some("PreToolUse".to_owned()),
                tool_use_id: tool_use_id.map(str::to_owned),
            },
            command_evaluations: vec![],
        }
    }

    fn allow_entry(command: &str, tool_use_id: Option<&str>) -> AuditEntry {
        AuditEntry {
            action: SerializableAction::Allow,
            ..ask_entry("2026-07-08T10:00:00Z", command, "sess-1", tool_use_id)
        }
    }

    fn write_today_file(dir: &TempDir, records: &[serde_json::Value]) {
        write_dated_file(dir, Utc::now().date_naive(), records);
    }

    fn write_dated_file(dir: &TempDir, date: chrono::NaiveDate, records: &[serde_json::Value]) {
        let path = dir
            .path()
            .join(format!("audit-{}.jsonl", date.format("%Y-%m-%d")));
        let mut content = String::new();
        for record in records {
            content.push_str(&record.to_string());
            content.push('\n');
        }
        std::fs::write(path, content).unwrap();
    }

    fn to_value<T: serde::Serialize>(record: &T) -> serde_json::Value {
        serde_json::to_value(record).unwrap()
    }

    fn approval(tool_use_id: Option<&str>, executed_command: &str) -> ApprovedToolUse {
        ApprovedToolUse {
            tool_use_id: tool_use_id.map(str::to_owned),
            session_id: "sess-1".to_owned(),
            cwd: "/tmp".to_owned(),
            executed_command: executed_command.to_owned(),
        }
    }

    /// Normalize the dynamic timestamp so the whole record can be asserted
    /// with a single equality check.
    fn normalize_timestamp(mut resolution: AskResolution) -> AskResolution {
        resolution.timestamp = "TIMESTAMP".to_owned();
        resolution
    }

    // The sandbox_wrapped case covers updatedInput rewrites: the executed
    // command differs from the original and is recorded separately.
    #[rstest]
    #[case::verbatim("terraform apply")]
    #[case::sandbox_wrapped("runok exec --sandbox restricted -- 'terraform apply'")]
    fn approval_with_matching_tool_use_id_writes_resolution(
        audit_dir: TempDir,
        #[case] executed_command: &str,
    ) {
        let entry = ask_entry(
            "2026-07-08T10:00:00Z",
            "terraform apply",
            "sess-1",
            Some("toolu_01"),
        );
        write_today_file(&audit_dir, &[to_value(&entry)]);

        let config = make_config(&audit_dir);
        let written = record_approval(&config, &approval(Some("toolu_01"), executed_command))
            .unwrap()
            .unwrap();

        assert_eq!(
            normalize_timestamp(written),
            AskResolution {
                timestamp: "TIMESTAMP".to_owned(),
                outcome: AskResolutionOutcome::Approved,
                tool_use_id: Some("toolu_01".to_owned()),
                session_id: Some("sess-1".to_owned()),
                cwd: Some("/tmp".to_owned()),
                command: "terraform apply".to_owned(),
                executed_command: executed_command.to_owned(),
            },
        );

        // The record is appended to the same file after the decision entry.
        let today = Utc::now().format("%Y-%m-%d");
        let content =
            std::fs::read_to_string(audit_dir.path().join(format!("audit-{today}.jsonl"))).unwrap();
        assert_eq!(content.lines().count(), 2);
    }

    #[rstest]
    #[case::no_matching_entry(vec![], Some("toolu_01"), "terraform apply")]
    #[case::allowed_entry_is_not_an_ask(
        vec![to_value(&allow_entry("terraform apply", Some("toolu_01")))],
        Some("toolu_01"),
        "terraform apply",
    )]
    #[case::different_tool_use_id(
        vec![to_value(&ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-1", Some("toolu_01")))],
        Some("toolu_99"),
        "terraform apply",
    )]
    #[case::fallback_different_session(
        vec![to_value(&ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-other", None))],
        None,
        "terraform apply",
    )]
    #[case::fallback_different_command(
        vec![to_value(&ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-1", None))],
        None,
        "terraform destroy",
    )]
    fn approval_without_matching_ask_writes_nothing(
        audit_dir: TempDir,
        #[case] records: Vec<serde_json::Value>,
        #[case] tool_use_id: Option<&str>,
        #[case] executed_command: &str,
    ) {
        write_today_file(&audit_dir, &records);
        let line_count_before = records.len();

        let config = make_config(&audit_dir);
        let written = record_approval(&config, &approval(tool_use_id, executed_command)).unwrap();

        assert_eq!(written, None);
        let today = Utc::now().format("%Y-%m-%d");
        let content =
            std::fs::read_to_string(audit_dir.path().join(format!("audit-{today}.jsonl"))).unwrap();
        assert_eq!(content.lines().count(), line_count_before);
    }

    #[rstest]
    fn approval_is_not_recorded_twice_for_same_tool_use_id(audit_dir: TempDir) {
        let entry = ask_entry(
            "2026-07-08T10:00:00Z",
            "terraform apply",
            "sess-1",
            Some("toolu_01"),
        );
        write_today_file(&audit_dir, &[to_value(&entry)]);

        let config = make_config(&audit_dir);
        let first =
            record_approval(&config, &approval(Some("toolu_01"), "terraform apply")).unwrap();
        let second =
            record_approval(&config, &approval(Some("toolu_01"), "terraform apply")).unwrap();

        assert!(first.is_some());
        assert_eq!(second, None);
    }

    #[rstest]
    fn approval_matches_ask_from_yesterday(audit_dir: TempDir) {
        let entry = ask_entry(
            "2026-07-07T23:59:00Z",
            "terraform apply",
            "sess-1",
            Some("toolu_01"),
        );
        write_dated_file(
            &audit_dir,
            Utc::now().date_naive() - chrono::Duration::days(1),
            &[to_value(&entry)],
        );

        let config = make_config(&audit_dir);
        let written =
            record_approval(&config, &approval(Some("toolu_01"), "terraform apply")).unwrap();

        assert!(written.is_some());
    }

    #[rstest]
    #[case::verbatim("terraform apply")]
    #[case::sandbox_wrapped("runok exec --sandbox restricted -- 'terraform apply'")]
    fn approval_without_tool_use_id_falls_back_to_session_and_command(
        audit_dir: TempDir,
        #[case] executed_command: &str,
    ) {
        // The entry timestamp must be in the past: the fallback join
        // requires the resolution (written at "now") to be no older than
        // its ask.
        let entry = ask_entry("2020-01-01T00:00:00Z", "terraform apply", "sess-1", None);
        write_today_file(&audit_dir, &[to_value(&entry)]);

        let config = make_config(&audit_dir);
        let written = record_approval(&config, &approval(None, executed_command))
            .unwrap()
            .unwrap();

        assert_eq!(
            normalize_timestamp(written),
            AskResolution {
                timestamp: "TIMESTAMP".to_owned(),
                outcome: AskResolutionOutcome::Approved,
                tool_use_id: None,
                session_id: Some("sess-1".to_owned()),
                cwd: Some("/tmp".to_owned()),
                command: "terraform apply".to_owned(),
                executed_command: executed_command.to_owned(),
            },
        );
    }

    #[rstest]
    fn fallback_skips_already_resolved_ask(audit_dir: TempDir) {
        let entry = ask_entry("2020-01-01T00:00:00Z", "terraform apply", "sess-1", None);
        write_today_file(&audit_dir, &[to_value(&entry)]);

        let config = make_config(&audit_dir);
        let first = record_approval(&config, &approval(None, "terraform apply")).unwrap();
        let second = record_approval(&config, &approval(None, "terraform apply")).unwrap();

        assert!(first.is_some());
        assert_eq!(second, None);
    }

    #[rstest]
    fn missing_audit_files_write_nothing(audit_dir: TempDir) {
        let config = make_config(&audit_dir);
        let written =
            record_approval(&config, &approval(Some("toolu_01"), "terraform apply")).unwrap();
        assert_eq!(written, None);
    }

    // --- is_approved ---

    fn resolution_for(tool_use_id: Option<&str>, command: &str, timestamp: &str) -> AskResolution {
        AskResolution {
            timestamp: timestamp.to_owned(),
            outcome: AskResolutionOutcome::Approved,
            tool_use_id: tool_use_id.map(str::to_owned),
            session_id: Some("sess-1".to_owned()),
            cwd: Some("/tmp".to_owned()),
            command: command.to_owned(),
            executed_command: command.to_owned(),
        }
    }

    #[rstest]
    #[case::matching_tool_use_id(
        ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-1", Some("toolu_01")),
        vec![resolution_for(Some("toolu_01"), "terraform apply", "2026-07-08T10:01:00Z")],
        true,
    )]
    #[case::different_tool_use_id(
        ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-1", Some("toolu_01")),
        vec![resolution_for(Some("toolu_99"), "terraform apply", "2026-07-08T10:01:00Z")],
        false,
    )]
    #[case::non_ask_entry(
        allow_entry("terraform apply", Some("toolu_01")),
        vec![resolution_for(Some("toolu_01"), "terraform apply", "2026-07-08T10:01:00Z")],
        false,
    )]
    #[case::fallback_session_and_command(
        ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-1", None),
        vec![resolution_for(None, "terraform apply", "2026-07-08T10:01:00Z")],
        true,
    )]
    #[case::fallback_resolution_older_than_ask(
        ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-1", None),
        vec![resolution_for(None, "terraform apply", "2026-07-08T09:00:00Z")],
        false,
    )]
    #[case::no_resolutions(
        ask_entry("2026-07-08T10:00:00Z", "terraform apply", "sess-1", Some("toolu_01")),
        vec![],
        false,
    )]
    fn is_approved_joins_entry_with_resolutions(
        #[case] entry: AuditEntry,
        #[case] resolutions: Vec<AskResolution>,
        #[case] expected: bool,
    ) {
        assert_eq!(is_approved(&entry, &resolutions), expected);
    }

    // --- unwrap_sandbox_exec ---

    #[rstest]
    #[case::wrapped(
        "runok exec --sandbox restricted -- 'terraform apply'",
        Some("terraform apply")
    )]
    #[case::plain_command("terraform apply", None)]
    #[case::different_binary("sudo exec --sandbox x -- ls", None)]
    #[case::missing_separator("runok exec --sandbox restricted 'terraform apply'", None)]
    #[case::extra_tokens("runok exec --sandbox restricted -- terraform apply", None)]
    fn unwrap_sandbox_exec_extracts_inner_command(
        #[case] executed: &str,
        #[case] expected: Option<&str>,
    ) {
        assert_eq!(unwrap_sandbox_exec(executed), expected.map(str::to_owned),);
    }
}
