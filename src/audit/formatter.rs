use std::io::{self, IsTerminal, Write};

use chrono::{DateTime, Local, Utc};
use owo_colors::{OwoColorize, Stream::Stdout};
use terminal_size::{Width, terminal_size};

use super::model::{AuditEntry, SerializableAction};

/// Format and print audit entries to stdout.
///
/// In TTY mode: prints a table with ANSI colors, truncating the COMMAND column
/// to fit the terminal width.
/// In non-TTY mode: prints tab-separated values without colors or truncation.
pub fn print_entries(entries: &[AuditEntry]) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    if stdout.is_terminal() {
        print_table(&mut out, entries);
    } else {
        print_tsv(&mut out, entries);
    }
}

fn action_str(action: &SerializableAction) -> &'static str {
    match action {
        SerializableAction::Allow => "allow",
        SerializableAction::Deny { .. } => "deny",
        SerializableAction::Ask { .. } => "ask",
        SerializableAction::Default => "default",
    }
}

fn format_timestamp_local(ts: &str) -> String {
    ts.parse::<DateTime<Utc>>()
        .map(|dt| {
            dt.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|_| ts.to_owned())
}

fn escape_control_chars(s: &str) -> String {
    s.replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn print_table(out: &mut impl Write, entries: &[AuditEntry]) {
    if entries.is_empty() {
        return;
    }

    let term_width = terminal_size()
        .map(|(Width(w), _)| w as usize)
        .unwrap_or(80);

    // Column widths: TIMESTAMP is fixed 19 chars ("2026-03-13 10:30:00"),
    // ACTION is fixed 7 chars ("default" is longest)
    let ts_width = 19;
    let action_width = 7;
    // Gaps between columns (2 spaces each, 2 gaps)
    let gap = 2;
    let fixed_width = ts_width + gap + action_width + gap;

    // Header
    let _ = writeln!(
        out,
        "{}",
        format!(
            "{:<ts_w$}  {:<act_w$}  COMMAND",
            "TIMESTAMP",
            "ACTION",
            ts_w = ts_width,
            act_w = action_width,
        )
        .if_supports_color(Stdout, |t| t.bold())
    );

    for entry in entries {
        let ts = format_timestamp_local(&entry.timestamp);
        let action = action_str(&entry.action);
        let command = escape_control_chars(&entry.command);

        // Truncate command to fit terminal width, respecting UTF-8 char boundaries
        let command_max = term_width.saturating_sub(fixed_width);
        let command_display = if command.len() <= command_max {
            command
        } else if command_max > 3 {
            let target = command_max - 3;
            let mut end = target;
            while !command.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &command[..end])
        } else {
            let mut end = command_max;
            while !command.is_char_boundary(end) {
                end -= 1;
            }
            command[..end].to_string()
        };

        // Pad action string first, then colorize to avoid ANSI escape codes
        // breaking the column alignment
        let padded_action = format!("{:<width$}", action, width = action_width);
        let colored_action = match &entry.action {
            SerializableAction::Allow => padded_action
                .if_supports_color(Stdout, |t| t.green())
                .to_string(),
            SerializableAction::Deny { .. } => padded_action
                .if_supports_color(Stdout, |t| t.red())
                .to_string(),
            SerializableAction::Ask { .. } => padded_action
                .if_supports_color(Stdout, |t| t.yellow())
                .to_string(),
            SerializableAction::Default => padded_action
                .if_supports_color(Stdout, |t| t.bright_black())
                .to_string(),
        };

        let _ = writeln!(
            out,
            "{:<ts_w$}  {}  {}",
            ts,
            colored_action,
            command_display,
            ts_w = ts_width,
        );
    }
}

fn print_tsv(out: &mut impl Write, entries: &[AuditEntry]) {
    for entry in entries {
        let ts = format_timestamp_local(&entry.timestamp);
        let action = action_str(&entry.action);
        let command = escape_control_chars(&entry.command);
        let _ = writeln!(out, "{}\t{}\t{}", ts, action, command);
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::audit::AuditMetadata;

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

    #[rstest]
    #[case::allow("allow", SerializableAction::Allow)]
    #[case::deny("deny", SerializableAction::Deny { message: None, fix_suggestion: None })]
    #[case::ask("ask", SerializableAction::Ask { message: None })]
    #[case::default("default", SerializableAction::Default)]
    fn test_action_str(#[case] expected: &str, #[case] action: SerializableAction) {
        assert_eq!(action_str(&action), expected);
    }

    #[rstest]
    #[case::no_control_chars("echo hello", "echo hello")]
    #[case::with_newline("echo\nhello", "echo\\nhello")]
    #[case::with_cr("echo\r\nhello", "echo\\r\\nhello")]
    #[case::with_tab("echo\thello", "echo\\thello")]
    fn test_escape_control_chars(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(escape_control_chars(input), expected);
    }

    #[test]
    fn test_print_tsv_format() {
        let entries = vec![
            make_entry(
                "2026-03-13T10:30:00Z",
                "git push origin main",
                SerializableAction::Allow,
            ),
            make_entry(
                "2026-03-13T11:00:00Z",
                "rm -rf /",
                SerializableAction::Deny {
                    message: None,
                    fix_suggestion: None,
                },
            ),
        ];

        let mut buf = Vec::new();
        print_tsv(&mut buf, &entries);
        let output = String::from_utf8(buf).unwrap();

        // TSV should have 3 tab-separated columns per line, no header
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert_eq!(line.split('\t').count(), 3);
        }
    }

    #[test]
    fn test_print_tsv_escapes_newlines() {
        let entries = vec![make_entry(
            "2026-03-13T10:30:00Z",
            "bash -c 'echo\nhello'",
            SerializableAction::Allow,
        )];

        let mut buf = Vec::new();
        print_tsv(&mut buf, &entries);
        let output = String::from_utf8(buf).unwrap();

        // Command should be on a single line with escaped newline
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("echo\\nhello"));
    }

    #[test]
    fn test_print_table_empty() {
        let mut buf = Vec::new();
        print_table(&mut buf, &[]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_print_table_has_header_and_rows() {
        let entries = vec![make_entry(
            "2026-03-13T10:30:00Z",
            "echo hello",
            SerializableAction::Allow,
        )];

        let mut buf = Vec::new();
        print_table(&mut buf, &entries);
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("TIMESTAMP"));
        assert!(lines[0].contains("ACTION"));
        assert!(lines[0].contains("COMMAND"));
    }

    #[test]
    fn test_print_table_multibyte_truncation_does_not_panic() {
        // "あいうえお" is 15 bytes (3 bytes per char), truncating at a byte
        // offset that falls mid-character must not panic
        let entries = vec![make_entry(
            "2026-03-13T10:30:00Z",
            "echo あいうえお",
            SerializableAction::Allow,
        )];

        let mut buf = Vec::new();
        // This should not panic even with a very narrow terminal width
        print_table(&mut buf, &entries);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.is_empty());
    }
}
