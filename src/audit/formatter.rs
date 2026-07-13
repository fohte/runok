use std::io::{self, IsTerminal, Write};

use chrono::{DateTime, Local, Utc};
use owo_colors::{OwoColorize, Stream::Stdout};
use terminal_size::{Width, terminal_size};

use super::model::{AskResolution, AuditEntry, SerializableAction};
use super::recheck::Recheck;
use super::resolution::is_approved;

/// Format and print audit entries to stdout, joining ask entries with their
/// resolution records (approved asks are marked in the ACTION column).
///
/// `recheck` is `Some` only for `runok audit --recheck`, one entry per
/// `entries` in the same order; it adds a NOW column showing the current
/// re-evaluation result alongside the recorded ACTION.
///
/// In TTY mode: prints a table with ANSI colors, truncating the COMMAND column
/// to fit the terminal width.
/// In non-TTY mode: prints tab-separated values without colors or truncation.
pub fn print_entries(
    entries: &[AuditEntry],
    resolutions: &[AskResolution],
    recheck: Option<&[Recheck]>,
) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    if stdout.is_terminal() {
        print_table(&mut out, entries, resolutions, recheck);
    } else {
        print_tsv(&mut out, entries, resolutions, recheck);
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

/// ACTION column text for an entry: the action name, with a check mark
/// appended when the ask was approved in the permission dialog.
fn action_display(entry: &AuditEntry, resolutions: &[AskResolution]) -> String {
    let base = action_str(&entry.action);
    if is_approved(entry, resolutions) {
        format!("{base} ✓")
    } else {
        base.to_owned()
    }
}

/// NOW column text: the current re-evaluation result, distinguishing an
/// `ask` resolved by an explicit rule from one resolved via
/// `defaults.action` fallback (`ask-def`).
fn recheck_str(recheck: &Recheck) -> &'static str {
    match recheck {
        Recheck::Error { .. } => "error",
        Recheck::Ok {
            action: SerializableAction::Ask { .. },
            ..
        } if recheck.is_default_fallback_ask() => "ask-def",
        Recheck::Ok { action, .. } => action_str(action),
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

// Column widths: TIMESTAMP is fixed 19 chars ("2026-03-13 10:30:00"),
// ACTION and NOW are fixed 7 chars ("default" / "ask-def" are longest)
const TS_WIDTH: usize = 19;
const ACTION_WIDTH: usize = 7;

/// Pad `text` to `ACTION_WIDTH`, then colorize per `action` -- padding first
/// keeps ANSI escape codes from breaking column alignment.
fn colorize_action(action: &SerializableAction, text: &str) -> String {
    let padded = format!("{:<width$}", text, width = ACTION_WIDTH);
    match action {
        SerializableAction::Allow => padded.if_supports_color(Stdout, |t| t.green()).to_string(),
        SerializableAction::Deny { .. } => {
            padded.if_supports_color(Stdout, |t| t.red()).to_string()
        }
        SerializableAction::Ask { .. } => {
            padded.if_supports_color(Stdout, |t| t.yellow()).to_string()
        }
        SerializableAction::Default => padded
            .if_supports_color(Stdout, |t| t.bright_black())
            .to_string(),
    }
}

/// NOW column cell: padded and colorized like the ACTION column, with
/// `Recheck::Error` rendered like `Default` (inconclusive, not a decision).
fn colorize_recheck(recheck: &Recheck) -> String {
    let text = recheck_str(recheck);
    match recheck {
        Recheck::Error { .. } => format!("{:<width$}", text, width = ACTION_WIDTH)
            .if_supports_color(Stdout, |t| t.bright_black())
            .to_string(),
        Recheck::Ok { action, .. } => colorize_action(action, text),
    }
}

/// Truncate `command` to `max_len` bytes, respecting UTF-8 char boundaries,
/// appending `...` when truncation actually occurs.
fn truncate_command(command: &str, max_len: usize) -> String {
    if command.len() <= max_len {
        return command.to_owned();
    }
    if max_len > 3 {
        let target = max_len - 3;
        let mut end = target;
        while !command.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &command[..end])
    } else {
        let mut end = max_len;
        while !command.is_char_boundary(end) {
            end -= 1;
        }
        command[..end].to_string()
    }
}

fn print_table(
    out: &mut impl Write,
    entries: &[AuditEntry],
    resolutions: &[AskResolution],
    recheck: Option<&[Recheck]>,
) {
    if entries.is_empty() {
        return;
    }

    let term_width = terminal_size()
        .map(|(Width(w), _)| w as usize)
        .unwrap_or(80);

    // Gap between columns (2 spaces), one gap per column including COMMAND.
    let gap = 2;
    let now_column_width = if recheck.is_some() {
        ACTION_WIDTH + gap
    } else {
        0
    };
    let fixed_width = TS_WIDTH + gap + ACTION_WIDTH + gap + now_column_width;

    let mut header = format!(
        "{:<ts_w$}  {:<act_w$}",
        "TIMESTAMP",
        "ACTION",
        ts_w = TS_WIDTH,
        act_w = ACTION_WIDTH,
    );
    if recheck.is_some() {
        header.push_str(&format!("  {:<width$}", "NOW", width = ACTION_WIDTH));
    }
    header.push_str("  COMMAND");
    let _ = writeln!(out, "{}", header.if_supports_color(Stdout, |t| t.bold()));

    for (i, entry) in entries.iter().enumerate() {
        let ts = format_timestamp_local(&entry.timestamp);
        let action = action_display(entry, resolutions);
        let command = escape_control_chars(&entry.command);
        let command_display = truncate_command(&command, term_width.saturating_sub(fixed_width));
        let colored_action = colorize_action(&entry.action, &action);

        let mut line = format!("{ts:<ts_w$}  {colored_action}", ts_w = TS_WIDTH);
        if let Some(recheck) = recheck {
            line.push_str("  ");
            line.push_str(&colorize_recheck(&recheck[i]));
        }
        line.push_str("  ");
        line.push_str(&command_display);
        let _ = writeln!(out, "{line}");
    }
}

fn print_tsv(
    out: &mut impl Write,
    entries: &[AuditEntry],
    resolutions: &[AskResolution],
    recheck: Option<&[Recheck]>,
) {
    for (i, entry) in entries.iter().enumerate() {
        let ts = format_timestamp_local(&entry.timestamp);
        let action = action_display(entry, resolutions);
        let command = escape_control_chars(&entry.command);
        match recheck {
            Some(recheck) => {
                let _ = writeln!(
                    out,
                    "{}\t{}\t{}\t{}",
                    ts,
                    action,
                    recheck_str(&recheck[i]),
                    command
                );
            }
            None => {
                let _ = writeln!(out, "{}\t{}\t{}", ts, action, command);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::audit::{
        AskResolutionOutcome, AuditMetadata, RecheckCommandEvaluation, SerializableRuleMatch,
    };

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

    fn make_ask_entry_with_tool_use_id(command: &str, tool_use_id: &str) -> AuditEntry {
        AuditEntry {
            metadata: AuditMetadata {
                tool_use_id: Some(tool_use_id.to_owned()),
                ..AuditMetadata::default()
            },
            ..make_entry(
                "2026-03-13T10:30:00Z",
                command,
                SerializableAction::Ask { message: None },
            )
        }
    }

    fn make_resolution(tool_use_id: &str, command: &str) -> AskResolution {
        AskResolution {
            timestamp: "2026-03-13T10:31:00Z".to_owned(),
            outcome: AskResolutionOutcome::Approved,
            tool_use_id: Some(tool_use_id.to_owned()),
            session_id: Some("sess-1".to_owned()),
            cwd: Some("/tmp".to_owned()),
            command: command.to_owned(),
            executed_command: command.to_owned(),
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
        print_tsv(&mut buf, &entries, &[], None);
        let output = String::from_utf8(buf).unwrap();

        // TSV should have 3 tab-separated columns per line, no header
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert_eq!(line.split('\t').count(), 3);
        }
    }

    /// The marked/unmarked decision itself is covered per-case by
    /// `action_display_marks_approved_asks`; this only pins that the marker
    /// reaches the TSV output.
    #[rstest]
    fn print_tsv_marks_approved_asks() {
        let entries = vec![make_ask_entry_with_tool_use_id(
            "terraform apply",
            "toolu_01",
        )];
        let resolutions = vec![make_resolution("toolu_01", "terraform apply")];

        let mut buf = Vec::new();
        print_tsv(&mut buf, &entries, &resolutions, None);
        let output = String::from_utf8(buf).unwrap();

        let columns: Vec<&str> = output.trim().split('\t').collect();
        assert_eq!(columns[1..], ["ask ✓", "terraform apply"]);
    }

    #[rstest]
    #[case::approved_ask(
        make_ask_entry_with_tool_use_id("terraform apply", "toolu_01"),
        vec![make_resolution("toolu_01", "terraform apply")],
        "ask ✓",
    )]
    #[case::unresolved_ask(
        make_ask_entry_with_tool_use_id("terraform apply", "toolu_01"),
        vec![],
        "ask",
    )]
    #[case::allow_never_marked(
        make_entry("2026-03-13T10:30:00Z", "echo hi", SerializableAction::Allow),
        vec![make_resolution("toolu_01", "echo hi")],
        "allow",
    )]
    fn action_display_marks_approved_asks(
        #[case] entry: AuditEntry,
        #[case] resolutions: Vec<AskResolution>,
        #[case] expected: &str,
    ) {
        assert_eq!(action_display(&entry, &resolutions), expected);
    }

    #[test]
    fn test_print_tsv_escapes_newlines() {
        let entries = vec![make_entry(
            "2026-03-13T10:30:00Z",
            "bash -c 'echo\nhello'",
            SerializableAction::Allow,
        )];

        let mut buf = Vec::new();
        print_tsv(&mut buf, &entries, &[], None);
        let output = String::from_utf8(buf).unwrap();

        // Command should be on a single line with escaped newline
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("echo\\nhello"));
    }

    #[test]
    fn test_print_table_empty() {
        let mut buf = Vec::new();
        print_table(&mut buf, &[], &[], None);
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
        print_table(&mut buf, &entries, &[], None);
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
        print_table(&mut buf, &entries, &[], None);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.is_empty());
    }

    // ========================================
    // --recheck NOW column
    // ========================================

    fn ok_recheck(action: SerializableAction) -> Recheck {
        Recheck::Ok {
            action,
            command_evaluations: vec![],
        }
    }

    #[rstest]
    #[case::allow(ok_recheck(SerializableAction::Allow), "allow")]
    #[case::deny(ok_recheck(SerializableAction::Deny { message: None, fix_suggestion: None }), "deny")]
    #[case::ask_default_fallback(ok_recheck(SerializableAction::Ask { message: None }), "ask-def")]
    #[case::ask_explicit_rule(
        Recheck::Ok {
            action: SerializableAction::Ask { message: None },
            command_evaluations: vec![RecheckCommandEvaluation {
                command: "terraform apply".to_owned(),
                action: SerializableAction::Ask { message: None },
                matched_rules: vec![SerializableRuleMatch {
                    action_kind: "ask".to_owned(),
                    pattern: "terraform apply".to_owned(),
                    matched_tokens: vec![],
                }],
            }],
        },
        "ask",
    )]
    #[case::error(Recheck::Error { error: "boom".to_owned() }, "error")]
    fn test_recheck_str(#[case] recheck: Recheck, #[case] expected: &str) {
        assert_eq!(recheck_str(&recheck), expected);
    }

    #[rstest]
    fn print_tsv_adds_now_column_when_recheck_present() {
        let entries = vec![make_entry(
            "2026-03-13T10:30:00Z",
            "terraform apply",
            SerializableAction::Ask { message: None },
        )];
        let recheck = vec![ok_recheck(SerializableAction::Allow)];

        let mut buf = Vec::new();
        print_tsv(&mut buf, &entries, &[], Some(&recheck));
        let output = String::from_utf8(buf).unwrap();

        let columns: Vec<&str> = output.trim().split('\t').collect();
        assert_eq!(columns[1..], ["ask", "allow", "terraform apply"]);
    }

    #[rstest]
    fn print_table_adds_now_header_when_recheck_present() {
        let entries = vec![make_entry(
            "2026-03-13T10:30:00Z",
            "terraform apply",
            SerializableAction::Ask { message: None },
        )];
        let recheck = vec![ok_recheck(SerializableAction::Allow)];

        let mut buf = Vec::new();
        print_table(&mut buf, &entries, &[], Some(&recheck));
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("NOW"));
        assert!(lines[1].contains("allow"));
    }
}
