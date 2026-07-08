use std::io::{self, IsTerminal, Write};

use chrono::{DateTime, Local, Utc};
use owo_colors::{OwoColorize, Stream::Stdout};
use terminal_size::{Width, terminal_size};

use super::model::PendingAskGroup;

/// Format and print pending-ask groups to stdout.
///
/// In TTY mode: prints a table, truncating the COMMAND column to fit the
/// terminal width. In non-TTY mode: prints tab-separated values without
/// truncation.
pub fn print_groups(groups: &[PendingAskGroup]) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    if stdout.is_terminal() {
        print_table(&mut out, groups);
    } else {
        print_tsv(&mut out, groups);
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

/// Truncate `s` to fit within `max` bytes, respecting UTF-8 char boundaries
/// and appending `...` when truncation occurs.
fn truncate_to_width(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    if max <= 3 {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        return s[..end].to_string();
    }
    let mut end = max - 3;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

fn print_table(out: &mut impl Write, groups: &[PendingAskGroup]) {
    if groups.is_empty() {
        return;
    }

    let term_width = terminal_size()
        .map(|(Width(w), _)| w as usize)
        .unwrap_or(80);

    // Column widths: ASK_COUNT / APPROVED size to their header text, the two
    // timestamp columns are fixed 19 chars ("2026-03-13 10:30:00").
    let ask_width = 9;
    let approved_width = 8;
    let ts_width = 19;
    let gap = 2;
    let fixed_width = ask_width + gap + approved_width + gap + ts_width + gap + ts_width + gap;

    let _ = writeln!(
        out,
        "{}",
        format!(
            "{:<ask_w$}  {:<app_w$}  {:<ts_w$}  {:<ts_w$}  COMMAND",
            "ASK_COUNT",
            "APPROVED",
            "FIRST_SEEN",
            "LAST_SEEN",
            ask_w = ask_width,
            app_w = approved_width,
            ts_w = ts_width,
        )
        .if_supports_color(Stdout, |t| t.bold())
    );

    for group in groups {
        let first_seen = format_timestamp_local(&group.first_seen);
        let last_seen = format_timestamp_local(&group.last_seen);
        let command = escape_control_chars(&group.command);
        let command_max = term_width.saturating_sub(fixed_width);
        let command_display = truncate_to_width(&command, command_max);

        let _ = writeln!(
            out,
            "{:<ask_w$}  {:<app_w$}  {:<ts_w$}  {:<ts_w$}  {}",
            group.ask_count,
            group.approved_count,
            first_seen,
            last_seen,
            command_display,
            ask_w = ask_width,
            app_w = approved_width,
            ts_w = ts_width,
        );
    }
}

fn print_tsv(out: &mut impl Write, groups: &[PendingAskGroup]) {
    for group in groups {
        let first_seen = format_timestamp_local(&group.first_seen);
        let last_seen = format_timestamp_local(&group.last_seen);
        let command = escape_control_chars(&group.command);
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            group.ask_count, group.approved_count, first_seen, last_seen, command
        );
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::*;

    fn make_group(command: &str, ask_count: usize, approved_count: usize) -> PendingAskGroup {
        PendingAskGroup {
            command: command.to_owned(),
            ask_count,
            approved_count,
            first_seen: "2026-03-13T10:30:00Z".to_owned(),
            last_seen: "2026-03-13T11:30:00Z".to_owned(),
            cwds: vec!["/home/user/project".to_owned()],
        }
    }

    // `first_seen`/`last_seen` go through `format_timestamp_local`, which
    // converts to the test runner's local timezone. Building the expected
    // value through the same helper keeps the assertion exact (per repo
    // convention: normalize dynamic fields rather than weaken the check)
    // without hardcoding a timezone-dependent literal.
    #[rstest]
    fn print_tsv_format() {
        let groups = vec![
            make_group("terraform apply", 3, 2),
            make_group("git push -f origin main", 1, 0),
        ];

        let mut buf = Vec::new();
        print_tsv(&mut buf, &groups);
        let output = String::from_utf8(buf).unwrap();

        let first_seen = format_timestamp_local("2026-03-13T10:30:00Z");
        let last_seen = format_timestamp_local("2026-03-13T11:30:00Z");
        assert_eq!(
            output,
            format!(
                indoc! {"
                3\t2\t{first_seen}\t{last_seen}\tterraform apply
                1\t0\t{first_seen}\t{last_seen}\tgit push -f origin main
            "},
                first_seen = first_seen,
                last_seen = last_seen,
            ),
        );
    }

    #[rstest]
    fn print_tsv_escapes_control_chars() {
        let groups = vec![make_group(
            indoc! {"
                bash -c 'echo
                hello'
            "}
            .trim_end(),
            1,
            0,
        )];

        let mut buf = Vec::new();
        print_tsv(&mut buf, &groups);
        let output = String::from_utf8(buf).unwrap();

        let first_seen = format_timestamp_local("2026-03-13T10:30:00Z");
        let last_seen = format_timestamp_local("2026-03-13T11:30:00Z");
        assert_eq!(
            output,
            format!(
                indoc! {"
                1\t0\t{first_seen}\t{last_seen}\tbash -c 'echo\\nhello'
            "},
                first_seen = first_seen,
                last_seen = last_seen,
            ),
        );
    }

    #[rstest]
    fn print_table_empty() {
        let mut buf = Vec::new();
        print_table(&mut buf, &[]);
        assert!(buf.is_empty());
    }

    #[rstest]
    fn print_table_has_header_and_rows() {
        let groups = vec![make_group("echo hello", 1, 0)];

        let mut buf = Vec::new();
        print_table(&mut buf, &groups);
        let output = String::from_utf8(buf).unwrap();

        let lines: Vec<&str> = output.trim_end().lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ASK_COUNT"));
        assert!(lines[0].contains("APPROVED"));
        assert!(lines[0].contains("FIRST_SEEN"));
        assert!(lines[0].contains("LAST_SEEN"));
        assert!(lines[0].contains("COMMAND"));
    }

    #[rstest]
    fn print_table_multibyte_truncation_does_not_panic() {
        let groups = vec![make_group("echo あいうえお", 1, 0)];

        let mut buf = Vec::new();
        print_table(&mut buf, &groups);
        let output = String::from_utf8(buf).unwrap();
        assert!(!output.is_empty());
    }

    #[rstest]
    #[case::fits("hi", 10, "hi")]
    #[case::exact_fit("hello", 5, "hello")]
    #[case::truncated("hello world", 8, "hello...")]
    #[case::too_narrow_for_ellipsis("hello world", 2, "he")]
    fn truncate_to_width_cases(#[case] input: &str, #[case] max: usize, #[case] expected: &str) {
        assert_eq!(truncate_to_width(input, max), expected);
    }
}
