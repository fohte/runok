use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};

use crate::config::ActionKind;

/// Time specification supporting both absolute and relative formats.
#[derive(Debug, Clone, PartialEq)]
pub enum TimeSpec {
    /// Absolute timestamp (ISO 8601 or date string).
    Absolute(DateTime<Utc>),
    /// Relative duration from now (e.g., "1h", "7d", "30m").
    Relative(Duration),
}

impl TimeSpec {
    /// Parse a time specification string.
    ///
    /// Supported formats:
    /// - Relative: "30m", "1h", "7d" (minutes, hours, days)
    /// - Absolute date: "2026-02-25" (interpreted as start of day UTC)
    /// - Absolute datetime: "2026-02-25T10:30:00Z" (ISO 8601)
    pub fn parse(s: &str) -> Result<Self, String> {
        // Try relative format first: number followed by unit
        if let Some(result) = Self::try_parse_relative(s) {
            return result;
        }

        // Try ISO 8601 datetime
        if let Ok(dt) = s.parse::<DateTime<Utc>>() {
            return Ok(TimeSpec::Absolute(dt));
        }

        // Try date-only format
        if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            let dt = date
                .and_hms_opt(0, 0, 0)
                .ok_or_else(|| format!("invalid date: {s}"))?;
            return Ok(TimeSpec::Absolute(DateTime::from_naive_utc_and_offset(
                dt, Utc,
            )));
        }

        Err(format!(
            "invalid time spec '{s}': expected relative (e.g. 1h, 7d, 30m) or absolute (e.g. 2026-02-25)"
        ))
    }

    fn try_parse_relative(s: &str) -> Option<Result<Self, String>> {
        let (idx, _) = s.char_indices().next_back()?;
        let (num_str, unit) = s.split_at(idx);
        match unit {
            "m" | "h" | "d" => {}
            _ => return None,
        }
        let num: u64 = match num_str.parse() {
            Ok(n) => n,
            Err(_) => return None,
        };
        let secs = match unit {
            "m" => num * 60,
            "h" => num * 3600,
            "d" => num * 86400,
            _ => unreachable!(),
        };
        Some(Ok(TimeSpec::Relative(Duration::from_secs(secs))))
    }

    /// Resolve this TimeSpec to an absolute DateTime relative to `now`.
    pub fn resolve(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            TimeSpec::Absolute(dt) => *dt,
            TimeSpec::Relative(dur) => now - chrono::Duration::seconds(dur.as_secs() as i64),
        }
    }
}

/// Filter criteria for audit log queries.
#[derive(Debug)]
pub struct AuditFilter {
    /// Filter by action kind.
    pub action: Option<ActionKind>,
    /// Only include entries after this time.
    pub since: Option<TimeSpec>,
    /// Only include entries before this time.
    pub until: Option<TimeSpec>,
    /// Filter by command substring match.
    pub command_pattern: Option<String>,
    /// Maximum number of entries to return (default: 50).
    pub limit: usize,
}

impl Default for AuditFilter {
    fn default() -> Self {
        Self {
            action: None,
            since: None,
            until: None,
            command_pattern: None,
            limit: 50,
        }
    }
}

impl AuditFilter {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::minutes("30m", Duration::from_secs(30 * 60))]
    #[case::hours("1h", Duration::from_secs(3600))]
    #[case::days("7d", Duration::from_secs(7 * 86400))]
    fn parse_relative(#[case] input: &str, #[case] expected_dur: Duration) {
        let ts = TimeSpec::parse(input).unwrap();
        assert_eq!(ts, TimeSpec::Relative(expected_dur));
    }

    #[rstest]
    #[case::date_only(
        "2026-02-25",
        "2026-02-25T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
    )]
    #[case::iso_8601(
        "2026-02-25T10:30:00Z",
        "2026-02-25T10:30:00Z".parse::<DateTime<Utc>>().unwrap()
    )]
    fn parse_absolute(#[case] input: &str, #[case] expected: DateTime<Utc>) {
        let ts = TimeSpec::parse(input).unwrap();
        assert_eq!(ts, TimeSpec::Absolute(expected));
    }

    #[rstest]
    #[case::empty("")]
    #[case::invalid("abc")]
    #[case::no_unit("30")]
    #[case::bad_unit("30x")]
    #[case::multibyte_suffix("30\u{00e9}")]
    fn parse_invalid(#[case] input: &str) {
        assert!(TimeSpec::parse(input).is_err());
    }

    #[rstest]
    #[case::relative(
        TimeSpec::Relative(Duration::from_secs(3600)),
        "2026-02-25T11:00:00Z".parse::<DateTime<Utc>>().unwrap(),
    )]
    #[case::absolute(
        TimeSpec::Absolute("2026-02-25T10:30:00Z".parse::<DateTime<Utc>>().unwrap()),
        "2026-02-25T10:30:00Z".parse::<DateTime<Utc>>().unwrap(),
    )]
    fn resolve(#[case] ts: TimeSpec, #[case] expected: DateTime<Utc>) {
        let now = "2026-02-25T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(ts.resolve(now), expected);
    }

    #[rstest]
    fn default_filter_has_limit_50() {
        let filter = AuditFilter::new();
        assert_eq!(filter.limit, 50);
        assert!(filter.action.is_none());
        assert!(filter.since.is_none());
        assert!(filter.until.is_none());
        assert!(filter.command_pattern.is_none());
    }
}
