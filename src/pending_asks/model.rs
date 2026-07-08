use serde::Serialize;

/// Ask-decision audit entries grouped by their exact raw command string,
/// restricted to entries still resolved via `defaults.action` fallback under
/// the current config (see `aggregator::compute_pending_ask_groups`).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PendingAskGroup {
    /// The raw command string shared by every entry in the group.
    pub command: String,
    /// Number of ask-decision entries in this group.
    pub ask_count: usize,
    /// Number of entries in this group approved by the user.
    pub approved_count: usize,
    /// Timestamp of the oldest entry in this group.
    pub first_seen: String,
    /// Timestamp of the newest entry in this group.
    pub last_seen: String,
    /// Distinct working directories the command was asked from, in
    /// first-seen order.
    pub cwds: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_ask_group_serializes() {
        let group = PendingAskGroup {
            command: "terraform apply".to_owned(),
            ask_count: 3,
            approved_count: 2,
            first_seen: "2026-07-01T10:00:00Z".to_owned(),
            last_seen: "2026-07-08T10:00:00Z".to_owned(),
            cwds: vec!["/home/user/project".to_owned()],
        };

        let json = serde_json::to_string(&group).unwrap();

        assert_eq!(
            json,
            r#"{"command":"terraform apply","ask_count":3,"approved_count":2,"first_seen":"2026-07-01T10:00:00Z","last_seen":"2026-07-08T10:00:00Z","cwds":["/home/user/project"]}"#,
        );
    }
}
