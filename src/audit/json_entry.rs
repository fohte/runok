use serde::Serialize;

use super::model::AuditEntry;
use super::recheck::Recheck;

/// Wraps an `AuditEntry` with additive JSON-only annotations for `runok
/// audit --json`.
///
/// `approved` and `recheck` are computed at output time and are not part of
/// the persisted audit-log schema -- they never appear in the JSONL files
/// on disk, only in this command's stdout.
#[derive(Serialize)]
pub struct AuditEntryJson<'a> {
    #[serde(flatten)]
    pub entry: &'a AuditEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recheck: Option<&'a Recheck>,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::audit::{AuditMetadata, RecheckCommandEvaluation, SerializableAction};

    fn entry() -> AuditEntry {
        AuditEntry {
            timestamp: "2026-07-08T10:00:00Z".to_owned(),
            command: "terraform apply".to_owned(),
            action: SerializableAction::Ask { message: None },
            sandbox_preset: None,
            default_action: None,
            metadata: AuditMetadata::default(),
            command_evaluations: vec![],
        }
    }

    #[rstest]
    fn omits_approved_and_recheck_when_absent() {
        let e = entry();
        let json = AuditEntryJson {
            entry: &e,
            approved: None,
            recheck: None,
        };
        let serialized = serde_json::to_string(&json).unwrap();
        assert!(!serialized.contains("approved"));
        assert!(!serialized.contains("recheck"));
    }

    #[rstest]
    fn includes_approved_and_recheck_when_present() {
        let e = entry();
        let recheck = Recheck::Ok {
            action: SerializableAction::Allow,
            command_evaluations: vec![RecheckCommandEvaluation {
                command: "terraform apply".to_owned(),
                action: SerializableAction::Allow,
                matched_rules: vec![],
            }],
        };
        let json = AuditEntryJson {
            entry: &e,
            approved: Some(true),
            recheck: Some(&recheck),
        };
        let serialized = serde_json::to_string(&json).unwrap();
        let value: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "timestamp": "2026-07-08T10:00:00Z",
                "command": "terraform apply",
                "action": {"type": "ask", "detail": {"message": null}},
                "sandbox_preset": null,
                "default_action": null,
                "metadata": {
                    "endpoint_type": "",
                    "session_id": null,
                    "cwd": null,
                    "tool_name": null,
                    "hook_event_name": null,
                    "tool_use_id": null,
                },
                "command_evaluations": [],
                "approved": true,
                "recheck": {
                    "action": {"type": "allow"},
                    "command_evaluations": [
                        {
                            "command": "terraform apply",
                            "action": {"type": "allow"},
                        },
                    ],
                },
            }),
        );
    }
}
