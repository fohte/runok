use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::ActionKind;

/// A single audit log entry recording a command evaluation result.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub action: SerializableAction,
    pub matched_rule: Option<SerializableRuleMatch>,
    pub sub_evaluations: Option<Vec<SubEvaluation>>,
    pub metadata: AuditMetadata,
}

/// The action taken, serializable for JSONL output.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SerializableAction {
    Allow,
    Deny,
    Ask,
}

impl From<ActionKind> for SerializableAction {
    fn from(kind: ActionKind) -> Self {
        match kind {
            ActionKind::Allow => Self::Allow,
            ActionKind::Deny => Self::Deny,
            ActionKind::Ask => Self::Ask,
        }
    }
}

/// Information about the rule that matched.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SerializableRuleMatch {
    pub pattern: String,
    pub action: SerializableAction,
}

/// A sub-evaluation result for compound or wrapper commands.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SubEvaluation {
    pub command: String,
    pub action: SerializableAction,
    pub matched_rule: Option<SerializableRuleMatch>,
}

/// Session and endpoint metadata attached to each audit entry.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct AuditMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subcommand: Option<String>,
}
