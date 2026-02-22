use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Sandbox policy passed from the runok main binary via JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub writable_roots: Vec<PathBuf>,
    pub read_only_subpaths: Vec<PathBuf>,
    pub network_allowed: bool,
}
