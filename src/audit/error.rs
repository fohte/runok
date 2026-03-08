#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("audit log serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("audit log file lock timeout")]
    LockTimeout,

    #[error("audit log parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
}
