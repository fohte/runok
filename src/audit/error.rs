/// Errors that can occur during audit log operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Log file I/O error (creation, writing, rotation).
    #[error("audit log I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error.
    #[error("audit log serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// File lock timeout.
    #[error("audit log file lock timeout")]
    LockTimeout,

    /// Log file parse error (when reading).
    #[error("audit log parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
}
