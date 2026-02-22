#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("landlock restriction failed: {0}")]
    Landlock(String),
    #[error("seccomp filter failed: {0}")]
    Seccomp(String),
    #[error("bubblewrap execution failed: {0}")]
    Bubblewrap(String),
    #[error("command execution failed: {0}")]
    Exec(#[from] std::io::Error),
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
}
