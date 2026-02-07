use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("command not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox not supported on this platform")]
    NotSupported,
    #[error("sandbox setup failed: {0}")]
    SetupFailed(String),
    #[error("landlock restriction failed: {0}")]
    Landlock(String),
    #[error("seccomp filter failed: {0}")]
    Seccomp(String),
    #[error("seatbelt policy failed: {0}")]
    Seatbelt(String),
    #[error("command execution failed: {0}")]
    Exec(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum ExtensionError {
    #[error("spawn error: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::time::Duration;

    // === ExecError ===

    #[rstest]
    #[case(ExecError::NotFound("git".to_string()), "command not found: git")]
    #[case(ExecError::PermissionDenied("/usr/bin/secret".to_string()), "permission denied: /usr/bin/secret")]
    fn exec_error_display(#[case] error: ExecError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn exec_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let exec_err: ExecError = io_err.into();
        assert_eq!(exec_err.to_string(), "io error: no such file");
    }

    #[test]
    fn exec_error_io_has_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let exec_err = ExecError::Io(io_err);
        let source = std::error::Error::source(&exec_err);
        assert!(source.is_some());
    }

    // === SandboxError ===

    #[rstest]
    #[case(SandboxError::NotSupported, "sandbox not supported on this platform")]
    #[case(SandboxError::SetupFailed("invalid policy".to_string()), "sandbox setup failed: invalid policy")]
    #[case(SandboxError::Landlock("ruleset creation failed".to_string()), "landlock restriction failed: ruleset creation failed")]
    #[case(SandboxError::Seccomp("filter load failed".to_string()), "seccomp filter failed: filter load failed")]
    #[case(SandboxError::Seatbelt("profile compilation failed".to_string()), "seatbelt policy failed: profile compilation failed")]
    fn sandbox_error_display(#[case] error: SandboxError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn sandbox_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let sandbox_err: SandboxError = io_err.into();
        assert_eq!(
            sandbox_err.to_string(),
            "command execution failed: access denied"
        );
    }

    // === ExtensionError ===

    #[test]
    fn extension_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "plugin not found");
        let ext_err: ExtensionError = io_err.into();
        assert_eq!(ext_err.to_string(), "spawn error: plugin not found");
    }

    #[rstest]
    #[case(ExtensionError::Timeout(Duration::from_secs(5)), "timeout after 5s")]
    #[case(
        ExtensionError::InvalidResponse("missing 'result' field".to_string()),
        "invalid response: missing 'result' field"
    )]
    fn extension_error_display(#[case] error: ExtensionError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn extension_error_implements_std_error() {
        let error: &dyn std::error::Error = &ExtensionError::Timeout(Duration::from_secs(5));
        assert!(error.source().is_none());
    }

    // === anyhow integration ===

    #[test]
    fn exec_error_into_anyhow() {
        let error = ExecError::NotFound("git".to_string());
        let anyhow_err: anyhow::Error = error.into();
        assert_eq!(anyhow_err.to_string(), "command not found: git");
    }

    #[test]
    fn sandbox_error_into_anyhow() {
        let error = SandboxError::NotSupported;
        let anyhow_err: anyhow::Error = error.into();
        assert_eq!(
            anyhow_err.to_string(),
            "sandbox not supported on this platform"
        );
    }

    #[test]
    fn extension_error_into_anyhow() {
        let error = ExtensionError::InvalidResponse("bad json".to_string());
        let anyhow_err: anyhow::Error = error.into();
        assert_eq!(anyhow_err.to_string(), "invalid response: bad json");
    }
}
