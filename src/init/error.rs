#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("prompt error: {0}")]
    Prompt(#[from] dialoguer::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::io_error(
        InitError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied"
        )),
        "io error: permission denied"
    )]
    fn error_display(#[case] error: InitError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[rstest]
    fn json_error_display() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{invalid").unwrap_err();
        let error = InitError::Json(json_err);
        assert!(error.to_string().starts_with("json parse error:"));
    }
}
