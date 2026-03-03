use super::error::InitError;

/// Ask a yes/no confirmation question.
///
/// When `auto_yes` is true, returns `default` without prompting.
pub fn confirm(message: &str, default: bool, auto_yes: bool) -> Result<bool, InitError> {
    if auto_yes {
        return Ok(default);
    }
    let result = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(message)
        .default(default)
        .interact()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::auto_yes_default_true("Continue?", true, true)]
    #[case::auto_yes_default_false("Continue?", false, false)]
    fn confirm_auto_yes_returns_default(
        #[case] message: &str,
        #[case] default: bool,
        #[case] expected: bool,
    ) {
        let result =
            confirm(message, default, true).unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(result, expected);
    }
}
