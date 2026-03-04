use super::error::InitError;

/// Abstraction over interactive prompts.
///
/// Production code uses `DialoguerPrompter`, which delegates to dialoguer.
/// Tests inject a `Prompter` that returns pre-configured responses.
pub trait Prompter {
    fn confirm(&self, message: &str, default: bool) -> Result<bool, InitError>;
    fn select(&self, message: &str, items: &[&str], default: usize) -> Result<usize, InitError>;
}

/// Production prompter that uses dialoguer for interactive prompts.
pub struct DialoguerPrompter;

impl Prompter for DialoguerPrompter {
    fn confirm(&self, message: &str, default: bool) -> Result<bool, InitError> {
        let items = ["Yes", "No"];
        let default_idx = if default { 0 } else { 1 };
        let selection = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(message)
            .items(&items)
            .default(default_idx)
            .report(false)
            .interact()?;
        let accepted = selection == 0;
        if accepted {
            eprintln!("\x1b[32m✔\x1b[0m {message} · Yes");
        } else {
            eprintln!("\x1b[33m✘\x1b[0m {message} · No");
        }
        Ok(accepted)
    }

    fn select(&self, message: &str, items: &[&str], default: usize) -> Result<usize, InitError> {
        let selection = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(message)
            .items(items)
            .default(default)
            .report(false)
            .interact()?;
        let label = items.get(selection).copied().unwrap_or("?");
        eprintln!("\x1b[32m✔\x1b[0m {message} · {label}");
        Ok(selection)
    }
}

/// Non-interactive prompter that always returns the default value.
///
/// Used when the `-y` flag is specified.
pub struct AutoYesPrompter;

impl Prompter for AutoYesPrompter {
    fn confirm(&self, _message: &str, default: bool) -> Result<bool, InitError> {
        Ok(default)
    }

    fn select(&self, _message: &str, _items: &[&str], default: usize) -> Result<usize, InitError> {
        Ok(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::auto_yes_default_true("Continue?", true, true)]
    #[case::auto_yes_default_false("Continue?", false, false)]
    fn auto_yes_confirm_returns_default(
        #[case] message: &str,
        #[case] default: bool,
        #[case] expected: bool,
    ) {
        let prompter = AutoYesPrompter;
        let result = prompter
            .confirm(message, default)
            .unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::select_default_zero(&["A", "B"], 0, 0)]
    #[case::select_default_one(&["A", "B"], 1, 1)]
    fn auto_yes_select_returns_default(
        #[case] items: &[&str],
        #[case] default: usize,
        #[case] expected: usize,
    ) {
        let prompter = AutoYesPrompter;
        let result = prompter
            .select("Pick one", items, default)
            .unwrap_or_else(|e| panic!("unexpected error: {e}"));
        assert_eq!(result, expected);
    }
}
