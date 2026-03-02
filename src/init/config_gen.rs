use std::path::Path;

use super::error::InitError;

/// Boilerplate template for a new runok.yml configuration file.
const BOILERPLATE_TEMPLATE: &str = "\
# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json
";

/// Config filenames to check for existing configuration.
const CONFIG_FILENAMES: &[&str] = &["runok.yml", "runok.yaml"];

/// Return the boilerplate template string.
#[cfg(test)]
fn boilerplate() -> &'static str {
    BOILERPLATE_TEMPLATE
}

/// Check if a runok config file already exists in the given directory.
///
/// Checks for both `runok.yml` and `runok.yaml`.
pub fn config_exists(dir: &Path) -> Option<std::path::PathBuf> {
    CONFIG_FILENAMES
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists())
}

/// Write a configuration file to the given path.
///
/// Creates parent directories if they don't exist.
/// If `force` is false and a config file already exists in the directory,
/// returns `InitError::ConfigExists`.
pub fn write_config(
    dir: &Path,
    content: &str,
    force: bool,
) -> Result<std::path::PathBuf, InitError> {
    if !force && let Some(existing) = config_exists(dir) {
        return Err(InitError::ConfigExists(existing));
    }

    std::fs::create_dir_all(dir)?;

    let path = dir.join("runok.yml");
    std::fs::write(&path, content)?;
    Ok(path)
}

/// Build configuration content by combining boilerplate with optional converted rules.
pub fn build_config_content(converted_rules: Option<&str>) -> String {
    let mut content = BOILERPLATE_TEMPLATE.to_string();
    if let Some(rules) = converted_rules
        && !rules.is_empty()
    {
        content.push('\n');
        content.push_str("# Converted from Claude Code permissions:\n");
        content.push_str("rules:\n");
        content.push_str(rules);
    }
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tempfile::TempDir;

    #[rstest]
    fn boilerplate_has_expected_content() {
        let tmpl = boilerplate();
        assert_eq!(
            tmpl,
            "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
        );
    }

    #[rstest]
    fn write_config_creates_directory_and_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("subdir");

        let path = write_config(&dir, "test content", false).unwrap();
        assert_eq!(path, dir.join("runok.yml"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "test content");
    }

    #[rstest]
    #[case::yml("runok.yml")]
    #[case::yaml("runok.yaml")]
    fn write_config_errors_on_existing_file(#[case] existing_name: &str) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("project");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(existing_name), "existing").unwrap();

        let result = write_config(&dir, "new content", false);
        assert!(matches!(result, Err(InitError::ConfigExists(_))));
    }

    #[rstest]
    fn write_config_force_overwrites() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("project");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("runok.yml"), "old content").unwrap();

        let path = write_config(&dir, "new content", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");
    }

    #[rstest]
    fn config_exists_returns_none_for_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert!(config_exists(tmp.path()).is_none());
    }

    #[rstest]
    #[case::yml("runok.yml")]
    #[case::yaml("runok.yaml")]
    fn config_exists_detects_file(#[case] filename: &str) {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(filename), "content").unwrap();
        assert!(config_exists(tmp.path()).is_some());
    }

    #[rstest]
    fn build_config_content_without_rules() {
        let content = build_config_content(None);
        assert_eq!(content, boilerplate());
    }

    #[rstest]
    fn build_config_content_with_rules() {
        let rules = "  - allow: 'git status'\n  - deny: 'rm -rf /'\n";
        let content = build_config_content(Some(rules));
        assert_eq!(
            content,
            indoc::indoc! {"\
                # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

                # Converted from Claude Code permissions:
                rules:
                  - allow: 'git status'
                  - deny: 'rm -rf /'
            "}
        );
    }

    #[rstest]
    fn build_config_content_with_empty_rules() {
        let content = build_config_content(Some(""));
        assert_eq!(content, boilerplate());
    }
}
