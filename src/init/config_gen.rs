use std::path::Path;

use super::error::InitError;

/// Boilerplate template for a new runok.yml configuration file.
const BOILERPLATE_TEMPLATE: &str = "\
# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json
";

/// Return the boilerplate template string.
#[cfg(test)]
fn boilerplate() -> &'static str {
    BOILERPLATE_TEMPLATE
}

/// Write a configuration file to the given directory.
///
/// Creates parent directories if they don't exist.
/// Overwrites existing files.
pub fn write_config(dir: &Path, content: &str) -> Result<std::path::PathBuf, InitError> {
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

        let path = write_config(&dir, "test content").unwrap();
        assert_eq!(path, dir.join("runok.yml"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "test content");
    }

    #[rstest]
    fn write_config_overwrites_existing() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("project");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("runok.yml"), "old content").unwrap();

        let path = write_config(&dir, "new content").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");
    }

    #[rstest]
    fn build_config_content_without_rules() {
        let content = build_config_content(None);
        assert_eq!(content, boilerplate());
    }

    #[rstest]
    fn build_config_content_with_rules() {
        let rules = concat!("  - allow: 'git status'\n", "  - deny: 'rm -rf /'\n",);
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
