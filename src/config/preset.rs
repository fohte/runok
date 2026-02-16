use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{Config, ConfigError, PresetError, parse_config};

fn home_dir() -> Option<String> {
    std::env::var("HOME").ok().filter(|h| !h.is_empty())
}

/// Resolve a preset reference string into a filesystem path.
///
/// Supports three forms:
/// - Relative path (`./rules/aws.yml`): resolved from `base_dir`
/// - Home directory (`~/presets/git.yml`): `~` expanded via `get_home`
/// - Absolute path (`/etc/runok/global.yml`): used as-is
fn resolve_local_path(
    reference: &str,
    base_dir: &Path,
    get_home: impl FnOnce() -> Option<String>,
) -> Result<PathBuf, PresetError> {
    if let Some(rest) = reference.strip_prefix("~/") {
        let home = get_home().ok_or_else(|| {
            PresetError::InvalidReference(
                "cannot expand '~': HOME environment variable is not set".to_string(),
            )
        })?;
        Ok(PathBuf::from(home).join(rest))
    } else {
        let path = Path::new(reference);
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(base_dir.join(reference))
        }
    }
}

/// Load a local preset file and parse it as a `Config`.
///
/// `reference` is a local path string (relative, absolute, or `~/`-prefixed).
/// `base_dir` is the directory of the file that contains the `extends` entry.
pub fn load_local_preset(
    reference: &str,
    base_dir: &Path,
    _visited: &mut HashSet<String>,
) -> Result<Config, ConfigError> {
    let path = resolve_local_path(reference, base_dir, home_dir)?;

    if !path.exists() {
        return Err(PresetError::LocalNotFound(path).into());
    }

    let yaml = std::fs::read_to_string(&path)?;
    let config = parse_config(&yaml)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;
    use std::fs;
    use tempfile::TempDir;

    #[rstest]
    #[case::relative_dot_slash(
        "./rules/aws.yml",
        "rules/aws.yml",
        indoc! {"
            rules:
              - allow: 'aws s3 ls'
        "},
    )]
    #[case::relative_no_dot(
        "presets/base.yml",
        "presets/base.yml",
        indoc! {"
            defaults:
              action: deny
        "},
    )]
    fn resolve_relative_path(
        #[case] reference: &str,
        #[case] relative_file_path: &str,
        #[case] yaml_content: &str,
    ) {
        let tmp = TempDir::new().unwrap();
        let base_dir = tmp.path().join("project");

        let file_path = base_dir.join(relative_file_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, yaml_content).unwrap();

        let mut visited = HashSet::new();
        let config = load_local_preset(reference, &base_dir, &mut visited).unwrap();
        assert!(
            config.rules.is_some() || config.defaults.is_some(),
            "loaded config should have content"
        );
    }

    #[test]
    fn resolve_absolute_path() {
        let tmp = TempDir::new().unwrap();
        let preset_path = tmp.path().join("absolute-preset.yml");
        fs::write(
            &preset_path,
            indoc! {"
                rules:
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        let other_dir = tmp.path().join("other");
        fs::create_dir_all(&other_dir).unwrap();

        let reference = preset_path.to_str().unwrap();
        let mut visited = HashSet::new();
        let config = load_local_preset(reference, &other_dir, &mut visited).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].deny.as_deref(), Some("rm -rf /"));
    }

    #[test]
    fn resolve_home_directory_path() {
        let tmp = TempDir::new().unwrap();
        let fake_home = tmp.path().join("fakehome");
        fs::create_dir_all(fake_home.join("presets")).unwrap();
        fs::write(
            fake_home.join("presets/git.yml"),
            indoc! {"
                rules:
                  - allow: 'git status'
            "},
        )
        .unwrap();

        let fake_home_str = fake_home.to_str().unwrap().to_string();
        let path =
            resolve_local_path("~/presets/git.yml", tmp.path(), || Some(fake_home_str)).unwrap();

        let yaml = fs::read_to_string(&path).unwrap();
        let config = parse_config(&yaml).unwrap();
        let rules = config.rules.unwrap();
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
    }

    #[test]
    fn error_on_home_not_set() {
        let err = resolve_local_path("~/presets/git.yml", Path::new("/tmp"), || None).unwrap_err();
        assert!(matches!(err, PresetError::InvalidReference(_)));
        assert!(err.to_string().contains("HOME"));
    }

    #[test]
    fn error_on_nonexistent_file() {
        let tmp = TempDir::new().unwrap();
        let base_dir = tmp.path();

        let mut visited = HashSet::new();
        let err = load_local_preset("./nonexistent.yml", base_dir, &mut visited).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::LocalNotFound(path)) => {
                assert!(
                    path.ends_with("nonexistent.yml"),
                    "error path should contain the filename, got: {path:?}"
                );
            }
            other => panic!("expected PresetError::LocalNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn error_on_nonexistent_absolute_path() {
        let tmp = TempDir::new().unwrap();
        let missing_path = tmp.path().join("does-not-exist.yml");
        let reference = missing_path.to_str().unwrap();

        let mut visited = HashSet::new();
        let err = load_local_preset(reference, tmp.path(), &mut visited).unwrap_err();

        match err {
            ConfigError::Preset(PresetError::LocalNotFound(path)) => {
                assert_eq!(path, missing_path);
            }
            other => panic!("expected PresetError::LocalNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn error_on_invalid_yaml_in_preset() {
        let tmp = TempDir::new().unwrap();
        let preset_path = tmp.path().join("bad.yml");
        fs::write(&preset_path, "rules: [invalid yaml\n  broken:").unwrap();

        let mut visited = HashSet::new();
        let err = load_local_preset("./bad.yml", tmp.path(), &mut visited).unwrap_err();
        assert!(matches!(err, ConfigError::Yaml(_)));
    }

    #[test]
    fn loaded_preset_config_is_valid() {
        let tmp = TempDir::new().unwrap();
        let base_dir = tmp.path();
        fs::write(
            base_dir.join("preset.yml"),
            indoc! {"
                defaults:
                  action: allow
                rules:
                  - allow: 'git status'
                  - deny: 'rm -rf /'
            "},
        )
        .unwrap();

        let mut visited = HashSet::new();
        let config = load_local_preset("./preset.yml", base_dir, &mut visited).unwrap();

        assert_eq!(
            config.defaults.as_ref().unwrap().action,
            Some(crate::config::ActionKind::Allow)
        );
        let rules = config.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].allow.as_deref(), Some("git status"));
        assert_eq!(rules[1].deny.as_deref(), Some("rm -rf /"));
    }
}
