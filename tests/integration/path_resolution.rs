//! Integration tests verifying consistent path resolution regardless of cwd.

use std::fs;

use indoc::indoc;
use rstest::rstest;
use runok::config::{ConfigLoader, DefaultConfigLoader};
use tempfile::TempDir;

struct PathResolutionEnv {
    _tmp: TempDir,
    project_dir: std::path::PathBuf,
}

fn make_env() -> Result<PathResolutionEnv, Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let project_dir = tmp.path().join("project");
    for dir in ["src", "src/nested", "tmp"] {
        fs::create_dir_all(project_dir.join(dir))?;
    }

    fs::write(
        project_dir.join("runok.yml"),
        indoc! {r#"
            definitions:
              paths:
                sensitive:
                  - ".env*"
                  - "secrets/credentials.json"
              sandbox:
                restricted:
                  fs:
                    writable:
                      - "./tmp"
                    deny:
                      - ".env*"
                      - "/etc/shadow"
        "#},
    )?;

    Ok(PathResolutionEnv {
        _tmp: tmp,
        project_dir,
    })
}

/// Relative paths in definitions.paths resolve relative to the config file's
/// parent directory, regardless of cwd.
#[rstest]
#[case::from_project_root("")]
#[case::from_src("src")]
#[case::from_nested("src/nested")]
fn paths_resolved_relative_to_config_file(
    #[case] subdir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = make_env()?;
    let cwd = if subdir.is_empty() {
        env.project_dir.clone()
    } else {
        env.project_dir.join(subdir)
    };

    let loader = DefaultConfigLoader::with_global_dir(env.project_dir.join("nonexistent_global"));
    let config = loader.load(&cwd)?;

    let defs = config.definitions.ok_or("definitions missing")?;
    let paths = defs.paths.ok_or("paths missing")?;
    let sensitive = &paths["sensitive"];

    // Relative paths are resolved against the config file's parent (project_dir)
    let expected_env = format!("{}/.env*", env.project_dir.display());
    let expected_creds = format!("{}/secrets/credentials.json", env.project_dir.display());
    assert_eq!(sensitive[0], expected_env, "cwd={}", cwd.display());
    assert_eq!(sensitive[1], expected_creds, "cwd={}", cwd.display());
    Ok(())
}

/// Sandbox writable/deny paths resolve relative to the config file's
/// parent directory, regardless of cwd.
#[rstest]
#[case::from_project_root("")]
#[case::from_src("src")]
fn sandbox_paths_resolved_relative_to_config_file(
    #[case] subdir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = make_env()?;
    let cwd = if subdir.is_empty() {
        env.project_dir.clone()
    } else {
        env.project_dir.join(subdir)
    };

    let loader = DefaultConfigLoader::with_global_dir(env.project_dir.join("nonexistent_global"));
    let config = loader.load(&cwd)?;

    let defs = config.definitions.ok_or("definitions missing")?;
    let sandbox = defs.sandbox.ok_or("sandbox missing")?;
    let restricted = &sandbox["restricted"];
    let fs_policy = restricted.fs.as_ref().ok_or("fs policy missing")?;

    // Relative writable path is resolved
    let writable = fs_policy.write_allow().ok_or("writable missing")?;
    let expected_tmp = format!("{}/tmp", env.project_dir.display());
    assert_eq!(writable[0], expected_tmp, "cwd={}", cwd.display());

    // Relative deny path is resolved
    let deny = fs_policy.write_deny().ok_or("deny missing")?;
    let expected_deny_env = format!("{}/.env*", env.project_dir.display());
    assert_eq!(deny[0], expected_deny_env, "cwd={}", cwd.display());
    // Absolute paths remain unchanged
    assert_eq!(deny[1], "/etc/shadow", "cwd={}", cwd.display());
    Ok(())
}

/// Global and local configs use different base_dir values;
/// paths are resolved before merging.
#[rstest]
fn global_and_local_use_different_base_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let home = tmp.path().join("home");
    let global_dir = tmp.path().join("global");
    let project_dir = home.join("project");

    fs::create_dir_all(&global_dir)?;
    fs::create_dir_all(&project_dir)?;

    fs::write(
        global_dir.join("runok.yml"),
        indoc! {r#"
            definitions:
              paths:
                global_paths:
                  - "global-data/**"
        "#},
    )?;

    fs::write(
        project_dir.join("runok.yml"),
        indoc! {r#"
            definitions:
              paths:
                local_paths:
                  - "local-data/**"
        "#},
    )?;

    let loader = DefaultConfigLoader::with_global_dir(global_dir.clone());
    let config = loader.load(&project_dir)?;

    let defs = config.definitions.ok_or("definitions missing")?;
    let paths = defs.paths.ok_or("paths missing")?;

    // Global config paths resolve relative to the global directory
    let global = &paths["global_paths"];
    assert_eq!(
        global[0],
        format!("{}/global-data/**", global_dir.display())
    );

    // Local config paths resolve relative to the project directory
    let local = &paths["local_paths"];
    assert_eq!(local[0], format!("{}/local-data/**", project_dir.display()));
    Ok(())
}

/// Paths inside a preset loaded via extends resolve relative to
/// the preset file's parent directory.
/// Calls load_local_preset directly to verify path resolution.
#[rstest]
fn preset_paths_resolved_relative_to_preset_file() -> Result<(), Box<dyn std::error::Error>> {
    use runok::config::load_local_preset;

    let tmp = TempDir::new()?;
    let project_dir = tmp.path().join("project");
    let presets_dir = project_dir.join("presets");
    fs::create_dir_all(&presets_dir)?;

    fs::write(
        presets_dir.join("base.yml"),
        indoc! {r#"
            definitions:
              paths:
                preset_sensitive:
                  - "preset-data/.env*"
        "#},
    )?;

    // load_local_preset resolves paths internally
    let config = load_local_preset("./presets/base.yml", &project_dir)?;

    let defs = config.definitions.ok_or("definitions missing")?;
    let paths = defs.paths.ok_or("paths missing")?;

    // Preset paths resolve relative to the preset's parent directory (presets/)
    let preset_paths = &paths["preset_sensitive"];
    assert_eq!(
        preset_paths[0],
        format!("{}/preset-data/.env*", presets_dir.display())
    );
    Ok(())
}
