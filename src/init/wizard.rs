use std::path::{Path, PathBuf};

use super::claude_code;
use super::config_gen;
use super::error::InitError;
use super::prompt;

/// Summary of actions performed by the init wizard.
struct Summary {
    user_config_created: Option<PathBuf>,
    project_config_created: Option<PathBuf>,
    hook_registered: bool,
    permissions_converted: usize,
    permissions_removed: bool,
    skipped_entries: Vec<String>,
}

/// Scope for init configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitScope {
    User,
    Project,
}

/// Paths resolved for the init wizard.
struct ResolvedPaths {
    user_config_dir: PathBuf,
    home_dir: PathBuf,
}

/// Resolve user config directory and home directory.
fn resolve_paths() -> Result<ResolvedPaths, InitError> {
    let home_dir = crate::config::dirs::home_dir().ok_or_else(|| {
        InitError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME not set",
        ))
    })?;
    let user_config_dir = crate::config::dirs::config_dir()
        .map(|d| d.join("runok"))
        .ok_or_else(|| {
            InitError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not determine user config directory (HOME not set)",
            ))
        })?;
    Ok(ResolvedPaths {
        user_config_dir,
        home_dir,
    })
}

/// Run the Claude Code integration steps for a given `.claude/` directory.
///
/// Returns `(converted_rules, skipped_entries, hook_registered, permissions_removed)`.
fn run_claude_code_integration(
    claude_dir: &Path,
    auto_yes: bool,
) -> Result<(Option<String>, Vec<String>, bool, bool), InitError> {
    let mut converted_rules = None;
    let mut skipped = Vec::new();
    let mut hook_registered = false;
    let mut permissions_removed = false;

    // Read and convert permissions
    let (allow, deny) = claude_code::read_permissions(claude_dir)?;
    if !allow.is_empty() || !deny.is_empty() {
        let conversion = claude_code::convert_permissions(&allow, &deny);
        if !conversion.rules.is_empty() {
            converted_rules = Some(conversion.rules);
        }
        skipped = conversion.skipped;

        // Remove converted permissions from settings.json
        let should_remove = prompt::confirm(
            "Remove converted permissions from Claude Code settings?",
            true,
            auto_yes,
        )?;
        if should_remove {
            permissions_removed = claude_code::remove_permissions(claude_dir)?;
        }
    }

    // Register hook
    let should_register = prompt::confirm(
        "Register runok hook in Claude Code settings?",
        true,
        auto_yes,
    )?;
    if should_register {
        hook_registered = claude_code::register_hook(claude_dir)?;
    }

    Ok((
        converted_rules,
        skipped,
        hook_registered,
        permissions_removed,
    ))
}

/// Result of setting up a single scope.
struct ScopeResult {
    config_path: Option<PathBuf>,
    hook_registered: bool,
    permissions_converted: usize,
    permissions_removed: bool,
    skipped_entries: Vec<String>,
}

/// Set up configuration for a given scope (user or project).
fn setup_scope(
    config_dir: &Path,
    claude_dir: Option<&Path>,
    auto_yes: bool,
    force: bool,
) -> Result<ScopeResult, InitError> {
    let mut converted_rules = None;
    let mut skipped = Vec::new();
    let mut hook_registered = false;
    let mut permissions_removed = false;

    if let Some(cd) = claude_dir
        && cd.exists()
    {
        let (rules, sk, hr, pr) = run_claude_code_integration(cd, auto_yes)?;
        converted_rules = rules;
        skipped = sk;
        hook_registered = hr;
        permissions_removed = pr;
    }

    let content = config_gen::build_config_content(converted_rules.as_deref());
    let config_path = config_gen::write_config(config_dir, &content, force)?;

    let permissions_count = converted_rules.as_deref().map_or(0, |r| {
        r.lines()
            .filter(|l| l.trim_start().starts_with("- "))
            .count()
    });

    Ok(ScopeResult {
        config_path: Some(config_path),
        hook_registered,
        permissions_converted: permissions_count,
        permissions_removed,
        skipped_entries: skipped,
    })
}

fn print_summary(summary: &Summary) {
    eprintln!();
    eprintln!("runok init complete:");
    if let Some(ref path) = summary.user_config_created {
        eprintln!("  - User config created: {}", path.display());
    }
    if let Some(ref path) = summary.project_config_created {
        eprintln!("  - Project config created: {}", path.display());
    }
    if summary.hook_registered {
        eprintln!("  - Claude Code hook registered");
    }
    if summary.permissions_converted > 0 {
        eprintln!(
            "  - {} permission(s) converted to runok rules",
            summary.permissions_converted
        );
    }
    if summary.permissions_removed {
        eprintln!("  - Claude Code permissions removed from settings.json");
    }
    if !summary.skipped_entries.is_empty() {
        eprintln!(
            "  - Skipped non-Bash entries: {}",
            summary.skipped_entries.join(", ")
        );
    }
}

fn claude_dir_if_exists(dir: &Path) -> Option<&Path> {
    if dir.exists() { Some(dir) } else { None }
}

/// Apply a scope result to the summary, replacing fields.
fn apply_scope_result(summary: &mut Summary, result: ScopeResult, is_user: bool) {
    if is_user {
        summary.user_config_created = result.config_path;
    } else {
        summary.project_config_created = result.config_path;
    }
    summary.hook_registered = result.hook_registered;
    summary.permissions_converted = result.permissions_converted;
    summary.permissions_removed = result.permissions_removed;
    summary.skipped_entries = result.skipped_entries;
}

/// Merge a scope result into the summary, accumulating fields.
fn merge_scope_result(summary: &mut Summary, result: ScopeResult, is_user: bool) {
    if is_user {
        summary.user_config_created = result.config_path;
    } else {
        summary.project_config_created = result.config_path;
    }
    if result.hook_registered {
        summary.hook_registered = true;
    }
    summary.permissions_converted += result.permissions_converted;
    if result.permissions_removed {
        summary.permissions_removed = true;
    }
    summary.skipped_entries.extend(result.skipped_entries);
}

/// Run the init wizard.
///
/// `scope`: optional scope from `--scope` flag
/// `auto_yes`: whether `-y` was specified
/// `force`: whether `--force` was specified
/// `cwd`: current working directory
pub fn run_wizard(
    scope: Option<&InitScope>,
    auto_yes: bool,
    force: bool,
    cwd: &Path,
) -> Result<(), InitError> {
    let paths = resolve_paths()?;
    run_wizard_with_paths(
        scope,
        auto_yes,
        force,
        cwd,
        &paths.user_config_dir,
        &paths.home_dir,
    )
}

/// Run the init wizard with explicit paths (for testing without relying on env vars).
pub fn run_wizard_with_paths(
    scope: Option<&InitScope>,
    auto_yes: bool,
    force: bool,
    cwd: &Path,
    user_config_dir: &Path,
    home_dir: &Path,
) -> Result<(), InitError> {
    let mut summary = Summary {
        user_config_created: None,
        project_config_created: None,
        hook_registered: false,
        permissions_converted: 0,
        permissions_removed: false,
        skipped_entries: Vec::new(),
    };

    match scope {
        Some(InitScope::User) => {
            let claude_dir = home_dir.join(".claude");
            let result = setup_scope(
                user_config_dir,
                claude_dir_if_exists(&claude_dir),
                auto_yes,
                force,
            )?;
            apply_scope_result(&mut summary, result, true);
        }
        Some(InitScope::Project) => {
            let claude_dir = cwd.join(".claude");
            let result = setup_scope(cwd, claude_dir_if_exists(&claude_dir), auto_yes, force)?;
            apply_scope_result(&mut summary, result, false);
        }
        None => {
            // No scope specified: setup user config, then optionally project config
            let user_claude_dir = home_dir.join(".claude");

            // User config
            if config_gen::config_exists(user_config_dir).is_some() && !force {
                eprintln!(
                    "User config already exists at {}, skipping.",
                    user_config_dir.display()
                );
            } else {
                let should_setup =
                    prompt::confirm("Set up user-level configuration?", true, auto_yes)?;
                if should_setup {
                    let result = setup_scope(
                        user_config_dir,
                        claude_dir_if_exists(&user_claude_dir),
                        auto_yes,
                        force,
                    )?;
                    apply_scope_result(&mut summary, result, true);
                }
            }

            // Project config
            let should_project =
                prompt::confirm("Set up project-level configuration?", false, auto_yes)?;
            if should_project {
                let project_claude_dir = cwd.join(".claude");
                match setup_scope(
                    cwd,
                    claude_dir_if_exists(&project_claude_dir),
                    auto_yes,
                    force,
                ) {
                    Ok(result) => {
                        merge_scope_result(&mut summary, result, false);
                    }
                    Err(InitError::ConfigExists(path)) => {
                        eprintln!(
                            "Project config already exists at {}, skipping.",
                            path.display()
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    print_summary(&summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;
    use tempfile::TempDir;

    /// Create a test environment with isolated home and project directories.
    struct TestEnv {
        _tmp: TempDir,
        home: PathBuf,
        cwd: PathBuf,
        user_config_dir: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let home = tmp.path().join("home");
            let cwd = tmp.path().join("project");
            let user_config_dir = home.join(".config").join("runok");
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(&cwd).unwrap();
            Self {
                _tmp: tmp,
                home,
                cwd,
                user_config_dir,
            }
        }

        fn user_claude_dir(&self) -> PathBuf {
            self.home.join(".claude")
        }

        fn project_claude_dir(&self) -> PathBuf {
            self.cwd.join(".claude")
        }

        fn setup_user_claude_settings(&self, content: &str) {
            let dir = self.user_claude_dir();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("settings.json"), content).unwrap();
        }

        fn run(
            &self,
            scope: Option<&InitScope>,
            auto_yes: bool,
            force: bool,
        ) -> Result<(), InitError> {
            run_wizard_with_paths(
                scope,
                auto_yes,
                force,
                &self.cwd,
                &self.user_config_dir,
                &self.home,
            )
        }
    }

    #[rstest]
    fn wizard_user_scope_creates_config() {
        let env = TestEnv::new();
        env.run(Some(&InitScope::User), true, false).unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_project_scope_creates_config() {
        let env = TestEnv::new();
        env.run(Some(&InitScope::Project), true, false).unwrap();

        assert!(env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_user_scope_with_claude_code_integration() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(indoc! {r#"
            {
                "permissions": {
                    "allow": ["Bash(git status)", "Read(/tmp)"],
                    "deny": ["Bash(rm -rf /)"]
                }
            }
        "#});

        env.run(Some(&InitScope::User), true, false).unwrap();

        let config_content =
            std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        // Verify the converted rules appear at the end of the config
        let expected_tail = indoc! {"
            # Converted from Claude Code permissions:
            rules:
              - allow: 'git status'
              - deny: 'rm -rf /'
        "};
        assert!(config_content.ends_with(expected_tail));

        // Hook should be registered
        let settings_content =
            std::fs::read_to_string(env.user_claude_dir().join("settings.json")).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&settings_content).unwrap();
        assert!(settings["hooks"]["PreToolUse"].is_array());

        // Permissions should be removed
        assert!(settings["permissions"].get("allow").is_none());
        assert!(settings["permissions"].get("deny").is_none());
    }

    #[rstest]
    fn wizard_force_overwrites_existing() {
        let env = TestEnv::new();
        // Create existing config
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "old content").unwrap();

        env.run(Some(&InitScope::User), true, true).unwrap();

        let content = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_ne!(content, "old content");
    }

    #[rstest]
    fn wizard_user_scope_errors_on_existing_without_force() {
        let env = TestEnv::new();
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "existing").unwrap();

        let result = env.run(Some(&InitScope::User), true, false);
        assert!(matches!(result, Err(InitError::ConfigExists(_))));
    }

    #[rstest]
    fn wizard_no_scope_with_auto_yes() {
        let env = TestEnv::new();

        // auto_yes with no scope: user setup (default yes), project setup (default no)
        env.run(None, true, false).unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
        // Project config should NOT be created (default is No for project)
        assert!(!env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_project_scope_with_claude_code() {
        let env = TestEnv::new();
        let project_claude = env.project_claude_dir();
        std::fs::create_dir_all(&project_claude).unwrap();
        std::fs::write(
            project_claude.join("settings.json"),
            indoc! {r#"
                {
                    "permissions": {
                        "allow": ["Bash(cargo test)"]
                    }
                }
            "#},
        )
        .unwrap();

        env.run(Some(&InitScope::Project), true, false).unwrap();

        let config_content = std::fs::read_to_string(env.cwd.join("runok.yml")).unwrap();
        let expected_tail = indoc! {"
            # Converted from Claude Code permissions:
            rules:
              - allow: 'cargo test'
        "};
        assert!(config_content.ends_with(expected_tail));
    }

    #[rstest]
    fn wizard_no_scope_skips_existing_user_config() {
        let env = TestEnv::new();
        // Create existing user config
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "existing").unwrap();

        // auto_yes: user config skipped (exists), project config skipped (default no)
        env.run(None, true, false).unwrap();

        // User config should not be overwritten
        let content = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(content, "existing");
    }
}
