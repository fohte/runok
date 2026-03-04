mod preview;
mod setup;

use std::path::{Path, PathBuf};

use setup::{ScopeResult, setup_scope};

use super::error::InitError;
use super::prompt::{AutoYesPrompter, DialoguerPrompter, Prompter};

/// Summary of actions performed by the init wizard.
struct Summary {
    user_config_created: Option<PathBuf>,
    project_config_created: Option<PathBuf>,
    hook_registered: bool,
    converted_rules: Option<String>,
    permissions_removed: bool,
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
    if summary.converted_rules.is_some() {
        eprintln!("  - Claude Code permissions converted to runok rules");
    }
    if summary.permissions_removed {
        eprintln!("  - Claude Code permissions removed from settings.json");
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
    summary.converted_rules = result.converted_rules;
    summary.permissions_removed = result.permissions_removed;
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
    let prompter: Box<dyn Prompter> = if auto_yes {
        Box::new(AutoYesPrompter)
    } else {
        Box::new(DialoguerPrompter)
    };
    run_wizard_with_paths(
        scope,
        prompter.as_ref(),
        force,
        cwd,
        &paths.user_config_dir,
        &paths.home_dir,
    )
}

/// Run the init wizard with explicit paths (for testing without relying on env vars).
pub fn run_wizard_with_paths(
    scope: Option<&InitScope>,
    prompter: &dyn Prompter,
    force: bool,
    cwd: &Path,
    user_config_dir: &Path,
    home_dir: &Path,
) -> Result<(), InitError> {
    let mut summary = Summary {
        user_config_created: None,
        project_config_created: None,
        hook_registered: false,
        converted_rules: None,
        permissions_removed: false,
    };

    match scope {
        Some(InitScope::User) => {
            let claude_dir = home_dir.join(".claude");
            let result = setup_scope(
                user_config_dir,
                claude_dir_if_exists(&claude_dir),
                prompter,
                force,
            )?;
            apply_scope_result(&mut summary, result, true);
        }
        Some(InitScope::Project) => {
            let claude_dir = cwd.join(".claude");
            let result = setup_scope(cwd, claude_dir_if_exists(&claude_dir), prompter, force)?;
            apply_scope_result(&mut summary, result, false);
        }
        None => {
            // No scope specified: ask user to choose
            let items = ["User (global)", "Project (local)"];
            let selection = prompter.select("Where do you want to set up runok?", &items, 0)?;

            match selection {
                0 => {
                    // User scope
                    let user_claude_dir = home_dir.join(".claude");
                    let result = setup_scope(
                        user_config_dir,
                        claude_dir_if_exists(&user_claude_dir),
                        prompter,
                        force,
                    )?;
                    apply_scope_result(&mut summary, result, true);
                }
                _ => {
                    // Project scope
                    let project_claude_dir = cwd.join(".claude");
                    let result = setup_scope(
                        cwd,
                        claude_dir_if_exists(&project_claude_dir),
                        prompter,
                        force,
                    )?;
                    apply_scope_result(&mut summary, result, false);
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

    /// Queued response for SequencePrompter: either a confirm (bool) or select (usize).
    #[derive(Debug)]
    enum Response {
        Confirm(bool),
        Select(usize),
    }

    /// Test prompter that returns pre-configured responses in sequence.
    struct SequencePrompter {
        responses: std::cell::RefCell<Vec<Response>>,
    }

    impl SequencePrompter {
        fn new(responses: Vec<Response>) -> Self {
            Self {
                responses: std::cell::RefCell::new(responses),
            }
        }

        fn assert_exhausted(&self) {
            let remaining = self.responses.borrow();
            assert!(
                remaining.is_empty(),
                "SequencePrompter has {} unused responses: {:?}",
                remaining.len(),
                &*remaining,
            );
        }
    }

    impl Prompter for SequencePrompter {
        fn confirm(&self, _message: &str, default: bool) -> Result<bool, InitError> {
            let mut responses = self.responses.borrow_mut();
            if responses.is_empty() {
                return Ok(default);
            }
            match responses.remove(0) {
                Response::Confirm(v) => Ok(v),
                other => panic!("expected Confirm response, got {other:?}"),
            }
        }

        fn select(
            &self,
            _message: &str,
            _items: &[&str],
            default: usize,
        ) -> Result<usize, InitError> {
            let mut responses = self.responses.borrow_mut();
            if responses.is_empty() {
                return Ok(default);
            }
            match responses.remove(0) {
                Response::Select(v) => Ok(v),
                other => panic!("expected Select response, got {other:?}"),
            }
        }
    }

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
            prompter: &dyn Prompter,
            force: bool,
        ) -> Result<(), InitError> {
            run_wizard_with_paths(
                scope,
                prompter,
                force,
                &self.cwd,
                &self.user_config_dir,
                &self.home,
            )
        }
    }

    fn claude_settings_with_permissions() -> &'static str {
        indoc! {r#"
            {
                "permissions": {
                    "allow": ["Bash(git status)", "Read(/tmp)"],
                    "deny": ["Bash(rm -rf /)"]
                }
            }
        "#}
    }

    #[rstest]
    fn wizard_user_scope_creates_config() {
        let env = TestEnv::new();
        env.run(Some(&InitScope::User), &AutoYesPrompter, false)
            .unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_project_scope_creates_config() {
        let env = TestEnv::new();
        env.run(Some(&InitScope::Project), &AutoYesPrompter, false)
            .unwrap();

        assert!(env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_user_scope_with_claude_code_integration() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(claude_settings_with_permissions());

        env.run(Some(&InitScope::User), &AutoYesPrompter, false)
            .unwrap();

        let config_content =
            std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(
            config_content,
            indoc! {"\
                # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

                # Converted from Claude Code permissions:
                rules:
                  - allow: 'git status'
                  - deny: 'rm -rf /'
            "}
        );

        // Hook registered, Bash permissions removed, non-Bash preserved
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(env.user_claude_dir().join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            settings,
            serde_json::json!({
                "permissions": {
                    "allow": ["Read(/tmp)"]
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "runok check --input-format claude-code-hook"
                                }
                            ]
                        }
                    ]
                }
            })
        );
    }

    #[rstest]
    fn wizard_force_overwrites_existing() {
        let env = TestEnv::new();
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "old content").unwrap();

        env.run(Some(&InitScope::User), &AutoYesPrompter, true)
            .unwrap();

        let content = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(
            content,
            "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
        );
    }

    #[rstest]
    fn wizard_user_scope_errors_on_existing_without_force() {
        let env = TestEnv::new();
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "existing").unwrap();

        let result = env.run(Some(&InitScope::User), &AutoYesPrompter, false);
        assert!(matches!(result, Err(InitError::ConfigExists(_))));
    }

    #[rstest]
    fn wizard_no_scope_with_auto_yes_selects_user() {
        let env = TestEnv::new();

        // AutoYesPrompter select default is 0 = User
        env.run(None, &AutoYesPrompter, false).unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
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

        env.run(Some(&InitScope::Project), &AutoYesPrompter, false)
            .unwrap();

        let config_content = std::fs::read_to_string(env.cwd.join("runok.yml")).unwrap();
        assert_eq!(
            config_content,
            indoc! {"\
                # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

                # Converted from Claude Code permissions:
                rules:
                  - allow: 'cargo test'
            "}
        );
    }

    #[rstest]
    fn wizard_no_scope_user_errors_on_existing_config() {
        let env = TestEnv::new();
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "existing").unwrap();

        // Select user scope (0), then setup_scope hits existing config
        let result = env.run(None, &AutoYesPrompter, false);
        assert!(matches!(result, Err(InitError::ConfigExists(_))));
    }

    // --- batch confirmation ---

    /// Helper: read and parse settings.json from a claude dir.
    fn read_settings(claude_dir: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(claude_dir.join("settings.json")).unwrap())
            .unwrap()
    }

    /// Hook JSON fragment used in expected settings assertions.
    fn hook_json() -> serde_json::Value {
        serde_json::json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "runok check --input-format claude-code-hook"
                        }
                    ]
                }
            ]
        })
    }

    fn config_with_rules() -> String {
        indoc! {"\
            # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

            # Converted from Claude Code permissions:
            rules:
              - allow: 'git status'
              - deny: 'rm -rf /'
        "}
        .to_string()
    }

    #[rstest]
    fn wizard_batch_accept_applies_all_changes() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(claude_settings_with_permissions());

        // Single confirm: accept all
        let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
        env.run(Some(&InitScope::User), &prompter, false).unwrap();
        prompter.assert_exhausted();

        let config_content =
            std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(config_content, config_with_rules());

        assert_eq!(
            read_settings(&env.user_claude_dir()),
            serde_json::json!({
                "permissions": {
                    "allow": ["Read(/tmp)"]
                },
                "hooks": hook_json()
            }),
        );
    }

    #[rstest]
    fn wizard_batch_decline_skips_all_changes() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(claude_settings_with_permissions());

        // Single confirm: decline all
        let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
        env.run(Some(&InitScope::User), &prompter, false).unwrap();
        prompter.assert_exhausted();

        assert!(
            !env.user_config_dir.join("runok.yml").exists(),
            "runok.yml should not exist when user declined"
        );

        // settings.json unchanged
        assert_eq!(
            read_settings(&env.user_claude_dir()),
            serde_json::json!({
                "permissions": {
                    "allow": ["Bash(git status)", "Read(/tmp)"],
                    "deny": ["Bash(rm -rf /)"]
                }
            }),
        );
    }

    // --- scope selection ---

    #[rstest]
    fn wizard_no_scope_select_user() {
        let env = TestEnv::new();

        // Select user (0)
        let prompter = SequencePrompter::new(vec![Response::Select(0)]);
        env.run(None, &prompter, false).unwrap();
        prompter.assert_exhausted();

        assert!(env.user_config_dir.join("runok.yml").exists());
        assert!(!env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_no_scope_select_project() {
        let env = TestEnv::new();

        // Select project (1)
        let prompter = SequencePrompter::new(vec![Response::Select(1)]);
        env.run(None, &prompter, false).unwrap();
        prompter.assert_exhausted();

        assert!(!env.user_config_dir.join("runok.yml").exists());
        assert!(env.cwd.join("runok.yml").exists());
    }

    // --- edge cases ---

    #[rstest]
    fn wizard_claude_dir_without_settings_json_registers_hook_only() {
        let env = TestEnv::new();
        // Create .claude dir but no settings.json
        let claude_dir = env.user_claude_dir();
        std::fs::create_dir_all(&claude_dir).unwrap();

        env.run(Some(&InitScope::User), &AutoYesPrompter, false)
            .unwrap();

        // runok.yml should be created with boilerplate only (no rules)
        let config = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(
            config,
            "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
        );

        // Hook should be registered in a newly created settings.json
        assert_eq!(
            read_settings(&claude_dir),
            serde_json::json!({
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "runok check --input-format claude-code-hook"
                                }
                            ]
                        }
                    ]
                }
            })
        );
    }

    #[rstest]
    fn wizard_non_bash_permissions_only_skips_rule_conversion() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(indoc! {r#"
            {
                "permissions": {
                    "allow": ["Read(/tmp)", "WebFetch", "Skill"],
                    "deny": ["Write(/etc/passwd)"]
                }
            }
        "#});

        env.run(Some(&InitScope::User), &AutoYesPrompter, false)
            .unwrap();

        let config = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(
            config,
            "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
        );

        assert_eq!(
            read_settings(&env.user_claude_dir()),
            serde_json::json!({
                "permissions": {
                    "allow": ["Read(/tmp)", "WebFetch", "Skill"],
                    "deny": ["Write(/etc/passwd)"]
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "runok check --input-format claude-code-hook"
                                }
                            ]
                        }
                    ]
                }
            })
        );
    }

    #[rstest]
    fn wizard_hook_already_registered_no_prompt_needed() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(indoc! {r#"
            {
                "permissions": {
                    "allow": ["Bash(git status)"]
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "runok check --input-format claude-code-hook"
                                }
                            ]
                        }
                    ]
                }
            }
        "#});

        // Has Bash permissions but hook already registered.
        // Still has_rules=true so has_any_change=true, needs 1 confirm.
        let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
        env.run(Some(&InitScope::User), &prompter, false).unwrap();
        prompter.assert_exhausted();

        let config = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(
            config,
            indoc! {"\
                # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

                # Converted from Claude Code permissions:
                rules:
                  - allow: 'git status'
            "}
        );

        assert_eq!(
            read_settings(&env.user_claude_dir()),
            serde_json::json!({
                "permissions": {},
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "runok check --input-format claude-code-hook"
                                }
                            ]
                        }
                    ]
                }
            })
        );
    }
}
