mod preview;
mod setup;

use std::path::{Path, PathBuf};

use setup::{HookPolicy, ScopeResult, setup_scope};

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
/// `cwd`: current working directory
pub fn run_wizard(scope: Option<&InitScope>, auto_yes: bool, cwd: &Path) -> Result<(), InitError> {
    let paths = resolve_paths()?;
    let prompter: Box<dyn Prompter> = if auto_yes {
        Box::new(AutoYesPrompter)
    } else {
        Box::new(DialoguerPrompter)
    };
    run_wizard_with_paths(
        scope,
        prompter.as_ref(),
        cwd,
        &paths.user_config_dir,
        &paths.home_dir,
    )
}

/// Run the init wizard with explicit paths (for testing without relying on env vars).
pub fn run_wizard_with_paths(
    scope: Option<&InitScope>,
    prompter: &dyn Prompter,
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
                HookPolicy::Register,
                true,
            )?;
            apply_scope_result(&mut summary, result, true);
        }
        Some(InitScope::Project) => {
            let claude_dir = cwd.join(".claude");
            let result = setup_scope(
                cwd,
                claude_dir_if_exists(&claude_dir),
                prompter,
                HookPolicy::Skip,
                false,
            )?;
            apply_scope_result(&mut summary, result, false);
        }
        None => {
            let items = ["User (global)", "Project (local)"];
            let selection = prompter.select("Where do you want to set up runok?", &items, 0)?;

            match selection {
                0 => {
                    let user_claude_dir = home_dir.join(".claude");
                    let result = setup_scope(
                        user_config_dir,
                        claude_dir_if_exists(&user_claude_dir),
                        prompter,
                        HookPolicy::Register,
                        true,
                    )?;
                    apply_scope_result(&mut summary, result, true);
                }
                _ => {
                    let project_claude_dir = cwd.join(".claude");
                    let result = setup_scope(
                        cwd,
                        claude_dir_if_exists(&project_claude_dir),
                        prompter,
                        HookPolicy::Skip,
                        false,
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

        fn run(&self, scope: Option<&InitScope>, prompter: &dyn Prompter) -> Result<(), InitError> {
            run_wizard_with_paths(
                scope,
                prompter,
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
        env.run(Some(&InitScope::User), &AutoYesPrompter).unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_project_scope_creates_config() {
        let env = TestEnv::new();
        env.run(Some(&InitScope::Project), &AutoYesPrompter)
            .unwrap();

        assert!(env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_user_scope_with_claude_code_integration() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(claude_settings_with_permissions());

        env.run(Some(&InitScope::User), &AutoYesPrompter).unwrap();

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
    fn wizard_no_scope_with_auto_yes_selects_user() {
        let env = TestEnv::new();

        // AutoYesPrompter select default is 0 = User
        env.run(None, &AutoYesPrompter).unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
        assert!(!env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_project_scope_auto_yes_migrates_and_applies() {
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

        // AutoYesPrompter: always returns true → migration Yes, apply Yes
        env.run(Some(&InitScope::Project), &AutoYesPrompter)
            .unwrap();

        let config = std::fs::read_to_string(env.cwd.join("runok.yml")).unwrap();
        assert_eq!(
            config,
            indoc! {"\
                # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

                # Converted from Claude Code permissions:
                rules:
                  - allow: 'cargo test'
            "}
        );

        // Permissions removed (migration accepted, no hook for project scope)
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project_claude.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            settings,
            serde_json::json!({
                "permissions": {}
            })
        );
    }

    #[rstest]
    fn wizard_project_scope_migrates_when_opted_in() {
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

        // Confirm(true) for migration ask, Confirm(true) for batch apply
        let prompter =
            SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
        env.run(Some(&InitScope::Project), &prompter).unwrap();
        prompter.assert_exhausted();

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

        // Permissions removed but no hook registered (project scope)
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project_claude.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            settings,
            serde_json::json!({
                "permissions": {}
            })
        );
    }

    #[rstest]
    fn wizard_project_scope_never_registers_hook() {
        let env = TestEnv::new();
        let project_claude = env.project_claude_dir();
        std::fs::create_dir_all(&project_claude).unwrap();
        std::fs::write(project_claude.join("settings.json"), "{}").unwrap();

        env.run(Some(&InitScope::Project), &AutoYesPrompter)
            .unwrap();

        // No hook should be added even though .claude exists
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(project_claude.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(settings, serde_json::json!({}));
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

        // Confirm(true) for migration ask, Confirm(true) for apply
        let prompter =
            SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
        env.run(Some(&InitScope::User), &prompter).unwrap();
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

        // Confirm(true) for migration ask, Confirm(false) for apply
        let prompter =
            SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
        env.run(Some(&InitScope::User), &prompter).unwrap();
        prompter.assert_exhausted();

        // runok.yml not created when user declined
        assert!(
            !env.user_config_dir.join("runok.yml").exists(),
            "runok.yml should not be created when user declined all changes"
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
        env.run(None, &prompter).unwrap();
        prompter.assert_exhausted();

        assert!(env.user_config_dir.join("runok.yml").exists());
        assert!(!env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_no_scope_select_project() {
        let env = TestEnv::new();

        // Select project (1)
        let prompter = SequencePrompter::new(vec![Response::Select(1)]);
        env.run(None, &prompter).unwrap();
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

        env.run(Some(&InitScope::User), &AutoYesPrompter).unwrap();

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

        env.run(Some(&InitScope::User), &AutoYesPrompter).unwrap();

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
        // Confirm(true) for migration, Confirm(true) for apply
        let prompter =
            SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
        env.run(Some(&InitScope::User), &prompter).unwrap();
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
