use std::cell::RefCell;

use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

use runok::init::error::InitError;
use runok::init::prompt::{AutoYesPrompter, Prompter};
use runok::init::{InitScope, run_wizard_with_paths};

/// Queued response for SequencePrompter.
#[derive(Debug)]
enum Response {
    Confirm(bool),
    Select(usize),
}

/// Test prompter that returns pre-configured responses in sequence.
struct SequencePrompter {
    responses: RefCell<Vec<Response>>,
}

impl SequencePrompter {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: RefCell::new(responses),
        }
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
            other => unreachable!("expected Confirm response, got {other:?}"),
        }
    }

    fn select(&self, _message: &str, _items: &[&str], default: usize) -> Result<usize, InitError> {
        let mut responses = self.responses.borrow_mut();
        if responses.is_empty() {
            return Ok(default);
        }
        match responses.remove(0) {
            Response::Select(v) => Ok(v),
            other => unreachable!("expected Select response, got {other:?}"),
        }
    }
}

/// Test environment for init wizard integration tests.
///
/// Uses explicit paths instead of environment variables to avoid data races.
struct InitTestEnv {
    _tmp: TempDir,
    home: std::path::PathBuf,
    cwd: std::path::PathBuf,
    user_config_dir: std::path::PathBuf,
}

impl InitTestEnv {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home = tmp.path().join("home");
        let cwd = tmp.path().join("project");
        let user_config_dir = home.join(".config").join("runok");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&cwd)?;

        Ok(Self {
            _tmp: tmp,
            home,
            cwd,
            user_config_dir,
        })
    }

    fn user_config_path(&self) -> std::path::PathBuf {
        self.user_config_dir.join("runok.yml")
    }

    fn user_claude_dir(&self) -> std::path::PathBuf {
        self.home.join(".claude")
    }

    fn project_claude_dir(&self) -> std::path::PathBuf {
        self.cwd.join(".claude")
    }

    fn setup_user_claude_settings(&self, content: &str) -> Result<(), Box<dyn std::error::Error>> {
        let dir = self.user_claude_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("settings.json"), content)?;
        Ok(())
    }

    fn setup_project_claude_settings(
        &self,
        content: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = self.project_claude_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("settings.json"), content)?;
        Ok(())
    }

    fn run(
        &self,
        scope: Option<&InitScope>,
        prompter: &dyn runok::init::prompt::Prompter,
    ) -> Result<(), runok::init::error::InitError> {
        run_wizard_with_paths(
            scope,
            prompter,
            &self.cwd,
            &self.user_config_dir,
            &self.home,
        )
    }
}

#[rstest]
fn full_user_flow_with_claude_code_integration() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_user_claude_settings(indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(git status)", "Bash(npm install *)", "Read(/tmp)"],
                "deny": ["Bash(rm -rf /)", "Write(/etc/passwd)"]
            }
        }
    "#})?;

    env.run(Some(&InitScope::User), &AutoYesPrompter)?;

    let config = std::fs::read_to_string(env.user_config_path())?;
    assert_eq!(
        config,
        indoc! {"\
            # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

            # Converted from Claude Code permissions:
            rules:
              - allow: 'git status'
              - allow: 'npm install *'
              - deny: 'rm -rf /'
        "}
    );

    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.user_claude_dir().join("settings.json"),
    )?)?;
    assert_eq!(
        settings,
        serde_json::json!({
            "permissions": {
                "allow": ["Read(/tmp)"],
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
    Ok(())
}

#[rstest]
fn project_flow_creates_config_in_cwd() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    env.run(Some(&InitScope::Project), &AutoYesPrompter)?;

    let config = std::fs::read_to_string(env.cwd.join("runok.yml"))?;
    assert_eq!(
        config,
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
    );
    Ok(())
}

#[rstest]
fn project_flow_skips_migration_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_project_claude_settings(indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"]
            }
        }
    "#})?;

    // AutoYesPrompter returns default=false for migration confirm → skips migration
    env.run(Some(&InitScope::Project), &AutoYesPrompter)?;

    let config = std::fs::read_to_string(env.cwd.join("runok.yml"))?;
    assert_eq!(
        config,
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
    );

    // settings.json unchanged (no migration, no hook)
    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.project_claude_dir().join("settings.json"),
    )?)?;
    assert_eq!(
        settings,
        serde_json::json!({
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"]
            }
        })
    );
    Ok(())
}

#[rstest]
fn project_flow_migrates_when_opted_in() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_project_claude_settings(indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"]
            }
        }
    "#})?;

    // First confirm: "Migrate?" → yes, Second confirm: "Apply these changes?" → yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    let config = std::fs::read_to_string(env.cwd.join("runok.yml"))?;
    assert_eq!(
        config,
        indoc! {"\
            # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

            # Converted from Claude Code permissions:
            rules:
              - allow: 'cargo test'
              - allow: 'cargo build'
        "}
    );

    // Permissions removed but no hook registered (project scope never adds hook)
    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.project_claude_dir().join("settings.json"),
    )?)?;
    assert_eq!(
        settings,
        serde_json::json!({
            "permissions": {}
        })
    );
    Ok(())
}

#[rstest]
fn non_interactive_mode_selects_user_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    // AutoYesPrompter select default is 0 = User
    env.run(None, &AutoYesPrompter)?;

    assert!(env.user_config_path().exists());
    assert!(!env.cwd.join("runok.yml").exists());
    Ok(())
}

// --- batch confirmation with mixed Bash / non-Bash entries ---

fn mixed_permissions_settings() -> &'static str {
    indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(git status)", "Read(/tmp)", "WebFetch"],
                "deny": ["Bash(rm -rf /)", "Write(/etc/passwd)"]
            }
        }
    "#}
}

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

fn original_settings() -> serde_json::Value {
    serde_json::json!({
        "permissions": {
            "allow": ["Bash(git status)", "Read(/tmp)", "WebFetch"],
            "deny": ["Bash(rm -rf /)", "Write(/etc/passwd)"]
        }
    })
}

fn boilerplate_config() -> String {
    "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n".to_string()
}

#[rstest]
#[case::accept_all(
    true,
    config_with_rules(),
    serde_json::json!({
        "permissions": {
            "allow": ["Read(/tmp)", "WebFetch"],
            "deny": ["Write(/etc/passwd)"]
        },
        "hooks": hook_json()
    }),
)]
#[case::decline_all(false, boilerplate_config(), original_settings())]
fn batch_confirmation_with_mixed_permissions(
    #[case] accept: bool,
    #[case] expected_config: String,
    #[case] expected_settings: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_user_claude_settings(mixed_permissions_settings())?;

    // First confirm: "Migrate?" → accept, Second confirm (if migration accepted): "Apply?" → accept
    let responses = if accept {
        vec![Response::Confirm(true), Response::Confirm(true)]
    } else {
        // Decline migration → hook-only change still shown → decline apply too
        vec![Response::Confirm(false), Response::Confirm(false)]
    };
    let prompter = SequencePrompter::new(responses);
    env.run(Some(&InitScope::User), &prompter)?;

    // runok.yml is always created (boilerplate if declined, with rules if accepted)
    let config = std::fs::read_to_string(env.user_config_path())?;
    assert_eq!(config, expected_config);

    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.user_claude_dir().join("settings.json"),
    )?)?;
    assert_eq!(settings, expected_settings);

    Ok(())
}

#[rstest]
fn non_bash_permissions_only_preserves_all_and_adds_hook() -> Result<(), Box<dyn std::error::Error>>
{
    let env = InitTestEnv::new()?;
    env.setup_user_claude_settings(indoc! {r#"
        {
            "permissions": {
                "allow": ["Read(/tmp)", "WebFetch", "Skill"],
                "deny": ["Write(/etc/passwd)"]
            }
        }
    "#})?;

    env.run(Some(&InitScope::User), &AutoYesPrompter)?;

    let config = std::fs::read_to_string(env.user_config_path())?;
    assert_eq!(
        config,
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
    );

    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.user_claude_dir().join("settings.json"),
    )?)?;
    assert_eq!(
        settings,
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
    Ok(())
}

#[rstest]
fn hook_already_registered_is_not_duplicated() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
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
    "#})?;

    env.run(Some(&InitScope::User), &AutoYesPrompter)?;

    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.user_claude_dir().join("settings.json"),
    )?)?;
    assert_eq!(
        settings,
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
    Ok(())
}

// --- scope selection ---

#[rstest]
#[case::select_user(0, true, false)]
#[case::select_project(1, false, true)]
fn no_scope_select(
    #[case] selection: usize,
    #[case] user_config_exists: bool,
    #[case] project_config_exists: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    let prompter = SequencePrompter::new(vec![Response::Select(selection)]);
    env.run(None, &prompter)?;

    assert_eq!(env.user_config_path().exists(), user_config_exists);
    assert_eq!(env.cwd.join("runok.yml").exists(), project_config_exists);
    Ok(())
}
