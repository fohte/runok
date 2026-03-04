use std::cell::RefCell;

use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

use runok::init::error::InitError;
use runok::init::prompt::{AutoYesPrompter, Prompter};
use runok::init::{InitScope, run_wizard_with_paths};

/// Test prompter that returns pre-configured responses in sequence.
struct SequencePrompter {
    responses: RefCell<Vec<bool>>,
}

impl SequencePrompter {
    fn new(responses: Vec<bool>) -> Self {
        Self {
            responses: RefCell::new(responses),
        }
    }
}

impl Prompter for SequencePrompter {
    fn confirm(&self, _message: &str, default: bool) -> Result<bool, InitError> {
        let mut responses = self.responses.borrow_mut();
        if responses.is_empty() {
            Ok(default)
        } else {
            Ok(responses.remove(0))
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
        force: bool,
    ) -> Result<(), runok::init::error::InitError> {
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

    env.run(Some(&InitScope::User), &AutoYesPrompter, false)?;

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
    // Non-Bash entries should be preserved
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

    env.run(Some(&InitScope::Project), &AutoYesPrompter, false)?;

    let config = std::fs::read_to_string(env.cwd.join("runok.yml"))?;
    assert_eq!(
        config,
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
    );
    Ok(())
}

#[rstest]
fn project_flow_with_claude_code() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_project_claude_settings(indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"]
            }
        }
    "#})?;

    env.run(Some(&InitScope::Project), &AutoYesPrompter, false)?;

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

    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.project_claude_dir().join("settings.json"),
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

#[rstest]
fn force_overwrites_existing_config() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    std::fs::write(env.cwd.join("runok.yml"), "old content")?;

    env.run(Some(&InitScope::Project), &AutoYesPrompter, true)?;

    let config = std::fs::read_to_string(env.cwd.join("runok.yml"))?;
    assert_eq!(
        config,
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json\n"
    );
    Ok(())
}

#[rstest]
fn non_interactive_mode_uses_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    // AutoYesPrompter: user scope (default yes), project scope (default no)
    env.run(None, &AutoYesPrompter, false)?;

    // User config should be created
    assert!(env.user_config_path().exists());

    // Project config should NOT be created (default is No)
    assert!(!env.cwd.join("runok.yml").exists());
    Ok(())
}

// --- per-step confirmation with mixed Bash / non-Bash entries ---

/// Settings with both Bash and non-Bash permission entries.
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

/// Original settings.json value (unchanged).
fn original_settings() -> serde_json::Value {
    serde_json::json!({
        "permissions": {
            "allow": ["Bash(git status)", "Read(/tmp)", "WebFetch"],
            "deny": ["Bash(rm -rf /)", "Write(/etc/passwd)"]
        }
    })
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

    env.run(Some(&InitScope::User), &AutoYesPrompter, false)?;

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

    env.run(Some(&InitScope::User), &AutoYesPrompter, false)?;

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

/// Responses: [remove_permissions, create_runok_yml, register_hook]
#[rstest]
#[case::accept_all(
    vec![true, true, true],
    Some(config_with_rules()),
    serde_json::json!({
        "permissions": {
            "allow": ["Read(/tmp)", "WebFetch"],
            "deny": ["Write(/etc/passwd)"]
        },
        "hooks": hook_json()
    }),
)]
#[case::decline_permissions_accept_rest(
    vec![false, true, true],
    Some(config_with_rules()),
    serde_json::json!({
        "permissions": {
            "allow": ["Bash(git status)", "Read(/tmp)", "WebFetch"],
            "deny": ["Bash(rm -rf /)", "Write(/etc/passwd)"]
        },
        "hooks": hook_json()
    }),
)]
#[case::accept_permissions_decline_config(
    vec![true, false, true],
    None,
    serde_json::json!({
        "permissions": {
            "allow": ["Read(/tmp)", "WebFetch"],
            "deny": ["Write(/etc/passwd)"]
        },
        "hooks": hook_json()
    }),
)]
#[case::accept_all_decline_hook(
    vec![true, true, false],
    Some(config_with_rules()),
    serde_json::json!({
        "permissions": {
            "allow": ["Read(/tmp)", "WebFetch"],
            "deny": ["Write(/etc/passwd)"]
        }
    }),
)]
#[case::decline_all(
    vec![false, false, false],
    None,
    original_settings(),
)]
fn per_step_confirmation_with_mixed_permissions(
    #[case] responses: Vec<bool>,
    #[case] expected_config: Option<String>,
    #[case] expected_settings: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_user_claude_settings(mixed_permissions_settings())?;

    let prompter = SequencePrompter::new(responses);
    env.run(Some(&InitScope::User), &prompter, false)?;

    let config_path = env.user_config_path();
    match expected_config {
        Some(expected) => {
            let config = std::fs::read_to_string(&config_path)?;
            assert_eq!(config, expected);
        }
        None => {
            assert!(
                !config_path.exists(),
                "runok.yml should not exist when user declined config creation"
            );
        }
    }

    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        env.user_claude_dir().join("settings.json"),
    )?)?;
    assert_eq!(settings, expected_settings);

    Ok(())
}
