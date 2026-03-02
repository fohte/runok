use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

use runok::init::{InitScope, run_wizard_with_paths};

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
        auto_yes: bool,
        force: bool,
    ) -> Result<(), runok::init::error::InitError> {
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
fn full_user_flow_with_claude_code_integration() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_user_claude_settings(indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(git status)", "Bash(npm:install:*)", "Read(/tmp)"],
                "deny": ["Bash(rm -rf /)", "Write(/etc/passwd)"]
            }
        }
    "#})?;

    env.run(Some(&InitScope::User), true, false)?;

    // Config file created
    let config = std::fs::read_to_string(env.user_config_path())?;
    let expected_tail = indoc! {"
        # Converted from Claude Code permissions:
        rules:
          - allow: 'git status'
          - allow: 'npm install *'
          - deny: 'rm -rf /'
    "};
    assert!(config.ends_with(expected_tail));

    // Hook registered
    let settings_path = env.user_claude_dir().join("settings.json");
    let settings_str = std::fs::read_to_string(&settings_path)?;
    let settings: serde_json::Value = serde_json::from_str(&settings_str)?;
    let hooks = &settings["hooks"]["PreToolUse"];
    assert!(hooks.is_array());
    assert_eq!(
        hooks[0]["command"].as_str(),
        Some("runok check --input-format claude-code-hook")
    );

    // Permissions removed
    assert!(settings["permissions"].get("allow").is_none());
    assert!(settings["permissions"].get("deny").is_none());
    Ok(())
}

#[rstest]
fn project_flow_creates_config_in_cwd() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    env.run(Some(&InitScope::Project), true, false)?;

    let config_path = env.cwd.join("runok.yml");
    assert!(config_path.exists());
    let config = std::fs::read_to_string(&config_path)?;
    assert!(config.starts_with("# runok configuration"));
    Ok(())
}

#[rstest]
fn project_flow_with_claude_code() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_project_claude_settings(indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo:build)"]
            }
        }
    "#})?;

    env.run(Some(&InitScope::Project), true, false)?;

    let config = std::fs::read_to_string(env.cwd.join("runok.yml"))?;
    let expected_tail = indoc! {"
        # Converted from Claude Code permissions:
        rules:
          - allow: 'cargo test'
          - allow: 'cargo build'
    "};
    assert!(config.ends_with(expected_tail));
    Ok(())
}

#[rstest]
fn force_overwrites_existing_config() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    std::fs::write(env.cwd.join("runok.yml"), "old content")?;

    env.run(Some(&InitScope::Project), true, true)?;

    let config = std::fs::read_to_string(env.cwd.join("runok.yml"))?;
    assert_ne!(config, "old content");
    assert!(config.starts_with("# runok configuration"));
    Ok(())
}

#[rstest]
fn non_interactive_mode_uses_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    // -y mode: user scope (default yes), project scope (default no)
    env.run(None, true, false)?;

    // User config should be created
    assert!(env.user_config_path().exists());

    // Project config should NOT be created (default is No)
    assert!(!env.cwd.join("runok.yml").exists());
    Ok(())
}
