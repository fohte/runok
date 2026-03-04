use helpers::TestEnv;
use indoc::indoc;
use rstest::rstest;

use crate::helpers;

/// Extended TestEnv for init tests with an isolated HOME.
struct InitTestEnv {
    env: TestEnv,
}

impl InitTestEnv {
    fn new() -> Self {
        Self {
            env: TestEnv::new(""),
        }
    }

    fn command(&self) -> assert_cmd::Command {
        self.env.command()
    }

    fn cwd(&self) -> &std::path::Path {
        &self.env.cwd
    }

    fn home(&self) -> &std::path::Path {
        &self.env.home
    }
}

#[rstest]
fn init_user_scope_creates_config() {
    let env = InitTestEnv::new();
    env.command()
        .args(["init", "--scope", "user", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("runok init complete:"));
}

#[rstest]
fn init_project_scope_creates_config() {
    let env = InitTestEnv::new();
    // Remove the default runok.yml that TestEnv creates
    let _ = std::fs::remove_file(env.cwd().join("runok.yml"));

    env.command()
        .args(["init", "--scope", "project", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Project config created"));

    assert!(env.cwd().join("runok.yml").exists());
}

#[rstest]
fn init_project_scope_errors_on_existing_without_force() {
    let env = InitTestEnv::new();
    // TestEnv already creates runok.yml

    env.command()
        .args(["init", "--scope", "project", "-y"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "configuration file already exists",
        ));
}

#[rstest]
fn init_project_scope_force_overwrites() {
    let env = InitTestEnv::new();
    // TestEnv already creates runok.yml

    env.command()
        .args(["init", "--scope", "project", "-y", "--force"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Project config created"));
}

#[rstest]
fn init_user_scope_with_claude_code_integration() {
    let env = InitTestEnv::new();

    // Set up ~/.claude/settings.json in isolated HOME
    let claude_dir = env.home().join(".claude");
    std::fs::create_dir_all(&claude_dir)
        .unwrap_or_else(|e| panic!("failed to create .claude dir: {e}"));
    std::fs::write(
        claude_dir.join("settings.json"),
        indoc! {r#"
            {
                "permissions": {
                    "allow": ["Bash(git status)", "Bash(npm install *)"],
                    "deny": ["Bash(rm -rf /)"]
                }
            }
        "#},
    )
    .unwrap_or_else(|e| panic!("failed to write settings.json: {e}"));

    env.command()
        .args(["init", "--scope", "user", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "permissions converted to runok rules",
        ))
        .stderr(predicates::str::contains("Claude Code hook registered"));

    // Verify config was created with converted rules
    let user_config_dir = env.home().join(".config").join("runok");
    let config = std::fs::read_to_string(user_config_dir.join("runok.yml"))
        .unwrap_or_else(|e| panic!("failed to read config: {e}"));
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

    // Verify hook registered and permissions removed
    let settings_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(claude_dir.join("settings.json"))
            .unwrap_or_else(|e| panic!("failed to read settings: {e}")),
    )
    .unwrap_or_else(|e| panic!("failed to parse settings: {e}"));
    assert_eq!(
        settings_json,
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

#[rstest]
fn init_invalid_scope() {
    let env = InitTestEnv::new();
    env.command()
        .args(["init", "--scope", "invalid"])
        .assert()
        .failure();
}
