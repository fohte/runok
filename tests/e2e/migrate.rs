#![allow(clippy::unwrap_used, reason = "test helper")]

use std::path::PathBuf;

use indoc::indoc;
use rstest::{fixture, rstest};

use super::helpers::TestEnv;

#[fixture]
fn migrate_env() -> TestEnv {
    TestEnv::new("rules:\n  - allow: git status\n")
}

/// Which `.claude/settings.json` location a test targets, matching the two
/// scopes `runok init` sets up.
enum Scope {
    User,
    Project,
}

impl Scope {
    fn claude_dir(&self, env: &TestEnv) -> PathBuf {
        match self {
            Scope::User => env.home.join(".claude"),
            Scope::Project => env.cwd.join(".claude"),
        }
    }
}

fn legacy_settings_json() -> String {
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
    .to_string()
}

fn migrated_settings_json() -> serde_json::Value {
    serde_json::json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "runok hook --agent claude-code"
                        }
                    ]
                }
            ]
        }
    })
}

fn read_settings(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[rstest]
#[case::user_scope(Scope::User)]
#[case::project_scope(Scope::Project)]
fn migrate_rewrites_legacy_hook_command(migrate_env: TestEnv, #[case] scope: Scope) {
    let claude_dir = scope.claude_dir(&migrate_env);
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");
    std::fs::write(&settings_path, legacy_settings_json()).unwrap();

    migrate_env
        .command()
        .args(["migrate", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("claude-code-hook"));

    assert_eq!(read_settings(&settings_path), migrated_settings_json());
}

#[rstest]
fn migrate_claude_settings_is_idempotent(migrate_env: TestEnv) {
    let claude_dir = migrate_env.home.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");
    std::fs::write(&settings_path, legacy_settings_json()).unwrap();

    migrate_env
        .command()
        .args(["migrate", "-y"])
        .assert()
        .success();
    let after_first = std::fs::read_to_string(&settings_path).unwrap();

    migrate_env
        .command()
        .args(["migrate", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Already up to date."));
    let after_second = std::fs::read_to_string(&settings_path).unwrap();

    assert_eq!(after_first, after_second);
}

#[rstest]
fn migrate_no_op_when_hook_command_already_current(migrate_env: TestEnv) {
    let claude_dir = migrate_env.home.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");
    let current = indoc! {r#"
        {
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "hooks": [
                  {
                    "type": "command",
                    "command": "runok hook --agent claude-code"
                  }
                ]
              }
            ]
          }
        }
    "#};
    std::fs::write(&settings_path, current).unwrap();

    migrate_env
        .command()
        .args(["migrate", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Already up to date."));

    assert_eq!(std::fs::read_to_string(&settings_path).unwrap(), current);
}

#[rstest]
fn migrate_preserves_unrelated_settings_json_content(migrate_env: TestEnv) {
    let claude_dir = migrate_env.home.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");

    let permissions = serde_json::json!({"allow": ["Bash(git status)"]});
    let mut before: serde_json::Value = serde_json::from_str(&legacy_settings_json()).unwrap();
    before["permissions"] = permissions.clone();
    std::fs::write(&settings_path, before.to_string()).unwrap();

    migrate_env
        .command()
        .args(["migrate", "-y"])
        .assert()
        .success();

    let mut expected = migrated_settings_json();
    expected["permissions"] = permissions;
    assert_eq!(read_settings(&settings_path), expected);
}
