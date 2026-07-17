#![allow(clippy::unwrap_used, reason = "test helper")]

use indoc::indoc;
use rstest::rstest;

use super::helpers::TestEnv;

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
fn migrate_rewrites_legacy_hook_command_at_user_scope() {
    let env = TestEnv::new("rules:\n  - allow: git status\n");
    let claude_dir = env.home.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");
    std::fs::write(&settings_path, legacy_settings_json()).unwrap();

    env.command()
        .args(["migrate", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("claude-code-hook"));

    assert_eq!(read_settings(&settings_path), migrated_settings_json());
}

#[rstest]
fn migrate_rewrites_legacy_hook_command_at_project_scope() {
    let env = TestEnv::new("rules:\n  - allow: git status\n");
    let claude_dir = env.cwd.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");
    std::fs::write(&settings_path, legacy_settings_json()).unwrap();

    env.command().args(["migrate", "-y"]).assert().success();

    assert_eq!(read_settings(&settings_path), migrated_settings_json());
}

#[rstest]
fn migrate_claude_settings_is_idempotent() {
    let env = TestEnv::new("rules:\n  - allow: git status\n");
    let claude_dir = env.home.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");
    std::fs::write(&settings_path, legacy_settings_json()).unwrap();

    env.command().args(["migrate", "-y"]).assert().success();
    let after_first = std::fs::read_to_string(&settings_path).unwrap();

    env.command()
        .args(["migrate", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Already up to date."));
    let after_second = std::fs::read_to_string(&settings_path).unwrap();

    assert_eq!(after_first, after_second);
}

#[rstest]
fn migrate_no_op_when_hook_command_already_current() {
    let env = TestEnv::new("rules:\n  - allow: git status\n");
    let claude_dir = env.home.join(".claude");
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

    env.command()
        .args(["migrate", "-y"])
        .assert()
        .success()
        .stderr(predicates::str::contains("Already up to date."));

    assert_eq!(std::fs::read_to_string(&settings_path).unwrap(), current);
}

#[rstest]
fn migrate_preserves_unrelated_settings_json_content() {
    let env = TestEnv::new("rules:\n  - allow: git status\n");
    let claude_dir = env.home.join(".claude");
    std::fs::create_dir_all(&claude_dir).unwrap();
    let settings_path = claude_dir.join("settings.json");
    std::fs::write(
        &settings_path,
        serde_json::json!({
            "permissions": {"allow": ["Bash(git status)"]},
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
        .to_string(),
    )
    .unwrap();

    env.command().args(["migrate", "-y"]).assert().success();

    assert_eq!(
        read_settings(&settings_path),
        serde_json::json!({
            "permissions": {"allow": ["Bash(git status)"]},
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
    );
}
