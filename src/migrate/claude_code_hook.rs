use super::MigrateError;
use super::migration::{Migration, MigrationTarget};
use crate::init::claude_code::migrate_legacy_hook_content;

/// Rewrites the legacy `runok check --input-format claude-code-hook` hook
/// command registered in Claude Code's `settings.json` to `runok hook
/// --agent claude-code`.
pub struct ClaudeCodeHookMigration;

impl Migration for ClaudeCodeHookMigration {
    fn id(&self) -> &'static str {
        "claude-code-hook"
    }

    fn description(&self) -> &'static str {
        "Rewrite the legacy `runok check --input-format claude-code-hook` hook command to `runok hook --agent claude-code`"
    }

    fn target(&self) -> MigrationTarget {
        MigrationTarget::ClaudeCodeSettings
    }

    fn migrate(&self, content: &str) -> Result<Option<String>, MigrateError> {
        migrate_claude_code_hook(content)
    }
}

/// Rewrite legacy hook command entries to the current `runok hook` command
/// within `hooks.PreToolUse`/`hooks.PostToolUse` of a settings.json string.
/// Returns `None` if there is nothing to rewrite.
fn migrate_claude_code_hook(content: &str) -> Result<Option<String>, MigrateError> {
    migrate_legacy_hook_content(content)
        .map_err(|e| MigrateError::Migration(format!("claude-code-hook: {e}")))
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use rstest::rstest;

    use super::*;

    fn migrate(input: &str) -> Option<String> {
        migrate_claude_code_hook(input).unwrap()
    }

    #[rstest]
    fn rewrites_legacy_command_for_pre_tool_use() {
        let input = indoc! {r#"
            {
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
            }"#};
        let result = migrate(input).unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            value,
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
        );
    }

    #[rstest]
    fn rewrites_both_pre_and_post_tool_use() {
        let input = indoc! {r#"
            {
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash", "hooks": [{"type": "command", "command": "runok check --input-format claude-code-hook"}]}
                ],
                "PostToolUse": [
                  {"matcher": "Bash", "hooks": [{"type": "command", "command": "runok check --input-format claude-code-hook"}]}
                ]
              }
            }"#};
        let result = migrate(input).unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        let runok_hook_entry = serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "runok hook --agent claude-code"}]
        });
        assert_eq!(
            value,
            serde_json::json!({
                "hooks": {
                    "PreToolUse": [runok_hook_entry.clone()],
                    "PostToolUse": [runok_hook_entry]
                }
            })
        );
    }

    #[rstest]
    fn preserves_other_entries_and_keys() {
        let input = indoc! {r#"
            {
              "someKey": "someValue",
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash", "hooks": [{"type": "command", "command": "runok check --input-format claude-code-hook"}]},
                  {"hooks": [{"type": "command", "command": "other-tool"}]}
                ]
              }
            }"#};
        let result = migrate(input).unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "someKey": "someValue",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "runok hook --agent claude-code"}]
                        },
                        {
                            "hooks": [{"type": "command", "command": "other-tool"}]
                        }
                    ]
                }
            })
        );
    }

    #[rstest]
    #[case::already_current(indoc! {r#"
        {
          "hooks": {
            "PreToolUse": [
              {"matcher": "Bash", "hooks": [{"type": "command", "command": "runok hook --agent claude-code"}]}
            ]
          }
        }"#})]
    #[case::no_hooks_key(r#"{}"#)]
    #[case::empty_input("")]
    fn returns_none_when_nothing_to_migrate(#[case] input: &str) {
        assert_eq!(migrate(input), None);
    }

    #[rstest]
    fn migration_is_idempotent() {
        let input = indoc! {r#"
            {
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash", "hooks": [{"type": "command", "command": "runok check --input-format claude-code-hook"}]}
                ]
              }
            }"#};
        let once = migrate(input).unwrap();
        assert_eq!(migrate(&once), None);
    }

    #[rstest]
    fn invalid_json_returns_err() {
        assert!(migrate_claude_code_hook("not json").is_err());
    }
}
