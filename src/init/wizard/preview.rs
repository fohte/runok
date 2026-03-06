use super::super::claude_code;
use super::super::error::InitError;

/// Simulate removing Bash permission entries from settings.json content.
///
/// Non-Bash entries are preserved. Mirrors `claude_code::remove_permissions`.
pub(super) fn preview_remove_permissions(content: &str) -> Result<String, InitError> {
    if content.is_empty() {
        return Ok(content.to_string());
    }
    let mut root: serde_json::Value = serde_json::from_str(content)?;
    if let Some(obj) = root.get_mut("permissions").and_then(|p| p.as_object_mut()) {
        for key in &["allow", "deny"] {
            if let Some(arr) = obj.get_mut(*key).and_then(|v| v.as_array_mut()) {
                arr.retain(|entry| {
                    entry
                        .as_str()
                        .and_then(claude_code::parse_permission_entry)
                        .is_none_or(|(tool, _)| tool != "Bash")
                });
                if arr.is_empty() {
                    obj.remove(*key);
                }
            }
        }
    }
    Ok(serde_json::to_string_pretty(&root)?)
}

/// Simulate registering the hook in settings.json content and return the result.
/// Returns `None` if the hook is already registered.
pub(super) fn preview_register_hook(content: &str) -> Result<Option<String>, InitError> {
    let mut root = if content.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str::<serde_json::Value>(content)?
    };

    let hook_command = "runok check --input-format claude-code-hook";

    // Check if already registered
    if let Some(arr) = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
    {
        for entry in arr {
            if claude_code::entry_has_runok_hook(entry, hook_command) {
                return Ok(None);
            }
        }
    }

    let hook_entry = serde_json::json!({
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": hook_command}]
    });

    let hooks = root
        .as_object_mut()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "settings.json root is not an object",
            )
        })?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    let pre_tool_use = hooks
        .as_object_mut()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "hooks is not an object")
        })?
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));

    pre_tool_use
        .as_array_mut()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PreToolUse is not an array",
            )
        })?
        .push(hook_entry);

    Ok(Some(serde_json::to_string_pretty(&root)?))
}

/// Re-format JSON through serde to normalize indentation.
pub(super) fn normalize_json(content: &str) -> Result<String, InitError> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    Ok(serde_json::to_string_pretty(&value)?)
}

/// Print a colored unified-style diff between two strings.
pub(super) fn print_diff(filename: &str, before: &str, after: &str) {
    use similar::ChangeTag;

    let diff = similar::TextDiff::from_lines(before, after);

    // ANSI color codes
    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    let (prefix_a, prefix_b) = if filename.starts_with('/') {
        ("--- ", "+++ ")
    } else {
        ("--- a/", "+++ b/")
    };
    eprintln!("{RED}{prefix_a}{filename}{RESET}");
    eprintln!("{GREEN}{prefix_b}{filename}{RESET}");

    for group in diff.grouped_ops(3) {
        let first = &group[0];
        let last = &group[group.len() - 1];
        let old_start = first.old_range().start + 1;
        let old_len = last.old_range().end - first.old_range().start;
        let new_start = first.new_range().start + 1;
        let new_len = last.new_range().end - first.new_range().start;
        eprintln!("{CYAN}@@ -{old_start},{old_len} +{new_start},{new_len} @@{RESET}");
        for op in &group {
            for change in diff.iter_changes(op) {
                let (sign, color) = match change.tag() {
                    ChangeTag::Delete => ("-", RED),
                    ChangeTag::Insert => ("+", GREEN),
                    ChangeTag::Equal => (" ", ""),
                };
                eprint!("{color}{sign}{change}{RESET}");
                if change.missing_newline() {
                    eprintln!();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    #[rstest]
    fn normalize_json_reformats_indentation() {
        let input = indoc! {r#"
            {
               "key":   "value"
            }"#};
        let result = normalize_json(input).unwrap();
        assert_eq!(
            result,
            indoc! {r#"
                {
                  "key": "value"
                }"#}
        );
    }

    #[rstest]
    fn preview_remove_permissions_strips_only_bash_entries() {
        let input = indoc! {r#"
            {
              "permissions": {
                "allow": ["Bash(git status)", "Read(/tmp)", "WebFetch"],
                "deny": ["Bash(rm *)", "NotebookEdit"],
                "defaultMode": "acceptEdits"
              },
              "hooks": {}
            }"#};
        let result = preview_remove_permissions(input).unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "permissions": {
                    "allow": ["Read(/tmp)", "WebFetch"],
                    "deny": ["NotebookEdit"],
                    "defaultMode": "acceptEdits"
                },
                "hooks": {}
            })
        );
    }

    #[rstest]
    fn preview_remove_permissions_empty_input() {
        let result = preview_remove_permissions("").unwrap();
        assert_eq!(result, "");
    }

    #[rstest]
    fn preview_register_hook_adds_hook_entry() {
        let input = indoc! {r#"
            {
              "permissions": {}
            }"#};
        let result = preview_register_hook(input).unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            value["hooks"]["PreToolUse"],
            serde_json::json!([
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "runok check --input-format claude-code-hook"
                        }
                    ]
                }
            ])
        );
    }

    #[rstest]
    fn preview_register_hook_returns_none_when_already_registered() {
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
        let result = preview_register_hook(input).unwrap();
        assert_eq!(result, None);
    }

    #[rstest]
    fn preview_register_hook_returns_none_for_legacy_format() {
        let input = indoc! {r#"
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "type": "command",
                            "command": "runok check --input-format claude-code-hook"
                        }
                    ]
                }
            }
        "#};
        let result = preview_register_hook(input).unwrap();
        assert_eq!(result, None);
    }

    #[rstest]
    fn preview_register_hook_returns_none_for_string_format() {
        let input = indoc! {r#"
            {
                "hooks": {
                    "PreToolUse": [
                        "runok check --input-format claude-code-hook"
                    ]
                }
            }
        "#};
        let result = preview_register_hook(input).unwrap();
        assert_eq!(result, None);
    }

    #[rstest]
    fn preview_register_hook_empty_input() {
        let result = preview_register_hook("").unwrap().unwrap();
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
