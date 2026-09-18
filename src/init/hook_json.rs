/// Check whether a hook entry already contains the specified command.
pub fn entry_has_runok_hook(entry: &serde_json::Value, command: &str) -> bool {
    // Plain string format: "runok check --input-format claude-code-hook"
    if entry.as_str() == Some(command) {
        return true;
    }
    // Current format: {"matcher": "Bash", "hooks": [{"type": "command", "command": "runok check ..."}]}
    // Also handles string hooks: {"hooks": ["runok check --input-format claude-code-hook"]}
    if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array())
        && hooks.iter().any(|h| {
            h.get("command").and_then(|c| c.as_str()) == Some(command)
                || h.as_str() == Some(command)
        })
    {
        return true;
    }
    // Legacy format: {"type": "command", "command": "runok check ..."} (top-level command)
    if entry.get("command").and_then(|c| c.as_str()) == Some(command)
        && entry.get("hooks").is_none()
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // --- entry_has_runok_hook ---

    #[rstest]
    #[case::current_format(
        serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "runok check --input-format claude-code-hook"}]
        }),
        true,
    )]
    #[case::legacy_format(
        serde_json::json!({
            "type": "command",
            "command": "runok check --input-format claude-code-hook"
        }),
        true,
    )]
    #[case::plain_string(
        serde_json::json!("runok check --input-format claude-code-hook"),
        true,
    )]
    #[case::string_hooks_in_object(
        serde_json::json!({
            "matcher": "Bash",
            "hooks": ["runok check --input-format claude-code-hook"]
        }),
        true,
    )]
    #[case::no_match_different_command(
        serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "other-tool"}]
        }),
        false,
    )]
    #[case::no_match_different_string(
        serde_json::json!("some-other-command"),
        false,
    )]
    #[case::no_match_empty_object(
        serde_json::json!({}),
        false,
    )]
    fn test_entry_has_runok_hook(#[case] entry: serde_json::Value, #[case] expected: bool) {
        let command = "runok check --input-format claude-code-hook";
        assert_eq!(entry_has_runok_hook(&entry, command), expected);
    }
}
