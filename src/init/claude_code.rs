use std::path::Path;

use super::error::InitError;

/// Result of converting Claude Code permissions to runok rules.
#[derive(Debug, Default)]
pub struct ConversionResult {
    /// YAML-formatted rule lines (each line starts with "  - ").
    pub rules: String,
    /// Tool entries that were skipped because they are not Bash.
    pub skipped: Vec<String>,
}

/// Parse a Claude Code permission entry like `Bash(command)` or `Bash(prefix:*)`.
///
/// Returns `Some((tool_name, pattern))` if the entry matches the expected format,
/// or `None` if parsing fails.
pub fn parse_permission_entry(entry: &str) -> Option<(&str, &str)> {
    let open = entry.find('(')?;
    let close = entry.rfind(')')?;
    if close <= open {
        return None;
    }
    let tool = &entry[..open];
    let pattern = &entry[open + 1..close];
    Some((tool, pattern))
}

/// Convert a Claude Code Bash pattern to a runok pattern.
///
/// Claude Code uses `:*` as a prefix-match operator (e.g. `npm install:*`
/// matches any command starting with `npm install`). runok has no `:*`
/// syntax, so we convert it to a space + glob: `npm install *`.
fn convert_bash_pattern(pattern: &str) -> String {
    if let Some(prefix) = pattern.strip_suffix(":*") {
        format!("{prefix} *")
    } else {
        pattern.to_string()
    }
}

/// Convert Claude Code permission entries to runok rule YAML lines.
///
/// Processes both `allow` and `deny` entries. Entries that are not `Bash(...)`
/// are collected in `skipped`.
pub fn convert_permissions(allow_entries: &[String], deny_entries: &[String]) -> ConversionResult {
    let mut result = ConversionResult::default();

    for entry in allow_entries {
        match parse_permission_entry(entry) {
            Some(("Bash", pattern)) => {
                let converted = convert_bash_pattern(pattern);
                let escaped = converted.replace('\'', "''");
                result.rules.push_str(&format!("  - allow: '{escaped}'\n"));
            }
            Some((tool, _)) => {
                result.skipped.push(format!("{tool}(...)"));
            }
            None => {
                result.skipped.push(entry.clone());
            }
        }
    }

    for entry in deny_entries {
        match parse_permission_entry(entry) {
            Some(("Bash", pattern)) => {
                let converted = convert_bash_pattern(pattern);
                let escaped = converted.replace('\'', "''");
                result.rules.push_str(&format!("  - deny: '{escaped}'\n"));
            }
            Some((tool, _)) => {
                result.skipped.push(format!("{tool}(...)"));
            }
            None => {
                result.skipped.push(entry.clone());
            }
        }
    }

    result
}

/// Read Claude Code settings.json and settings.local.json and extract permissions.
///
/// Returns `(allow_entries, deny_entries)` merged from both files.
pub fn read_permissions(claude_dir: &Path) -> Result<(Vec<String>, Vec<String>), InitError> {
    let mut allow_entries = Vec::new();
    let mut deny_entries = Vec::new();

    for filename in &["settings.json", "settings.local.json"] {
        let path = claude_dir.join(filename);
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;

        if let Some(permissions) = value.get("permissions") {
            if let Some(arr) = permissions.get("allow").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        allow_entries.push(s.to_string());
                    }
                }
            }
            if let Some(arr) = permissions.get("deny").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        deny_entries.push(s.to_string());
                    }
                }
            }
        }
    }

    Ok((allow_entries, deny_entries))
}

/// Check whether a PreToolUse entry already contains the runok hook command.
pub fn entry_has_runok_hook(entry: &serde_json::Value, command: &str) -> bool {
    // Current format: {"matcher": "Bash", "hooks": [{"type": "command", "command": "runok check ..."}]}
    if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array())
        && hooks
            .iter()
            .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(command))
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

/// Register runok hook in Claude Code settings.json.
///
/// Adds a PreToolUse hook entry with `"matcher": "Bash"` that runs
/// `runok check --input-format claude-code-hook`.
/// If the hook is already registered, does nothing.
/// Creates the file if it doesn't exist.
pub fn register_hook(claude_dir: &Path) -> Result<bool, InitError> {
    let path = claude_dir.join("settings.json");

    let mut root = if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str::<serde_json::Value>(&content)?
    } else {
        serde_json::json!({})
    };

    let hook_command = "runok check --input-format claude-code-hook";

    // Check if hook already exists in any format
    if let Some(arr) = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
    {
        for entry in arr {
            if entry_has_runok_hook(entry, hook_command) {
                return Ok(false);
            }
        }
    }

    // Add the hook in the current Claude Code format
    let hook_entry = serde_json::json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": hook_command
            }
        ]
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

    std::fs::create_dir_all(claude_dir)?;
    let output = serde_json::to_string_pretty(&root)?;
    std::fs::write(&path, output)?;

    Ok(true)
}

/// Remove permissions.allow and permissions.deny from Claude Code settings.json.
///
/// Preserves other keys within the permissions object and other top-level keys.
/// Remove only Bash permission entries from allow/deny arrays.
///
/// Non-Bash entries (e.g. `Read(...)`, `Skill`, `WebFetch`) are preserved.
/// If an array becomes empty after filtering, the key is removed entirely.
pub fn remove_permissions(claude_dir: &Path) -> Result<bool, InitError> {
    let path = claude_dir.join("settings.json");
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(&path)?;
    let mut root: serde_json::Value = serde_json::from_str(&content)?;

    let mut modified = false;
    if let Some(obj) = root.get_mut("permissions").and_then(|p| p.as_object_mut()) {
        for key in &["allow", "deny"] {
            if let Some(arr) = obj.get_mut(*key).and_then(|v| v.as_array_mut()) {
                let before_len = arr.len();
                arr.retain(|entry| {
                    entry
                        .as_str()
                        .and_then(parse_permission_entry)
                        .is_none_or(|(tool, _)| tool != "Bash")
                });
                if arr.len() != before_len {
                    modified = true;
                }
                if arr.is_empty() {
                    obj.remove(*key);
                }
            }
        }
    }

    if modified {
        let output = serde_json::to_string_pretty(&root)?;
        std::fs::write(&path, output)?;
    }

    Ok(modified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;
    use tempfile::TempDir;

    // --- parse_permission_entry ---

    #[rstest]
    #[case::bash_simple("Bash(git status)", Some(("Bash", "git status")))]
    #[case::bash_wildcard("Bash(git *)", Some(("Bash", "git *")))]
    #[case::read_tool("Read(/tmp/file)", Some(("Read", "/tmp/file")))]
    #[case::no_parens("invalid", None)]
    #[case::empty_parens("Bash()", Some(("Bash", "")))]
    fn test_parse_permission_entry(#[case] entry: &str, #[case] expected: Option<(&str, &str)>) {
        assert_eq!(parse_permission_entry(entry), expected);
    }

    // --- convert_bash_pattern ---

    #[rstest]
    #[case::plain("git status", "git status")]
    #[case::glob("npm install *", "npm install *")]
    #[case::prefix_match("runok exec:*", "runok exec *")]
    #[case::prefix_match_nested("npm run:*", "npm run *")]
    #[case::colon_in_middle("foo:bar", "foo:bar")]
    fn test_convert_bash_pattern(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(convert_bash_pattern(input), expected);
    }

    // --- convert_permissions ---

    #[rstest]
    fn convert_permissions_basic() {
        let allow = vec![
            "Bash(git status)".to_string(),
            "Bash(npm install *)".to_string(),
        ];
        let deny = vec!["Bash(rm -rf /)".to_string()];

        let result = convert_permissions(&allow, &deny);

        assert_eq!(
            result.rules,
            concat!(
                "  - allow: 'git status'\n",
                "  - allow: 'npm install *'\n",
                "  - deny: 'rm -rf /'\n",
            )
        );
        assert!(result.skipped.is_empty());
    }

    #[rstest]
    fn convert_permissions_converts_prefix_match() {
        let allow = vec![
            "Bash(runok exec:*)".to_string(),
            "Bash(npm run:*)".to_string(),
        ];
        let deny = vec![];

        let result = convert_permissions(&allow, &deny);

        assert_eq!(
            result.rules,
            concat!("  - allow: 'runok exec *'\n", "  - allow: 'npm run *'\n",)
        );
    }

    #[rstest]
    fn convert_permissions_skips_non_bash() {
        let allow = vec![
            "Bash(git status)".to_string(),
            "Read(/tmp/file)".to_string(),
            "Write(/tmp/file)".to_string(),
        ];
        let deny = vec![];

        let result = convert_permissions(&allow, &deny);

        assert_eq!(result.rules, "  - allow: 'git status'\n");
        assert_eq!(result.skipped, vec!["Read(...)", "Write(...)"]);
    }

    #[rstest]
    fn convert_permissions_empty() {
        let result = convert_permissions(&[], &[]);
        assert!(result.rules.is_empty());
        assert!(result.skipped.is_empty());
    }

    #[rstest]
    fn convert_permissions_escapes_single_quotes() {
        let allow = vec!["Bash(echo 'hello')".to_string()];
        let deny = vec![];

        let result = convert_permissions(&allow, &deny);

        assert_eq!(result.rules, "  - allow: 'echo ''hello'''\n");
    }

    // --- read_permissions ---

    #[rstest]
    fn read_permissions_from_settings_json() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

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
        .unwrap();

        let (allow, deny) = read_permissions(&claude_dir).unwrap();
        assert_eq!(allow, vec!["Bash(git status)", "Bash(npm install *)"]);
        assert_eq!(deny, vec!["Bash(rm -rf /)"]);
    }

    #[rstest]
    fn read_permissions_merges_both_files() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        std::fs::write(
            claude_dir.join("settings.json"),
            indoc! {r#"
                {
                    "permissions": {
                        "allow": ["Bash(git status)"]
                    }
                }
            "#},
        )
        .unwrap();

        std::fs::write(
            claude_dir.join("settings.local.json"),
            indoc! {r#"
                {
                    "permissions": {
                        "allow": ["Bash(cargo test)"],
                        "deny": ["Bash(rm *)"]
                    }
                }
            "#},
        )
        .unwrap();

        let (allow, deny) = read_permissions(&claude_dir).unwrap();
        assert_eq!(allow, vec!["Bash(git status)", "Bash(cargo test)"]);
        assert_eq!(deny, vec!["Bash(rm *)"]);
    }

    #[rstest]
    fn read_permissions_no_files() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        let (allow, deny) = read_permissions(&claude_dir).unwrap();
        assert!(allow.is_empty());
        assert!(deny.is_empty());
    }

    // --- register_hook ---

    #[rstest]
    fn register_hook_creates_new_file() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");

        let registered = register_hook(&claude_dir).unwrap();
        assert!(registered);

        let value: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(claude_dir.join("settings.json")).unwrap(),
        )
        .unwrap();
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

    #[rstest]
    #[case::current_format(indoc! {r#"
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
        }
    "#})]
    #[case::legacy_format(indoc! {r#"
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
    "#})]
    fn register_hook_skips_duplicate(#[case] existing: &str) {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("settings.json"), existing).unwrap();

        let registered = register_hook(&claude_dir).unwrap();
        assert!(!registered);
    }

    #[rstest]
    fn register_hook_preserves_existing_keys() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        std::fs::write(
            claude_dir.join("settings.json"),
            indoc! {r#"
                {
                    "someKey": "someValue",
                    "hooks": {
                        "PostToolUse": [{"hooks": [{"command": "other-tool", "type": "command"}]}]
                    }
                }
            "#},
        )
        .unwrap();

        let registered = register_hook(&claude_dir).unwrap();
        assert!(registered);

        let value: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(claude_dir.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(value["someKey"], "someValue");
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

    // --- remove_permissions ---

    #[rstest]
    fn remove_permissions_removes_only_bash_entries() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        std::fs::write(
            claude_dir.join("settings.json"),
            indoc! {r#"
                {
                    "permissions": {
                        "allow": ["Bash(git status)", "Read(/tmp)", "WebFetch"],
                        "deny": ["Bash(rm *)", "NotebookEdit"],
                        "scopes": {"project": {}}
                    },
                    "hooks": {}
                }
            "#},
        )
        .unwrap();

        let modified = remove_permissions(&claude_dir).unwrap();
        assert!(modified);

        let content = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "permissions": {
                    "allow": ["Read(/tmp)", "WebFetch"],
                    "deny": ["NotebookEdit"],
                    "scopes": {"project": {}}
                },
                "hooks": {}
            })
        );
    }

    #[rstest]
    fn remove_permissions_removes_key_when_only_bash() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        std::fs::write(
            claude_dir.join("settings.json"),
            indoc! {r#"
                {
                    "permissions": {
                        "allow": ["Bash(git status)"],
                        "deny": ["Bash(rm *)"],
                        "scopes": {"project": {}}
                    },
                    "hooks": {}
                }
            "#},
        )
        .unwrap();

        let modified = remove_permissions(&claude_dir).unwrap();
        assert!(modified);

        let content = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "permissions": {
                    "scopes": {"project": {}}
                },
                "hooks": {}
            })
        );
    }

    #[rstest]
    fn remove_permissions_noop_when_empty() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        std::fs::write(
            claude_dir.join("settings.json"),
            indoc! {r#"
                {
                    "permissions": {},
                    "hooks": {}
                }
            "#},
        )
        .unwrap();

        let modified = remove_permissions(&claude_dir).unwrap();
        assert!(!modified);
    }

    #[rstest]
    fn remove_permissions_no_file() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        let modified = remove_permissions(&claude_dir).unwrap();
        assert!(!modified);
    }
}
