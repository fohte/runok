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
fn parse_permission_entry(entry: &str) -> Option<(&str, &str)> {
    let open = entry.find('(')?;
    let close = entry.rfind(')')?;
    if close <= open {
        return None;
    }
    let tool = &entry[..open];
    let pattern = &entry[open + 1..close];
    Some((tool, pattern))
}

/// Convert a Bash permission pattern to a runok rule pattern.
///
/// - Replaces `:` separators with spaces (e.g., `git:status` -> `git status`)
/// - Preserves `*` wildcards
fn convert_bash_pattern(pattern: &str) -> String {
    pattern.replace(':', " ")
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
                result
                    .rules
                    .push_str(&format!("  - allow: '{}'\n", converted));
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
                result
                    .rules
                    .push_str(&format!("  - deny: '{}'\n", converted));
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

/// Register runok hook in Claude Code settings.json.
///
/// Adds a PreToolUse hook entry that runs `runok check --input-format claude-code-hook`.
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

    // Check if hook already exists
    if let Some(arr) = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
    {
        for entry in arr {
            if entry.get("command").and_then(|c| c.as_str()) == Some(hook_command) {
                return Ok(false);
            }
        }
    }

    // Add the hook
    let hook_entry = serde_json::json!({
        "type": "command",
        "command": hook_command
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
pub fn remove_permissions(claude_dir: &Path) -> Result<bool, InitError> {
    let path = claude_dir.join("settings.json");
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(&path)?;
    let mut root: serde_json::Value = serde_json::from_str(&content)?;

    let mut modified = false;
    if let Some(obj) = root.get_mut("permissions").and_then(|p| p.as_object_mut()) {
        if obj.remove("allow").is_some() {
            modified = true;
        }
        if obj.remove("deny").is_some() {
            modified = true;
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
    #[case::bash_wildcard("Bash(git:*)", Some(("Bash", "git:*")))]
    #[case::read_tool("Read(/tmp/file)", Some(("Read", "/tmp/file")))]
    #[case::no_parens("invalid", None)]
    #[case::empty_parens("Bash()", Some(("Bash", "")))]
    fn test_parse_permission_entry(#[case] entry: &str, #[case] expected: Option<(&str, &str)>) {
        assert_eq!(parse_permission_entry(entry), expected);
    }

    // --- convert_bash_pattern ---

    #[rstest]
    #[case::simple("git status", "git status")]
    #[case::colon_separated("git:status", "git status")]
    #[case::wildcard("git:*", "git *")]
    #[case::complex("npm:install:*", "npm install *")]
    #[case::no_colon("ls", "ls")]
    fn test_convert_bash_pattern(#[case] pattern: &str, #[case] expected: &str) {
        assert_eq!(convert_bash_pattern(pattern), expected);
    }

    // --- convert_permissions ---

    #[rstest]
    fn convert_permissions_basic() {
        let allow = vec![
            "Bash(git status)".to_string(),
            "Bash(npm:install:*)".to_string(),
        ];
        let deny = vec!["Bash(rm -rf /)".to_string()];

        let result = convert_permissions(&allow, &deny);

        assert_eq!(
            result.rules,
            "  - allow: 'git status'\n  - allow: 'npm install *'\n  - deny: 'rm -rf /'\n"
        );
        assert!(result.skipped.is_empty());
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
                        "allow": ["Bash(git status)", "Bash(npm:install:*)"],
                        "deny": ["Bash(rm -rf /)"]
                    }
                }
            "#},
        )
        .unwrap();

        let (allow, deny) = read_permissions(&claude_dir).unwrap();
        assert_eq!(allow, vec!["Bash(git status)", "Bash(npm:install:*)"]);
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

        let content = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        let hooks = &value["hooks"]["PreToolUse"];
        assert!(hooks.is_array());
        assert_eq!(
            hooks[0]["command"],
            "runok check --input-format claude-code-hook"
        );
    }

    #[rstest]
    fn register_hook_skips_duplicate() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();

        std::fs::write(
            claude_dir.join("settings.json"),
            indoc! {r#"
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
            "#},
        )
        .unwrap();

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
                        "PostToolUse": [{"type": "command", "command": "other-tool"}]
                    }
                }
            "#},
        )
        .unwrap();

        let registered = register_hook(&claude_dir).unwrap();
        assert!(registered);

        let content = std::fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(value["someKey"], "someValue");
        assert!(value["hooks"]["PostToolUse"].is_array());
        assert!(value["hooks"]["PreToolUse"].is_array());
    }

    // --- remove_permissions ---

    #[rstest]
    fn remove_permissions_deletes_allow_and_deny() {
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
        assert!(value["permissions"].get("allow").is_none());
        assert!(value["permissions"].get("deny").is_none());
        // Other keys preserved
        assert!(value["permissions"]["scopes"].is_object());
        assert!(value["hooks"].is_object());
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
