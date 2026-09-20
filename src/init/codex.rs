use std::path::{Path, PathBuf};

use super::error::InitError;
use super::hook_json;

/// The hook command registered in Codex's hooks.json for both the
/// `PreToolUse` and `PermissionRequest` events.
pub const HOOK_COMMAND: &str = "runok hook --agent codex";

/// Regex matcher used for the `matcher` field. Codex hook matchers are
/// regexes (unlike Claude Code's literal `"Bash"` matcher).
pub const MATCHER: &str = "^Bash$";

/// The two Codex hook events runok registers. Always registered together --
/// Codex has no opt-in PostToolUse equivalent.
pub const EVENTS: [&str; 2] = ["PreToolUse", "PermissionRequest"];

/// Relative path of the exec policy file managed by runok.
pub const EXEC_POLICY_PATH: &str = "rules/runok.rules";

/// Exec policy rules required for Codex to apply runok's allow/ask decisions.
pub const EXEC_POLICY_RULES: [&str; 2] = [
    "prefix_rule(pattern = [\"runok\", \"exec\"], decision = \"allow\")",
    "prefix_rule(pattern = [\"runok\", \"exec\", \"--ask\"], decision = \"prompt\")",
];

fn resolve_codex_home_with(codex_home_env: Option<String>, home_dir: &Path) -> PathBuf {
    codex_home_env
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir.join(".codex"))
}

/// Resolve `$CODEX_HOME`, falling back to `<home_dir>/.codex`.
pub fn resolve_codex_home(home_dir: &Path) -> PathBuf {
    resolve_codex_home_with(std::env::var("CODEX_HOME").ok(), home_dir)
}

/// Register the runok hook for a single event within an in-memory
/// hooks.json value. Returns `true` if the value changed.
pub(super) fn register_hook_for_event(
    root: &mut serde_json::Value,
    event: &str,
) -> Result<bool, InitError> {
    if let Some(arr) = root
        .get("hooks")
        .and_then(|h| h.get(event))
        .and_then(|p| p.as_array())
    {
        for entry in arr {
            if hook_json::entry_has_runok_hook(entry, HOOK_COMMAND) {
                return Ok(false);
            }
        }
    }

    let hook_entry = serde_json::json!({
        "matcher": MATCHER,
        "hooks": [
            {
                "type": "command",
                "command": HOOK_COMMAND
            }
        ]
    });

    let hooks = root
        .as_object_mut()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "hooks.json root is not an object",
            )
        })?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    let event_hooks = hooks
        .as_object_mut()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "hooks is not an object")
        })?
        .entry(event)
        .or_insert_with(|| serde_json::json!([]));

    event_hooks
        .as_array_mut()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{event} is not an array"),
            )
        })?
        .push(hook_entry);

    Ok(true)
}

/// Register the runok hook in Codex's hooks.json for both `PreToolUse` and
/// `PermissionRequest`. If an event already has a matching entry, it is left
/// untouched. Creates the file (and `codex_home`) if they don't exist.
/// Returns `true` if the file was modified.
pub fn register_hook(codex_home: &Path) -> Result<bool, InitError> {
    let path = codex_home.join("hooks.json");

    let mut root = if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        if content.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str::<serde_json::Value>(&content)?
        }
    } else {
        serde_json::json!({})
    };

    let mut changed = false;
    for event in EVENTS {
        if register_hook_for_event(&mut root, event)? {
            changed = true;
        }
    }

    if changed {
        std::fs::create_dir_all(codex_home)?;
        let output = serde_json::to_string_pretty(&root)?;
        std::fs::write(&path, output)?;
    }

    Ok(changed)
}

/// Return an exec policy file with all rules required by the Codex adapter.
/// Existing rules and formatting are preserved; only missing runok rules are
/// appended.
pub(super) fn add_exec_policy_rules(content: &str) -> Option<String> {
    let missing: Vec<&str> = EXEC_POLICY_RULES
        .iter()
        .filter(|rule| !content.lines().any(|line| line.trim() == **rule))
        .copied()
        .collect();
    if missing.is_empty() {
        return None;
    }

    let mut output = content.to_string();
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    for rule in missing {
        output.push_str(rule);
        output.push('\n');
    }
    Some(output)
}

/// Register the exec policy rules in `<codex_home>/rules/runok.rules`.
/// Existing rules are kept intact and missing runok rules are appended.
pub fn register_exec_policy(codex_home: &Path) -> Result<bool, InitError> {
    let path = codex_home.join(EXEC_POLICY_PATH);
    let content = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };
    let Some(output) = add_exec_policy_rules(&content) else {
        return Ok(false);
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, output)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;
    use tempfile::TempDir;

    // --- resolve_codex_home ---

    #[rstest]
    #[case::env_set(Some("/custom/codex"), "/home/user", PathBuf::from("/custom/codex"))]
    #[case::env_empty_falls_back(Some(""), "/home/user", PathBuf::from("/home/user/.codex"))]
    #[case::env_unset_falls_back(None, "/home/user", PathBuf::from("/home/user/.codex"))]
    fn test_resolve_codex_home_with(
        #[case] codex_home_env: Option<&str>,
        #[case] home: &str,
        #[case] expected: PathBuf,
    ) {
        assert_eq!(
            resolve_codex_home_with(codex_home_env.map(String::from), Path::new(home)),
            expected
        );
    }

    // --- register_hook ---

    fn runok_hook_entry() -> serde_json::Value {
        serde_json::json!({
            "matcher": "^Bash$",
            "hooks": [
                {
                    "type": "command",
                    "command": "runok hook --agent codex"
                }
            ]
        })
    }

    #[rstest]
    fn register_hook_creates_new_file_with_both_events() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");

        let registered = register_hook(&codex_home).unwrap();
        assert!(registered);

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(codex_home.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "hooks": {
                    "PreToolUse": [runok_hook_entry()],
                    "PermissionRequest": [runok_hook_entry()]
                }
            })
        );
    }

    #[rstest]
    fn register_hook_is_noop_on_second_call() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");

        assert!(register_hook(&codex_home).unwrap());
        let path = codex_home.join("hooks.json");
        let before = std::fs::read_to_string(&path).unwrap();

        let registered = register_hook(&codex_home).unwrap();
        assert!(!registered);

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, before);
    }

    #[rstest]
    fn register_hook_treats_preexisting_empty_file_as_empty_object() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        std::fs::write(codex_home.join("hooks.json"), "").unwrap();

        let registered = register_hook(&codex_home).unwrap();
        assert!(registered);

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(codex_home.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "hooks": {
                    "PreToolUse": [runok_hook_entry()],
                    "PermissionRequest": [runok_hook_entry()]
                }
            })
        );
    }

    #[rstest]
    fn register_hook_preserves_existing_keys_and_events() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        std::fs::write(
            codex_home.join("hooks.json"),
            indoc! {r#"
                {
                    "someKey": "someValue",
                    "hooks": {
                        "SomeOtherEvent": [{"matcher": "^Read$", "hooks": [{"type": "command", "command": "other-tool"}]}]
                    }
                }
            "#},
        )
        .unwrap();

        let registered = register_hook(&codex_home).unwrap();
        assert!(registered);

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(codex_home.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "someKey": "someValue",
                "hooks": {
                    "SomeOtherEvent": [
                        {"matcher": "^Read$", "hooks": [{"type": "command", "command": "other-tool"}]}
                    ],
                    "PreToolUse": [runok_hook_entry()],
                    "PermissionRequest": [runok_hook_entry()]
                }
            })
        );
    }

    #[rstest]
    fn register_hook_fills_in_missing_event() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        std::fs::write(
            codex_home.join("hooks.json"),
            indoc! {r#"
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "^Bash$",
                                "hooks": [{"type": "command", "command": "runok hook --agent codex"}]
                            }
                        ]
                    }
                }
            "#},
        )
        .unwrap();

        let registered = register_hook(&codex_home).unwrap();
        assert!(registered);

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(codex_home.join("hooks.json")).unwrap())
                .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "hooks": {
                    "PreToolUse": [runok_hook_entry()],
                    "PermissionRequest": [runok_hook_entry()]
                }
            })
        );
    }

    // --- exec policy ---

    fn lines_with_trailing_newline(lines: &[&str]) -> String {
        lines.join("\n") + "\n"
    }

    #[rstest]
    fn register_exec_policy_creates_rules_file() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();

        let registered = register_exec_policy(&codex_home).unwrap();

        assert_eq!(
            (
                registered,
                std::fs::read_to_string(codex_home.join(EXEC_POLICY_PATH)).unwrap()
            ),
            (true, lines_with_trailing_newline(&EXEC_POLICY_RULES))
        );
    }

    #[rstest]
    fn register_exec_policy_preserves_existing_rules_and_appends_missing_rules() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");
        let rules_path = codex_home.join(EXEC_POLICY_PATH);
        std::fs::create_dir_all(rules_path.parent().unwrap()).unwrap();
        std::fs::write(
            &rules_path,
            lines_with_trailing_newline(&["# existing", EXEC_POLICY_RULES[0]]),
        )
        .unwrap();

        let registered = register_exec_policy(&codex_home).unwrap();

        assert_eq!(
            (registered, std::fs::read_to_string(rules_path).unwrap()),
            (
                true,
                lines_with_trailing_newline(&[
                    "# existing",
                    EXEC_POLICY_RULES[0],
                    EXEC_POLICY_RULES[1],
                ])
            )
        );
    }

    #[rstest]
    fn register_exec_policy_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let codex_home = tmp.path().join(".codex");

        let first_registered = register_exec_policy(&codex_home).unwrap();
        let before = std::fs::read_to_string(codex_home.join(EXEC_POLICY_PATH)).unwrap();
        let second_registered = register_exec_policy(&codex_home).unwrap();
        let after = std::fs::read_to_string(codex_home.join(EXEC_POLICY_PATH)).unwrap();

        assert_eq!(
            (first_registered, second_registered, after),
            (true, false, before)
        );
    }
}
