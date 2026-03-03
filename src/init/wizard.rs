use std::path::{Path, PathBuf};

use super::claude_code;
use super::config_gen;
use super::error::InitError;
use super::prompt;

/// Simulate removing permissions from settings.json content and return the result.
fn preview_remove_permissions(content: &str) -> Result<String, InitError> {
    if content.is_empty() {
        return Ok(content.to_string());
    }
    let mut root: serde_json::Value = serde_json::from_str(content)?;
    if let Some(obj) = root.get_mut("permissions").and_then(|p| p.as_object_mut()) {
        obj.remove("allow");
        obj.remove("deny");
    }
    Ok(serde_json::to_string_pretty(&root)?)
}

/// Simulate registering the hook in settings.json content and return the result.
/// Returns `None` if the hook is already registered.
fn preview_register_hook(content: &str) -> Result<Option<String>, InitError> {
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
            if entry
                .get("hooks")
                .and_then(|h| h.as_array())
                .is_some_and(|hooks| {
                    hooks
                        .iter()
                        .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(hook_command))
                })
            {
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
fn normalize_json(content: &str) -> Result<String, InitError> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    Ok(serde_json::to_string_pretty(&value)?)
}

/// Print a colored unified-style diff between two strings.
fn print_diff(filename: &str, before: &str, after: &str) {
    use similar::ChangeTag;

    let diff = similar::TextDiff::from_lines(before, after);

    // ANSI color codes
    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    eprintln!("{RED}--- a/{filename}{RESET}");
    eprintln!("{GREEN}+++ b/{filename}{RESET}");

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

/// Summary of actions performed by the init wizard.
struct Summary {
    user_config_created: Option<PathBuf>,
    project_config_created: Option<PathBuf>,
    hook_registered: bool,
    converted_rules: Option<String>,
    permissions_removed: bool,
}

/// Scope for init configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitScope {
    User,
    Project,
}

/// Paths resolved for the init wizard.
struct ResolvedPaths {
    user_config_dir: PathBuf,
    home_dir: PathBuf,
}

/// Resolve user config directory and home directory.
fn resolve_paths() -> Result<ResolvedPaths, InitError> {
    let home_dir = crate::config::dirs::home_dir().ok_or_else(|| {
        InitError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME not set",
        ))
    })?;
    let user_config_dir = crate::config::dirs::config_dir()
        .map(|d| d.join("runok"))
        .ok_or_else(|| {
            InitError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not determine user config directory (HOME not set)",
            ))
        })?;
    Ok(ResolvedPaths {
        user_config_dir,
        home_dir,
    })
}

/// Run the Claude Code integration steps for a given `.claude/` directory.
///
/// Returns `(converted_rules, hook_registered, permissions_removed)`.
fn run_claude_code_integration(
    claude_dir: &Path,
    auto_yes: bool,
) -> Result<(Option<String>, bool, bool), InitError> {
    let mut converted_rules = None;

    let settings_path = claude_dir.join("settings.json");
    let original_content = if settings_path.exists() {
        normalize_json(&std::fs::read_to_string(&settings_path)?)?
    } else {
        String::new()
    };

    // Determine what changes are needed
    let (allow, deny) = claude_code::read_permissions(claude_dir)?;
    let has_permissions = !allow.is_empty() || !deny.is_empty();
    let mut has_rules = false;

    if has_permissions {
        let conversion = claude_code::convert_permissions(&allow, &deny);
        if !conversion.rules.is_empty() {
            converted_rules = Some(conversion.rules.clone());
            has_rules = true;
        }
    }

    // Build the preview: simulate both operations to show combined diff
    let after_permissions = if has_rules {
        preview_remove_permissions(&original_content)?
    } else {
        original_content.clone()
    };
    let hook_preview = preview_register_hook(&after_permissions)?;
    let has_hook_change = hook_preview.is_some();

    if !has_rules && !has_hook_change {
        return Ok((converted_rules, false, false));
    }

    // Display all planned changes with step numbers
    let mut step = 1;
    let total_steps = usize::from(has_rules) + usize::from(has_hook_change);

    if has_rules {
        eprintln!("[{step}/{total_steps}] Convert Claude Code permissions to runok rules");
        eprintln!("  Bash permissions in settings.json will be moved to runok.yml.");
        eprintln!();
        print_diff("settings.json", &original_content, &after_permissions);
        eprintln!();
        eprintln!("  The following rules will be created in runok.yml:");
        if let Some(ref rules) = converted_rules {
            for line in rules.lines() {
                eprintln!("    {}", line.trim());
            }
        }
        eprintln!();
        step += 1;
    }

    if has_hook_change {
        eprintln!("[{step}/{total_steps}] Register runok hook");
        eprintln!("  runok will evaluate Bash commands via a PreToolUse hook.");
        eprintln!();
        if let Some(ref after_hook) = hook_preview {
            print_diff("settings.json", &after_permissions, after_hook);
        }
        eprintln!();
    }

    let should_apply = prompt::confirm("Apply these changes?", true, auto_yes)?;

    if !should_apply {
        return Ok((converted_rules, false, false));
    }

    // Apply changes
    let mut permissions_removed = false;
    if has_rules {
        permissions_removed = claude_code::remove_permissions(claude_dir)?;
    }

    let mut hook_registered = false;
    if has_hook_change {
        hook_registered = claude_code::register_hook(claude_dir)?;
    }

    Ok((converted_rules, hook_registered, permissions_removed))
}

/// Result of setting up a single scope.
struct ScopeResult {
    config_path: Option<PathBuf>,
    hook_registered: bool,
    converted_rules: Option<String>,
    permissions_removed: bool,
}

/// Set up configuration for a given scope (user or project).
fn setup_scope(
    config_dir: &Path,
    claude_dir: Option<&Path>,
    auto_yes: bool,
    force: bool,
) -> Result<ScopeResult, InitError> {
    let mut converted_rules = None;
    let mut hook_registered = false;
    let mut permissions_removed = false;

    if let Some(cd) = claude_dir
        && cd.exists()
    {
        let (rules, hr, pr) = run_claude_code_integration(cd, auto_yes)?;
        converted_rules = rules;
        hook_registered = hr;
        permissions_removed = pr;
    }

    let content = config_gen::build_config_content(converted_rules.as_deref());
    let config_path = config_gen::write_config(config_dir, &content, force)?;

    Ok(ScopeResult {
        config_path: Some(config_path),
        hook_registered,
        converted_rules,
        permissions_removed,
    })
}

fn print_summary(summary: &Summary) {
    eprintln!();
    eprintln!("runok init complete:");
    if let Some(ref path) = summary.user_config_created {
        eprintln!("  - User config created: {}", path.display());
    }
    if let Some(ref path) = summary.project_config_created {
        eprintln!("  - Project config created: {}", path.display());
    }
    if summary.hook_registered {
        eprintln!("  - Claude Code hook registered");
    }
    if summary.converted_rules.is_some() {
        eprintln!("  - Claude Code permissions converted to runok rules");
    }
    if summary.permissions_removed {
        eprintln!("  - Claude Code permissions removed from settings.json");
    }
}

fn claude_dir_if_exists(dir: &Path) -> Option<&Path> {
    if dir.exists() { Some(dir) } else { None }
}

/// Apply a scope result to the summary, replacing fields.
fn apply_scope_result(summary: &mut Summary, result: ScopeResult, is_user: bool) {
    if is_user {
        summary.user_config_created = result.config_path;
    } else {
        summary.project_config_created = result.config_path;
    }
    summary.hook_registered = result.hook_registered;
    summary.converted_rules = result.converted_rules;
    summary.permissions_removed = result.permissions_removed;
}

/// Merge a scope result into the summary, accumulating fields.
fn merge_scope_result(summary: &mut Summary, result: ScopeResult, is_user: bool) {
    if is_user {
        summary.user_config_created = result.config_path;
    } else {
        summary.project_config_created = result.config_path;
    }
    if result.hook_registered {
        summary.hook_registered = true;
    }
    if let Some(rules) = result.converted_rules {
        match summary.converted_rules {
            Some(ref mut existing) => {
                existing.push_str(&rules);
            }
            None => {
                summary.converted_rules = Some(rules);
            }
        }
    }
    if result.permissions_removed {
        summary.permissions_removed = true;
    }
}

/// Run the init wizard.
///
/// `scope`: optional scope from `--scope` flag
/// `auto_yes`: whether `-y` was specified
/// `force`: whether `--force` was specified
/// `cwd`: current working directory
pub fn run_wizard(
    scope: Option<&InitScope>,
    auto_yes: bool,
    force: bool,
    cwd: &Path,
) -> Result<(), InitError> {
    let paths = resolve_paths()?;
    run_wizard_with_paths(
        scope,
        auto_yes,
        force,
        cwd,
        &paths.user_config_dir,
        &paths.home_dir,
    )
}

/// Run the init wizard with explicit paths (for testing without relying on env vars).
pub fn run_wizard_with_paths(
    scope: Option<&InitScope>,
    auto_yes: bool,
    force: bool,
    cwd: &Path,
    user_config_dir: &Path,
    home_dir: &Path,
) -> Result<(), InitError> {
    let mut summary = Summary {
        user_config_created: None,
        project_config_created: None,
        hook_registered: false,
        converted_rules: None,
        permissions_removed: false,
    };

    match scope {
        Some(InitScope::User) => {
            let claude_dir = home_dir.join(".claude");
            let result = setup_scope(
                user_config_dir,
                claude_dir_if_exists(&claude_dir),
                auto_yes,
                force,
            )?;
            apply_scope_result(&mut summary, result, true);
        }
        Some(InitScope::Project) => {
            let claude_dir = cwd.join(".claude");
            let result = setup_scope(cwd, claude_dir_if_exists(&claude_dir), auto_yes, force)?;
            apply_scope_result(&mut summary, result, false);
        }
        None => {
            // No scope specified: setup user config, then optionally project config
            let user_claude_dir = home_dir.join(".claude");

            // User config
            if config_gen::config_exists(user_config_dir).is_some() && !force {
                eprintln!(
                    "User config already exists at {}, skipping.",
                    user_config_dir.display()
                );
            } else {
                let should_setup =
                    prompt::confirm("Set up user-level configuration?", true, auto_yes)?;
                if should_setup {
                    let result = setup_scope(
                        user_config_dir,
                        claude_dir_if_exists(&user_claude_dir),
                        auto_yes,
                        force,
                    )?;
                    apply_scope_result(&mut summary, result, true);
                }
            }

            // Project config
            let should_project =
                prompt::confirm("Set up project-level configuration?", false, auto_yes)?;
            if should_project {
                let project_claude_dir = cwd.join(".claude");
                match setup_scope(
                    cwd,
                    claude_dir_if_exists(&project_claude_dir),
                    auto_yes,
                    force,
                ) {
                    Ok(result) => {
                        merge_scope_result(&mut summary, result, false);
                    }
                    Err(InitError::ConfigExists(path)) => {
                        eprintln!(
                            "Project config already exists at {}, skipping.",
                            path.display()
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    print_summary(&summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;
    use tempfile::TempDir;

    /// Create a test environment with isolated home and project directories.
    struct TestEnv {
        _tmp: TempDir,
        home: PathBuf,
        cwd: PathBuf,
        user_config_dir: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let tmp = TempDir::new().unwrap();
            let home = tmp.path().join("home");
            let cwd = tmp.path().join("project");
            let user_config_dir = home.join(".config").join("runok");
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(&cwd).unwrap();
            Self {
                _tmp: tmp,
                home,
                cwd,
                user_config_dir,
            }
        }

        fn user_claude_dir(&self) -> PathBuf {
            self.home.join(".claude")
        }

        fn project_claude_dir(&self) -> PathBuf {
            self.cwd.join(".claude")
        }

        fn setup_user_claude_settings(&self, content: &str) {
            let dir = self.user_claude_dir();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("settings.json"), content).unwrap();
        }

        fn run(
            &self,
            scope: Option<&InitScope>,
            auto_yes: bool,
            force: bool,
        ) -> Result<(), InitError> {
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
    fn wizard_user_scope_creates_config() {
        let env = TestEnv::new();
        env.run(Some(&InitScope::User), true, false).unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_project_scope_creates_config() {
        let env = TestEnv::new();
        env.run(Some(&InitScope::Project), true, false).unwrap();

        assert!(env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_user_scope_with_claude_code_integration() {
        let env = TestEnv::new();
        env.setup_user_claude_settings(indoc! {r#"
            {
                "permissions": {
                    "allow": ["Bash(git status)", "Read(/tmp)"],
                    "deny": ["Bash(rm -rf /)"]
                }
            }
        "#});

        env.run(Some(&InitScope::User), true, false).unwrap();

        let config_content =
            std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(
            config_content,
            indoc! {"\
                # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

                # Converted from Claude Code permissions:
                rules:
                  - allow: 'git status'
                  - deny: 'rm -rf /'
            "}
        );

        // Hook registered and permissions removed
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(env.user_claude_dir().join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            settings,
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
    fn wizard_force_overwrites_existing() {
        let env = TestEnv::new();
        // Create existing config
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "old content").unwrap();

        env.run(Some(&InitScope::User), true, true).unwrap();

        let content = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_ne!(content, "old content");
    }

    #[rstest]
    fn wizard_user_scope_errors_on_existing_without_force() {
        let env = TestEnv::new();
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "existing").unwrap();

        let result = env.run(Some(&InitScope::User), true, false);
        assert!(matches!(result, Err(InitError::ConfigExists(_))));
    }

    #[rstest]
    fn wizard_no_scope_with_auto_yes() {
        let env = TestEnv::new();

        // auto_yes with no scope: user setup (default yes), project setup (default no)
        env.run(None, true, false).unwrap();

        assert!(env.user_config_dir.join("runok.yml").exists());
        // Project config should NOT be created (default is No for project)
        assert!(!env.cwd.join("runok.yml").exists());
    }

    #[rstest]
    fn wizard_project_scope_with_claude_code() {
        let env = TestEnv::new();
        let project_claude = env.project_claude_dir();
        std::fs::create_dir_all(&project_claude).unwrap();
        std::fs::write(
            project_claude.join("settings.json"),
            indoc! {r#"
                {
                    "permissions": {
                        "allow": ["Bash(cargo test)"]
                    }
                }
            "#},
        )
        .unwrap();

        env.run(Some(&InitScope::Project), true, false).unwrap();

        let config_content = std::fs::read_to_string(env.cwd.join("runok.yml")).unwrap();
        assert_eq!(
            config_content,
            indoc! {"\
                # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

                # Converted from Claude Code permissions:
                rules:
                  - allow: 'cargo test'
            "}
        );
    }

    #[rstest]
    fn wizard_no_scope_skips_existing_user_config() {
        let env = TestEnv::new();
        // Create existing user config
        std::fs::create_dir_all(&env.user_config_dir).unwrap();
        std::fs::write(env.user_config_dir.join("runok.yml"), "existing").unwrap();

        // auto_yes: user config skipped (exists), project config skipped (default no)
        env.run(None, true, false).unwrap();

        // User config should not be overwritten
        let content = std::fs::read_to_string(env.user_config_dir.join("runok.yml")).unwrap();
        assert_eq!(content, "existing");
    }

    // --- preview helpers ---

    #[rstest]
    fn normalize_json_reformats_indentation() {
        let input = "{\n   \"key\":   \"value\"\n}";
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
    fn preview_remove_permissions_strips_allow_and_deny() {
        let input = indoc! {r#"
            {
              "permissions": {
                "allow": ["Bash(git status)"],
                "deny": ["Bash(rm *)"],
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
