use std::cell::RefCell;

use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

use runok::init::error::InitError;
use runok::init::prompt::Prompter;
use runok::init::{InitScope, run_wizard_with_paths};

/// Queued response for SequencePrompter.
#[derive(Debug)]
enum Response {
    Confirm(bool),
    Select(usize),
}

/// Test prompter that returns pre-configured responses in sequence.
struct SequencePrompter {
    responses: RefCell<Vec<Response>>,
}

impl SequencePrompter {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: RefCell::new(responses),
        }
    }
}

impl Prompter for SequencePrompter {
    fn confirm(&self, _message: &str, default: bool) -> Result<bool, InitError> {
        let mut responses = self.responses.borrow_mut();
        if responses.is_empty() {
            return Ok(default);
        }
        match responses.remove(0) {
            Response::Confirm(v) => Ok(v),
            other => unreachable!("expected Confirm response, got {other:?}"),
        }
    }

    fn select(&self, _message: &str, _items: &[&str], default: usize) -> Result<usize, InitError> {
        let mut responses = self.responses.borrow_mut();
        if responses.is_empty() {
            return Ok(default);
        }
        match responses.remove(0) {
            Response::Select(v) => Ok(v),
            other => unreachable!("expected Select response, got {other:?}"),
        }
    }
}

/// Test environment for init wizard integration tests.
///
/// Uses explicit paths instead of environment variables to avoid data races.
struct InitTestEnv {
    _tmp: TempDir,
    home: std::path::PathBuf,
    cwd: std::path::PathBuf,
    user_config_dir: std::path::PathBuf,
}

impl InitTestEnv {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home = tmp.path().join("home");
        let cwd = tmp.path().join("project");
        let user_config_dir = home.join(".config").join("runok");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&cwd)?;

        Ok(Self {
            _tmp: tmp,
            home,
            cwd,
            user_config_dir,
        })
    }

    fn user_config_path(&self) -> std::path::PathBuf {
        self.user_config_dir.join("runok.yml")
    }

    fn user_claude_dir(&self) -> std::path::PathBuf {
        self.home.join(".claude")
    }

    fn project_claude_dir(&self) -> std::path::PathBuf {
        self.cwd.join(".claude")
    }

    fn claude_dir_for_scope(&self, scope: &InitScope) -> std::path::PathBuf {
        match scope {
            InitScope::User => self.user_claude_dir(),
            InitScope::Project => self.project_claude_dir(),
        }
    }

    fn config_path_for_scope(&self, scope: &InitScope) -> std::path::PathBuf {
        match scope {
            InitScope::User => self.user_config_path(),
            InitScope::Project => self.cwd.join("runok.yml"),
        }
    }

    fn setup_claude_settings(
        &self,
        scope: &InitScope,
        content: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = self.claude_dir_for_scope(scope);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("settings.json"), content)?;
        Ok(())
    }

    fn run(&self, scope: Option<&InitScope>, prompter: &dyn Prompter) -> Result<(), InitError> {
        run_wizard_with_paths(
            scope,
            prompter,
            &self.cwd,
            &self.user_config_dir,
            &self.home,
        )
    }
}

// --- constants for expected outputs ---

const BOILERPLATE: &str = "\
# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json
";

fn hook_json() -> serde_json::Value {
    serde_json::json!({
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
    })
}

// --- settings.json fixtures ---

/// Bash permissions only (no non-Bash, no hook)
const SETTINGS_BASH_ONLY: &str = r#"
{
    "permissions": {
        "allow": ["Bash(cargo test)", "Bash(cargo build)"],
        "deny": ["Bash(rm -rf /)"]
    }
}
"#;

/// Bash permissions only, with hook already registered
fn settings_bash_only_with_hook() -> &'static str {
    indoc! {r#"
        {
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"],
                "deny": ["Bash(rm -rf /)"]
            },
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
    "#}
}

/// No Bash permissions, no hook
const SETTINGS_NO_BASH_NO_HOOK: &str = r#"
{
    "permissions": {
        "allow": ["Read(/tmp)", "WebFetch"],
        "deny": ["Write(/etc/passwd)"]
    }
}
"#;

/// No Bash permissions, with hook already registered
fn settings_no_bash_with_hook() -> &'static str {
    indoc! {r#"
        {
            "permissions": {
                "allow": ["Read(/tmp)", "WebFetch"],
                "deny": ["Write(/etc/passwd)"]
            },
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
    "#}
}

/// Expected runok.yml with converted rules from SETTINGS_BASH_ONLY
fn config_with_bash_rules() -> String {
    indoc! {"\
        # yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

        # Converted from Claude Code permissions:
        rules:
          - allow: 'cargo test'
          - allow: 'cargo build'
          - deny: 'rm -rf /'
    "}
    .to_string()
}

// ============================================================
// Exhaustive 23-pattern test
// ============================================================
//
// Each pattern corresponds to one row in the pattern table:
//
// | # | settings.json | Bash perms | Hook exists | Scope   | Migration | Apply | runok.yml  | settings.json change   |
// |---|---------------|------------|-------------|---------|-----------|-------|------------|------------------------|
// |  1| no            | -          | -           | user    | -         | -     | boilerplate| -                      |
// |  2| no            | -          | -           | project | -         | -     | boilerplate| -                      |
// |  3| yes           | no         | no          | user    | -         | yes   | boilerplate| hook added             |
// |  4| yes           | no         | no          | user    | -         | no    | none       | none                   |
// |  5| yes           | no         | yes         | user    | -         | -     | boilerplate| none                   |
// |  6| yes           | no         | no          | project | -         | -     | boilerplate| none                   |
// |  7| yes           | no         | yes         | project | -         | -     | boilerplate| none                   |
// |  8| yes           | yes        | no          | user    | yes       | yes   | with rules | perms removed + hook   |
// |  9| yes           | yes        | no          | user    | yes       | no    | none       | none                   |
// | 10| yes           | yes        | no          | user    | no        | yes   | boilerplate| hook added             |
// | 11| yes           | yes        | no          | user    | no        | no    | none       | none                   |
// | 12| yes           | yes        | yes         | user    | yes       | yes   | with rules | perms removed          |
// | 13| yes           | yes        | yes         | user    | yes       | no    | none       | none                   |
// | 14| yes           | yes        | yes         | user    | no        | yes   | boilerplate| none                   |
// | 15| yes           | yes        | yes         | user    | no        | no    | none       | none                   |
// | 16| yes           | yes        | no          | project | yes       | yes   | with rules | perms removed          |
// | 17| yes           | yes        | no          | project | yes       | no    | none       | none                   |
// | 18| yes           | yes        | no          | project | no        | yes   | boilerplate| none                   |
// | 19| yes           | yes        | no          | project | no        | no    | none       | none                   |
// | 20| yes           | yes        | yes         | project | yes       | yes   | with rules | perms removed          |
// | 21| yes           | yes        | yes         | project | yes       | no    | none       | none                   |
// | 22| yes           | yes        | yes         | project | no        | yes   | boilerplate| none                   |
// | 23| yes           | yes        | yes         | project | no        | no    | none       | none                   |

/// Helper to assert the final state after running the wizard.
fn assert_wizard_result(
    env: &InitTestEnv,
    scope: &InitScope,
    expected_config: Option<&str>,
    expected_settings: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env.config_path_for_scope(scope);
    match expected_config {
        Some(expected) => {
            let config = std::fs::read_to_string(&config_path)?;
            assert_eq!(config, expected, "runok.yml content mismatch");
        }
        None => {
            assert!(
                !config_path.exists(),
                "runok.yml should not exist but was found at {}",
                config_path.display()
            );
        }
    }

    if let Some(expected) = expected_settings {
        let settings_path = env.claude_dir_for_scope(scope).join("settings.json");
        let content = std::fs::read_to_string(&settings_path)?;
        let actual: serde_json::Value = serde_json::from_str(&content)?;
        assert_eq!(actual, expected, "settings.json content mismatch");
    }

    Ok(())
}

// --- #1: no settings.json, user scope ---
#[rstest]
fn p01_no_settings_user_scope() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(&env, &InitScope::User, Some(BOILERPLATE), None)?;
    assert!(!env.user_claude_dir().join("settings.json").exists());
    Ok(())
}

// --- #2: no settings.json, project scope ---
#[rstest]
fn p02_no_settings_project_scope() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::Project), &prompter)?;

    assert_wizard_result(&env, &InitScope::Project, Some(BOILERPLATE), None)?;
    assert!(!env.project_claude_dir().join("settings.json").exists());
    Ok(())
}

// --- #3: settings exists, no bash, no hook, user scope, apply=yes ---
#[rstest]
fn p03_no_bash_no_hook_user_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_NO_BASH_NO_HOOK)?;

    // Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        Some(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Read(/tmp)", "WebFetch"],
                "deny": ["Write(/etc/passwd)"]
            },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #4: settings exists, no bash, no hook, user scope, apply=no ---
#[rstest]
fn p04_no_bash_no_hook_user_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_NO_BASH_NO_HOOK)?;

    // Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        None,
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Read(/tmp)", "WebFetch"],
                "deny": ["Write(/etc/passwd)"]
            }
        })),
    )?;
    Ok(())
}

// --- #5: settings exists, no bash, hook exists, user scope ---
#[rstest]
fn p05_no_bash_hook_exists_user() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_no_bash_with_hook())?;

    // No prompts expected (no changes to propose)
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        Some(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Read(/tmp)", "WebFetch"],
                "deny": ["Write(/etc/passwd)"]
            },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #6: settings exists, no bash, no hook, project scope ---
#[rstest]
fn p06_no_bash_no_hook_project() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_NO_BASH_NO_HOOK)?;

    // No prompts expected (project scope never adds hook, no bash to migrate)
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::Project), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::Project,
        Some(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Read(/tmp)", "WebFetch"],
                "deny": ["Write(/etc/passwd)"]
            }
        })),
    )?;
    Ok(())
}

// --- #7: settings exists, no bash, hook exists, project scope ---
#[rstest]
fn p07_no_bash_hook_exists_project() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_no_bash_with_hook())?;

    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::Project), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::Project,
        Some(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Read(/tmp)", "WebFetch"],
                "deny": ["Write(/etc/passwd)"]
            },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #8: bash, no hook, user, migrate=yes, apply=yes ---
#[rstest]
fn p08_bash_no_hook_user_migrate_yes_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;

    // Migrate? -> yes, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        Some(&config_with_bash_rules()),
        Some(serde_json::json!({
            "permissions": {},
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #9: bash, no hook, user, migrate=yes, apply=no ---
#[rstest]
fn p09_bash_no_hook_user_migrate_yes_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;

    // Migrate? -> yes, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        None,
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"],
                "deny": ["Bash(rm -rf /)"]
            }
        })),
    )?;
    Ok(())
}

// --- #10: bash, no hook, user, migrate=no, apply=yes ---
#[rstest]
fn p10_bash_no_hook_user_migrate_no_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;

    // Migrate? -> no, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        Some(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"],
                "deny": ["Bash(rm -rf /)"]
            },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #11: bash, no hook, user, migrate=no, apply=no ---
#[rstest]
fn p11_bash_no_hook_user_migrate_no_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;

    // Migrate? -> no, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        None,
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"],
                "deny": ["Bash(rm -rf /)"]
            }
        })),
    )?;
    Ok(())
}

// --- #12: bash, hook exists, user, migrate=yes, apply=yes ---
#[rstest]
fn p12_bash_hook_exists_user_migrate_yes_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;

    // Migrate? -> yes, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        Some(&config_with_bash_rules()),
        Some(serde_json::json!({
            "permissions": {},
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #13: bash, hook exists, user, migrate=yes, apply=no ---
#[rstest]
fn p13_bash_hook_exists_user_migrate_yes_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;

    // Migrate? -> yes, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;

    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(&env, &InitScope::User, None, Some(original))?;
    Ok(())
}

// --- #14: bash, hook exists, user, migrate=no, apply=yes ---
#[rstest]
fn p14_bash_hook_exists_user_migrate_no_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;

    // Migrate? -> no, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;

    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(&env, &InitScope::User, Some(BOILERPLATE), Some(original))?;
    Ok(())
}

// --- #15: bash, hook exists, user, migrate=no, apply=no ---
#[rstest]
fn p15_bash_hook_exists_user_migrate_no_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;

    // Migrate? -> no, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;

    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(&env, &InitScope::User, None, Some(original))?;
    Ok(())
}

// --- #16: bash, no hook, project, migrate=yes, apply=yes ---
#[rstest]
fn p16_bash_no_hook_project_migrate_yes_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;

    // Migrate? -> yes, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    // Project scope: perms removed, no hook added
    assert_wizard_result(
        &env,
        &InitScope::Project,
        Some(&config_with_bash_rules()),
        Some(serde_json::json!({
            "permissions": {}
        })),
    )?;
    Ok(())
}

// --- #17: bash, no hook, project, migrate=yes, apply=no ---
#[rstest]
fn p17_bash_no_hook_project_migrate_yes_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;

    // Migrate? -> yes, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::Project,
        None,
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"],
                "deny": ["Bash(rm -rf /)"]
            }
        })),
    )?;
    Ok(())
}

// --- #18: bash, no hook, project, migrate=no, apply=yes ---
#[rstest]
fn p18_bash_no_hook_project_migrate_no_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;

    // Migrate? -> no, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    // No migration, no hook -> only boilerplate, settings unchanged
    assert_wizard_result(
        &env,
        &InitScope::Project,
        Some(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"],
                "deny": ["Bash(rm -rf /)"]
            }
        })),
    )?;
    Ok(())
}

// --- #19: bash, no hook, project, migrate=no, apply=no ---
#[rstest]
fn p19_bash_no_hook_project_migrate_no_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;

    // Migrate? -> no, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::Project,
        None,
        Some(serde_json::json!({
            "permissions": {
                "allow": ["Bash(cargo test)", "Bash(cargo build)"],
                "deny": ["Bash(rm -rf /)"]
            }
        })),
    )?;
    Ok(())
}

// --- #20: bash, hook exists, project, migrate=yes, apply=yes ---
#[rstest]
fn p20_bash_hook_exists_project_migrate_yes_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;

    // Migrate? -> yes, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    assert_wizard_result(
        &env,
        &InitScope::Project,
        Some(&config_with_bash_rules()),
        Some(serde_json::json!({
            "permissions": {},
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #21: bash, hook exists, project, migrate=yes, apply=no ---
#[rstest]
fn p21_bash_hook_exists_project_migrate_yes_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;

    // Migrate? -> yes, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(&env, &InitScope::Project, None, Some(original))?;
    Ok(())
}

// --- #22: bash, hook exists, project, migrate=no, apply=yes ---
#[rstest]
fn p22_bash_hook_exists_project_migrate_no_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;

    // Migrate? -> no, Apply? -> yes
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(&env, &InitScope::Project, Some(BOILERPLATE), Some(original))?;
    Ok(())
}

// --- #23: bash, hook exists, project, migrate=no, apply=no ---
#[rstest]
fn p23_bash_hook_exists_project_migrate_no_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;

    // Migrate? -> no, Apply? -> no
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;

    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(&env, &InitScope::Project, None, Some(original))?;
    Ok(())
}

// --- scope selection (separate from exhaustive patterns) ---

#[rstest]
#[case::select_user(0, true, false)]
#[case::select_project(1, false, true)]
fn scope_select_without_explicit_scope(
    #[case] selection: usize,
    #[case] user_config_exists: bool,
    #[case] project_config_exists: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    let prompter = SequencePrompter::new(vec![Response::Select(selection)]);
    env.run(None, &prompter)?;

    assert_eq!(env.user_config_path().exists(), user_config_exists);
    assert_eq!(env.cwd.join("runok.yml").exists(), project_config_exists);
    Ok(())
}
