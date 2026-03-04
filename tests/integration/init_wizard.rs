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

/// Content pre-seeded into runok.yml for "existing config" test cases.
const EXISTING_CONFIG: &str = "\
# existing user config
rules:
  - allow: 'echo hello'
";

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

    fn setup_existing_config(&self, scope: &InitScope) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.config_path_for_scope(scope);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, EXISTING_CONFIG)?;
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
// Exhaustive 51-pattern test
// ============================================================
//
// Condition axes, grouped into State / Response / Result:
//
// |    |                           State                                |          Response              |               Result               |
// | #  | settings.json | Bash perms | Hook exists | Scope   | runok.yml | Migrate? | Apply? | Overwrite? | runok.yml   | settings.json change |
// |----|---------------|------------|-------------|---------|-----------|----------|--------|------------|-------------|----------------------|
// |  1 | no            | N/A        | N/A         | user    | no        | N/A      | N/A    | N/A        | boilerplate | N/A                  |
// |  2 | no            | N/A        | N/A         | user    | yes       | N/A      | N/A    | yes        | boilerplate | N/A                  |
// |  3 | no            | N/A        | N/A         | user    | yes       | N/A      | N/A    | no         | preserved   | N/A                  |
// |  4 | no            | N/A        | N/A         | project | no        | N/A      | N/A    | N/A        | boilerplate | N/A                  |
// |  5 | no            | N/A        | N/A         | project | yes       | N/A      | N/A    | yes        | boilerplate | N/A                  |
// |  6 | no            | N/A        | N/A         | project | yes       | N/A      | N/A    | no         | preserved   | N/A                  |
// |  7 | yes           | no         | no          | user    | no        | N/A      | yes    | N/A        | boilerplate | hook added           |
// |  8 | yes           | no         | no          | user    | yes       | N/A      | yes    | N/A        | boilerplate | hook added           |
// |  9 | yes           | no         | no          | user    | no        | N/A      | no     | N/A        | none        | none                 |
// | 10 | yes           | no         | no          | user    | yes       | N/A      | no     | N/A        | preserved   | none                 |
// | 11 | yes           | no         | yes         | user    | no        | N/A      | N/A    | N/A        | boilerplate | none                 |
// | 12 | yes           | no         | yes         | user    | yes       | N/A      | N/A    | yes        | boilerplate | none                 |
// | 13 | yes           | no         | yes         | user    | yes       | N/A      | N/A    | no         | preserved   | none                 |
// | 14 | yes           | no         | no          | project | no        | N/A      | N/A    | N/A        | boilerplate | none                 |
// | 15 | yes           | no         | no          | project | yes       | N/A      | N/A    | yes        | boilerplate | none                 |
// | 16 | yes           | no         | no          | project | yes       | N/A      | N/A    | no         | preserved   | none                 |
// | 17 | yes           | no         | yes         | project | no        | N/A      | N/A    | N/A        | boilerplate | none                 |
// | 18 | yes           | no         | yes         | project | yes       | N/A      | N/A    | yes        | boilerplate | none                 |
// | 19 | yes           | no         | yes         | project | yes       | N/A      | N/A    | no         | preserved   | none                 |
// | 20 | yes           | yes        | no          | user    | no        | yes      | yes    | N/A        | with rules  | perms removed + hook |
// | 21 | yes           | yes        | no          | user    | yes       | yes      | yes    | N/A        | with rules  | perms removed + hook |
// | 22 | yes           | yes        | no          | user    | no        | yes      | no     | N/A        | none        | none                 |
// | 23 | yes           | yes        | no          | user    | yes       | yes      | no     | N/A        | preserved   | none                 |
// | 24 | yes           | yes        | no          | user    | no        | no       | yes    | N/A        | boilerplate | hook added           |
// | 25 | yes           | yes        | no          | user    | yes       | no       | yes    | N/A        | boilerplate | hook added           |
// | 26 | yes           | yes        | no          | user    | no        | no       | no     | N/A        | none        | none                 |
// | 27 | yes           | yes        | no          | user    | yes       | no       | no     | N/A        | preserved   | none                 |
// | 28 | yes           | yes        | yes         | user    | no        | yes      | yes    | N/A        | with rules  | perms removed        |
// | 29 | yes           | yes        | yes         | user    | yes       | yes      | yes    | N/A        | with rules  | perms removed        |
// | 30 | yes           | yes        | yes         | user    | no        | yes      | no     | N/A        | none        | none                 |
// | 31 | yes           | yes        | yes         | user    | yes       | yes      | no     | N/A        | preserved   | none                 |
// | 32 | yes           | yes        | yes         | user    | no        | no       | yes    | N/A        | boilerplate | none                 |
// | 33 | yes           | yes        | yes         | user    | yes       | no       | yes    | N/A        | boilerplate | none                 |
// | 34 | yes           | yes        | yes         | user    | no        | no       | no     | N/A        | none        | none                 |
// | 35 | yes           | yes        | yes         | user    | yes       | no       | no     | N/A        | preserved   | none                 |
// | 36 | yes           | yes        | no          | project | no        | yes      | yes    | N/A        | with rules  | perms removed        |
// | 37 | yes           | yes        | no          | project | yes       | yes      | yes    | N/A        | with rules  | perms removed        |
// | 38 | yes           | yes        | no          | project | no        | yes      | no     | N/A        | none        | none                 |
// | 39 | yes           | yes        | no          | project | yes       | yes      | no     | N/A        | preserved   | none                 |
// | 40 | yes           | yes        | no          | project | no        | no       | yes    | N/A        | boilerplate | none                 |
// | 41 | yes           | yes        | no          | project | yes       | no       | yes    | N/A        | boilerplate | none                 |
// | 42 | yes           | yes        | no          | project | no        | no       | no     | N/A        | none        | none                 |
// | 43 | yes           | yes        | no          | project | yes       | no       | no     | N/A        | preserved   | none                 |
// | 44 | yes           | yes        | yes         | project | no        | yes      | yes    | N/A        | with rules  | perms removed        |
// | 45 | yes           | yes        | yes         | project | yes       | yes      | yes    | N/A        | with rules  | perms removed        |
// | 46 | yes           | yes        | yes         | project | no        | yes      | no     | N/A        | none        | none                 |
// | 47 | yes           | yes        | yes         | project | yes       | yes      | no     | N/A        | preserved   | none                 |
// | 48 | yes           | yes        | yes         | project | no        | no       | yes    | N/A        | boilerplate | none                 |
// | 49 | yes           | yes        | yes         | project | yes       | no       | yes    | N/A        | boilerplate | none                 |
// | 50 | yes           | yes        | yes         | project | no        | no       | no     | N/A        | none        | none                 |
// | 51 | yes           | yes        | yes         | project | yes       | no       | no     | N/A        | preserved   | none                 |
//
// "preserved" in Result means the existing runok.yml is left unchanged (wizard does not touch it)
// "none" in Result means runok.yml does not exist after the wizard
// Overwrite? is only asked when there is no "Detected" block and runok.yml already exists

/// Expected runok.yml content after the wizard runs.
enum ExpectedConfig {
    /// runok.yml is created/overwritten with the given content.
    Content(&'static str),
    /// runok.yml is created/overwritten with a computed String.
    ContentOwned(String),
    /// runok.yml does not exist (was not created, and none existed before).
    None,
    /// runok.yml is preserved as-is (wizard did not touch it).
    Preserved,
}

/// Helper to assert the final state after running the wizard.
fn assert_wizard_result(
    env: &InitTestEnv,
    scope: &InitScope,
    expected_config: &ExpectedConfig,
    expected_settings: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env.config_path_for_scope(scope);
    match expected_config {
        ExpectedConfig::Content(expected) => {
            let config = std::fs::read_to_string(&config_path)?;
            assert_eq!(config, *expected, "runok.yml content mismatch");
        }
        ExpectedConfig::ContentOwned(expected) => {
            let config = std::fs::read_to_string(&config_path)?;
            assert_eq!(config, *expected, "runok.yml content mismatch");
        }
        ExpectedConfig::None => {
            assert!(
                !config_path.exists(),
                "runok.yml should not exist but was found at {}",
                config_path.display()
            );
        }
        ExpectedConfig::Preserved => {
            let config = std::fs::read_to_string(&config_path)?;
            assert_eq!(
                config, EXISTING_CONFIG,
                "runok.yml should be preserved but was modified"
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

// --- #1: no settings, user, no existing config ---
#[rstest]
fn p01_no_settings_user() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        None,
    )?;
    assert!(!env.user_claude_dir().join("settings.json").exists());
    Ok(())
}

// --- #2: no settings, user, existing config, overwrite=yes ---
#[rstest]
fn p02_no_settings_user_existing_overwrite_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        None,
    )?;
    Ok(())
}

// --- #3: no settings, user, existing config, overwrite=no ---
#[rstest]
fn p03_no_settings_user_existing_overwrite_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(&env, &InitScope::User, &ExpectedConfig::Preserved, None)?;
    Ok(())
}

// --- #4: no settings, project, no existing config ---
#[rstest]
fn p04_no_settings_project() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        None,
    )?;
    assert!(!env.project_claude_dir().join("settings.json").exists());
    Ok(())
}

// --- #5: no settings, project, existing config, overwrite=yes ---
#[rstest]
fn p05_no_settings_project_existing_overwrite_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        None,
    )?;
    Ok(())
}

// --- #6: no settings, project, existing config, overwrite=no ---
#[rstest]
fn p06_no_settings_project_existing_overwrite_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(&env, &InitScope::Project, &ExpectedConfig::Preserved, None)?;
    Ok(())
}

// --- #7: no bash, no hook, user, no config, apply=yes ---
#[rstest]
fn p07_no_bash_no_hook_user_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_NO_BASH_NO_HOOK)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #8: no bash, no hook, user, existing config, apply=yes ---
#[rstest]
fn p08_no_bash_no_hook_user_existing_apply_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_NO_BASH_NO_HOOK)?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #9: no bash, no hook, user, no config, apply=no ---
#[rstest]
fn p09_no_bash_no_hook_user_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_NO_BASH_NO_HOOK)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::None,
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] }
        })),
    )?;
    Ok(())
}

// --- #10: no bash, no hook, user, existing config, apply=no ---
#[rstest]
fn p10_no_bash_no_hook_user_existing_apply_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_NO_BASH_NO_HOOK)?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] }
        })),
    )?;
    Ok(())
}

// --- #11: no bash, hook exists, user, no config ---
#[rstest]
fn p11_no_bash_hook_exists_user() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_no_bash_with_hook())?;
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #12: no bash, hook exists, user, existing config, overwrite=yes ---
#[rstest]
fn p12_no_bash_hook_exists_user_existing_overwrite_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_no_bash_with_hook())?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #13: no bash, hook exists, user, existing config, overwrite=no ---
#[rstest]
fn p13_no_bash_hook_exists_user_existing_overwrite_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_no_bash_with_hook())?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #14: no bash, no hook, project, no config ---
#[rstest]
fn p14_no_bash_no_hook_project() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_NO_BASH_NO_HOOK)?;
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] }
        })),
    )?;
    Ok(())
}

// --- #15: no bash, no hook, project, existing config, overwrite=yes ---
#[rstest]
fn p15_no_bash_no_hook_project_existing_overwrite_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_NO_BASH_NO_HOOK)?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] }
        })),
    )?;
    Ok(())
}

// --- #16: no bash, no hook, project, existing config, overwrite=no ---
#[rstest]
fn p16_no_bash_no_hook_project_existing_overwrite_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_NO_BASH_NO_HOOK)?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] }
        })),
    )?;
    Ok(())
}

// --- #17: no bash, hook exists, project, no config ---
#[rstest]
fn p17_no_bash_hook_exists_project() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_no_bash_with_hook())?;
    let prompter = SequencePrompter::new(vec![]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #18: no bash, hook exists, project, existing config, overwrite=yes ---
#[rstest]
fn p18_no_bash_hook_exists_project_existing_overwrite_yes() -> Result<(), Box<dyn std::error::Error>>
{
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_no_bash_with_hook())?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #19: no bash, hook exists, project, existing config, overwrite=no ---
#[rstest]
fn p19_no_bash_hook_exists_project_existing_overwrite_no() -> Result<(), Box<dyn std::error::Error>>
{
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_no_bash_with_hook())?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #20: bash, no hook, user, no config, migrate=yes, apply=yes ---
#[rstest]
fn p20_bash_no_hook_user_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {}, "hooks": hook_json() })),
    )?;
    Ok(())
}

// --- #21: bash, no hook, user, existing config, migrate=yes, apply=yes ---
#[rstest]
fn p21_bash_no_hook_user_existing_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {}, "hooks": hook_json() })),
    )?;
    Ok(())
}

// --- #22: bash, no hook, user, no config, migrate=yes, apply=no ---
#[rstest]
fn p22_bash_no_hook_user_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::None,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #23: bash, no hook, user, existing config, migrate=yes, apply=no ---
#[rstest]
fn p23_bash_no_hook_user_existing_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #24: bash, no hook, user, no config, migrate=no, apply=yes ---
#[rstest]
fn p24_bash_no_hook_user_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #25: bash, no hook, user, existing config, migrate=no, apply=yes ---
#[rstest]
fn p25_bash_no_hook_user_existing_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] },
            "hooks": hook_json()
        })),
    )?;
    Ok(())
}

// --- #26: bash, no hook, user, no config, migrate=no, apply=no ---
#[rstest]
fn p26_bash_no_hook_user_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::None,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #27: bash, no hook, user, existing config, migrate=no, apply=no ---
#[rstest]
fn p27_bash_no_hook_user_existing_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #28: bash, hook exists, user, no config, migrate=yes, apply=yes ---
#[rstest]
fn p28_bash_hook_user_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {}, "hooks": hook_json() })),
    )?;
    Ok(())
}

// --- #29: bash, hook exists, user, existing config, migrate=yes, apply=yes ---
#[rstest]
fn p29_bash_hook_user_existing_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {}, "hooks": hook_json() })),
    )?;
    Ok(())
}

// --- #30: bash, hook exists, user, no config, migrate=yes, apply=no ---
#[rstest]
fn p30_bash_hook_user_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::None,
        Some(original),
    )?;
    Ok(())
}

// --- #31: bash, hook exists, user, existing config, migrate=yes, apply=no ---
#[rstest]
fn p31_bash_hook_user_existing_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Preserved,
        Some(original),
    )?;
    Ok(())
}

// --- #32: bash, hook exists, user, no config, migrate=no, apply=yes ---
#[rstest]
fn p32_bash_hook_user_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(original),
    )?;
    Ok(())
}

// --- #33: bash, hook exists, user, existing config, migrate=no, apply=yes ---
#[rstest]
fn p33_bash_hook_user_existing_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::User), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(original),
    )?;
    Ok(())
}

// --- #34: bash, hook exists, user, no config, migrate=no, apply=no ---
#[rstest]
fn p34_bash_hook_user_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::None,
        Some(original),
    )?;
    Ok(())
}

// --- #35: bash, hook exists, user, existing config, migrate=no, apply=no ---
#[rstest]
fn p35_bash_hook_user_existing_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::User)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::User), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Preserved,
        Some(original),
    )?;
    Ok(())
}

// --- #36: bash, no hook, project, no config, migrate=yes, apply=yes ---
#[rstest]
fn p36_bash_no_hook_project_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {} })),
    )?;
    Ok(())
}

// --- #37: bash, no hook, project, existing config, migrate=yes, apply=yes ---
#[rstest]
fn p37_bash_no_hook_project_existing_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {} })),
    )?;
    Ok(())
}

// --- #38: bash, no hook, project, no config, migrate=yes, apply=no ---
#[rstest]
fn p38_bash_no_hook_project_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::None,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #39: bash, no hook, project, existing config, migrate=yes, apply=no ---
#[rstest]
fn p39_bash_no_hook_project_existing_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #40: bash, no hook, project, no config, migrate=no, apply=yes ---
#[rstest]
fn p40_bash_no_hook_project_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #41: bash, no hook, project, existing config, migrate=no, apply=yes ---
#[rstest]
fn p41_bash_no_hook_project_existing_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #42: bash, no hook, project, no config, migrate=no, apply=no ---
#[rstest]
fn p42_bash_no_hook_project_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::None,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #43: bash, no hook, project, existing config, migrate=no, apply=no ---
#[rstest]
fn p43_bash_no_hook_project_existing_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
        })),
    )?;
    Ok(())
}

// --- #44: bash, hook exists, project, no config, migrate=yes, apply=yes ---
#[rstest]
fn p44_bash_hook_project_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {}, "hooks": hook_json() })),
    )?;
    Ok(())
}

// --- #45: bash, hook exists, project, existing config, migrate=yes, apply=yes ---
#[rstest]
fn p45_bash_hook_project_existing_mig_yes_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::ContentOwned(config_with_bash_rules()),
        Some(serde_json::json!({ "permissions": {}, "hooks": hook_json() })),
    )?;
    Ok(())
}

// --- #46: bash, hook exists, project, no config, migrate=yes, apply=no ---
#[rstest]
fn p46_bash_hook_project_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::None,
        Some(original),
    )?;
    Ok(())
}

// --- #47: bash, hook exists, project, existing config, migrate=yes, apply=no ---
#[rstest]
fn p47_bash_hook_project_existing_mig_yes_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(true), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Preserved,
        Some(original),
    )?;
    Ok(())
}

// --- #48: bash, hook exists, project, no config, migrate=no, apply=yes ---
#[rstest]
fn p48_bash_hook_project_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(original),
    )?;
    Ok(())
}

// --- #49: bash, hook exists, project, existing config, migrate=no, apply=yes ---
#[rstest]
fn p49_bash_hook_project_existing_mig_no_app_yes() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(true)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Content(BOILERPLATE),
        Some(original),
    )?;
    Ok(())
}

// --- #50: bash, hook exists, project, no config, migrate=no, apply=no ---
#[rstest]
fn p50_bash_hook_project_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::None,
        Some(original),
    )?;
    Ok(())
}

// --- #51: bash, hook exists, project, existing config, migrate=no, apply=no ---
#[rstest]
fn p51_bash_hook_project_existing_mig_no_app_no() -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::Project, settings_bash_only_with_hook())?;
    env.setup_existing_config(&InitScope::Project)?;
    let prompter = SequencePrompter::new(vec![Response::Confirm(false), Response::Confirm(false)]);
    env.run(Some(&InitScope::Project), &prompter)?;
    let original: serde_json::Value = serde_json::from_str(settings_bash_only_with_hook())?;
    assert_wizard_result(
        &env,
        &InitScope::Project,
        &ExpectedConfig::Preserved,
        Some(original),
    )?;
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
