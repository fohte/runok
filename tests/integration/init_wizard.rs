use std::cell::RefCell;

use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

use runok::init::error::InitError;
use runok::init::prompt::Prompter;
use runok::init::{InitScope, run_wizard_with_paths};

/// Queued response for SequencePrompter.
#[derive(Debug, Clone)]
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

// --- test case parameter struct ---

/// All parameters for a single exhaustive wizard test case.
struct Case {
    /// Content of settings.json before the wizard runs, or None to skip creating it.
    settings: Option<&'static str>,
    /// Scope to pass to the wizard.
    scope: InitScope,
    /// Whether to pre-seed runok.yml with EXISTING_CONFIG.
    existing_config: bool,
    /// Responses the prompter will return.
    responses: Vec<Response>,
    /// Expected runok.yml state after the wizard.
    expected_config: ExpectedConfig,
    /// Expected settings.json content after the wizard, or None to skip checking.
    expected_settings: Option<serde_json::Value>,
    /// Whether to assert that settings.json was NOT created (for no-settings cases).
    assert_no_settings_created: bool,
}

// --- shorthand helpers for expected settings values ---

fn no_bash_perms() -> serde_json::Value {
    serde_json::json!({
        "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] }
    })
}

fn no_bash_perms_with_hook() -> serde_json::Value {
    serde_json::json!({
        "permissions": { "allow": ["Read(/tmp)", "WebFetch"], "deny": ["Write(/etc/passwd)"] },
        "hooks": hook_json()
    })
}

fn bash_perms_unchanged() -> serde_json::Value {
    serde_json::json!({
        "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] }
    })
}

fn bash_perms_with_hook() -> serde_json::Value {
    serde_json::json!({
        "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] },
        "hooks": hook_json()
    })
}

fn perms_removed_with_hook() -> serde_json::Value {
    serde_json::json!({ "permissions": {}, "hooks": hook_json() })
}

/// For project scope: permissions removed but no hook added (hook is user-scope only in migration)
fn perms_removed_no_hook() -> serde_json::Value {
    serde_json::json!({ "permissions": {} })
}

fn bash_hook_original() -> serde_json::Value {
    serde_json::json!({
        "permissions": {
            "allow": ["Bash(cargo test)", "Bash(cargo build)"],
            "deny": ["Bash(rm -rf /)"]
        },
        "hooks": hook_json()
    })
}

// --- shorthand aliases for Response ---

fn yes() -> Response {
    Response::Confirm(true)
}

fn no() -> Response {
    Response::Confirm(false)
}

#[rstest]
// --- No settings.json (cases 1-6) ---
#[case::p01_no_settings_user(Case {
    settings: None, scope: InitScope::User, existing_config: false,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: None,
    assert_no_settings_created: true,
})]
#[case::p02_no_settings_user_existing_overwrite_yes(Case {
    settings: None, scope: InitScope::User, existing_config: true,
    responses: vec![yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: None,
    assert_no_settings_created: false,
})]
#[case::p03_no_settings_user_existing_overwrite_no(Case {
    settings: None, scope: InitScope::User, existing_config: true,
    responses: vec![no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: None,
    assert_no_settings_created: false,
})]
#[case::p04_no_settings_project(Case {
    settings: None, scope: InitScope::Project, existing_config: false,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: None,
    assert_no_settings_created: true,
})]
#[case::p05_no_settings_project_existing_overwrite_yes(Case {
    settings: None, scope: InitScope::Project, existing_config: true,
    responses: vec![yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: None,
    assert_no_settings_created: false,
})]
#[case::p06_no_settings_project_existing_overwrite_no(Case {
    settings: None, scope: InitScope::Project, existing_config: true,
    responses: vec![no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: None,
    assert_no_settings_created: false,
})]
// --- No Bash perms, no hook (cases 7-10) ---
#[case::p07_no_bash_no_hook_user_apply_yes(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::User, existing_config: false,
    responses: vec![yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p08_no_bash_no_hook_user_existing_apply_yes(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::User, existing_config: true,
    responses: vec![yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p09_no_bash_no_hook_user_apply_no(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::User, existing_config: false,
    responses: vec![no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(no_bash_perms()),
    assert_no_settings_created: false,
})]
#[case::p10_no_bash_no_hook_user_existing_apply_no(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::User, existing_config: true,
    responses: vec![no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(no_bash_perms()),
    assert_no_settings_created: false,
})]
// --- No Bash perms, hook exists (cases 11-13) ---
#[case::p11_no_bash_hook_exists_user(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::User, existing_config: false,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p12_no_bash_hook_exists_user_existing_overwrite_yes(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::User, existing_config: true,
    responses: vec![yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p13_no_bash_hook_exists_user_existing_overwrite_no(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::User, existing_config: true,
    responses: vec![no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
// --- No Bash perms, no hook, project (cases 14-16) ---
#[case::p14_no_bash_no_hook_project(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::Project, existing_config: false,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms()),
    assert_no_settings_created: false,
})]
#[case::p15_no_bash_no_hook_project_existing_overwrite_yes(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::Project, existing_config: true,
    responses: vec![yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms()),
    assert_no_settings_created: false,
})]
#[case::p16_no_bash_no_hook_project_existing_overwrite_no(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::Project, existing_config: true,
    responses: vec![no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(no_bash_perms()),
    assert_no_settings_created: false,
})]
// --- No Bash perms, hook exists, project (cases 17-19) ---
#[case::p17_no_bash_hook_exists_project(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::Project, existing_config: false,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p18_no_bash_hook_exists_project_existing_overwrite_yes(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::Project, existing_config: true,
    responses: vec![yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p19_no_bash_hook_exists_project_existing_overwrite_no(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::Project, existing_config: true,
    responses: vec![no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
// --- Bash perms, no hook, user (cases 20-27) ---
#[case::p20_bash_no_hook_user_mig_yes_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: false,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p21_bash_no_hook_user_existing_mig_yes_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: true,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p22_bash_no_hook_user_mig_yes_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: false,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p23_bash_no_hook_user_existing_mig_yes_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: true,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p24_bash_no_hook_user_mig_no_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: false,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p25_bash_no_hook_user_existing_mig_no_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: true,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p26_bash_no_hook_user_mig_no_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: false,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p27_bash_no_hook_user_existing_mig_no_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User, existing_config: true,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
// --- Bash perms, hook exists, user (cases 28-35) ---
#[case::p28_bash_hook_user_mig_yes_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: false,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p29_bash_hook_user_existing_mig_yes_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: true,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p30_bash_hook_user_mig_yes_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: false,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p31_bash_hook_user_existing_mig_yes_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: true,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p32_bash_hook_user_mig_no_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: false,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p33_bash_hook_user_existing_mig_no_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: true,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p34_bash_hook_user_mig_no_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: false,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p35_bash_hook_user_existing_mig_no_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User, existing_config: true,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
// --- Bash perms, no hook, project (cases 36-43) ---
#[case::p36_bash_no_hook_project_mig_yes_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: false,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_no_hook()),
    assert_no_settings_created: false,
})]
#[case::p37_bash_no_hook_project_existing_mig_yes_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: true,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_no_hook()),
    assert_no_settings_created: false,
})]
#[case::p38_bash_no_hook_project_mig_yes_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: false,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p39_bash_no_hook_project_existing_mig_yes_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: true,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p40_bash_no_hook_project_mig_no_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: false,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p41_bash_no_hook_project_existing_mig_no_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: true,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p42_bash_no_hook_project_mig_no_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: false,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p43_bash_no_hook_project_existing_mig_no_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project, existing_config: true,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
// --- Bash perms, hook exists, project (cases 44-51) ---
#[case::p44_bash_hook_project_mig_yes_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: false,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p45_bash_hook_project_existing_mig_yes_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: true,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p46_bash_hook_project_mig_yes_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: false,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p47_bash_hook_project_existing_mig_yes_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: true,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p48_bash_hook_project_mig_no_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: false,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p49_bash_hook_project_existing_mig_no_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: true,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p50_bash_hook_project_mig_no_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: false,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p51_bash_hook_project_existing_mig_no_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project, existing_config: true,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::Preserved,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
fn exhaustive_wizard_test(#[case] case: Case) -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    if let Some(settings) = case.settings {
        env.setup_claude_settings(&case.scope, settings)?;
    }
    if case.existing_config {
        env.setup_existing_config(&case.scope)?;
    }

    let prompter = SequencePrompter::new(case.responses);
    env.run(Some(&case.scope), &prompter)?;

    assert_wizard_result(
        &env,
        &case.scope,
        &case.expected_config,
        case.expected_settings,
    )?;

    if case.assert_no_settings_created {
        let claude_dir = env.claude_dir_for_scope(&case.scope);
        assert!(
            !claude_dir.join("settings.json").exists(),
            "settings.json should not have been created"
        );
    }

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
