use std::cell::RefCell;

use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

use runok::init::error::InitError;
use runok::init::prompt::{AutoYesPrompter, Prompter};
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

    fn codex_home_dir(&self) -> std::path::PathBuf {
        self.home.join(".codex")
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
            &self.codex_home_dir(),
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
                        "command": "runok hook --agent claude-code"
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
                                "command": "runok hook --agent claude-code"
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
                                "command": "runok hook --agent claude-code"
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
// Matrix A: wizard behavior when runok.yml does not exist yet
// ============================================================
//
// This is init's "first-time setup" path: it is unaffected by whether an
// existing runok.yml would need to be protected, so it is exercised
// exhaustively across settings.json / Bash perms / hook / scope / migrate
// / apply combinations. Whether an existing runok.yml survives init is a
// single, orthogonal guard covered separately in Matrix B below — init
// never writes into an existing runok.yml, full stop, so that axis does
// not need to be crossed with all of these.
//
// Condition axes, grouped into State / Response / Result:
//
// In user scope with a settings.json present, the wizard also asks the
// PostToolUse opt-in ("Track ask approvals in the audit log?") between
// Migrate? and Apply?. Every case in this matrix answers it No so the
// original axes stay comparable; the opt-in behavior itself is covered by
// dedicated tests in src/init/wizard and tests/e2e/init.rs.
//
// |    |                     State                 |    Response      |          Result          |
// | #  | settings.json | Bash perms | Hook exists | Scope   | Migrate? | Apply? | runok.yml   | settings.json change |
// |----|---------------|------------|-------------|---------|----------|--------|-------------|----------------------|
// | 01 | no            | N/A        | N/A         | user    | N/A      | N/A    | boilerplate | N/A                  |
// | 04 | no            | N/A        | N/A         | project | N/A      | N/A    | boilerplate | N/A                  |
// | 07 | yes           | no         | no          | user    | N/A      | yes    | boilerplate | hook added            |
// | 09 | yes           | no         | no          | user    | N/A      | no     | none        | none                 |
// | 11 | yes           | no         | yes         | user    | N/A      | yes    | boilerplate | none                 |
// | 14 | yes           | no         | no          | project | N/A      | N/A    | boilerplate | none                 |
// | 17 | yes           | no         | yes         | project | N/A      | N/A    | boilerplate | none                 |
// | 20 | yes           | yes        | no          | user    | yes      | yes    | with rules  | perms removed + hook |
// | 22 | yes           | yes        | no          | user    | yes      | no     | none        | none                 |
// | 24 | yes           | yes        | no          | user    | no       | yes    | boilerplate | hook added           |
// | 26 | yes           | yes        | no          | user    | no       | no     | none        | none                 |
// | 28 | yes           | yes        | yes         | user    | yes      | yes    | with rules  | perms removed        |
// | 30 | yes           | yes        | yes         | user    | yes      | no     | none        | none                 |
// | 32 | yes           | yes        | yes         | user    | no       | yes    | boilerplate | none                 |
// | 34 | yes           | yes        | yes         | user    | no       | no     | none        | none                 |
// | 36 | yes           | yes        | no          | project | yes      | yes    | with rules  | perms removed        |
// | 38 | yes           | yes        | no          | project | yes      | no     | none        | none                 |
// | 40 | yes           | yes        | no          | project | no       | yes    | boilerplate | none                 |
// | 42 | yes           | yes        | no          | project | no       | no     | none        | none                 |
// | 44 | yes           | yes        | yes         | project | yes      | yes    | with rules  | perms removed        |
// | 46 | yes           | yes        | yes         | project | yes      | no     | none        | none                 |
// | 48 | yes           | yes        | yes         | project | no       | yes    | boilerplate | none                 |
// | 50 | yes           | yes        | yes         | project | no       | no     | none        | none                 |

/// Expected runok.yml content after the wizard runs.
enum ExpectedConfig {
    /// runok.yml is created with the given content.
    Content(&'static str),
    /// runok.yml is created with a computed String.
    ContentOwned(String),
    /// runok.yml does not exist (was not created).
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

/// All parameters for a single Matrix A wizard test case.
struct Case {
    /// Content of settings.json before the wizard runs, or None to skip creating it.
    settings: Option<&'static str>,
    /// Scope to pass to the wizard.
    scope: InitScope,
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
// --- No settings.json ---
#[case::p01_no_settings_user(Case {
    settings: None, scope: InitScope::User,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: None,
    assert_no_settings_created: true,
})]
#[case::p04_no_settings_project(Case {
    settings: None, scope: InitScope::Project,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: None,
    assert_no_settings_created: true,
})]
// --- No Bash perms, no hook (user) ---
#[case::p07_no_bash_no_hook_user_apply_yes(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::User,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p09_no_bash_no_hook_user_apply_no(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::User,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(no_bash_perms()),
    assert_no_settings_created: false,
})]
// --- No Bash perms, hook exists (user) ---
#[case::p11_no_bash_hook_exists_user(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::User,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
// --- No Bash perms, no hook (project) ---
#[case::p14_no_bash_no_hook_project(Case {
    settings: Some(SETTINGS_NO_BASH_NO_HOOK), scope: InitScope::Project,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms()),
    assert_no_settings_created: false,
})]
// --- No Bash perms, hook exists (project) ---
#[case::p17_no_bash_hook_exists_project(Case {
    settings: Some(settings_no_bash_with_hook()), scope: InitScope::Project,
    responses: vec![],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(no_bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
// --- Bash perms, no hook (user) ---
#[case::p20_bash_no_hook_user_mig_yes_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User,
    responses: vec![yes(), no(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p22_bash_no_hook_user_mig_yes_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User,
    responses: vec![yes(), no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p24_bash_no_hook_user_mig_no_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User,
    responses: vec![no(), no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_perms_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p26_bash_no_hook_user_mig_no_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::User,
    responses: vec![no(), no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
// --- Bash perms, hook exists (user) ---
#[case::p28_bash_hook_user_mig_yes_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User,
    responses: vec![yes(), no(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p30_bash_hook_user_mig_yes_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User,
    responses: vec![yes(), no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p32_bash_hook_user_mig_no_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User,
    responses: vec![no(), no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p34_bash_hook_user_mig_no_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::User,
    responses: vec![no(), no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
// --- Bash perms, no hook (project) ---
#[case::p36_bash_no_hook_project_mig_yes_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_no_hook()),
    assert_no_settings_created: false,
})]
#[case::p38_bash_no_hook_project_mig_yes_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p40_bash_no_hook_project_mig_no_app_yes(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
#[case::p42_bash_no_hook_project_mig_no_app_no(Case {
    settings: Some(SETTINGS_BASH_ONLY), scope: InitScope::Project,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_perms_unchanged()),
    assert_no_settings_created: false,
})]
// --- Bash perms, hook exists (project) ---
#[case::p44_bash_hook_project_mig_yes_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project,
    responses: vec![yes(), yes()],
    expected_config: ExpectedConfig::ContentOwned(config_with_bash_rules()),
    expected_settings: Some(perms_removed_with_hook()),
    assert_no_settings_created: false,
})]
#[case::p46_bash_hook_project_mig_yes_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project,
    responses: vec![yes(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p48_bash_hook_project_mig_no_app_yes(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project,
    responses: vec![no(), yes()],
    expected_config: ExpectedConfig::Content(BOILERPLATE),
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
#[case::p50_bash_hook_project_mig_no_app_no(Case {
    settings: Some(settings_bash_only_with_hook()), scope: InitScope::Project,
    responses: vec![no(), no()],
    expected_config: ExpectedConfig::None,
    expected_settings: Some(bash_hook_original()),
    assert_no_settings_created: false,
})]
fn wizard_first_time_setup_result(#[case] case: Case) -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;

    if let Some(settings) = case.settings {
        env.setup_claude_settings(&case.scope, settings)?;
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

// ============================================================
// Matrix B: an existing runok.yml is never touched by init
// ============================================================
//
// `-y` (AutoYesPrompter, which answers every confirmation with "yes") is
// used deliberately here: it is the strongest form of this guarantee,
// since `-y` means "skip confirmations", not "permit destructive
// overwrites". Regardless of Claude Code settings.json state or scope,
// an existing runok.yml must survive `-y`.

#[rstest]
#[case::no_settings_user(None, InitScope::User)]
#[case::no_settings_project(None, InitScope::Project)]
#[case::no_bash_perms_user(Some(SETTINGS_NO_BASH_NO_HOOK), InitScope::User)]
#[case::no_bash_perms_project(Some(SETTINGS_NO_BASH_NO_HOOK), InitScope::Project)]
#[case::bash_perms_no_hook_user(Some(SETTINGS_BASH_ONLY), InitScope::User)]
#[case::bash_perms_no_hook_project(Some(SETTINGS_BASH_ONLY), InitScope::Project)]
#[case::bash_perms_hook_exists_user(Some(settings_bash_only_with_hook()), InitScope::User)]
#[case::bash_perms_hook_exists_project(Some(settings_bash_only_with_hook()), InitScope::Project)]
fn existing_config_survives_auto_yes(
    #[case] settings: Option<&str>,
    #[case] scope: InitScope,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    if let Some(settings) = settings {
        env.setup_claude_settings(&scope, settings)?;
    }
    env.setup_existing_config(&scope)?;

    env.run(Some(&scope), &AutoYesPrompter)?;

    let config = std::fs::read_to_string(env.config_path_for_scope(&scope))?;
    assert_eq!(
        config, EXISTING_CONFIG,
        "runok.yml should be preserved but was modified"
    );

    Ok(())
}

/// When Bash permissions exist but runok.yml already exists, migration must
/// not run at all: permissions stay in settings.json (nothing to migrate
/// them into) rather than being silently dropped, while hook registration
/// -- an independent, non-destructive change to settings.json -- still
/// happens.
#[rstest]
fn existing_config_blocks_migration_but_not_hook_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let env = InitTestEnv::new()?;
    env.setup_claude_settings(&InitScope::User, SETTINGS_BASH_ONLY)?;
    env.setup_existing_config(&InitScope::User)?;

    env.run(Some(&InitScope::User), &AutoYesPrompter)?;

    assert_wizard_result(
        &env,
        &InitScope::User,
        &ExpectedConfig::Preserved,
        Some(serde_json::json!({
            "permissions": { "allow": ["Bash(cargo test)", "Bash(cargo build)"], "deny": ["Bash(rm -rf /)"] },
            "hooks": {
                "PreToolUse": hook_json()["PreToolUse"].clone(),
                "PostToolUse": hook_json()["PreToolUse"].clone(),
            }
        })),
    )?;

    Ok(())
}

// --- scope selection (separate from Matrix A) ---

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
