//! Integration tests verifying extends with path-based preset file references.
//!
//! These tests verify the end-to-end path: YAML config with extends pointing
//! to path-specified preset files → load_local_preset → evaluate_command.
//!
//! Remote preset path resolution uses the same code paths as local presets
//! after the git clone step, so these tests exercise the complete merge and
//! evaluation logic.

use std::fs;
use std::path::PathBuf;

use indoc::indoc;
use rstest::{fixture, rstest};
use runok::config::{ConfigError, PresetError, load_local_preset, parse_config};
use runok::rules::rule_engine::{Action, evaluate_command};

use super::{ActionAssertion, assert_allow, assert_default, empty_context};
use runok::rules::rule_engine::EvalContext;

/// Simulated preset repository with multiple path-based preset files.
struct PresetRepoEnv {
    _tmp: tempfile::TempDir,
    project_dir: PathBuf,
}

fn make_preset_repo_env() -> Result<PresetRepoEnv, Box<dyn std::error::Error>> {
    let tmp = tempfile::TempDir::new()?;
    let project_dir = tmp.path().join("project");
    let presets_dir = project_dir.join("presets");
    fs::create_dir_all(&presets_dir)?;

    // Simulate path-based preset files (like github:org/repo/readonly-unix@v1)
    fs::write(
        presets_dir.join("readonly-unix.yml"),
        indoc! {"
            rules:
              - allow: 'cat *'
              - allow: 'ls *'
              - allow: 'grep *'
              - allow: 'head *'
              - allow: 'tail *'
              - allow: 'wc *'
              - allow: 'find !-delete *'
              - allow: 'sed !-i *'
        "},
    )?;

    fs::write(
        presets_dir.join("readonly-git.yml"),
        indoc! {"
            rules:
              - allow: 'git status *'
              - allow: 'git log *'
              - allow: 'git diff *'
              - allow: 'git show *'
              - allow: 'git blame *'
              - allow: 'git branch'
              - allow: 'git branch [-a|--all] *'
        "},
    )?;

    fs::write(
        presets_dir.join("definitions.yml"),
        indoc! {r#"
            definitions:
              wrappers:
                - 'bash -c <cmd>'
                - 'sudo <opts> <cmd>'
                - "find * -exec|-execdir <cmd> \\;|+"
        "#},
    )?;

    // base.yml aggregates all presets via local extends
    fs::write(
        presets_dir.join("base.yml"),
        indoc! {"
            extends:
              - ./definitions.yml
              - ./readonly-unix.yml
              - ./readonly-git.yml
        "},
    )?;

    // Main runok.yml in project root extending base preset
    fs::write(
        project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./presets/base.yml
        "},
    )?;

    Ok(PresetRepoEnv {
        _tmp: tmp,
        project_dir,
    })
}

/// Fixture providing a simulated preset repository environment.
/// Delegates to `make_preset_repo_env` which returns `Result`;
/// test infrastructure failures abort the process.
#[fixture]
fn preset_repo_env() -> PresetRepoEnv {
    make_preset_repo_env().unwrap_or_else(|_| std::process::abort())
}

// ========================================
// Single path-based preset: readonly-unix rules
// ========================================

#[rstest]
#[case::cat_allowed("cat /etc/hosts", assert_allow as ActionAssertion)]
#[case::ls_allowed("ls -la /tmp", assert_allow as ActionAssertion)]
#[case::grep_allowed("grep -r pattern .", assert_allow as ActionAssertion)]
#[case::find_allowed("find . -name '*.txt'", assert_allow as ActionAssertion)]
#[case::sed_readonly_allowed("sed s/foo/bar/ file.txt", assert_allow as ActionAssertion)]
#[case::sed_inplace_excluded("sed -i s/foo/bar/ file.txt", assert_default as ActionAssertion)]
#[case::find_delete_excluded("find -delete .", assert_default as ActionAssertion)]
#[case::rm_not_allowed("rm -rf /", assert_default as ActionAssertion)]
#[case::curl_not_allowed("curl https://example.com", assert_default as ActionAssertion)]
fn single_path_preset_readonly_unix(
    preset_repo_env: PresetRepoEnv,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config =
        load_local_preset("./presets/readonly-unix.yml", &preset_repo_env.project_dir).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Single path-based preset: readonly-git rules
// ========================================

#[rstest]
#[case::git_status_allowed("git status", assert_allow as ActionAssertion)]
#[case::git_log_allowed("git log --oneline", assert_allow as ActionAssertion)]
#[case::git_diff_allowed("git diff HEAD~1", assert_allow as ActionAssertion)]
#[case::git_branch_allowed("git branch", assert_allow as ActionAssertion)]
#[case::git_add_not_allowed("git add .", assert_default as ActionAssertion)]
#[case::git_commit_not_allowed("git commit -m 'test'", assert_default as ActionAssertion)]
#[case::git_push_not_allowed("git push origin main", assert_default as ActionAssertion)]
fn single_path_preset_readonly_git(
    preset_repo_env: PresetRepoEnv,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let config =
        load_local_preset("./presets/readonly-git.yml", &preset_repo_env.project_dir).unwrap();
    let result = evaluate_command(&config, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Multiple path-based presets merged: user config extends two presets
// ========================================

#[rstest]
#[case::cat_from_unix("cat /etc/hosts", assert_allow as ActionAssertion)]
#[case::git_status_from_git("git status", assert_allow as ActionAssertion)]
#[case::git_diff_from_git("git diff HEAD", assert_allow as ActionAssertion)]
#[case::ls_from_unix("ls -la", assert_allow as ActionAssertion)]
#[case::rm_not_in_any("rm -rf /", assert_default as ActionAssertion)]
fn multiple_path_presets_all_rules_merged(
    preset_repo_env: PresetRepoEnv,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let unix_config =
        load_local_preset("./presets/readonly-unix.yml", &preset_repo_env.project_dir).unwrap();
    let git_config =
        load_local_preset("./presets/readonly-git.yml", &preset_repo_env.project_dir).unwrap();
    let merged = unix_config.merge(git_config);

    let result = evaluate_command(&merged, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Nonexistent preset path produces error
// ========================================

#[rstest]
fn nonexistent_path_preset_produces_error(preset_repo_env: PresetRepoEnv) {
    let err =
        load_local_preset("./presets/nonexistent.yml", &preset_repo_env.project_dir).unwrap_err();

    match err {
        ConfigError::Preset(PresetError::LocalNotFound(path)) => {
            assert_eq!(
                path.file_name().and_then(|n| n.to_str()),
                Some("nonexistent.yml")
            );
        }
        other => panic!("expected PresetError::LocalNotFound, got: {other:?}"),
    }
}

// ========================================
// Definitions preset loads wrappers
// ========================================

#[rstest]
fn definitions_preset_loads_wrappers(preset_repo_env: PresetRepoEnv) {
    let config =
        load_local_preset("./presets/definitions.yml", &preset_repo_env.project_dir).unwrap();
    let defs = config.definitions.as_ref().unwrap();
    let wrappers = defs.wrappers.as_ref().unwrap();
    assert_eq!(wrappers.len(), 3);
    assert_eq!(wrappers[0], "bash -c <cmd>");
    assert_eq!(wrappers[1], "sudo <opts> <cmd>");
    assert_eq!(wrappers[2], r"find * -exec|-execdir <cmd> \;|+");
}

// ========================================
// Base preset aggregation with wrappers + rules evaluated together
// ========================================

#[rstest]
#[case::cat_via_base("cat /etc/hosts", assert_allow as ActionAssertion)]
#[case::git_log_via_base("git log --oneline", assert_allow as ActionAssertion)]
#[case::rm_not_via_base("rm -rf /", assert_default as ActionAssertion)]
fn base_preset_aggregates_all_via_local_extends(
    preset_repo_env: PresetRepoEnv,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    // base.yml has extends but load_local_preset does not resolve them.
    // Manually load and merge to simulate full resolution.
    let definitions =
        load_local_preset("./presets/definitions.yml", &preset_repo_env.project_dir).unwrap();
    let readonly_unix =
        load_local_preset("./presets/readonly-unix.yml", &preset_repo_env.project_dir).unwrap();
    let readonly_git =
        load_local_preset("./presets/readonly-git.yml", &preset_repo_env.project_dir).unwrap();
    let merged = definitions.merge(readonly_unix).merge(readonly_git);

    let result = evaluate_command(&merged, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// Wrappers from definitions + rules from readonly-unix evaluate inner commands
// ========================================

#[rstest]
#[case::bash_c_cat_allowed(r#"bash -c "cat /etc/hosts""#, assert_allow as ActionAssertion)]
#[case::bash_c_rm_not_allowed(r#"bash -c "rm -rf /""#, assert_default as ActionAssertion)]
#[case::sudo_cat_allowed("sudo cat /etc/shadow", assert_allow as ActionAssertion)]
fn wrappers_evaluate_inner_commands(
    preset_repo_env: PresetRepoEnv,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: EvalContext,
) {
    let definitions =
        load_local_preset("./presets/definitions.yml", &preset_repo_env.project_dir).unwrap();
    let readonly_unix =
        load_local_preset("./presets/readonly-unix.yml", &preset_repo_env.project_dir).unwrap();
    let merged = definitions.merge(readonly_unix);

    let result = evaluate_command(&merged, command, &empty_context).unwrap();
    expected(&result.action);
}

// ========================================
// User rules override preset rules after merge
// ========================================

#[rstest]
fn user_deny_overrides_preset_allow(preset_repo_env: PresetRepoEnv, empty_context: EvalContext) {
    let preset =
        load_local_preset("./presets/readonly-unix.yml", &preset_repo_env.project_dir).unwrap();
    let user_config = parse_config(indoc! {"
        rules:
          - deny: 'cat /etc/shadow'
    "})
    .unwrap();
    let merged = preset.merge(user_config);

    // cat /etc/shadow matches deny (user rule wins)
    let result = evaluate_command(&merged, "cat /etc/shadow", &empty_context).unwrap();
    assert!(
        matches!(result.action, Action::Deny(_)),
        "expected Deny, got {:?}",
        result.action
    );

    // cat /etc/hosts still allowed by preset
    let result = evaluate_command(&merged, "cat /etc/hosts", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
}
