//! Integration tests verifying that inline tests from presets are evaluated
//! against the preset's rules only, not the full merged config.
//!
//! This prevents downstream overrides from breaking upstream preset tests.

use std::fs;
use std::path::PathBuf;

use indoc::indoc;
use rstest::{fixture, rstest};
use tempfile::TempDir;

use runok::test::{load_test_config, parse_test_cases_scoped, run_tests};

struct TestEnv {
    _tmp: TempDir,
    dir: PathBuf,
}

fn make_env() -> Result<TestEnv, Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().to_path_buf();
    Ok(TestEnv { _tmp: tmp, dir })
}

impl TestEnv {
    fn write_file(&self, name: &str, content: &str) {
        let path = self.dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|_| std::process::abort());
        }
        fs::write(&path, content).unwrap_or_else(|_| std::process::abort());
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("runok.yml")
    }
}

#[fixture]
fn env() -> TestEnv {
    make_env().unwrap_or_else(|_| std::process::abort())
}

#[rstest]
fn preset_inline_test_not_affected_by_local_override(env: TestEnv) {
    // Preset defines an ask rule with an inline test
    env.write_file(
        "preset.yml",
        indoc! {"
            rules:
              - ask: 'gh api * --paginate *'
                tests:
                  - ask: 'gh api --paginate /repos/cli/cli/issues'
        "},
    );

    // Local config extends the preset and overrides with a deny rule
    env.write_file(
        "runok.yml",
        indoc! {"
            extends:
              - ./preset.yml
            rules:
              - deny: 'gh api * --paginate *'
        "},
    );

    let loaded = load_test_config(&env.config_path()).unwrap_or_else(|e| panic!("{e}"));
    let test_cases = parse_test_cases_scoped(
        &loaded.config,
        &loaded.path,
        loaded.preset_config.as_ref(),
        loaded.preset_rule_count,
    );

    assert_eq!(test_cases.len(), 1, "should have 1 inline test from preset");

    let results = run_tests(&loaded.config, &test_cases);
    assert!(
        results.is_success(),
        "preset inline test should pass: evaluated against preset config only, \
         not affected by local deny override"
    );
}

#[rstest]
fn local_inline_test_uses_full_merged_config(env: TestEnv) {
    // Preset defines an ask rule
    env.write_file(
        "preset.yml",
        indoc! {"
            rules:
              - ask: 'gh api *'
        "},
    );

    // Local config extends the preset and adds its own rule with inline test
    env.write_file(
        "runok.yml",
        indoc! {"
            extends:
              - ./preset.yml
            rules:
              - deny: 'gh api * --paginate *'
                tests:
                  - deny: 'gh api --paginate /repos/cli/cli/issues'
        "},
    );

    let loaded = load_test_config(&env.config_path()).unwrap_or_else(|e| panic!("{e}"));
    let test_cases = parse_test_cases_scoped(
        &loaded.config,
        &loaded.path,
        loaded.preset_config.as_ref(),
        loaded.preset_rule_count,
    );

    assert_eq!(test_cases.len(), 1, "should have 1 inline test from local");

    let results = run_tests(&loaded.config, &test_cases);
    assert!(
        results.is_success(),
        "local inline test should pass: evaluated against full merged config"
    );
}

#[rstest]
fn preset_and_local_inline_tests_both_pass(env: TestEnv) {
    // Preset defines ask rule for 'gh api *' with inline test
    env.write_file(
        "preset.yml",
        indoc! {"
            rules:
              - ask: 'gh api * --paginate *'
                tests:
                  - ask: 'gh api --paginate /repos/cli/cli/issues'
        "},
    );

    // Local overrides with deny and has its own inline test
    env.write_file(
        "runok.yml",
        indoc! {"
            extends:
              - ./preset.yml
            rules:
              - deny: 'gh api * --paginate *'
                tests:
                  - deny: 'gh api --paginate /repos/cli/cli/issues'
        "},
    );

    let loaded = load_test_config(&env.config_path()).unwrap_or_else(|e| panic!("{e}"));
    let test_cases = parse_test_cases_scoped(
        &loaded.config,
        &loaded.path,
        loaded.preset_config.as_ref(),
        loaded.preset_rule_count,
    );

    assert_eq!(
        test_cases.len(),
        2,
        "should have 2 inline tests: 1 preset + 1 local"
    );

    let results = run_tests(&loaded.config, &test_cases);
    assert!(
        results.is_success(),
        "both preset and local inline tests should pass independently"
    );
    assert_eq!(results.passed_count(), 2);
}

#[rstest]
fn no_extends_works_as_before(env: TestEnv) {
    // Config without extends should work exactly as before
    env.write_file(
        "runok.yml",
        indoc! {"
            rules:
              - allow: 'git status'
                tests:
                  - allow: 'git status'
              - deny: 'rm *'
                tests:
                  - deny: 'rm foo'
        "},
    );

    let loaded = load_test_config(&env.config_path()).unwrap_or_else(|e| panic!("{e}"));
    let test_cases = parse_test_cases_scoped(
        &loaded.config,
        &loaded.path,
        loaded.preset_config.as_ref(),
        loaded.preset_rule_count,
    );

    assert_eq!(test_cases.len(), 2);
    assert!(
        loaded.preset_config.is_none(),
        "no preset_config without extends"
    );

    let results = run_tests(&loaded.config, &test_cases);
    assert!(results.is_success());
}
