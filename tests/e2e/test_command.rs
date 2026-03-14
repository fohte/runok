use indoc::indoc;
use predicates::prelude::*;
use rstest::rstest;
use std::fs;

use crate::helpers::TestEnv;

// ---------------------------------------------------------------------------
// Basic test execution
// ---------------------------------------------------------------------------

#[rstest]
#[case::all_pass(
    indoc! {"
        rules:
          - allow: 'git status'
            tests:
              - allow: 'git status'
          - deny: 'rm -rf /'
            tests:
              - deny: 'rm -rf /'
    "},
    0,
    "PASS",
    "2 passed, 0 failed, 2 total",
)]
#[case::some_fail(
    indoc! {"
        rules:
          - allow: 'git status'
            tests:
              - allow: 'git status'
              - deny: 'git status'
    "},
    1,
    "FAIL",
    "1 passed, 1 failed, 2 total",
)]
#[case::all_fail(
    indoc! {"
        rules:
          - allow: 'git status'
            tests:
              - deny: 'git status'
    "},
    1,
    "FAIL",
    "0 passed, 1 failed, 1 total",
)]
fn inline_tests(
    #[case] config: &str,
    #[case] exit_code: i32,
    #[case] expected_label: &str,
    #[case] expected_summary: &str,
) {
    let env = TestEnv::new(config);
    env.command()
        .args(["test"])
        .assert()
        .code(exit_code)
        .stdout(predicate::str::contains(expected_label))
        .stdout(predicate::str::contains(expected_summary));
}

#[rstest]
fn top_level_tests() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'git *'
          - deny: 'git push -f|--force *'
        tests:
          cases:
            - allow: 'git push origin main'
            - deny: 'git push --force origin main'
    "});
    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("2 passed, 0 failed, 2 total"));
}

#[rstest]
fn mixed_inline_and_top_level() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'git status'
            tests:
              - allow: 'git status'
          - allow: 'echo *'
        tests:
          cases:
            - allow: 'echo hello'
    "});
    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("2 passed, 0 failed, 2 total"));
}

// ---------------------------------------------------------------------------
// Config file option
// ---------------------------------------------------------------------------

#[rstest]
#[case::short_flag("-c")]
#[case::long_flag("--config")]
fn config_option(#[case] flag: &str) {
    let env = TestEnv::new("");
    let config_path = env.cwd.join("custom.yml");
    fs::write(
        &config_path,
        indoc! {"
            rules:
              - allow: 'echo hello'
                tests:
                  - allow: 'echo hello'
        "},
    )
    .unwrap_or_else(|e| panic!("failed to write custom config: {e}"));

    env.command()
        .args(["test", flag, config_path.to_str().unwrap_or_default()])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 passed"));
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

#[rstest]
fn exit_code_2_on_no_test_cases() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'git status'
    "});
    env.command()
        .args(["test"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no test cases found"));
}

#[rstest]
fn exit_code_2_on_config_not_found() {
    let env = TestEnv::new("");
    env.command()
        .args(["test", "-c", "/nonexistent/runok.yml"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("config file not found"));
}

// ---------------------------------------------------------------------------
// Output format
// ---------------------------------------------------------------------------

#[rstest]
fn output_shows_pass_and_fail_details() {
    let env = TestEnv::new(indoc! {"
        defaults:
          action: allow
        rules:
          - deny: 'rm *'
            tests:
              - deny: 'rm -rf /'
              - allow: 'rm -rf /'
    "});
    let output = env.command().args(["test"]).assert().code(1);

    output
        .stdout(predicate::str::contains("PASS: rm -rf / => deny"))
        .stdout(predicate::str::contains(
            "FAIL: rm -rf / => expected allow, got deny",
        ));
}

// ---------------------------------------------------------------------------
// extends and test environment isolation
// ---------------------------------------------------------------------------

#[rstest]
fn extends_in_config() {
    let env = TestEnv::new(indoc! {"
        extends:
          - ./base.yml
        tests:
          cases:
            - allow: 'git status'
    "});
    fs::write(
        env.cwd.join("base.yml"),
        indoc! {"
            rules:
              - allow: 'git *'
        "},
    )
    .unwrap_or_else(|e| panic!("failed to write base config: {e}"));

    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 passed"));
}

#[rstest]
fn tests_extends_merges_additional_rules() {
    let env = TestEnv::new(indoc! {"
        tests:
          extends:
            - ./extra-rules.yml
          cases:
            - allow: 'echo hello'
    "});
    fs::write(
        env.cwd.join("extra-rules.yml"),
        indoc! {"
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap_or_else(|e| panic!("failed to write extra rules: {e}"));

    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 passed"));
}

#[rstest]
fn global_config_does_not_affect_test() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo hello'
            tests:
              - allow: 'echo hello'
    "});

    // Write a global config that would deny everything
    let global_dir = env.home.join(".config").join("runok");
    fs::create_dir_all(&global_dir).unwrap_or_else(|e| panic!("failed to create global dir: {e}"));
    fs::write(
        global_dir.join("runok.yml"),
        indoc! {"
            defaults:
              action: deny
            rules:
              - deny: 'echo *'
        "},
    )
    .unwrap_or_else(|e| panic!("failed to write global config: {e}"));

    // Test should pass because global config is excluded
    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("1 passed, 0 failed"));
}

#[rstest]
fn extends_resolution_error_shows_path() {
    let env = TestEnv::new(indoc! {"
        extends:
          - ./nonexistent.yml
        tests:
          cases:
            - allow: 'echo hello'
    "});
    env.command()
        .args(["test"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("nonexistent.yml"));
}

// ---------------------------------------------------------------------------
// ask decision
// ---------------------------------------------------------------------------

#[rstest]
fn ask_decision_test() {
    let env = TestEnv::new(indoc! {"
        rules:
          - ask: 'terraform apply'
            tests:
              - ask: 'terraform apply'
    "});
    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("PASS: terraform apply => ask"));
}
