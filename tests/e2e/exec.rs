use indoc::indoc;
use rstest::{fixture, rstest};

use super::helpers::TestEnv;

#[fixture]
fn exec_env() -> TestEnv {
    TestEnv::new(indoc! {"
        rules:
          - deny: 'curl -X|--request POST *'
            message: 'POST requests are not allowed'
          - allow: 'git status'
          - allow: 'curl [-X|--request GET] *'
          - allow: 'echo *'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [/tmp]
              network:
                allow: false
    "})
}

// Denied commands are never executed, so no --dry-run needed for deny cases.
// Allow cases use --dry-run to avoid actual command execution and side effects.

#[rstest]
#[case::deny_post(
    &["exec", "--", "curl", "-X", "POST", "https://example.com"],
    3,
)]
#[case::allow_git_status_dry_run(
    &["exec", "--dry-run", "--", "git", "status"],
    0,
)]
#[case::allow_curl_without_method_dry_run(
    &["exec", "--dry-run", "--", "curl", "https://example.com"],
    0,
)]
#[case::allow_curl_get_dry_run(
    &["exec", "--dry-run", "--", "curl", "-X", "GET", "https://example.com"],
    0,
)]
fn exec_exit_code(exec_env: TestEnv, #[case] args: &[&str], #[case] expected_exit: i32) {
    let assert = exec_env.command().args(args).assert();
    assert.code(expected_exit);
}

#[rstest]
fn exec_deny_prints_reason(exec_env: TestEnv) {
    let assert = exec_env
        .command()
        .args(["exec", "--", "curl", "-X", "POST", "https://example.com"])
        .assert();
    assert.code(3).stderr(predicates::str::contains("denied"));
}

#[rstest]
fn exec_ask_treated_as_deny() {
    let env = TestEnv::new(indoc! {"
        rules:
          - ask: 'git push *'
    "});
    let assert = env
        .command()
        .args(["exec", "--", "git", "push", "origin", "main"])
        .assert();
    assert.code(3);
}

#[rstest]
fn exec_sandbox_allow_with_dry_run(exec_env: TestEnv) {
    let assert = exec_env
        .command()
        .args([
            "exec",
            "--dry-run",
            "--sandbox",
            "restricted",
            "--",
            "echo",
            "hello",
        ])
        .assert();
    assert.code(0).stderr(predicates::str::contains("allowed"));
}

#[rstest]
fn exec_no_match_uses_default_deny() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'git status'
        defaults:
          action: deny
    "});
    let assert = env.command().args(["exec", "--", "ls", "-la"]).assert();
    assert.code(3);
}

#[rstest]
fn exec_allow_runs_command() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
    "});
    let assert = env
        .command()
        .args(["exec", "--", "echo", "hello world"])
        .assert();
    assert
        .code(0)
        .stdout(predicates::str::contains("hello world"));
}
