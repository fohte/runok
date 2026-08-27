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

#[rstest]
#[case::deny_post(
    &["exec", "--", "curl", "-X", "POST", "https://example.com"],
    3,
)]
#[case::no_match_denies_when_defaults_action_unset(&["exec", "--", "ls", "-la"], 3)]
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
fn exec_pass_with_sandbox_denies_when_typed_directly() {
    // `defaults.action: pass` + `defaults.sandbox` only takes effect for
    // wrappers the hook generated (marked via `RUNOK_HOOK_ORIGIN`). A user
    // typing `--sandbox` directly must still be denied.
    let env = TestEnv::new(indoc! {"
        defaults:
          action: pass
          sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "});
    let assert = env
        .command()
        .args(["exec", "--sandbox", "restricted", "--", "ls", "-la"])
        .assert();
    assert.code(3);
}

#[rstest]
fn exec_pass_with_sandbox_runs_when_marked_as_hook_origin() {
    // The counterpart to the test above: the hidden `RUNOK_HOOK_ORIGIN` env
    // var marks the wrapper as hook-generated, so `pass` defers to the
    // sandbox and the command actually executes.
    let env = TestEnv::new(indoc! {"
        defaults:
          action: pass
          sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "});
    std::fs::create_dir_all(env.cwd.join("tmp"))
        .unwrap_or_else(|e| panic!("failed to create tmp dir: {e}"));
    let assert = env
        .command()
        .env("RUNOK_HOOK_ORIGIN", "test-token")
        .args(["exec", "--sandbox", "restricted", "--", "ls", "-la"])
        .assert();
    assert.code(0);
}

// `RUNOK_HOOK_ORIGIN` only relaxes `Action::Pass`. A caller who forges the
// env var on a command that actually matches a deny/ask rule must still be
// rejected -- this is the guarantee that makes the env var's forgeability an
// accepted risk rather than a privilege escalation (see the doc comment on
// `ExecAdapter::hook_origin`).

#[rstest]
fn exec_deny_still_rejects_with_hook_origin() {
    let env = TestEnv::new(indoc! {"
        rules:
          - deny: 'rm -rf *'
        defaults:
          action: pass
          sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "});
    let assert = env
        .command()
        .env("RUNOK_HOOK_ORIGIN", "test-token")
        .args([
            "exec",
            "--sandbox",
            "restricted",
            "--",
            "rm",
            "-rf",
            "/tmp/x",
        ])
        .assert();
    assert.code(3);
}

#[rstest]
fn exec_ask_still_rejects_with_hook_origin() {
    let env = TestEnv::new(indoc! {"
        rules:
          - ask: 'git push *'
        defaults:
          action: pass
          sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "});
    let assert = env
        .command()
        .env("RUNOK_HOOK_ORIGIN", "test-token")
        .args([
            "exec",
            "--sandbox",
            "restricted",
            "--",
            "git",
            "push",
            "origin",
            "main",
        ])
        .assert();
    assert.code(3);
}

#[rstest]
fn exec_pass_with_sandbox_does_not_leak_hook_origin_to_child_env() {
    // `RUNOK_HOOK_ORIGIN` must not propagate into the spawned command's own
    // environment -- env vars are inherited by children, so a nested `runok
    // exec` that command runs would otherwise inherit hook-origin trust it
    // was never granted.
    let env = TestEnv::new(indoc! {"
        defaults:
          action: pass
          sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "});
    let output = env
        .command()
        .env("RUNOK_HOOK_ORIGIN", "test-token")
        .args([
            "exec",
            "--sandbox",
            "restricted",
            "--",
            "printenv",
            "RUNOK_HOOK_ORIGIN",
        ])
        .output()
        .unwrap_or_else(|e| panic!("failed to run command: {e}"));

    // `printenv NAME` prints nothing and exits 1 when `NAME` is unset.
    assert_eq!((output.status.code(), output.stdout), (Some(1), Vec::new()),);
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
