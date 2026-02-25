use indoc::indoc;
use rstest::rstest;

use super::helpers::TestEnv;

// --- Invalid config: syntax error ---

#[rstest]
#[case::check(&["check", "--", "git", "status"], 2)]
#[case::exec(&["exec", "--dry-run", "--", "echo", "hello"], 1)]
fn invalid_config_exits_with_error(#[case] args: &[&str], #[case] expected_exit: i32) {
    let env = TestEnv::new("rules: [invalid yaml\n  broken:");
    let assert = env.command().args(args).assert();
    assert
        .code(expected_exit)
        .stderr(predicates::str::contains("config error"));
}

// --- Invalid config: validation error (deny + sandbox) ---

#[rstest]
#[case::check(&["check", "--", "rm", "-rf", "/"], 2)]
#[case::exec(&["exec", "--dry-run", "--", "rm", "-rf", "/"], 1)]
fn validation_error_deny_with_sandbox(#[case] args: &[&str], #[case] expected_exit: i32) {
    let env = TestEnv::new(indoc! {"
        rules:
          - deny: 'rm -rf /'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
    "});
    let assert = env.command().args(args).assert();
    assert
        .code(expected_exit)
        .stderr(predicates::str::contains("config error"));
}

// --- Nonexistent command with exec ---

#[rstest]
fn exec_nonexistent_command() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'this-command-does-not-exist-xyz *'
    "});
    let assert = env
        .command()
        .args(["exec", "--", "this-command-does-not-exist-xyz", "arg1"])
        .assert();
    // The command should fail with a non-zero exit code
    assert.code(predicates::ord::ne(0));
}

// --- Exit codes ---

#[rstest]
#[case::exec_deny(
    &["exec", "--", "rm", "-rf", "/"],
    3,
    indoc! {"
        rules:
          - deny: 'rm -rf /'
    "},
)]
#[case::check_deny(
    &["check", "--", "rm", "-rf", "/"],
    0,
    indoc! {"
        rules:
          - deny: 'rm -rf /'
    "},
)]
fn exit_codes(#[case] args: &[&str], #[case] expected_exit: i32, #[case] config: &str) {
    let env = TestEnv::new(config);
    let assert = env.command().args(args).assert();
    assert.code(expected_exit);
}

// --- No config file: should still work (empty config) ---

#[rstest]
fn no_config_check_returns_default() {
    let env = TestEnv::new("{}");
    let assert = env
        .command()
        .args(["check", "--output-format", "json", "--", "git", "status"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    // No rules match → defaults to "ask" (default action)
    assert_eq!(json["decision"], "ask");
}

// --- Unknown format flag ---

#[rstest]
fn unknown_format_flag_exits_2() {
    let env = TestEnv::new("{}");
    let assert = env
        .command()
        .args(["check", "--input-format", "unknown-format"])
        .write_stdin(r#"{"command":"ls"}"#)
        .assert();
    assert.code(2);
}

// --- Check with --format but non-JSON stdin ---

#[rstest]
fn format_with_non_json_stdin_exits_2() {
    let env = TestEnv::new("{}");
    let assert = env
        .command()
        .args(["check", "--input-format", "claude-code-hook"])
        .write_stdin("not valid json")
        .assert();
    assert.code(2);
}
