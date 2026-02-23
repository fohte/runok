use indoc::indoc;
use rstest::rstest;

use super::helpers::TestEnv;

fn check_env() -> TestEnv {
    TestEnv::new(indoc! {"
        rules:
          - deny: 'rm -rf /'
            message: 'Dangerous command'
          - allow: 'git status'
    "})
}

// --- CLI argument mode ---

#[rstest]
#[case::deny_rm("rm -rf /", 0, "deny")]
#[case::allow_git_status("git status", 0, "allow")]
fn check_command_arg(
    #[case] command: &str,
    #[case] expected_exit: i32,
    #[case] expected_decision: &str,
) {
    let env = check_env();
    let assert = env.command().args(["check", "--command", command]).assert();
    let output = assert.code(expected_exit).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], expected_decision);
}

// --- stdin JSON mode ---

#[rstest]
fn check_stdin_json_deny() {
    let env = check_env();
    let assert = env
        .command()
        .arg("check")
        .write_stdin(r#"{"command":"rm -rf /"}"#)
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "deny");
}

#[rstest]
fn check_stdin_json_allow() {
    let env = check_env();
    let assert = env
        .command()
        .arg("check")
        .write_stdin(r#"{"command":"git status"}"#)
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
}

// --- No input: exit 2 ---

#[rstest]
fn check_no_input_exits_2() {
    let env = check_env();
    let assert = env.command().arg("check").write_stdin("").assert();
    assert.code(2);
}

// --- Plaintext stdin ---

#[rstest]
fn check_plaintext_stdin_single_line() {
    let env = check_env();
    let assert = env
        .command()
        .arg("check")
        .write_stdin("git status\n")
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
}

// --- Check deny includes reason ---

#[rstest]
fn check_deny_includes_reason() {
    let env = check_env();
    let assert = env
        .command()
        .args(["check", "--command", "rm -rf /"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "deny");
    assert!(json["reason"].is_string());
}

// --- Check with sandbox info ---

#[rstest]
fn check_allow_with_sandbox_info() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'python3 *'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                writable: [./tmp]
              network:
                allow: true
    "});
    let assert = env
        .command()
        .args(["check", "--command", "python3 script.py"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert!(json["sandbox"].is_object());
    assert_eq!(json["sandbox"]["preset"], "restricted");
}
