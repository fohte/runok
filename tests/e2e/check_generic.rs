use indoc::indoc;
use rstest::{fixture, rstest};

use super::helpers::TestEnv;

#[fixture]
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
#[case::deny_rm(&["rm", "-rf", "/"], 0, "deny")]
#[case::allow_git_status(&["git", "status"], 0, "allow")]
fn check_command_arg(
    check_env: TestEnv,
    #[case] command: &[&str],
    #[case] expected_exit: i32,
    #[case] expected_decision: &str,
) {
    let assert = check_env
        .command()
        .arg("check")
        .arg("--")
        .args(command)
        .assert();
    let output = assert.code(expected_exit).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], expected_decision);
}

// --- Plaintext stdin with comments ---

#[rstest]
fn check_stdin_comment_before_command(check_env: TestEnv) {
    let assert = check_env
        .command()
        .arg("check")
        .write_stdin(indoc! {"
            # description
            git status
        "})
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let stdout = String::from_utf8(output).unwrap();
    let jsons: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(jsons.len(), 2);
    assert_eq!(jsons[0]["decision"], "ask");
    assert_eq!(jsons[1]["decision"], "allow");
}

#[rstest]
fn check_stdin_comment_only(check_env: TestEnv) {
    let assert = check_env
        .command()
        .arg("check")
        .write_stdin("# just a comment\n")
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "ask");
}

// --- stdin JSON mode ---

#[rstest]
fn check_stdin_json_deny(check_env: TestEnv) {
    let assert = check_env
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
fn check_stdin_json_allow(check_env: TestEnv) {
    let assert = check_env
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
fn check_no_input_exits_2(check_env: TestEnv) {
    let assert = check_env.command().arg("check").write_stdin("").assert();
    assert.code(2);
}

// --- Plaintext stdin ---

#[rstest]
fn check_plaintext_stdin_single_line(check_env: TestEnv) {
    let assert = check_env
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
fn check_deny_includes_reason(check_env: TestEnv) {
    let assert = check_env
        .command()
        .args(["check", "--", "rm", "-rf", "/"])
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
        .args(["check", "--", "python3", "script.py"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: serde_json::Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert!(json["sandbox"].is_object());
    assert_eq!(json["sandbox"]["preset"], "restricted");
}
