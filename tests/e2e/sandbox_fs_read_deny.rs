use indoc::indoc;
use rstest::rstest;
use serde_json::Value;

use super::helpers::TestEnv;

// === New fs format: read/write with allow/deny ===

#[rstest]
fn check_new_fs_format_parses_correctly() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'cat *'
            sandbox: restricted
        definitions:
          sandbox:
            restricted:
              fs:
                read:
                  deny: [~/.ssh, ~/.gnupg]
                write:
                  allow: [., /tmp]
                  deny: [.env, .envrc]
              network:
                allow: true
    "});
    let assert = env
        .command()
        .args([
            "check",
            "--output-format",
            "json",
            "--",
            "cat",
            "/etc/passwd",
        ])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert!(
        json["sandbox"].is_object(),
        "sandbox info should be present"
    );
    assert_eq!(json["sandbox"]["preset"], "restricted");
}

#[rstest]
fn check_new_fs_format_write_only() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
            sandbox: write_only
        definitions:
          sandbox:
            write_only:
              fs:
                write:
                  allow: [.]
                  deny: [.git]
    "});
    let assert = env
        .command()
        .args(["check", "--output-format", "json", "--", "echo", "hello"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["sandbox"]["preset"], "write_only");
}

#[rstest]
fn check_new_fs_format_read_deny_only() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'cat *'
            sandbox: read_deny
        definitions:
          sandbox:
            read_deny:
              fs:
                read:
                  deny: [~/.ssh]
    "});
    let assert = env
        .command()
        .args(["check", "--output-format", "json", "--", "cat", "file.txt"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["sandbox"]["preset"], "read_deny");
}

// === Backward compatibility: legacy fs format ===

#[rstest]
fn check_legacy_fs_format_still_works() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
            sandbox: legacy
        definitions:
          sandbox:
            legacy:
              fs:
                writable: [.]
                deny: [.git]
              network:
                allow: false
    "});
    let assert = env
        .command()
        .args(["check", "--output-format", "json", "--", "echo", "hello"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["sandbox"]["preset"], "legacy");
}

// === Validation: new format passes runok test ===

#[rstest]
fn test_command_with_new_fs_format() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'cat *'
            sandbox: restricted
            tests:
              - allow: 'cat /etc/passwd'
        definitions:
          sandbox:
            restricted:
              fs:
                read:
                  deny: [~/.ssh]
                write:
                  allow: [., /tmp]
    "});
    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("1 passed"));
}

#[rstest]
fn test_command_with_legacy_fs_format() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
            sandbox: legacy
            tests:
              - allow: 'echo hello'
        definitions:
          sandbox:
            legacy:
              fs:
                writable: [.]
                deny: [.git]
    "});
    env.command()
        .args(["test"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("1 passed"));
}

// === Path reference expansion in new format ===

#[rstest]
fn check_path_ref_in_new_format_write_deny() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
            sandbox: with_refs
        definitions:
          paths:
            sensitive:
              - .env
              - .envrc
          sandbox:
            with_refs:
              fs:
                write:
                  allow: [.]
                  deny: ['<path:sensitive>']
    "});
    let assert = env
        .command()
        .args(["check", "--output-format", "json", "--", "echo", "hello"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["sandbox"]["preset"], "with_refs");
}

#[rstest]
fn check_path_ref_in_new_format_read_deny() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'cat *'
            sandbox: with_refs
        definitions:
          paths:
            secrets:
              - ~/.ssh
              - ~/.gnupg
          sandbox:
            with_refs:
              fs:
                read:
                  deny: ['<path:secrets>']
    "});
    let assert = env
        .command()
        .args(["check", "--output-format", "json", "--", "cat", "file.txt"])
        .assert();
    let output = assert.code(0).get_output().stdout.clone();
    let json: Value =
        serde_json::from_slice(&output).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["sandbox"]["preset"], "with_refs");
}

// === Validation error: undefined path ref in new format ===

#[rstest]
fn config_error_on_undefined_path_ref_in_read_deny() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'cat *'
            sandbox: bad_ref
        definitions:
          sandbox:
            bad_ref:
              fs:
                read:
                  deny: ['<path:nonexistent>']
    "});
    // check with an invalid config should fail with config error (exit 2)
    let assert = env
        .command()
        .args(["check", "--", "cat", "file.txt"])
        .assert();
    assert.code(2);
}

// === macOS sandbox: read deny enforcement ===

#[cfg(target_os = "macos")]
mod macos_sandbox_read_deny {
    use super::*;

    fn skip_if_nested_sandbox() -> bool {
        std::env::var("SANDBOX_RUNTIME").is_ok()
    }

    #[rstest]
    fn exec_sandbox_denies_read_of_denied_path() {
        if skip_if_nested_sandbox() {
            return;
        }

        let tmpdir = tempfile::tempdir().unwrap();
        let canonical_dir = tmpdir.path().canonicalize().unwrap();

        // Create a secret file that should be unreadable
        let secret_dir = canonical_dir.join("secrets");
        std::fs::create_dir(&secret_dir).unwrap();
        let secret_file = secret_dir.join("key.pem");
        std::fs::write(&secret_file, "secret-content").unwrap();

        // Create a normal file that should be readable
        let normal_file = canonical_dir.join("normal.txt");
        std::fs::write(&normal_file, "normal-content").unwrap();

        let env = TestEnv::new(&format!(
            indoc! {"
                rules:
                  - allow: 'cat *'
                    sandbox: read_restricted
                  - allow: 'sh *'
                    sandbox: read_restricted
                definitions:
                  sandbox:
                    read_restricted:
                      fs:
                        read:
                          deny:
                            - {}
                        write:
                          allow:
                            - {}
            "},
            secret_dir.display(),
            canonical_dir.display(),
        ));

        // Reading the normal file should succeed
        let assert = env
            .command()
            .args(["exec", "--", "cat", normal_file.to_str().unwrap()])
            .assert();
        assert
            .code(0)
            .stdout(predicates::str::contains("normal-content"));

        // Reading the secret file should fail
        let assert = env
            .command()
            .args(["exec", "--", "cat", secret_file.to_str().unwrap()])
            .assert();
        assert.code(predicates::ord::ne(0));
    }

    #[rstest]
    fn exec_sandbox_read_deny_blocks_directory_listing() {
        if skip_if_nested_sandbox() {
            return;
        }

        let tmpdir = tempfile::tempdir().unwrap();
        let canonical_dir = tmpdir.path().canonicalize().unwrap();

        let protected_dir = canonical_dir.join(".ssh");
        std::fs::create_dir(&protected_dir).unwrap();
        std::fs::write(protected_dir.join("id_rsa"), "private-key").unwrap();

        let env = TestEnv::new(&format!(
            indoc! {"
                rules:
                  - allow: 'ls *'
                    sandbox: deny_ssh_read
                  - allow: 'sh *'
                    sandbox: deny_ssh_read
                definitions:
                  sandbox:
                    deny_ssh_read:
                      fs:
                        read:
                          deny:
                            - {}
            "},
            protected_dir.display(),
        ));

        // Listing the protected directory should fail
        let assert = env
            .command()
            .args(["exec", "--", "ls", protected_dir.to_str().unwrap()])
            .assert();
        assert.code(predicates::ord::ne(0));
    }
}
