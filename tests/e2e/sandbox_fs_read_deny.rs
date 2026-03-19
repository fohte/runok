use indoc::indoc;
use rstest::rstest;

use super::helpers::TestEnv;

// === Legacy format emits deprecation warning ===

#[rstest]
fn exec_legacy_format_emits_deprecation_warning() {
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
    "});
    let assert = env.command().args(["exec", "--", "echo", "hello"]).assert();
    assert
        .code(0)
        .stderr(predicates::str::contains("deprecated"))
        .stdout(predicates::str::contains("hello"));
}

#[rstest]
fn exec_new_format_does_not_emit_deprecation_warning() {
    let env = TestEnv::new(indoc! {"
        rules:
          - allow: 'echo *'
            sandbox: new
        definitions:
          sandbox:
            new:
              fs:
                write:
                  allow: [.]
                  deny: [.git]
    "});
    let assert = env.command().args(["exec", "--", "echo", "hello"]).assert();
    assert
        .code(0)
        .stderr(predicates::str::is_empty())
        .stdout(predicates::str::contains("hello"));
}

// === Config validation: undefined path ref in read.deny ===

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
    env.command()
        .args(["check", "--", "cat", "file.txt"])
        .assert()
        .code(2);
}

// === macOS sandbox: actual enforcement via runok exec ===

#[cfg(target_os = "macos")]
mod macos_sandbox {
    use super::*;

    fn skip_if_nested_sandbox() -> bool {
        std::env::var("SANDBOX_RUNTIME").is_ok()
    }

    // --- write.allow / write.deny (new format) ---

    #[rstest]
    fn exec_new_format_allows_write_to_writable_root() {
        if skip_if_nested_sandbox() {
            return;
        }

        let tmpdir = tempfile::tempdir().unwrap();
        let canonical_dir = tmpdir.path().canonicalize().unwrap();
        let test_file = canonical_dir.join("allowed_write");

        let env = TestEnv::new(&format!(
            indoc! {"
                rules:
                  - allow: 'sh *'
                    sandbox: writable
                definitions:
                  sandbox:
                    writable:
                      fs:
                        write:
                          allow:
                            - {}
            "},
            canonical_dir.display(),
        ));

        env.command()
            .args([
                "exec",
                "--",
                "sh",
                "-c",
                &format!("touch {}", test_file.display()),
            ])
            .assert()
            .code(0);

        assert!(
            test_file.exists(),
            "file should be created in writable root"
        );
    }

    #[rstest]
    fn exec_new_format_denies_write_outside_writable_root() {
        if skip_if_nested_sandbox() {
            return;
        }

        let tmpdir = tempfile::tempdir().unwrap();
        let canonical_dir = tmpdir.path().canonicalize().unwrap();

        let allowed_dir = canonical_dir.join("allowed");
        std::fs::create_dir(&allowed_dir).unwrap();

        let forbidden_file = canonical_dir.join("forbidden_write");

        let env = TestEnv::new(&format!(
            indoc! {"
                rules:
                  - allow: 'sh *'
                    sandbox: restricted
                definitions:
                  sandbox:
                    restricted:
                      fs:
                        write:
                          allow:
                            - {}
            "},
            allowed_dir.display(),
        ));

        env.command()
            .args([
                "exec",
                "--",
                "sh",
                "-c",
                &format!("touch {}", forbidden_file.display()),
            ])
            .assert()
            .code(predicates::ord::ne(0));

        assert!(
            !forbidden_file.exists(),
            "file should not be created outside writable root"
        );
    }

    #[rstest]
    fn exec_new_format_denies_write_to_write_deny_path() {
        if skip_if_nested_sandbox() {
            return;
        }

        let tmpdir = tempfile::tempdir().unwrap();
        let canonical_dir = tmpdir.path().canonicalize().unwrap();

        let git_dir = canonical_dir.join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        let forbidden_file = git_dir.join("should_not_write");

        // Use absolute path for deny — config path resolver resolves relative
        // paths against the project cwd, not the writable root.
        let env = TestEnv::new(&format!(
            indoc! {"
                rules:
                  - allow: 'sh *'
                    sandbox: protected
                definitions:
                  sandbox:
                    protected:
                      fs:
                        write:
                          allow:
                            - {}
                          deny:
                            - {}
            "},
            canonical_dir.display(),
            git_dir.display(),
        ));

        env.command()
            .args([
                "exec",
                "--",
                "sh",
                "-c",
                &format!("touch {}", forbidden_file.display()),
            ])
            .assert()
            .code(predicates::ord::ne(0));

        assert!(
            !forbidden_file.exists(),
            "file should not be created in write.deny path"
        );
    }

    // --- read.deny ---

    #[rstest]
    fn exec_read_deny_blocks_file_read() {
        if skip_if_nested_sandbox() {
            return;
        }

        let tmpdir = tempfile::tempdir().unwrap();
        let canonical_dir = tmpdir.path().canonicalize().unwrap();

        let secret_dir = canonical_dir.join("secrets");
        std::fs::create_dir(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("key.pem"), "secret-content").unwrap();

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

        // Normal file is readable
        env.command()
            .args(["exec", "--", "cat", normal_file.to_str().unwrap()])
            .assert()
            .code(0)
            .stdout(predicates::str::contains("normal-content"));

        // Secret file is NOT readable
        env.command()
            .args([
                "exec",
                "--",
                "cat",
                secret_dir.join("key.pem").to_str().unwrap(),
            ])
            .assert()
            .code(predicates::ord::ne(0));
    }

    #[rstest]
    fn exec_read_deny_blocks_directory_listing() {
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
                    sandbox: deny_ssh
                  - allow: 'sh *'
                    sandbox: deny_ssh
                definitions:
                  sandbox:
                    deny_ssh:
                      fs:
                        read:
                          deny:
                            - {}
            "},
            protected_dir.display(),
        ));

        env.command()
            .args(["exec", "--", "ls", protected_dir.to_str().unwrap()])
            .assert()
            .code(predicates::ord::ne(0));
    }
}
