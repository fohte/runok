use indoc::indoc;
use predicates::prelude::PredicateBooleanExt;
use rstest::rstest;

use super::helpers::TestEnv;

// === Legacy format emits deprecation warning ===

#[rstest]
fn legacy_format_emits_deprecation_warning() {
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
    // Use check to avoid sandbox execution (bwrap not available on all CI)
    env.command()
        .args(["check", "--", "echo", "hello"])
        .assert()
        .code(0)
        .stderr(
            predicates::str::contains("runok warning:")
                .and(predicates::str::contains("deprecated"))
                .and(predicates::str::contains("runok.yml")),
        );
}

#[rstest]
fn new_format_does_not_emit_deprecation_warning() {
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
    env.command()
        .args(["check", "--", "echo", "hello"])
        .assert()
        .code(0)
        .stderr(predicates::str::is_empty());
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
