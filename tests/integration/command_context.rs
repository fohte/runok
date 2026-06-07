#![allow(clippy::unwrap_used, reason = "test setup helpers")]

//! Integration tests for the `command.*` CEL context (argv0, cwd,
//! real_path). Exercises identity-bound and location-bound `when`
//! clauses end-to-end: YAML config -> parse_config -> evaluate_command
//! / evaluate_compound.

use super::{ActionAssertion, assert_allow, assert_ask, assert_deny};

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use indoc::{formatdoc, indoc};
use rstest::rstest;
use runok::config::parse_config;
use runok::rules::rule_engine::{EvalContext, evaluate_command, evaluate_compound};

fn context_with_cwd(cwd: PathBuf) -> EvalContext {
    EvalContext {
        env: HashMap::new(),
        cwd,
    }
}

fn context_with_cwd_and_path(cwd: PathBuf, path_env: &str) -> EvalContext {
    EvalContext {
        env: HashMap::from([("PATH".to_string(), path_env.to_string())]),
        cwd,
    }
}

/// macOS resolves `/var` -> `/private/var`, so a raw `tempfile::tempdir()`
/// path differs from its canonical form. `build_expr_context` canonicalizes
/// the effective cwd, so tests that compare against `command.cwd` need the
/// canonical form for both the rule pattern and `EvalContext.cwd`.
fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap()
}

#[cfg(unix)]
fn make_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_: &Path) {}

// ========================================
// command.argv0
// ========================================

#[rstest]
#[case::matches_cargo("cargo test", "cargo", assert_allow as ActionAssertion)]
#[case::matches_cargo_build("cargo build --release", "cargo", assert_allow as ActionAssertion)]
#[case::no_match("git status", "cargo", assert_ask as ActionAssertion)]
fn argv0_matches_raw_command_token(
    #[case] command: &str,
    #[case] expected_argv0: &str,
    #[case] expected: ActionAssertion,
) {
    let config = parse_config(&formatdoc! {"
        rules:
          - allow: '* *'
            when: \"command.argv0 == '{expected_argv0}'\"
    "})
    .unwrap();

    let result = evaluate_command(&config, command, &context_with_cwd("/tmp".into())).unwrap();
    expected(&result.action);
}

// ========================================
// command.cwd — static `cd` chain accumulation
// ========================================

#[rstest]
fn cwd_reflects_session_cwd_when_no_cd() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let config = parse_config(&formatdoc! {"
        rules:
          - allow: 'ls *'
            when: \"command.cwd == '{}'\"
    ", cwd.display()})
    .unwrap();

    let result = evaluate_command(&config, "ls -la", &context_with_cwd(cwd)).unwrap();
    assert_allow(&result.action);
}

fn allow_cd_and_when(when_predicate: &str) -> String {
    formatdoc! {"
        rules:
          - allow: 'cd *'
          - allow: 'ls *'
            when: \"{when_predicate}\"
    "}
}

#[rstest]
fn cwd_reflects_static_absolute_cd_in_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let inner = cwd.join("subdir");
    std::fs::create_dir(&inner).unwrap();

    let config = parse_config(&allow_cd_and_when(&format!(
        "command.cwd == '{}'",
        inner.display()
    )))
    .unwrap();

    let command = format!("cd {} && ls -la", inner.display());
    let result = evaluate_compound(&config, &command, &context_with_cwd(cwd)).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn cwd_reflects_relative_cd_joined_with_session_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let inner = cwd.join("subdir");
    std::fs::create_dir(&inner).unwrap();

    let config = parse_config(&allow_cd_and_when(&format!(
        "command.cwd == '{}'",
        inner.display()
    )))
    .unwrap();

    let result = evaluate_compound(&config, "cd subdir && ls -la", &context_with_cwd(cwd)).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn cwd_accumulates_chained_relative_cd() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let ab = cwd.join("a").join("b");
    std::fs::create_dir_all(&ab).unwrap();

    let config = parse_config(&allow_cd_and_when(&format!(
        "command.cwd == '{}'",
        ab.display()
    )))
    .unwrap();

    let result =
        evaluate_compound(&config, "cd a && cd b && ls -la", &context_with_cwd(cwd)).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn cwd_falls_back_to_session_when_cd_target_is_dynamic() {
    // The `when` rule allows only when cwd matches the inner path.
    // A dynamic `cd $VAR` must NOT pretend the cwd advanced — otherwise
    // `cd $UNTRUSTED && rm -rf *` could be silently allowed. With
    // dynamic fallback, cwd stays at the session root, so the `when`
    // is false and the action falls through to the default (`Ask`).
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let inner = cwd.join("subdir");
    std::fs::create_dir(&inner).unwrap();

    let config = parse_config(&allow_cd_and_when(&format!(
        "command.cwd == '{}'",
        inner.display()
    )))
    .unwrap();

    let result =
        evaluate_compound(&config, "cd $TARGET && ls -la", &context_with_cwd(cwd)).unwrap();
    assert_ask(&result.action);
}

#[rstest]
fn cwd_falls_back_to_session_after_cd_dash() {
    // `cd -` resolves to OLDPWD at runtime; we treat it as dynamic.
    // The dynamic flag persists for the rest of the chain, so the
    // trailing `ls` runs at the (statically-unknown) cwd and falls
    // back to the session cwd, which does not match the inner path.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let inner = cwd.join("subdir");
    std::fs::create_dir(&inner).unwrap();

    let config = parse_config(&allow_cd_and_when(&format!(
        "command.cwd == '{}'",
        inner.display()
    )))
    .unwrap();

    let command = format!("cd {} && cd - && ls -la", inner.display());
    let result = evaluate_compound(&config, &command, &context_with_cwd(cwd)).unwrap();
    assert_ask(&result.action);
}

#[rstest]
fn cd_in_pipeline_does_not_affect_following_stages() {
    // `cd a | tail` runs cd in a subshell — the parent shell's cwd is
    // unchanged. Our accumulator only updates at the list level, so a
    // pipeline stage's cd never leaks out.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let inner = cwd.join("subdir");
    std::fs::create_dir(&inner).unwrap();

    let config = parse_config(&formatdoc! {"
        rules:
          - allow: 'cd *'
          - allow: 'tail *'
            when: \"command.cwd == '{}'\"
    ", cwd.display()})
    .unwrap();

    let result =
        evaluate_compound(&config, "cd subdir | tail -n 1", &context_with_cwd(cwd)).unwrap();
    assert_allow(&result.action);
}

// ========================================
// command.real_path
// ========================================

#[rstest]
fn real_path_resolves_relative_argv0_against_effective_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let scripts_dir = cwd.join("scripts");
    std::fs::create_dir(&scripts_dir).unwrap();
    let script_path = scripts_dir.join("hello");
    std::fs::write(&script_path, b"#!/bin/sh\n").unwrap();
    make_executable(&script_path);

    let canonical_script = canonical(&script_path);
    let config = parse_config(&formatdoc! {"
        rules:
          - allow: '* *'
            when: \"command.real_path == '{}'\"
    ", canonical_script.display()})
    .unwrap();

    let result =
        evaluate_command(&config, "./scripts/hello world", &context_with_cwd(cwd)).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn real_path_resolves_through_path_lookup_for_bare_name() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let bin_dir = cwd.join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let bin = bin_dir.join("myscript");
    std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
    make_executable(&bin);

    let canonical_bin = canonical(&bin);
    let config = parse_config(&formatdoc! {"
        rules:
          - allow: '* *'
            when: \"command.real_path == '{}'\"
    ", canonical_bin.display()})
    .unwrap();

    let context = context_with_cwd_and_path(cwd, bin_dir.to_str().unwrap());
    let result = evaluate_command(&config, "myscript --flag", &context).unwrap();
    assert_allow(&result.action);
}

#[cfg(unix)]
#[rstest]
fn real_path_canonicalizes_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let target = cwd.join("actual");
    std::fs::write(&target, b"#!/bin/sh\n").unwrap();
    make_executable(&target);
    let link = cwd.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let canonical_target = canonical(&target);
    let config = parse_config(&formatdoc! {"
        rules:
          - allow: '* *'
            when: \"command.real_path == '{}'\"
    ", canonical_target.display()})
    .unwrap();

    let command = format!("{} arg", link.display());
    let result = evaluate_command(&config, &command, &context_with_cwd(cwd)).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn real_path_is_empty_string_when_resolution_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let config = parse_config(indoc! {r#"
        rules:
          - allow: 'nonexistent-command-xyz *'
            when: "command.real_path == ''"
    "#})
    .unwrap();

    let context = context_with_cwd_and_path(cwd, "/nowhere");
    let result = evaluate_command(&config, "nonexistent-command-xyz arg", &context).unwrap();
    assert_allow(&result.action);
}

#[rstest]
fn real_path_resolves_against_compound_cwd_offset() {
    // `cd <scripts> && ./local-tool` — argv0 is relative, so it must
    // be joined against the effective cwd produced by the preceding
    // static `cd`, not the session cwd.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let scripts = cwd.join("scripts");
    std::fs::create_dir(&scripts).unwrap();
    let tool = scripts.join("local-tool");
    std::fs::write(&tool, b"#!/bin/sh\n").unwrap();
    make_executable(&tool);

    let canonical_tool = canonical(&tool);
    let config = parse_config(&formatdoc! {"
        rules:
          - allow: 'cd *'
          - allow: '* *'
            when: \"command.real_path == '{}'\"
    ", canonical_tool.display()})
    .unwrap();

    let result = evaluate_compound(
        &config,
        "cd scripts && ./local-tool run",
        &context_with_cwd(cwd),
    )
    .unwrap();
    assert_allow(&result.action);
}

// ========================================
// Identity-bound + portable rule
// ========================================

#[rstest]
fn identity_bound_rule_matches_regardless_of_invocation_form() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = canonical(tmp.path());
    let scripts = cwd.join("scripts");
    std::fs::create_dir(&scripts).unwrap();
    let script = scripts.join("check");
    std::fs::write(&script, b"#!/bin/sh\n").unwrap();
    make_executable(&script);

    let canonical_script = canonical(&script);
    let config = parse_config(&formatdoc! {"
        rules:
          - allow: '* *'
            when: \"command.real_path == '{}'\"
    ", canonical_script.display()})
    .unwrap();

    // Invocation 1: absolute path
    let r1 = evaluate_command(
        &config,
        &format!("{} run", script.display()),
        &context_with_cwd(cwd.clone()),
    )
    .unwrap();
    assert_allow(&r1.action);

    // Invocation 2: relative path
    let r2 = evaluate_command(&config, "./scripts/check run", &context_with_cwd(cwd)).unwrap();
    assert_allow(&r2.action);
}

// ========================================
// Sanity: command.* is purely additive — rules without `when`
// referencing command.* still work exactly as before.
// ========================================

#[rstest]
fn command_context_does_not_affect_rules_without_when() {
    let config = parse_config(indoc! {"
        rules:
          - deny: 'rm -rf *'
    "})
    .unwrap();

    let result =
        evaluate_command(&config, "rm -rf /tmp/foo", &context_with_cwd("/tmp".into())).unwrap();
    assert_deny(&result.action);
}
