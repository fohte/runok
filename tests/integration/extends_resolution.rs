//! Integration tests verifying that `extends` references are resolved
//! end-to-end: YAML config → parse → resolve_extends → evaluate_command.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use indoc::{formatdoc, indoc};
use rstest::{fixture, rstest};
use tempfile::TempDir;

use runok::config::{PresetCache, parse_config, resolve_extends};
use runok::rules::rule_engine::evaluate_command;

use super::{ActionAssertion, assert_allow, assert_ask, assert_deny, empty_context};

struct ExtendsTestEnv {
    _tmp: TempDir,
    project_dir: PathBuf,
    cache: PresetCache,
}

fn make_env() -> Result<ExtendsTestEnv, Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(&project_dir)?;
    let cache = PresetCache::with_config(tmp.path().join("cache"), Duration::from_secs(3600));
    Ok(ExtendsTestEnv {
        _tmp: tmp,
        project_dir,
        cache,
    })
}

#[fixture]
fn env() -> ExtendsTestEnv {
    make_env().unwrap_or_else(|_| std::process::abort())
}

#[rstest]
#[case::child_allow_rule_applied(
    indoc! {"
        rules:
          - allow: 'echo *'
    "},
    "echo hello",
    assert_allow as ActionAssertion,
)]
#[case::child_ask_rule_applied(
    indoc! {"
        rules:
          - ask: 'rm *'
    "},
    "rm foo",
    assert_ask as ActionAssertion,
)]
#[case::child_rule_no_match_returns_default(
    indoc! {"
        rules:
          - allow: 'echo *'
    "},
    "ls -la",
    assert_ask as ActionAssertion,
)]
fn extends_resolves_child_rules(
    #[case] child_yaml: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    env: ExtendsTestEnv,
    empty_context: runok::rules::rule_engine::EvalContext,
) {
    fs::write(env.project_dir.join("child.yml"), child_yaml).unwrap();
    fs::write(
        env.project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(env.project_dir.join("runok.yml")).unwrap()).unwrap();

    let resolved =
        resolve_extends(parent_config, &env.project_dir, "runok.yml", &env.cache).unwrap();

    let result = evaluate_command(&resolved, command, &empty_context).unwrap();
    expected(&result.action);
}

/// Parent rules take priority over child rules when both match the same command.
/// Due to Explicit Deny Wins, the most restrictive action wins regardless of order.
#[rstest]
#[case::parent_ask_over_child_allow(
    "allow: 'git push *'",
    "ask: 'git push *'",
    assert_ask as ActionAssertion,
)]
#[case::parent_deny_over_child_allow(
    "allow: 'git push *'",
    "deny: 'git push *'",
    assert_deny as ActionAssertion,
)]
#[case::parent_deny_over_child_ask(
    "ask: 'git push *'",
    "deny: 'git push *'",
    assert_deny as ActionAssertion,
)]
fn parent_rules_override_child_rules(
    #[case] child_rule: &str,
    #[case] parent_rule: &str,
    #[case] assert_action: ActionAssertion,
    env: ExtendsTestEnv,
    empty_context: runok::rules::rule_engine::EvalContext,
) {
    fs::write(
        env.project_dir.join("child.yml"),
        formatdoc! {"
            rules:
              - {child_rule}
        "},
    )
    .unwrap();

    fs::write(
        env.project_dir.join("runok.yml"),
        formatdoc! {"
            extends:
              - ./child.yml
            rules:
              - {parent_rule}
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(env.project_dir.join("runok.yml")).unwrap()).unwrap();

    let resolved =
        resolve_extends(parent_config, &env.project_dir, "runok.yml", &env.cache).unwrap();

    let result = evaluate_command(&resolved, "git push origin main", &empty_context).unwrap();
    assert_action(&result.action);
}

/// Multiple extends merge rules from all referenced files regardless of order.
/// Each extends entry contributes its rules to the final config.
#[rstest]
#[case::base_then_extra(&["./base.yml", "./extra.yml"])]
#[case::extra_then_base(&["./extra.yml", "./base.yml"])]
fn multiple_extends_rules_are_merged(
    #[case] extends_order: &[&str],
    env: ExtendsTestEnv,
    empty_context: runok::rules::rule_engine::EvalContext,
) {
    fs::write(
        env.project_dir.join("base.yml"),
        indoc! {"
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap();

    fs::write(
        env.project_dir.join("extra.yml"),
        indoc! {"
            rules:
              - allow: 'make *'
        "},
    )
    .unwrap();

    let extends_yaml = extends_order
        .iter()
        .map(|s| format!("  - {s}"))
        .collect::<Vec<_>>()
        .join("\n");

    fs::write(
        env.project_dir.join("runok.yml"),
        formatdoc! {"
            extends:
            {extends_yaml}
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(env.project_dir.join("runok.yml")).unwrap()).unwrap();

    let resolved =
        resolve_extends(parent_config, &env.project_dir, "runok.yml", &env.cache).unwrap();

    // Rules from both extends entries are available regardless of order
    let echo_result = evaluate_command(&resolved, "echo hello", &empty_context).unwrap();
    assert_allow(&echo_result.action);

    let make_result = evaluate_command(&resolved, "make build", &empty_context).unwrap();
    assert_allow(&make_result.action);
}

/// Nested extends (child extends grandchild) are resolved transitively.
#[rstest]
fn nested_extends_resolved_transitively(
    env: ExtendsTestEnv,
    empty_context: runok::rules::rule_engine::EvalContext,
) {
    fs::write(
        env.project_dir.join("grandchild.yml"),
        indoc! {"
            rules:
              - allow: 'make build'
        "},
    )
    .unwrap();

    fs::write(
        env.project_dir.join("child.yml"),
        indoc! {"
            extends:
              - ./grandchild.yml
        "},
    )
    .unwrap();

    fs::write(
        env.project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(env.project_dir.join("runok.yml")).unwrap()).unwrap();

    let resolved =
        resolve_extends(parent_config, &env.project_dir, "runok.yml", &env.cache).unwrap();

    let result = evaluate_command(&resolved, "make build", &empty_context).unwrap();
    assert_allow(&result.action);
}

/// Config without extends returns the same rules unchanged.
#[rstest]
fn no_extends_returns_config_unchanged(
    env: ExtendsTestEnv,
    empty_context: runok::rules::rule_engine::EvalContext,
) {
    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
    "})
    .unwrap();

    let resolved =
        resolve_extends(config, env.project_dir.as_path(), "runok.yml", &env.cache).unwrap();

    let result = evaluate_command(&resolved, "echo hello", &empty_context).unwrap();
    assert_allow(&result.action);
}

/// Extends resolution uses the config file's directory as base_dir,
/// not the current working directory. When running from a subdirectory,
/// relative paths in extends should resolve against the config's parent directory.
#[rstest]
fn extends_resolved_relative_to_config_dir_not_cwd(
    env: ExtendsTestEnv,
    empty_context: runok::rules::rule_engine::EvalContext,
) {
    use runok::config::{ConfigLoader, DefaultConfigLoader};

    fs::write(
        env.project_dir.join("child.yml"),
        indoc! {"
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap();

    fs::write(
        env.project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
        "},
    )
    .unwrap();

    // Run from a subdirectory; the loader should find project_dir/runok.yml
    // and resolve extends relative to project_dir, not the subdirectory.
    let subdir = env.project_dir.join("src").join("lib");
    fs::create_dir_all(&subdir).unwrap();

    let loader = DefaultConfigLoader::with_global_dir(env.project_dir.join("nonexistent_global"));
    let config = loader.load(&subdir).unwrap();

    let result = evaluate_command(&config, "echo hello", &empty_context).unwrap();
    assert_allow(&result.action);
}
