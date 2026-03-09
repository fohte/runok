//! Integration tests verifying that `extends` references are resolved
//! end-to-end: YAML config → parse → resolve_extends → evaluate_command.

use std::fs;
use std::time::Duration;

use indoc::indoc;
use rstest::rstest;
use tempfile::TempDir;

use runok::config::{PresetCache, parse_config, resolve_extends};
use runok::rules::rule_engine::{Action, evaluate_command};

use super::{ActionAssertion, assert_allow, assert_ask, assert_default, empty_context};

/// Helper: create a PresetCache backed by a temporary directory.
fn temp_cache(tmp: &TempDir) -> PresetCache {
    PresetCache::with_config(tmp.path().join("cache"), Duration::from_secs(3600))
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
    assert_default as ActionAssertion,
)]
fn extends_resolves_child_rules(
    #[case] child_yaml: &str,
    #[case] command: &str,
    #[case] expected: ActionAssertion,
    empty_context: runok::rules::rule_engine::EvalContext,
) {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(&project_dir).unwrap();

    fs::write(project_dir.join("child.yml"), child_yaml).unwrap();
    fs::write(
        project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(project_dir.join("runok.yml")).unwrap()).unwrap();

    let cache = temp_cache(&tmp);
    let resolved = resolve_extends(parent_config, &project_dir, "runok.yml", &cache).unwrap();

    let result = evaluate_command(&resolved, command, &empty_context).unwrap();
    expected(&result.action);
}

/// Parent rules take priority over child rules when both match the same command.
#[rstest]
fn parent_rules_override_child_rules(empty_context: runok::rules::rule_engine::EvalContext) {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(&project_dir).unwrap();

    fs::write(
        project_dir.join("child.yml"),
        indoc! {"
            rules:
              - allow: 'git push *'
        "},
    )
    .unwrap();

    fs::write(
        project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
            rules:
              - ask: 'git push *'
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(project_dir.join("runok.yml")).unwrap()).unwrap();

    let cache = temp_cache(&tmp);
    let resolved = resolve_extends(parent_config, &project_dir, "runok.yml", &cache).unwrap();

    let result = evaluate_command(&resolved, "git push origin main", &empty_context).unwrap();
    assert!(
        matches!(result.action, Action::Ask(_)),
        "parent ask rule should override child allow rule, got {:?}",
        result.action,
    );
}

/// Multiple extends are merged in order, with later entries taking priority.
#[rstest]
fn multiple_extends_merged_in_order(empty_context: runok::rules::rule_engine::EvalContext) {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(&project_dir).unwrap();

    fs::write(
        project_dir.join("base.yml"),
        indoc! {"
            rules:
              - allow: 'echo *'
        "},
    )
    .unwrap();

    fs::write(
        project_dir.join("override.yml"),
        indoc! {"
            rules:
              - ask: 'echo *'
        "},
    )
    .unwrap();

    fs::write(
        project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./base.yml
              - ./override.yml
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(project_dir.join("runok.yml")).unwrap()).unwrap();

    let cache = temp_cache(&tmp);
    let resolved = resolve_extends(parent_config, &project_dir, "runok.yml", &cache).unwrap();

    // override.yml's ask rule should take priority over base.yml's allow rule
    let result = evaluate_command(&resolved, "echo hello", &empty_context).unwrap();
    assert!(
        matches!(result.action, Action::Ask(_)),
        "later extends entry should take priority, got {:?}",
        result.action,
    );
}

/// Nested extends (child extends grandchild) are resolved transitively.
#[rstest]
fn nested_extends_resolved_transitively(empty_context: runok::rules::rule_engine::EvalContext) {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("project");
    fs::create_dir_all(&project_dir).unwrap();

    fs::write(
        project_dir.join("grandchild.yml"),
        indoc! {"
            rules:
              - allow: 'make build'
        "},
    )
    .unwrap();

    fs::write(
        project_dir.join("child.yml"),
        indoc! {"
            extends:
              - ./grandchild.yml
        "},
    )
    .unwrap();

    fs::write(
        project_dir.join("runok.yml"),
        indoc! {"
            extends:
              - ./child.yml
        "},
    )
    .unwrap();

    let parent_config =
        parse_config(&fs::read_to_string(project_dir.join("runok.yml")).unwrap()).unwrap();

    let cache = temp_cache(&tmp);
    let resolved = resolve_extends(parent_config, &project_dir, "runok.yml", &cache).unwrap();

    let result = evaluate_command(&resolved, "make build", &empty_context).unwrap();
    assert_eq!(
        result.action,
        Action::Allow,
        "grandchild allow rule should be resolved transitively",
    );
}

/// Config without extends returns the same rules unchanged.
#[rstest]
fn no_extends_returns_config_unchanged(empty_context: runok::rules::rule_engine::EvalContext) {
    let tmp = TempDir::new().unwrap();

    let config = parse_config(indoc! {"
        rules:
          - allow: 'echo *'
    "})
    .unwrap();

    let cache = temp_cache(&tmp);
    let resolved = resolve_extends(config, tmp.path(), "runok.yml", &cache).unwrap();

    let result = evaluate_command(&resolved, "echo hello", &empty_context).unwrap();
    assert_eq!(result.action, Action::Allow);
}
