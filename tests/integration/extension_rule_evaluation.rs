use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indoc::{formatdoc, indoc};
use runok::config::{ActionKind, parse_config};
use runok::exec::ExtensionError;
use runok::exec::extension_runner::{ExtensionCall, ExtensionRunner, ProcessExtensionRunner};
use runok::rules::rule_engine::{
    Action, AskResponse, DenyResponse, EvalContext, EvalResult, RuleMatchInfo, StubCommandResolver,
    evaluate_command,
};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq)]
struct RecordedCall {
    name: String,
    executor: String,
    params: Map<String, Value>,
    parent_env: HashMap<String, String>,
    extra_env: Vec<String>,
    cwd: PathBuf,
    timeout: Duration,
}

struct RecordingRunner {
    result: Result<Value, String>,
    calls: Mutex<Vec<RecordedCall>>,
}

impl RecordingRunner {
    fn new(result: Result<Value, String>) -> Self {
        Self {
            result,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<RecordedCall> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl ExtensionRunner for RecordingRunner {
    fn call(&self, call: ExtensionCall<'_>) -> Result<Value, ExtensionError> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(RecordedCall {
                name: call.name.to_string(),
                executor: call.executor_cmd.to_string(),
                params: call.params.clone(),
                parent_env: call.parent_env.clone(),
                extra_env: call.extra_env.to_vec(),
                cwd: call.cwd.to_path_buf(),
                timeout: call.timeout,
            });
        self.result.clone().map_err(ExtensionError::InvalidResponse)
    }
}

fn context(runner: Arc<dyn ExtensionRunner>) -> EvalContext {
    EvalContext {
        env: HashMap::from([
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("HOME".to_string(), "/home/example".to_string()),
            ("RUNOK_MODE".to_string(), "test".to_string()),
            ("RUNOK_SECRET".to_string(), "private".to_string()),
        ]),
        cwd: PathBuf::from("/workspace"),
        resolver: Arc::new(StubCommandResolver),
        extension_runner: runner,
        verbose: false,
    }
}

fn extension_config(rule_yaml: &str) -> Result<runok::config::Config, Box<dyn Error>> {
    Ok(parse_config(&formatdoc! {r#"
        definitions:
          extensions:
            lookup:
              executor: fixture-executor
              timeout: 2s
              env: [RUNOK_MODE]
        {rule_yaml}
    "#})?)
}

fn call(params: Map<String, Value>) -> RecordedCall {
    RecordedCall {
        name: "lookup".into(),
        executor: "fixture-executor".into(),
        params,
        parent_env: HashMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/home/example".into()),
            ("RUNOK_MODE".into(), "test".into()),
            ("RUNOK_SECRET".into(), "private".into()),
        ]),
        extra_env: vec!["RUNOK_MODE".into()],
        cwd: PathBuf::from("/workspace"),
        timeout: Duration::from_secs(2),
    }
}

#[cfg(unix)]
fn write_extension_script(path: &Path, contents: &str) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, contents)?;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[test]
fn extension_returns_json_values_and_caches_same_call_within_one_when() -> Result<(), Box<dyn Error>>
{
    let runner = Arc::new(RecordingRunner::new(Ok(serde_json::json!({
        "branch": "release",
        "payload": ["ready", null]
    }))));
    let config = extension_config(indoc! {r#"
        rules:
          - deny: 'deploy *'
            when: "ext.lookup({'branch': args[0]}).branch == 'release' && ext.lookup({'branch': args[0]}).payload[1] == null"
    "#})?;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))?;

    assert_eq!(
        (result, runner.calls()),
        (
            EvalResult {
                action: Action::Deny(DenyResponse {
                    message: None,
                    fix_suggestion: None,
                    matched_rule: "deploy *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![RuleMatchInfo {
                    action_kind: ActionKind::Deny,
                    pattern: "deploy *".into(),
                    matched_tokens: vec!["release".into()],
                }],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            vec![call(Map::from_iter([(
                "branch".into(),
                Value::String("release".into()),
            )]))],
        ),
    );
    Ok(())
}

#[test]
fn short_circuit_does_not_start_the_extension() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(Ok(Value::Bool(true))));
    let config = extension_config(indoc! {r#"
        defaults:
          action: allow
        rules:
          - deny: 'deploy *'
            when: 'false && ext.lookup({}).allowed'
    "#})?;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))?;

    assert_eq!((result.action, runner.calls()), (Action::Allow, Vec::new()));
    Ok(())
}

#[test]
fn extension_failure_becomes_ask_but_another_rule_can_deny() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(Err("fixture failure".into())));
    let config = extension_config(indoc! {r#"
        rules:
          - allow: 'deploy *'
            when: 'ext.lookup({}).allowed'
          - allow: 'deploy *'
            when: 'ext.lookup({}).allowed'
          - deny: 'deploy *'
            message: blocked by policy
    "#})?;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))?;

    assert_eq!(
        (result, runner.calls()),
        (
            EvalResult {
                action: Action::Deny(DenyResponse {
                    message: Some("blocked by policy".into()),
                    fix_suggestion: None,
                    matched_rule: "deploy *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![
                    RuleMatchInfo {
                        action_kind: ActionKind::Ask,
                        pattern: "deploy *".into(),
                        matched_tokens: vec!["release".into()],
                    },
                    RuleMatchInfo {
                        action_kind: ActionKind::Ask,
                        pattern: "deploy *".into(),
                        matched_tokens: vec!["release".into()],
                    },
                    RuleMatchInfo {
                        action_kind: ActionKind::Deny,
                        pattern: "deploy *".into(),
                        matched_tokens: vec!["release".into()],
                    },
                ],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            vec![call(Map::new()), call(Map::new())],
        ),
    );
    Ok(())
}

#[test]
fn a_when_error_after_an_extension_call_becomes_ask() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(Ok(
        serde_json::json!({"unrelated": true}),
    )));
    let config = extension_config(indoc! {r#"
        rules:
          - allow: 'deploy *'
            when: 'ext.lookup({}).missing'
    "#})?;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))?;

    assert_eq!(
        (result, runner.calls()),
        (
            EvalResult {
                action: Action::Ask(AskResponse {
                    message: Some("when evaluation failed after calling extension 'lookup': evaluation error: No such key: missing; asking user for confirmation".into()),
                    fix_suggestion: None,
                    matched_rule: "deploy *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![RuleMatchInfo {
                    action_kind: ActionKind::Ask,
                    pattern: "deploy *".into(),
                    matched_tokens: vec!["release".into()],
                }],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            vec![call(Map::new())],
        ),
    );
    Ok(())
}

#[test]
fn an_unpassable_extension_argument_becomes_ask() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(Ok(Value::Bool(true))));
    let config = extension_config(indoc! {r#"
        rules:
          - allow: 'deploy *'
            when: 'ext.lookup([1]).allowed'
    "#})?;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))?;

    assert_eq!(
        (result, runner.calls()),
        (
            EvalResult {
                action: Action::Ask(AskResponse {
                    message: Some("Extension 'lookup' failed: extension argument must be a map; asking user for confirmation".into()),
                    fix_suggestion: None,
                    matched_rule: "deploy *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![RuleMatchInfo {
                    action_kind: ActionKind::Ask,
                    pattern: "deploy *".into(),
                    matched_tokens: vec!["release".into()],
                }],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            Vec::new(),
        ),
    );
    Ok(())
}

#[test]
fn a_when_error_without_an_extension_call_still_stops_evaluation() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(Ok(Value::Bool(true))));
    let config = parse_config(indoc! {r#"
        rules:
          - allow: 'deploy *'
            when: "missing.value == 'release'"
    "#})?;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))
        .map(|_| ())
        .map_err(|error| error.to_string());

    assert_eq!(
        (result, runner.calls()),
        (
            Err(
                "expression evaluation error: evaluation error: Undeclared reference to 'missing'"
                    .into()
            ),
            Vec::new(),
        ),
    );
    Ok(())
}

#[test]
fn project_rule_extension_calls_fail_as_ask() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(Ok(
        serde_json::json!({"allowed": true}),
    )));
    let mut config = extension_config(indoc! {r#"
        rules:
          - allow: 'deploy *'
            when: 'ext.lookup({}).allowed'
    "#})?;
    config.rules.as_mut().unwrap()[0].extension_calls_allowed = false;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))?;

    assert_eq!(
        (result, runner.calls()),
        (
            EvalResult {
                action: Action::Ask(AskResponse {
                    message: Some("Extension 'lookup' failed: extension calls from project-discovered rules are not permitted; asking user for confirmation".into()),
                    fix_suggestion: None,
                    matched_rule: "deploy *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![RuleMatchInfo {
                    action_kind: ActionKind::Ask,
                    pattern: "deploy *".into(),
                    matched_tokens: vec!["release".into()],
                }],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            Vec::new(),
        ),
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn process_extension_receives_params_and_runs_once_for_repeated_calls() -> Result<(), Box<dyn Error>>
{
    use std::fs;

    let temp_dir = tempfile::tempdir()?;
    let counter = temp_dir.path().join("counter");
    let script = temp_dir.path().join("extension.sh");
    write_extension_script(
        &script,
        &format!(
            r#"#!/bin/sh
IFS= read -r request
printf x >> '{}'
case "$request" in
  *'"branch":"release"'*) printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"branch":"release"}}}}' ;;
  *) printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"branch":"other"}}}}' ;;
esac
"#,
            counter.display(),
        ),
    )?;

    let script = script.to_string_lossy();
    let yaml = indoc! {r#"
        definitions:
          extensions:
            lookup:
              executor: '__EXECUTOR__'
              env: [RUNOK_COUNTER]
        rules:
          - deny: 'deploy *'
            when: "ext.lookup({'branch': args[0]}).branch == 'release' && ext.lookup({'branch': args[0]}).branch == 'release'"
    "#}
    .replace("__EXECUTOR__", script.as_ref());
    let config = parse_config(&yaml)?;
    let mut eval_context = context(Arc::new(ProcessExtensionRunner));
    eval_context.cwd = temp_dir.path().to_path_buf();
    eval_context.env.insert(
        "RUNOK_COUNTER".into(),
        counter.to_string_lossy().into_owned(),
    );
    let result = evaluate_command(&config, "deploy release", &eval_context)?;
    let count = fs::read_to_string(&counter)?;

    assert_eq!(
        (result, count),
        (
            EvalResult {
                action: Action::Deny(DenyResponse {
                    message: None,
                    fix_suggestion: None,
                    matched_rule: "deploy *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![RuleMatchInfo {
                    action_kind: ActionKind::Deny,
                    pattern: "deploy *".into(),
                    matched_tokens: vec!["release".into()],
                }],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            "x".into()
        ),
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn process_extension_results_can_be_top_level_list_and_null() -> Result<(), Box<dyn Error>> {
    use std::fs;

    let temp_dir = tempfile::tempdir()?;
    let counter = temp_dir.path().join("counter");
    let script = temp_dir.path().join("extension.sh");
    write_extension_script(
        &script,
        &format!(
            r#"#!/bin/sh
IFS= read -r request
printf x >> '{}'
case "$request" in
  *'"branch":"null"'*) printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":null}}' ;;
  *) printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":["ready"]}}' ;;
esac
"#,
            counter.display(),
        ),
    )?;

    let yaml = indoc! {r#"
        definitions:
          extensions:
            lookup:
              executor: '__EXECUTOR__'
        rules:
          - deny: 'deploy *'
            when: "ext.lookup({'branch': 'list'})[0] == 'ready' && ext.lookup({'branch': 'null'}) == null"
    "#}
    .replace("__EXECUTOR__", &script.to_string_lossy());
    let config = parse_config(&yaml)?;
    let mut eval_context = context(Arc::new(ProcessExtensionRunner));
    eval_context.cwd = temp_dir.path().to_path_buf();
    let result = evaluate_command(&config, "deploy release", &eval_context)?;
    let count = fs::read_to_string(&counter)?;

    assert_eq!(
        (result, count),
        (
            EvalResult {
                action: Action::Deny(DenyResponse {
                    message: None,
                    fix_suggestion: None,
                    matched_rule: "deploy *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![RuleMatchInfo {
                    action_kind: ActionKind::Deny,
                    pattern: "deploy *".into(),
                    matched_tokens: vec!["release".into()],
                }],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            "xx".into()
        ),
    );
    Ok(())
}
