use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indoc::{formatdoc, indoc};
use runok::config::{ActionKind, parse_config};
use runok::exec::ExtensionError;
use runok::exec::extension_runner::{ExtensionRequest, ExtensionResponse, ExtensionRunner};
use runok::rules::rule_engine::{
    Action, AskResponse, DenyResponse, EvalContext, EvalResult, RuleMatchInfo, StubCommandResolver,
    evaluate_command,
};

enum StubResult {
    Response(ExtensionResponse),
    Failure,
}

struct RecordingRunner {
    result: StubResult,
    requests: Mutex<Vec<ExtensionRequest>>,
}

impl RecordingRunner {
    fn new(result: StubResult) -> Self {
        Self {
            result,
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl ExtensionRunner for RecordingRunner {
    fn validate(
        &self,
        _executor_cmd: &str,
        request: &ExtensionRequest,
        _timeout: Duration,
    ) -> Result<ExtensionResponse, ExtensionError> {
        match self.requests.lock() {
            Ok(mut requests) => requests.push(request.clone()),
            Err(poisoned) => poisoned.into_inner().push(request.clone()),
        }
        match &self.result {
            StubResult::Response(response) => Ok(response.clone()),
            StubResult::Failure => Err(ExtensionError::InvalidResponse("fixture failure".into())),
        }
    }
}

fn context(runner: Arc<dyn ExtensionRunner>) -> EvalContext {
    EvalContext {
        env: HashMap::from([("RUNOK_MODE".to_string(), "test".to_string())]),
        cwd: PathBuf::from("/workspace"),
        resolver: Arc::new(StubCommandResolver),
        extension_runner: runner,
    }
}

fn extension_config(rule: &str) -> Result<runok::config::Config, Box<dyn Error>> {
    Ok(parse_config(&formatdoc! {r#"
        definitions:
          extensions:
            gate:
              executor: fixture-executor
        {rule}
    "#})?)
}

#[test]
fn extension_rule_receives_parsed_request_and_returns_its_decision() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(StubResult::Response(
        ExtensionResponse {
            status: "deny".into(),
            message: Some("deployment is blocked".into()),
            fix_suggestion: Some("deploy --target preview".into()),
        },
    )));
    let config = extension_config(indoc! {"
        rules:
          - extension: gate
            match: 'git [-C *] push *'
    "})?;
    let result = evaluate_command(
        &config,
        "git -C /workspace push origin",
        &context(runner.clone()),
    )?;
    let requests = match runner.requests.lock() {
        Ok(requests) => requests.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };

    assert_eq!(
        (result, requests),
        (
            EvalResult {
                action: Action::Deny(DenyResponse {
                    message: Some("deployment is blocked".into()),
                    fix_suggestion: Some("deploy --target preview".into()),
                    matched_rule: "git [-C *] push *".into(),
                }),
                sandbox_preset: None,
                matched_rules: vec![RuleMatchInfo {
                    action_kind: ActionKind::Deny,
                    pattern: "git [-C *] push *".into(),
                    matched_tokens: vec!["/workspace".into(), "origin".into()],
                }],
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            vec![ExtensionRequest {
                command: "git".into(),
                flags: HashMap::from([("C".into(), "/workspace".into())]),
                args: vec!["push".into(), "origin".into()],
                raw_command_line: "git -C /workspace push origin".into(),
                env: HashMap::from([("RUNOK_MODE".into(), "test".into())]),
                cwd: "/workspace".into(),
            }],
        ),
    );
    Ok(())
}

#[test]
fn extension_and_static_rules_use_deny_ask_allow_precedence() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(StubResult::Response(
        ExtensionResponse {
            status: "allow".into(),
            message: None,
            fix_suggestion: None,
        },
    )));
    let config = extension_config(indoc! {"
        rules:
          - extension: gate
            match: 'deploy *'
          - allow: 'deploy *'
          - ask: 'deploy *'
            message: require approval
          - deny: 'deploy *'
            message: denied by policy
    "})?;
    let result = evaluate_command(&config, "deploy release", &context(runner))?;

    assert_eq!(
        result,
        EvalResult {
            action: Action::Deny(DenyResponse {
                message: Some("denied by policy".into()),
                fix_suggestion: None,
                matched_rule: "deploy *".into(),
            }),
            sandbox_preset: None,
            matched_rules: vec![
                RuleMatchInfo {
                    action_kind: ActionKind::Allow,
                    pattern: "deploy *".into(),
                    matched_tokens: vec!["release".into()],
                },
                RuleMatchInfo {
                    action_kind: ActionKind::Allow,
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
    );
    Ok(())
}

#[test]
fn extension_pass_falls_through_to_other_rules() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(StubResult::Response(
        ExtensionResponse {
            status: "pass".into(),
            message: None,
            fix_suggestion: None,
        },
    )));
    let config = extension_config(indoc! {"
        rules:
          - extension: gate
            match: 'deploy *'
          - ask: 'deploy *'
            message: require manual approval
    "})?;
    let result = evaluate_command(&config, "deploy release", &context(runner))?;

    assert_eq!(
        result,
        EvalResult {
            action: Action::Ask(AskResponse {
                message: Some("require manual approval".into()),
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
    );
    Ok(())
}

#[test]
fn extension_pass_uses_the_unmatched_default() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(StubResult::Response(
        ExtensionResponse {
            status: "pass".into(),
            message: None,
            fix_suggestion: None,
        },
    )));
    let config = extension_config(indoc! {"
        defaults:
          action: deny
        rules:
          - extension: gate
            match: 'deploy *'
    "})?;
    let result = evaluate_command(&config, "deploy release", &context(runner))?;

    assert_eq!(
        result,
        EvalResult {
            action: Action::Deny(DenyResponse {
                message: None,
                fix_suggestion: None,
                matched_rule: String::new(),
            }),
            sandbox_preset: None,
            matched_rules: Vec::new(),
            alias_chain: Vec::new(),
            require_command_in_path: None,
        },
    );
    Ok(())
}

#[test]
fn extension_failure_falls_back_to_ask() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(StubResult::Failure));
    let config = extension_config(indoc! {"
        rules:
          - extension: gate
            match: 'deploy *'
    "})?;
    let result = evaluate_command(&config, "deploy release", &context(runner))?;

    assert_eq!(
        result,
        EvalResult {
            action: Action::Ask(AskResponse {
                message: Some(
                    "Extension returned invalid response, asking user for confirmation".into(),
                ),
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
    );
    Ok(())
}

#[test]
fn false_when_skips_the_extension() -> Result<(), Box<dyn Error>> {
    let runner = Arc::new(RecordingRunner::new(StubResult::Response(
        ExtensionResponse {
            status: "deny".into(),
            message: Some("should not run".into()),
            fix_suggestion: None,
        },
    )));
    let config = extension_config(indoc! {r#"
        defaults:
          action: allow
        rules:
          - extension: gate
            match: 'deploy *'
            when: 'env.RUNOK_MODE == "never"'
    "#})?;
    let result = evaluate_command(&config, "deploy release", &context(runner.clone()))?;
    let requests = match runner.requests.lock() {
        Ok(requests) => requests.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };

    assert_eq!(
        (result, requests),
        (
            EvalResult {
                action: Action::Allow,
                sandbox_preset: None,
                matched_rules: Vec::new(),
                alias_chain: Vec::new(),
                require_command_in_path: None,
            },
            Vec::new(),
        ),
    );
    Ok(())
}

#[test]
fn extension_rule_rejects_an_undefined_executor() -> Result<(), Box<dyn Error>> {
    let mut config = parse_config(indoc! {"
        rules:
          - extension: missing
            match: 'deploy *'
    "})?;

    let error = match config.validate() {
        Ok(()) => {
            return Err(std::io::Error::other("undefined extension passed validation").into());
        }
        Err(error) => error.to_string(),
    };

    assert_eq!(
        error,
        "validation errors:\n  - rules[0]: extension 'missing' is not defined in definitions.extensions",
    );
    Ok(())
}
