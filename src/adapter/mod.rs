pub mod check_adapter;
pub mod hook_adapter;

use crate::config::{Config, Defaults, MergedSandboxPolicy};
use crate::rules::command_parser::extract_commands;
use crate::rules::rule_engine::{Action, EvalContext, evaluate_command, evaluate_compound};

/// Unified evaluation result for the adapter layer.
///
/// For single commands, carries the sandbox preset name (to be resolved later).
/// For compound commands, carries the already-merged sandbox policy.
#[derive(Debug)]
pub struct ActionResult {
    pub action: Action,
    pub sandbox: SandboxInfo,
}

/// Sandbox information from rule evaluation, varying by command type.
#[derive(Debug)]
pub enum SandboxInfo {
    /// Single command: preset name to be resolved by the adapter.
    Preset(Option<String>),
    /// Compound command: already-merged policy from `evaluate_compound`.
    MergedPolicy(Option<MergedSandboxPolicy>),
}

/// Abstracts protocol-specific input/output differences across
/// exec, check, and Claude Code hook endpoints.
pub trait Endpoint {
    /// Extract the command string from protocol-specific input.
    /// Returns `None` when the input is not subject to command evaluation
    /// (e.g., `tool_name != "Bash"` in Claude Code hooks).
    fn extract_command(&self) -> Result<Option<String>, anyhow::Error>;

    /// Convert an `ActionResult` into protocol-specific output and return the exit code.
    fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error>;

    /// Handle the case when no rule matched or the action is `Default`.
    fn handle_no_match(&self, defaults: &Defaults) -> Result<i32, anyhow::Error>;

    /// Handle an error with protocol-specific error reporting. Returns the exit code.
    fn handle_error(&self, error: anyhow::Error) -> i32;
}

/// Run the common evaluation flow for any endpoint.
///
/// 1. Extract the command from protocol-specific input
/// 2. Evaluate the command against the config rules
/// 3. Dispatch to the appropriate handler based on the result
pub fn run(endpoint: &dyn Endpoint, config: &Config) -> i32 {
    let defaults = config.defaults.clone().unwrap_or_default();

    let command = match endpoint.extract_command() {
        Ok(Some(cmd)) => cmd,
        Ok(None) => {
            return endpoint.handle_no_match(&defaults).unwrap_or(0);
        }
        Err(e) => return endpoint.handle_error(e),
    };

    let context = EvalContext::from_env();

    // Determine if the command is compound (contains pipes, &&, ||, ;)
    let commands = extract_commands(&command).unwrap_or_else(|_| vec![command.clone()]);

    let action_result = if commands.len() > 1 {
        match evaluate_compound(config, &command, &context) {
            Ok(compound_result) => ActionResult {
                action: compound_result.action,
                sandbox: SandboxInfo::MergedPolicy(compound_result.sandbox_policy),
            },
            Err(e) => return endpoint.handle_error(e.into()),
        }
    } else {
        match evaluate_command(config, &command, &context) {
            Ok(result) => ActionResult {
                action: result.action,
                sandbox: SandboxInfo::Preset(result.sandbox_preset),
            },
            Err(e) => return endpoint.handle_error(e.into()),
        }
    };

    if matches!(action_result.action, Action::Default) {
        return endpoint.handle_no_match(&defaults).unwrap_or(0);
    }

    endpoint.handle_action(action_result).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ActionKind, RuleEntry};
    use rstest::rstest;
    use std::cell::RefCell;

    /// Tracks which Endpoint methods were called and what they received.
    struct MockEndpoint {
        command: Result<Option<String>, String>,
        action_exit_code: i32,
        no_match_exit_code: i32,
        error_exit_code: i32,
        called_handle_action: RefCell<bool>,
        called_handle_no_match: RefCell<bool>,
        called_handle_error: RefCell<bool>,
        last_action: RefCell<Option<Action>>,
        last_sandbox: RefCell<Option<SandboxInfo>>,
        last_defaults_action: RefCell<Option<Option<ActionKind>>>,
    }

    impl MockEndpoint {
        fn new(command: Result<Option<String>, String>) -> Self {
            Self {
                command,
                action_exit_code: 0,
                no_match_exit_code: 0,
                error_exit_code: 2,
                called_handle_action: RefCell::new(false),
                called_handle_no_match: RefCell::new(false),
                called_handle_error: RefCell::new(false),
                last_action: RefCell::new(None),
                last_sandbox: RefCell::new(None),
                last_defaults_action: RefCell::new(None),
            }
        }

        fn with_action_exit_code(mut self, code: i32) -> Self {
            self.action_exit_code = code;
            self
        }

        fn with_no_match_exit_code(mut self, code: i32) -> Self {
            self.no_match_exit_code = code;
            self
        }

        fn with_error_exit_code(mut self, code: i32) -> Self {
            self.error_exit_code = code;
            self
        }
    }

    impl Endpoint for MockEndpoint {
        fn extract_command(&self) -> Result<Option<String>, anyhow::Error> {
            match &self.command {
                Ok(cmd) => Ok(cmd.clone()),
                Err(msg) => Err(anyhow::anyhow!("{}", msg)),
            }
        }

        fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
            *self.called_handle_action.borrow_mut() = true;
            *self.last_action.borrow_mut() = Some(result.action);
            *self.last_sandbox.borrow_mut() = Some(result.sandbox);
            Ok(self.action_exit_code)
        }

        fn handle_no_match(&self, defaults: &Defaults) -> Result<i32, anyhow::Error> {
            *self.called_handle_no_match.borrow_mut() = true;
            *self.last_defaults_action.borrow_mut() = Some(defaults.action);
            Ok(self.no_match_exit_code)
        }

        fn handle_error(&self, _error: anyhow::Error) -> i32 {
            *self.called_handle_error.borrow_mut() = true;
            self.error_exit_code
        }
    }

    fn make_config(rules: Vec<RuleEntry>) -> Config {
        Config {
            rules: Some(rules),
            ..Default::default()
        }
    }

    fn allow_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            allow: Some(pattern.to_string()),
            deny: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
        }
    }

    fn deny_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            deny: Some(pattern.to_string()),
            allow: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
        }
    }

    fn ask_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            ask: Some(pattern.to_string()),
            allow: None,
            deny: None,
            when: None,
            message: Some("please confirm".to_string()),
            fix_suggestion: None,
            sandbox: None,
        }
    }

    // --- extract_command returns None -> handle_no_match ---

    #[rstest]
    fn extract_none_calls_handle_no_match() {
        let endpoint = MockEndpoint::new(Ok(None));
        let config = Config::default();
        let exit_code = run(&endpoint, &config);

        assert!(*endpoint.called_handle_no_match.borrow());
        assert!(!*endpoint.called_handle_action.borrow());
        assert!(!*endpoint.called_handle_error.borrow());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn extract_none_passes_defaults_to_handle_no_match() {
        let endpoint = MockEndpoint::new(Ok(None));
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Deny),
                sandbox: None,
            }),
            ..Default::default()
        };
        run(&endpoint, &config);

        assert_eq!(
            *endpoint.last_defaults_action.borrow(),
            Some(Some(ActionKind::Deny))
        );
    }

    // --- extract_command returns Err -> handle_error ---

    #[rstest]
    fn extract_error_calls_handle_error() {
        let endpoint = MockEndpoint::new(Err("parse failed".to_string())).with_error_exit_code(2);
        let config = Config::default();
        let exit_code = run(&endpoint, &config);

        assert!(*endpoint.called_handle_error.borrow());
        assert!(!*endpoint.called_handle_action.borrow());
        assert!(!*endpoint.called_handle_no_match.borrow());
        assert_eq!(exit_code, 2);
    }

    // --- rule match dispatches to handle_action with correct Action variant ---

    #[rstest]
    #[case::allow("git status", allow_rule("git status"), Action::Allow)]
    #[case::deny("rm -rf /", deny_rule("rm -rf /"), Action::Deny(crate::rules::rule_engine::DenyResponse { message: None, fix_suggestion: None, matched_rule: "rm -rf /".to_string() }))]
    #[case::ask("terraform apply", ask_rule("terraform apply"), Action::Ask(Some("please confirm".to_string())))]
    fn rule_match_calls_handle_action(
        #[case] command: &str,
        #[case] rule: RuleEntry,
        #[case] expected_action: Action,
    ) {
        let endpoint = MockEndpoint::new(Ok(Some(command.to_string())));
        let config = make_config(vec![rule]);
        run(&endpoint, &config);

        assert!(*endpoint.called_handle_action.borrow());
        assert!(!*endpoint.called_handle_no_match.borrow());

        let last_action = endpoint.last_action.borrow();
        assert_eq!(
            std::mem::discriminant(last_action.as_ref().unwrap()),
            std::mem::discriminant(&expected_action)
        );
    }

    // --- no matching rule -> handle_no_match ---

    #[rstest]
    #[case::no_matching_rule("unknown-command", make_config(vec![allow_rule("git status")]))]
    #[case::empty_config("git status", Config::default())]
    fn no_match_calls_handle_no_match(#[case] command: &str, #[case] config: Config) {
        let endpoint = MockEndpoint::new(Ok(Some(command.to_string())));
        let exit_code = run(&endpoint, &config);

        assert!(*endpoint.called_handle_no_match.borrow());
        assert!(!*endpoint.called_handle_action.borrow());
        assert_eq!(exit_code, 0);
    }

    // --- defaults are passed through when no rules match ---

    #[rstest]
    fn no_match_uses_config_defaults() {
        let endpoint =
            MockEndpoint::new(Ok(Some("unknown-command".to_string()))).with_no_match_exit_code(5);
        let config = Config {
            defaults: Some(Defaults {
                action: Some(ActionKind::Allow),
                sandbox: None,
            }),
            rules: Some(vec![deny_rule("rm *")]),
            ..Default::default()
        };
        let exit_code = run(&endpoint, &config);

        assert!(*endpoint.called_handle_no_match.borrow());
        assert_eq!(exit_code, 5);
        assert_eq!(
            *endpoint.last_defaults_action.borrow(),
            Some(Some(ActionKind::Allow))
        );
    }

    // --- compound command: deny wins over allow ---

    #[rstest]
    fn compound_deny_wins_over_allow() {
        let endpoint = MockEndpoint::new(Ok(Some("git status && rm -rf /".to_string())))
            .with_action_exit_code(3);
        let config = make_config(vec![allow_rule("git status"), deny_rule("rm -rf /")]);
        let exit_code = run(&endpoint, &config);

        assert!(*endpoint.called_handle_action.borrow());
        assert_eq!(exit_code, 3);
        assert!(matches!(
            *endpoint.last_action.borrow(),
            Some(Action::Deny(_))
        ));
        // Compound commands carry MergedPolicy sandbox info
        assert!(matches!(
            *endpoint.last_sandbox.borrow(),
            Some(SandboxInfo::MergedPolicy(_))
        ));
    }

    // --- compound command: all default -> handle_no_match ---

    #[rstest]
    fn compound_all_default_calls_handle_no_match() {
        let endpoint = MockEndpoint::new(Ok(Some("unknown-cmd1 && unknown-cmd2".to_string())));
        let config = make_config(vec![allow_rule("git status")]);
        let exit_code = run(&endpoint, &config);

        assert!(*endpoint.called_handle_no_match.borrow());
        assert!(!*endpoint.called_handle_action.borrow());
        assert_eq!(exit_code, 0);
    }

    // --- exit code propagation ---

    #[rstest]
    #[case::exit_0(0)]
    #[case::exit_1(1)]
    #[case::exit_42(42)]
    fn handle_action_exit_code_propagated(#[case] exit_code: i32) {
        let endpoint =
            MockEndpoint::new(Ok(Some("git status".to_string()))).with_action_exit_code(exit_code);
        let config = make_config(vec![allow_rule("git status")]);
        let result = run(&endpoint, &config);

        assert_eq!(result, exit_code);
    }

    #[rstest]
    #[case::exit_2(2)]
    #[case::exit_1(1)]
    fn handle_error_exit_code_propagated(#[case] exit_code: i32) {
        let endpoint = MockEndpoint::new(Err("error".to_string())).with_error_exit_code(exit_code);
        let config = Config::default();
        let result = run(&endpoint, &config);

        assert_eq!(result, exit_code);
    }

    #[rstest]
    #[case::exit_0(0)]
    #[case::exit_5(5)]
    fn handle_no_match_exit_code_propagated(#[case] exit_code: i32) {
        let endpoint = MockEndpoint::new(Ok(None)).with_no_match_exit_code(exit_code);
        let config = Config::default();
        let result = run(&endpoint, &config);

        assert_eq!(result, exit_code);
    }

    // --- sandbox_preset is propagated via SandboxInfo::Preset ---

    #[rstest]
    fn allow_with_sandbox_preset_passes_to_handle_action() {
        let endpoint = MockEndpoint::new(Ok(Some("python3 script.py".to_string())));
        let config = make_config(vec![RuleEntry {
            allow: Some("python3 *".to_string()),
            deny: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: Some("restricted".to_string()),
        }]);
        run(&endpoint, &config);

        assert!(*endpoint.called_handle_action.borrow());
        assert!(matches!(
            *endpoint.last_action.borrow(),
            Some(Action::Allow)
        ));
        match &*endpoint.last_sandbox.borrow() {
            Some(SandboxInfo::Preset(Some(preset))) => {
                assert_eq!(preset, "restricted");
            }
            other => panic!("expected SandboxInfo::Preset(Some(\"restricted\")), got {other:?}"),
        }
    }
}
