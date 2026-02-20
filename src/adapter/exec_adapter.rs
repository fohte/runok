use crate::adapter::{ActionResult, Endpoint, SandboxInfo};
use crate::config::{ActionKind, Defaults};
use crate::exec::command_executor::{CommandExecutor, CommandInput};
use crate::rules::command_parser::shell_quote_join;
use crate::rules::rule_engine::Action;

/// Sandbox execution wrapper endpoint, invoked internally by hooks via `updatedInput`.
///
/// Receives a command as CLI arguments (`-- <command>`) and evaluates it against
/// the configured rules. Allowed commands are executed via `CommandExecutor`;
/// denied (or ask) commands produce stderr output and exit code 3.
pub struct ExecAdapter {
    args: Vec<String>,
    sandbox_preset: Option<String>,
    executor: Box<dyn CommandExecutor>,
}

impl ExecAdapter {
    pub fn new(
        args: Vec<String>,
        sandbox_preset: Option<String>,
        executor: Box<dyn CommandExecutor>,
    ) -> Self {
        Self {
            args,
            sandbox_preset,
            executor,
        }
    }

    fn command_input(&self) -> CommandInput {
        if self.args.len() == 1 {
            CommandInput::Shell(self.args[0].clone())
        } else {
            CommandInput::Argv(self.args.clone())
        }
    }
}

impl Endpoint for ExecAdapter {
    fn extract_command(&self) -> Result<Option<String>, anyhow::Error> {
        if self.args.is_empty() {
            return Ok(None);
        }
        // Return single arguments unquoted so the rule engine can detect
        // shell metacharacters (&&, ;, |) in compound commands.
        if self.args.len() == 1 {
            return Ok(Some(self.args[0].clone()));
        }
        Ok(Some(shell_quote_join(&self.args)))
    }

    fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
        match result.action {
            Action::Allow => {
                let command_input = self.command_input();

                // Determine sandbox policy from the result or from the constructor preset
                let sandbox = match result.sandbox {
                    SandboxInfo::Preset(ref preset) => {
                        // Use the rule's preset, falling back to the constructor preset
                        preset.as_ref().or(self.sandbox_preset.as_ref())
                    }
                    SandboxInfo::MergedPolicy(_) => {
                        // MergedPolicy is for compound commands; sandbox execution
                        // with merged policies is not yet implemented (Phase 2)
                        None
                    }
                };

                // Sandbox execution is Phase 2; for now, execute without sandbox
                let _ = sandbox;
                let exit_code = self.executor.exec(&command_input, None)?;
                Ok(exit_code)
            }
            Action::Deny(deny_response) => {
                let msg = deny_response
                    .message
                    .unwrap_or_else(|| format!("command denied: {}", deny_response.matched_rule));
                eprintln!("runok: {}", msg);
                if let Some(suggestion) = deny_response.fix_suggestion {
                    eprintln!("runok: suggestion: {}", suggestion);
                }
                Ok(3)
            }
            Action::Ask(message) => {
                // Ask is treated as deny in exec mode
                let msg = message.unwrap_or_else(|| "command requires confirmation".to_string());
                eprintln!("runok: {}", msg);
                Ok(3)
            }
            Action::Default => {
                // Should not reach here; run() handles Default before calling handle_action
                Ok(0)
            }
        }
    }

    fn handle_no_match(&self, defaults: &Defaults) -> Result<i32, anyhow::Error> {
        match defaults.action {
            Some(ActionKind::Allow) | None => {
                if self.args.is_empty() {
                    return Ok(0);
                }
                let command_input = self.command_input();
                let exit_code = self.executor.exec(&command_input, None)?;
                Ok(exit_code)
            }
            Some(ActionKind::Deny) => {
                eprintln!("runok: command denied by default policy");
                Ok(3)
            }
            Some(ActionKind::Ask) => {
                // Ask is treated as deny in exec mode
                eprintln!("runok: command requires confirmation (default policy)");
                Ok(3)
            }
        }
    }

    fn handle_error(&self, error: anyhow::Error) -> i32 {
        eprintln!("runok: error: {}", error);
        1
    }

    fn handle_dry_run(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
        match &result.action {
            Action::Allow => {
                eprintln!("runok: dry-run: command would be allowed");
            }
            Action::Deny(deny_response) => {
                let msg = deny_response
                    .message
                    .as_deref()
                    .unwrap_or("command would be denied");
                eprintln!("runok: dry-run: {}", msg);
                if let Some(suggestion) = &deny_response.fix_suggestion {
                    eprintln!("runok: dry-run: suggestion: {}", suggestion);
                }
            }
            Action::Ask(message) => {
                let msg = message
                    .as_deref()
                    .unwrap_or("command would require confirmation");
                eprintln!("runok: dry-run: {}", msg);
            }
            Action::Default => {
                eprintln!("runok: dry-run: no matching rule (default behavior)");
            }
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::ExecError;
    use crate::exec::command_executor::{CommandInput, DryRunResult, ExecMode, SandboxPolicy};
    use crate::rules::rule_engine::DenyResponse;
    use rstest::rstest;
    use std::cell::RefCell;

    struct MockExecutor {
        exit_code: i32,
        last_command: RefCell<Option<CommandInput>>,
    }

    impl MockExecutor {
        fn new(exit_code: i32) -> Self {
            Self {
                exit_code,
                last_command: RefCell::new(None),
            }
        }
    }

    impl CommandExecutor for MockExecutor {
        fn exec(
            &self,
            command: &CommandInput,
            _sandbox: Option<&SandboxPolicy>,
        ) -> Result<i32, ExecError> {
            *self.last_command.borrow_mut() = Some(command.clone());
            Ok(self.exit_code)
        }

        fn validate(&self, _command: &[String]) -> Result<(), ExecError> {
            Ok(())
        }

        fn dry_run(
            &self,
            _command: &CommandInput,
            _sandbox: Option<&SandboxPolicy>,
        ) -> DryRunResult {
            DryRunResult {
                program: String::new(),
                exec_mode: ExecMode::SpawnAndWait,
                is_valid: true,
                error: None,
            }
        }

        fn determine_exec_mode(
            &self,
            _sandbox: Option<&SandboxPolicy>,
            _is_compound: bool,
        ) -> ExecMode {
            ExecMode::SpawnAndWait
        }
    }

    struct CapturingExecutor {
        captured: std::sync::Arc<std::sync::Mutex<Option<CommandInput>>>,
    }

    impl CommandExecutor for CapturingExecutor {
        fn exec(
            &self,
            command: &CommandInput,
            _sandbox: Option<&SandboxPolicy>,
        ) -> Result<i32, ExecError> {
            *self.captured.lock().unwrap() = Some(command.clone());
            Ok(0)
        }

        fn validate(&self, _command: &[String]) -> Result<(), ExecError> {
            Ok(())
        }

        fn dry_run(
            &self,
            _command: &CommandInput,
            _sandbox: Option<&SandboxPolicy>,
        ) -> DryRunResult {
            DryRunResult {
                program: String::new(),
                exec_mode: ExecMode::SpawnAndWait,
                is_valid: true,
                error: None,
            }
        }

        fn determine_exec_mode(
            &self,
            _sandbox: Option<&SandboxPolicy>,
            _is_compound: bool,
        ) -> ExecMode {
            ExecMode::SpawnAndWait
        }
    }

    // --- extract_command ---

    #[rstest]
    #[case::empty_args(vec![], None)]
    #[case::single_arg(vec!["git".into()], Some("git".to_string()))]
    #[case::single_compound_arg(
        vec!["echo hello && echo world".into()],
        Some("echo hello && echo world".to_string())
    )]
    #[case::multiple_args(
        vec!["git".into(), "status".into()],
        Some("git status".to_string())
    )]
    #[case::args_with_spaces(
        vec!["echo".into(), "hello world".into()],
        Some("echo 'hello world'".to_string())
    )]
    fn extract_command_returns_expected(
        #[case] args: Vec<String>,
        #[case] expected: Option<String>,
    ) {
        let adapter = ExecAdapter::new(args, None, Box::new(MockExecutor::new(0)));
        let result = adapter.extract_command().unwrap();
        assert_eq!(result, expected);
    }

    // --- handle_action: Allow ---

    #[rstest]
    #[case::exit_0(0)]
    #[case::exit_1(1)]
    #[case::exit_42(42)]
    fn handle_action_allow_executes_and_returns_exit_code(#[case] exit_code: i32) {
        let adapter = ExecAdapter::new(
            vec!["git".into(), "status".into()],
            None,
            Box::new(MockExecutor::new(exit_code)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Allow,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, exit_code);
    }

    #[rstest]
    fn handle_action_allow_with_merged_policy() {
        let adapter = ExecAdapter::new(
            vec!["git".into(), "status".into()],
            Some("default-preset".into()),
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Allow,
                sandbox: SandboxInfo::MergedPolicy(None),
            })
            .unwrap();
        assert_eq!(result, 0);
    }

    // --- handle_action: Deny ---

    #[rstest]
    fn handle_action_deny_with_fix_suggestion() {
        let adapter = ExecAdapter::new(
            vec!["rm".into(), "-rf".into(), "/".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Deny(DenyResponse {
                    message: Some("dangerous command".to_string()),
                    fix_suggestion: Some("use rm with specific paths".to_string()),
                    matched_rule: "rm -rf /".to_string(),
                }),
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, 3);
    }

    #[rstest]
    #[case::with_message(Some("dangerous command".to_string()))]
    #[case::without_message(None)]
    fn handle_action_deny_returns_exit_3(#[case] message: Option<String>) {
        let adapter = ExecAdapter::new(
            vec!["rm".into(), "-rf".into(), "/".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Deny(DenyResponse {
                    message,
                    fix_suggestion: None,
                    matched_rule: "rm -rf /".to_string(),
                }),
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, 3);
    }

    // --- handle_action: Ask (treated as deny) ---

    #[rstest]
    #[case::with_message(Some("please confirm".to_string()))]
    #[case::without_message(None)]
    fn handle_action_ask_returns_exit_3(#[case] message: Option<String>) {
        let adapter = ExecAdapter::new(
            vec!["terraform".into(), "apply".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Ask(message),
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, 3);
    }

    // --- handle_action: Default ---

    #[rstest]
    fn handle_action_default_returns_exit_0() {
        let adapter = ExecAdapter::new(
            vec!["git".into(), "status".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Default,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, 0);
    }

    // --- handle_no_match ---

    #[rstest]
    #[case::allow_default(Some(ActionKind::Allow), 0, true)]
    #[case::none_default(None, 0, true)]
    #[case::deny_default(Some(ActionKind::Deny), 3, false)]
    #[case::ask_default(Some(ActionKind::Ask), 3, false)]
    fn handle_no_match_follows_defaults(
        #[case] default_action: Option<ActionKind>,
        #[case] expected_exit_code: i32,
        #[case] should_execute: bool,
    ) {
        let executor = std::sync::Arc::new(std::sync::Mutex::new(false));
        let executor_clone = executor.clone();

        struct TrackingExecutor {
            exit_code: i32,
            executed: std::sync::Arc<std::sync::Mutex<bool>>,
        }

        impl CommandExecutor for TrackingExecutor {
            fn exec(
                &self,
                _command: &CommandInput,
                _sandbox: Option<&SandboxPolicy>,
            ) -> Result<i32, ExecError> {
                *self.executed.lock().unwrap() = true;
                Ok(self.exit_code)
            }

            fn validate(&self, _command: &[String]) -> Result<(), ExecError> {
                Ok(())
            }

            fn dry_run(
                &self,
                _command: &CommandInput,
                _sandbox: Option<&SandboxPolicy>,
            ) -> DryRunResult {
                DryRunResult {
                    program: String::new(),
                    exec_mode: ExecMode::SpawnAndWait,
                    is_valid: true,
                    error: None,
                }
            }

            fn determine_exec_mode(
                &self,
                _sandbox: Option<&SandboxPolicy>,
                _is_compound: bool,
            ) -> ExecMode {
                ExecMode::SpawnAndWait
            }
        }

        let adapter = ExecAdapter::new(
            vec!["some-command".into()],
            None,
            Box::new(TrackingExecutor {
                exit_code: 0,
                executed: executor_clone,
            }),
        );

        let defaults = Defaults {
            action: default_action,
            sandbox: None,
        };
        let result = adapter.handle_no_match(&defaults).unwrap();
        assert_eq!(result, expected_exit_code);
        assert_eq!(*executor.lock().unwrap(), should_execute);
    }

    #[rstest]
    fn handle_no_match_empty_args_returns_0() {
        let adapter = ExecAdapter::new(vec![], None, Box::new(MockExecutor::new(0)));
        let defaults = Defaults {
            action: None,
            sandbox: None,
        };
        let result = adapter.handle_no_match(&defaults).unwrap();
        assert_eq!(result, 0);
    }

    // --- handle_error ---

    #[rstest]
    fn handle_error_returns_exit_1() {
        let adapter = ExecAdapter::new(vec![], None, Box::new(MockExecutor::new(0)));
        let result = adapter.handle_error(anyhow::anyhow!("something went wrong"));
        assert_eq!(result, 1);
    }

    // --- command_input dispatching ---

    #[rstest]
    #[case::single_arg_shell(
        vec!["echo hello && echo world".into()],
        CommandInput::Shell("echo hello && echo world".to_string())
    )]
    #[case::multiple_args_argv(
        vec!["git".into(), "status".into()],
        CommandInput::Argv(vec!["git".into(), "status".into()])
    )]
    fn handle_action_dispatches_correct_command_input(
        #[case] args: Vec<String>,
        #[case] expected: CommandInput,
    ) {
        let executed_command: std::sync::Arc<std::sync::Mutex<Option<CommandInput>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));

        let adapter = ExecAdapter::new(
            args,
            None,
            Box::new(CapturingExecutor {
                captured: executed_command.clone(),
            }),
        );

        adapter
            .handle_action(ActionResult {
                action: Action::Allow,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();

        let captured = executed_command.lock().unwrap();
        assert_eq!(*captured, Some(expected));
    }

    // --- handle_dry_run ---

    #[rstest]
    #[case::allow(Action::Allow, 0)]
    #[case::deny(
        Action::Deny(DenyResponse {
            message: Some("dangerous".to_string()),
            fix_suggestion: Some("use safer command".to_string()),
            matched_rule: "rm *".to_string(),
        }),
        0
    )]
    #[case::ask(
        Action::Ask(Some("please confirm".to_string())),
        0
    )]
    #[case::default_action(Action::Default, 0)]
    fn handle_dry_run_always_returns_exit_0(
        #[case] action: Action,
        #[case] expected_exit_code: i32,
    ) {
        let adapter = ExecAdapter::new(
            vec!["git".into(), "status".into()],
            None,
            Box::new(MockExecutor::new(42)),
        );
        let result = adapter
            .handle_dry_run(ActionResult {
                action,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, expected_exit_code);
    }

    #[rstest]
    fn handle_dry_run_does_not_execute_command() {
        let captured: std::sync::Arc<std::sync::Mutex<Option<CommandInput>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));

        let adapter = ExecAdapter::new(
            vec!["git".into(), "status".into()],
            None,
            Box::new(CapturingExecutor {
                captured: captured.clone(),
            }),
        );

        adapter
            .handle_dry_run(ActionResult {
                action: Action::Allow,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();

        // Command should NOT be executed in dry-run mode
        assert!(captured.lock().unwrap().is_none());
    }
}
