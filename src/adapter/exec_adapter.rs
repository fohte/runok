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
}

impl Endpoint for ExecAdapter {
    fn extract_command(&self) -> Result<Option<String>, anyhow::Error> {
        if self.args.is_empty() {
            return Ok(None);
        }
        Ok(Some(shell_quote_join(&self.args)))
    }

    fn handle_action(&self, result: ActionResult) -> Result<i32, anyhow::Error> {
        match result.action {
            Action::Allow => {
                let command_input = if self.args.len() == 1 {
                    // Single token might be a compound command (e.g., "cmd1 && cmd2")
                    CommandInput::Shell(self.args[0].clone())
                } else {
                    CommandInput::Argv(self.args.clone())
                };

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
                // Execute the command
                let command_input = if self.args.len() == 1 {
                    CommandInput::Shell(self.args[0].clone())
                } else {
                    CommandInput::Argv(self.args.clone())
                };
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

    // --- extract_command ---

    #[rstest]
    #[case::empty_args(vec![], None)]
    #[case::single_arg(vec!["git".into()], Some("git".to_string()))]
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

    // --- handle_action: Deny ---

    #[rstest]
    fn handle_action_deny_returns_exit_3() {
        let adapter = ExecAdapter::new(
            vec!["rm".into(), "-rf".into(), "/".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Deny(DenyResponse {
                    message: Some("dangerous command".to_string()),
                    fix_suggestion: None,
                    matched_rule: "rm -rf /".to_string(),
                }),
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, 3);
    }

    #[rstest]
    fn handle_action_deny_without_message_uses_default() {
        let adapter = ExecAdapter::new(
            vec!["rm".into(), "-rf".into(), "/".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Deny(DenyResponse {
                    message: None,
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
    fn handle_action_ask_returns_exit_3() {
        let adapter = ExecAdapter::new(
            vec!["terraform".into(), "apply".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Ask(Some("please confirm".to_string())),
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, 3);
    }

    #[rstest]
    fn handle_action_ask_without_message_returns_exit_3() {
        let adapter = ExecAdapter::new(
            vec!["terraform".into(), "apply".into()],
            None,
            Box::new(MockExecutor::new(0)),
        );
        let result = adapter
            .handle_action(ActionResult {
                action: Action::Ask(None),
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();
        assert_eq!(result, 3);
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

    // --- handle_error ---

    #[rstest]
    fn handle_error_returns_exit_1() {
        let adapter = ExecAdapter::new(vec![], None, Box::new(MockExecutor::new(0)));
        let result = adapter.handle_error(anyhow::anyhow!("something went wrong"));
        assert_eq!(result, 1);
    }

    // --- single arg treated as shell command ---

    #[rstest]
    fn single_arg_uses_shell_command_input() {
        let executed_command: std::sync::Arc<std::sync::Mutex<Option<CommandInput>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let executed_clone = executed_command.clone();

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

        let adapter = ExecAdapter::new(
            vec!["echo hello && echo world".into()],
            None,
            Box::new(CapturingExecutor {
                captured: executed_clone,
            }),
        );

        adapter
            .handle_action(ActionResult {
                action: Action::Allow,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();

        let captured = executed_command.lock().unwrap();
        assert_eq!(
            *captured,
            Some(CommandInput::Shell("echo hello && echo world".to_string()))
        );
    }

    #[rstest]
    fn multiple_args_uses_argv_command_input() {
        let executed_command: std::sync::Arc<std::sync::Mutex<Option<CommandInput>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let executed_clone = executed_command.clone();

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

        let adapter = ExecAdapter::new(
            vec!["git".into(), "status".into()],
            None,
            Box::new(CapturingExecutor {
                captured: executed_clone,
            }),
        );

        adapter
            .handle_action(ActionResult {
                action: Action::Allow,
                sandbox: SandboxInfo::Preset(None),
            })
            .unwrap();

        let captured = executed_command.lock().unwrap();
        assert_eq!(
            *captured,
            Some(CommandInput::Argv(vec!["git".into(), "status".into()]))
        );
    }
}
