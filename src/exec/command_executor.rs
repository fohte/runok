use std::process::Command;

use super::ExecError;

/// The execution mode for a command, determined by command form and sandbox presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Replace the current process via exec() syscall (single command, no sandbox, Unix only).
    TransparentProxy,
    /// Spawn a child process and wait for it to finish.
    SpawnAndWait,
    /// Execute via `sh -c "..."` as a child process (compound commands).
    ShellExec,
}

/// Stub sandbox policy for Phase 2. The actual implementation will provide
/// filesystem and network restrictions.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    _private: (),
}

/// Trait for executing commands in a sandboxed environment.
///
/// Phase 2 will provide real implementations (macOS seatbelt, Linux landlock/seccomp).
/// For now, only a stub is provided.
pub trait SandboxExecutor {
    /// Execute a command within a sandbox, returning the exit code.
    fn exec_sandboxed(&self, command: &[String], policy: &SandboxPolicy) -> Result<i32, ExecError>;
}

/// Stub sandbox executor that returns an error indicating sandbox is not yet supported.
pub struct StubSandboxExecutor;

impl SandboxExecutor for StubSandboxExecutor {
    fn exec_sandboxed(
        &self,
        _command: &[String],
        _policy: &SandboxPolicy,
    ) -> Result<i32, ExecError> {
        Err(ExecError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "sandbox execution is not yet implemented",
        )))
    }
}

/// Trait for executing commands and returning exit codes.
pub trait CommandExecutor {
    /// Execute a command and return the exit code.
    ///
    /// The execution mode is determined by `is_compound` and `sandbox`:
    /// - Single command + no sandbox (Unix): exec() syscall (transparent proxy)
    /// - Single command + sandbox: SandboxExecutor via spawn + wait
    /// - Compound command: sh -c "..." via spawn + wait
    /// - Non-Unix: always spawn + wait
    fn exec(
        &self,
        command: &[String],
        sandbox: Option<&SandboxPolicy>,
        is_compound: bool,
    ) -> Result<i32, ExecError>;

    /// Check that the command exists and is executable (for dry-run validation).
    fn validate(&self, command: &[String]) -> Result<(), ExecError>;

    /// Determine the execution mode based on sandbox presence and command form.
    fn determine_exec_mode(&self, sandbox: Option<&SandboxPolicy>, is_compound: bool) -> ExecMode;
}

/// Default command executor that dispatches to exec(), spawn+wait, or sh -c
/// depending on command form and sandbox presence.
pub struct ProcessCommandExecutor<S: SandboxExecutor> {
    sandbox_executor: S,
}

impl<S: SandboxExecutor> ProcessCommandExecutor<S> {
    pub fn new(sandbox_executor: S) -> Self {
        Self { sandbox_executor }
    }
}

impl ProcessCommandExecutor<StubSandboxExecutor> {
    /// Create a ProcessCommandExecutor with the stub sandbox executor.
    pub fn new_without_sandbox() -> Self {
        Self::new(StubSandboxExecutor)
    }
}

impl<S: SandboxExecutor> CommandExecutor for ProcessCommandExecutor<S> {
    fn exec(
        &self,
        command: &[String],
        sandbox: Option<&SandboxPolicy>,
        is_compound: bool,
    ) -> Result<i32, ExecError> {
        if command.is_empty() {
            return Err(ExecError::NotFound(String::new()));
        }

        match self.determine_exec_mode(sandbox, is_compound) {
            ExecMode::TransparentProxy => exec_transparent_proxy(command),
            ExecMode::SpawnAndWait => {
                if let Some(policy) = sandbox {
                    self.sandbox_executor.exec_sandboxed(command, policy)
                } else {
                    spawn_and_wait(command)
                }
            }
            ExecMode::ShellExec => {
                let shell_cmd = command.join(" ");
                if let Some(policy) = sandbox {
                    self.sandbox_executor
                        .exec_sandboxed(&["sh".into(), "-c".into(), shell_cmd], policy)
                } else {
                    spawn_and_wait(&["sh".into(), "-c".into(), shell_cmd])
                }
            }
        }
    }

    fn validate(&self, command: &[String]) -> Result<(), ExecError> {
        if command.is_empty() {
            return Err(ExecError::NotFound(String::new()));
        }

        let program = &command[0];

        // Check if the command exists and is executable using `which`-style lookup.
        // On Unix, we use std::process::Command to probe. On all platforms,
        // attempting to resolve the command via the shell is a simple approach.
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {}", shell_escape(program)))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(ExecError::Io)?;

        if status.success() {
            Ok(())
        } else {
            Err(ExecError::NotFound(program.clone()))
        }
    }

    fn determine_exec_mode(&self, sandbox: Option<&SandboxPolicy>, is_compound: bool) -> ExecMode {
        if is_compound {
            return ExecMode::ShellExec;
        }

        if sandbox.is_some() {
            return ExecMode::SpawnAndWait;
        }

        if cfg!(unix) {
            ExecMode::TransparentProxy
        } else {
            ExecMode::SpawnAndWait
        }
    }
}

/// Replace the current process with the given command using exec() syscall.
///
/// On Unix, this calls execvp which never returns on success.
/// On non-Unix, falls back to spawn + wait.
fn exec_transparent_proxy(command: &[String]) -> Result<i32, ExecError> {
    #[cfg(unix)]
    {
        use std::ffi::CString;

        let c_args: Vec<CString> = command
            .iter()
            .map(|arg| {
                CString::new(arg.as_bytes()).map_err(|e| {
                    ExecError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("command argument contains NUL byte: {e}"),
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let c_arg_ptrs: Vec<*const libc::c_char> = c_args
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // execvp replaces the current process image. It only returns on error.
        // SAFETY: c_arg_ptrs is a null-terminated array of valid C string pointers.
        // The CString values in c_args are alive for the duration of this call.
        unsafe {
            libc::execvp(c_args[0].as_ptr(), c_arg_ptrs.as_ptr());
        }

        // execvp only returns on error
        let errno = std::io::Error::last_os_error();
        match errno.raw_os_error() {
            Some(libc::ENOENT) => Err(ExecError::NotFound(command[0].clone())),
            Some(libc::EACCES) => Err(ExecError::PermissionDenied(command[0].clone())),
            _ => Err(ExecError::Io(errno)),
        }
    }

    #[cfg(not(unix))]
    {
        spawn_and_wait(command)
    }
}

/// Spawn a child process and wait for it to finish, returning the exit code.
fn spawn_and_wait(command: &[String]) -> Result<i32, ExecError> {
    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ExecError::NotFound(command[0].clone()),
            std::io::ErrorKind::PermissionDenied => ExecError::PermissionDenied(command[0].clone()),
            _ => ExecError::Io(e),
        })?;

    Ok(exit_code_from_status(status))
}

/// Extract the exit code from a process exit status.
///
/// On Unix, if the process was killed by a signal, return 128 + signal number
/// (standard shell convention). On other platforms, default to 1 for non-zero exits.
fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    // Process was terminated by a signal (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    // Fallback for platforms where neither code nor signal is available
    1
}

/// Simple shell escaping for use in `command -v` lookups.
/// Wraps the string in single quotes, escaping any embedded single quotes.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === ExecMode determination ===

    #[rstest]
    #[case::single_no_sandbox(None, false, ExecMode::TransparentProxy)]
    #[case::single_with_sandbox(Some(&SandboxPolicy { _private: () }), false, ExecMode::SpawnAndWait)]
    #[case::compound_no_sandbox(None, true, ExecMode::ShellExec)]
    #[case::compound_with_sandbox(Some(&SandboxPolicy { _private: () }), true, ExecMode::ShellExec)]
    fn determine_exec_mode(
        #[case] sandbox: Option<&SandboxPolicy>,
        #[case] is_compound: bool,
        #[case] expected: ExecMode,
    ) {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        let mode = executor.determine_exec_mode(sandbox, is_compound);

        if cfg!(unix) {
            assert_eq!(mode, expected);
        } else {
            // On non-Unix, TransparentProxy falls back to SpawnAndWait
            let non_unix_expected = match expected {
                ExecMode::TransparentProxy => ExecMode::SpawnAndWait,
                other => other,
            };
            assert_eq!(mode, non_unix_expected);
        }
    }

    // === Exit code tests ===
    //
    // Note: TransparentProxy (exec() syscall) cannot be tested in-process because
    // it replaces the current process. The exec() path is tested via spawn+wait
    // by using is_compound=true or sandbox=Some to force SpawnAndWait/ShellExec mode.

    #[test]
    fn exec_spawn_returns_zero_on_success() {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        // Use compound mode to force ShellExec (avoids exec() replacing test process)
        let code = executor
            .exec(&["true".into()], None, true)
            .expect("true should succeed");
        assert_eq!(code, 0);
    }

    #[test]
    fn exec_shell_exec_returns_nonzero() {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        let code = executor
            .exec(&["false".into()], None, true)
            .expect("false should complete");
        assert_eq!(code, 1);
    }

    #[test]
    fn exec_compound_command_returns_exit_code() {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        let code = executor
            .exec(&["exit".into(), "42".into()], None, true)
            .expect("sh -c should complete");
        assert_eq!(code, 42);
    }

    #[test]
    fn exec_compound_command_pipeline() {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        let code = executor
            .exec(
                &["echo".into(), "hello".into(), "|".into(), "cat".into()],
                None,
                true,
            )
            .expect("pipeline should complete");
        assert_eq!(code, 0);
    }

    #[cfg(unix)]
    #[test]
    fn exec_signal_termination_returns_128_plus_signal() {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        // sh -c "kill -9 $$" sends SIGKILL to the shell process itself
        let code = executor
            .exec(
                &["kill".into(), "-9".into(), "$$".into()],
                None,
                true, // compound to use sh -c
            )
            .expect("should complete");
        // SIGKILL = 9, so exit code should be 128 + 9 = 137
        assert_eq!(code, 137);
    }

    #[test]
    fn exec_not_found_returns_error() {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        let result = executor.exec(
            &["__nonexistent_command_12345__".into()],
            None,
            true, // compound to force spawn+wait
        );
        // sh -c will return 127 for command not found
        match result {
            Ok(code) => assert_eq!(code, 127),
            Err(ExecError::NotFound(_)) => {} // also acceptable
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn exec_empty_command_returns_not_found() {
        let executor = ProcessCommandExecutor::new_without_sandbox();

        let result = executor.exec(&[], None, false);
        assert!(matches!(result, Err(ExecError::NotFound(_))));
    }

    // === Sandbox execution ===

    #[test]
    fn exec_with_sandbox_calls_sandbox_executor() {
        let executor = ProcessCommandExecutor::new(StubSandboxExecutor);
        let policy = SandboxPolicy { _private: () };

        let result = executor.exec(&["echo".into(), "test".into()], Some(&policy), false);

        // StubSandboxExecutor returns Unsupported error
        assert!(matches!(result, Err(ExecError::Io(_))));
    }

    #[test]
    fn exec_compound_with_sandbox_calls_sandbox_executor() {
        let executor = ProcessCommandExecutor::new(StubSandboxExecutor);
        let policy = SandboxPolicy { _private: () };

        let result = executor.exec(
            &[
                "echo".into(),
                "a".into(),
                "&&".into(),
                "echo".into(),
                "b".into(),
            ],
            Some(&policy),
            true,
        );

        assert!(matches!(result, Err(ExecError::Io(_))));
    }

    // === Validate ===

    #[test]
    fn validate_existing_command() {
        let executor = ProcessCommandExecutor::new_without_sandbox();
        assert!(executor.validate(&["sh".into()]).is_ok());
    }

    #[test]
    fn validate_nonexistent_command() {
        let executor = ProcessCommandExecutor::new_without_sandbox();
        let result = executor.validate(&["__nonexistent_command_12345__".into()]);
        assert!(matches!(result, Err(ExecError::NotFound(_))));
    }

    #[test]
    fn validate_empty_command() {
        let executor = ProcessCommandExecutor::new_without_sandbox();
        let result = executor.validate(&[]);
        assert!(matches!(result, Err(ExecError::NotFound(_))));
    }

    // === exit_code_from_status ===

    #[test]
    fn exit_code_from_successful_status() {
        let status = Command::new("true").status().expect("true should succeed");
        assert_eq!(exit_code_from_status(status), 0);
    }

    #[test]
    fn exit_code_from_failed_status() {
        let status = Command::new("false")
            .status()
            .expect("false should complete");
        assert_eq!(exit_code_from_status(status), 1);
    }

    #[test]
    fn exit_code_from_custom_exit() {
        let status = Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .status()
            .expect("sh should complete");
        assert_eq!(exit_code_from_status(status), 42);
    }

    #[cfg(unix)]
    #[test]
    fn exit_code_from_signal() {
        let status = Command::new("sh")
            .arg("-c")
            .arg("kill -9 $$")
            .status()
            .expect("sh should complete");
        assert_eq!(exit_code_from_status(status), 137); // 128 + SIGKILL(9)
    }

    // === shell_escape ===

    #[rstest]
    #[case::simple("echo", "'echo'")]
    #[case::with_spaces("hello world", "'hello world'")]
    #[case::with_single_quote("it's", "'it'\\''s'")]
    fn shell_escape_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(shell_escape(input), expected);
    }

    // === Custom SandboxExecutor for testing ===

    use std::cell::RefCell;

    struct MockSandboxExecutor {
        exit_code: i32,
        invocations: RefCell<Vec<Vec<String>>>,
    }

    impl MockSandboxExecutor {
        fn new(exit_code: i32) -> Self {
            Self {
                exit_code,
                invocations: RefCell::new(Vec::new()),
            }
        }
    }

    impl SandboxExecutor for MockSandboxExecutor {
        fn exec_sandboxed(
            &self,
            command: &[String],
            _policy: &SandboxPolicy,
        ) -> Result<i32, ExecError> {
            self.invocations.borrow_mut().push(command.to_vec());
            Ok(self.exit_code)
        }
    }

    #[test]
    fn exec_with_mock_sandbox_returns_exit_code() {
        let executor = ProcessCommandExecutor::new(MockSandboxExecutor::new(0));
        let policy = SandboxPolicy { _private: () };

        let code = executor
            .exec(&["echo".into(), "test".into()], Some(&policy), false)
            .expect("mock sandbox should succeed");
        assert_eq!(code, 0);

        let invocations = executor.sandbox_executor.invocations.borrow();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0], vec!["echo", "test"]);
    }

    #[test]
    fn exec_with_mock_sandbox_nonzero() {
        let executor = ProcessCommandExecutor::new(MockSandboxExecutor::new(42));
        let policy = SandboxPolicy { _private: () };

        let code = executor
            .exec(&["echo".into(), "test".into()], Some(&policy), false)
            .expect("mock sandbox should succeed");
        assert_eq!(code, 42);
    }

    #[test]
    fn exec_compound_with_mock_sandbox_wraps_in_sh() {
        let executor = ProcessCommandExecutor::new(MockSandboxExecutor::new(7));
        let policy = SandboxPolicy { _private: () };

        let code = executor
            .exec(
                &[
                    "echo".into(),
                    "a".into(),
                    "&&".into(),
                    "echo".into(),
                    "b".into(),
                ],
                Some(&policy),
                true,
            )
            .expect("mock sandbox should succeed");
        assert_eq!(code, 7);

        // Compound + sandbox should wrap the command in sh -c
        let invocations = executor.sandbox_executor.invocations.borrow();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0], vec!["sh", "-c", "echo a && echo b"]);
    }
}
