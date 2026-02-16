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

/// The command to execute, either as an argv array or a raw shell string.
///
/// - `Argv`: A single command with its arguments (e.g., `["git", "status"]`).
///   Used for exec() syscall or direct spawn.
/// - `Shell`: A raw shell command string (e.g., `"cmd1 && cmd2 | cmd3"`).
///   Passed directly to `sh -c` without any transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandInput {
    /// A single command as an argument vector. The first element is the program name.
    Argv(Vec<String>),
    /// A raw shell command string, passed to `sh -c` as-is.
    Shell(String),
}

impl CommandInput {
    /// Returns true if this is a shell command string (compound command).
    pub fn is_compound(&self) -> bool {
        matches!(self, CommandInput::Shell(_))
    }

    /// Returns the program name for validation purposes.
    /// For `Shell` commands, returns `"sh"` since that is the actual program invoked.
    pub fn program(&self) -> &str {
        match self {
            CommandInput::Argv(args) => args.first().map(|s| s.as_str()).unwrap_or(""),
            CommandInput::Shell(_) => "sh",
        }
    }
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
    /// The execution mode is determined by the `CommandInput` variant and `sandbox`:
    /// - `Argv` + no sandbox (Unix): exec() syscall (transparent proxy)
    /// - `Argv` + sandbox: SandboxExecutor via spawn + wait
    /// - `Shell`: sh -c via spawn + wait
    /// - Non-Unix: always spawn + wait
    fn exec(
        &self,
        command: &CommandInput,
        sandbox: Option<&SandboxPolicy>,
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
        command: &CommandInput,
        sandbox: Option<&SandboxPolicy>,
    ) -> Result<i32, ExecError> {
        match command {
            CommandInput::Argv(args) => {
                if args.is_empty() {
                    return Err(ExecError::NotFound(String::new()));
                }
                match self.determine_exec_mode(sandbox, false) {
                    ExecMode::TransparentProxy => exec_transparent_proxy(args),
                    ExecMode::SpawnAndWait => {
                        if let Some(policy) = sandbox {
                            self.sandbox_executor.exec_sandboxed(args, policy)
                        } else {
                            spawn_and_wait(args)
                        }
                    }
                    ExecMode::ShellExec => {
                        unreachable!("ShellExec is not used for Argv commands")
                    }
                }
            }
            CommandInput::Shell(shell_cmd) => {
                let sh_args: Vec<String> = vec!["sh".into(), "-c".into(), shell_cmd.clone()];
                if let Some(policy) = sandbox {
                    self.sandbox_executor.exec_sandboxed(&sh_args, policy)
                } else {
                    spawn_and_wait(&sh_args)
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
            .arg(format!(
                "command -v {}",
                shlex::try_quote(program).map_err(|_| {
                    ExecError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "command name contains NUL byte",
                    ))
                })?
            ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};
    use std::cell::RefCell;

    #[fixture]
    fn executor() -> ProcessCommandExecutor<StubSandboxExecutor> {
        ProcessCommandExecutor::new_without_sandbox()
    }

    // === ExecMode determination ===

    #[rstest]
    #[case::single_no_sandbox(None, false, ExecMode::TransparentProxy)]
    #[case::single_with_sandbox(Some(&SandboxPolicy { _private: () }), false, ExecMode::SpawnAndWait)]
    #[case::compound_no_sandbox(None, true, ExecMode::ShellExec)]
    #[case::compound_with_sandbox(Some(&SandboxPolicy { _private: () }), true, ExecMode::ShellExec)]
    fn determine_exec_mode(
        executor: ProcessCommandExecutor<StubSandboxExecutor>,
        #[case] sandbox: Option<&SandboxPolicy>,
        #[case] is_compound: bool,
        #[case] expected: ExecMode,
    ) {
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

    // === Exit code tests (Shell mode) ===
    //
    // Note: TransparentProxy (exec() syscall) cannot be tested in-process because
    // it replaces the current process. Shell mode tests verify exit code handling.

    #[rstest]
    #[case::success("true", 0)]
    #[case::failure("false", 1)]
    #[case::custom_exit_code("exit 42", 42)]
    #[case::pipeline("echo hello | cat", 0)]
    fn exec_shell_returns_correct_exit_code(
        executor: ProcessCommandExecutor<StubSandboxExecutor>,
        #[case] shell_cmd: &str,
        #[case] expected_code: i32,
    ) {
        let code = executor
            .exec(&CommandInput::Shell(shell_cmd.into()), None)
            .expect("command should complete");
        assert_eq!(code, expected_code);
    }

    #[cfg(unix)]
    #[rstest]
    fn exec_signal_termination_returns_128_plus_signal(
        executor: ProcessCommandExecutor<StubSandboxExecutor>,
    ) {
        // sh -c "kill -9 $$" sends SIGKILL to the shell process itself
        let code = executor
            .exec(&CommandInput::Shell("kill -9 $$".into()), None)
            .expect("should complete");
        // SIGKILL = 9, so exit code should be 128 + 9 = 137
        assert_eq!(code, 137);
    }

    #[rstest]
    fn exec_not_found_returns_error(executor: ProcessCommandExecutor<StubSandboxExecutor>) {
        let result = executor.exec(
            &CommandInput::Shell("__nonexistent_command_12345__".into()),
            None,
        );
        // sh -c will return 127 for command not found
        match result {
            Ok(code) => assert_eq!(code, 127),
            Err(ExecError::NotFound(_)) => {} // also acceptable
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[rstest]
    fn exec_empty_argv_returns_not_found(executor: ProcessCommandExecutor<StubSandboxExecutor>) {
        let result = executor.exec(&CommandInput::Argv(vec![]), None);
        assert!(matches!(result, Err(ExecError::NotFound(_))));
    }

    // === Sandbox execution ===

    #[test]
    fn exec_argv_with_sandbox_calls_sandbox_executor() {
        let executor = ProcessCommandExecutor::new(StubSandboxExecutor);
        let policy = SandboxPolicy { _private: () };

        let result = executor.exec(
            &CommandInput::Argv(vec!["echo".into(), "test".into()]),
            Some(&policy),
        );

        // StubSandboxExecutor returns Unsupported error
        assert!(matches!(result, Err(ExecError::Io(_))));
    }

    #[test]
    fn exec_shell_with_sandbox_calls_sandbox_executor() {
        let executor = ProcessCommandExecutor::new(StubSandboxExecutor);
        let policy = SandboxPolicy { _private: () };

        let result = executor.exec(
            &CommandInput::Shell("echo a && echo b".into()),
            Some(&policy),
        );

        assert!(matches!(result, Err(ExecError::Io(_))));
    }

    // === CommandInput ===

    #[rstest]
    #[case::argv(CommandInput::Argv(vec!["git".into(), "status".into()]), false)]
    #[case::shell(CommandInput::Shell("git status".into()), true)]
    fn command_input_is_compound(#[case] input: CommandInput, #[case] expected: bool) {
        assert_eq!(input.is_compound(), expected);
    }

    #[rstest]
    #[case::argv(CommandInput::Argv(vec!["git".into(), "status".into()]), "git")]
    #[case::shell(CommandInput::Shell("git status".into()), "sh")]
    #[case::empty_argv(CommandInput::Argv(vec![]), "")]
    fn command_input_program(#[case] input: CommandInput, #[case] expected: &str) {
        assert_eq!(input.program(), expected);
    }

    // === Validate ===

    #[rstest]
    #[case::exists(&["sh"], true)]
    #[case::nonexistent(&["__nonexistent_command_12345__"], false)]
    #[case::empty(&[], false)]
    fn validate_command(
        executor: ProcessCommandExecutor<StubSandboxExecutor>,
        #[case] cmd: &[&str],
        #[case] should_succeed: bool,
    ) {
        let command: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
        let result = executor.validate(&command);

        if should_succeed {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(ExecError::NotFound(_))));
        }
    }

    // === exit_code_from_status ===

    #[rstest]
    #[case::success("true", &[], 0)]
    #[case::failure("false", &[], 1)]
    #[case::custom_exit("sh", &["-c", "exit 42"], 42)]
    fn exit_code_from_status_cases(
        #[case] cmd: &str,
        #[case] args: &[&str],
        #[case] expected_code: i32,
    ) {
        let status = Command::new(cmd)
            .args(args)
            .status()
            .expect("command should complete");
        assert_eq!(exit_code_from_status(status), expected_code);
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

    // === Custom SandboxExecutor for testing ===

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
    fn exec_argv_with_mock_sandbox_returns_exit_code() {
        let executor = ProcessCommandExecutor::new(MockSandboxExecutor::new(0));
        let policy = SandboxPolicy { _private: () };

        let code = executor
            .exec(
                &CommandInput::Argv(vec!["echo".into(), "test".into()]),
                Some(&policy),
            )
            .expect("mock sandbox should succeed");
        assert_eq!(code, 0);

        let invocations = executor.sandbox_executor.invocations.borrow();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0], vec!["echo", "test"]);
    }

    #[test]
    fn exec_argv_with_mock_sandbox_nonzero() {
        let executor = ProcessCommandExecutor::new(MockSandboxExecutor::new(42));
        let policy = SandboxPolicy { _private: () };

        let code = executor
            .exec(
                &CommandInput::Argv(vec!["echo".into(), "test".into()]),
                Some(&policy),
            )
            .expect("mock sandbox should succeed");
        assert_eq!(code, 42);
    }

    #[test]
    fn exec_shell_with_mock_sandbox_passes_sh_c() {
        let executor = ProcessCommandExecutor::new(MockSandboxExecutor::new(7));
        let policy = SandboxPolicy { _private: () };

        let code = executor
            .exec(
                &CommandInput::Shell("echo a && echo b".into()),
                Some(&policy),
            )
            .expect("mock sandbox should succeed");
        assert_eq!(code, 7);

        // Shell + sandbox should pass sh -c with the raw shell string
        let invocations = executor.sandbox_executor.invocations.borrow();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0], vec!["sh", "-c", "echo a && echo b"]);
    }
}
