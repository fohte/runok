use std::borrow::Cow;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

use super::ExecError;
use super::error::SandboxError;

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

/// Sandbox policy defining filesystem and network restrictions for command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Writable root directories (cwd is always included by the caller).
    pub writable_roots: Vec<PathBuf>,
    /// Read-only subpaths that are always protected (e.g., .git, .runok).
    pub read_only_subpaths: Vec<PathBuf>,
    /// Whether network access is allowed.
    pub network_allowed: bool,
}

/// Protected paths that are automatically added to read_only_subpaths.
const PROTECTED_PATHS: &[&str] = &[".git", ".gitmodules", ".runok"];

impl SandboxPolicy {
    /// Build a `SandboxPolicy` from writable roots, read-only subpaths, and network flag.
    ///
    /// Automatically adds protected paths (.git, .gitmodules, .runok) to read_only_subpaths
    /// and normalizes all paths.
    ///
    /// - `writable_roots` are canonicalized to prevent TOCTOU attacks via symlinks.
    ///   Returns an error if any writable path cannot be canonicalized.
    /// - `read_only_subpaths` (deny paths) only have `~` expanded, not canonicalized,
    ///   because they may contain glob patterns (e.g., `.env*`, `~/.ssh/**`).
    pub fn build(
        writable_roots: Vec<String>,
        read_only_subpaths: Vec<String>,
        network_allowed: bool,
    ) -> Result<Self, SandboxError> {
        let mut resolved_writable: Vec<PathBuf> = Vec::new();
        for path in &writable_roots {
            let expanded = expand_tilde(path);
            let canonical = canonicalize_path(&expanded)?;
            resolved_writable.push(canonical);
        }
        resolved_writable.sort();
        resolved_writable.dedup();

        // Deny paths may contain glob patterns (e.g., `.env*`, `~/.ssh/**`, `/etc/**`)
        // from expanded `<path:name>` references, so they cannot be canonicalized.
        // Only expand `~` to $HOME.
        let mut readonly_set: HashSet<PathBuf> = HashSet::new();
        for path in &read_only_subpaths {
            let expanded = expand_tilde(path);
            readonly_set.insert(PathBuf::from(expanded));
        }

        // Protected paths are relative markers resolved at sandbox enforcement time,
        // so they are added without canonicalization.
        for protected in PROTECTED_PATHS {
            readonly_set.insert(PathBuf::from(protected));
        }

        let mut resolved_readonly: Vec<PathBuf> = readonly_set.into_iter().collect();
        resolved_readonly.sort();

        Ok(SandboxPolicy {
            writable_roots: resolved_writable,
            read_only_subpaths: resolved_readonly,
            network_allowed,
        })
    }

    /// Merge multiple policies using Strictest Wins strategy.
    ///
    /// - `writable_roots`: intersection (narrowest write scope)
    /// - `read_only_subpaths`: union (broadest protection)
    /// - `network_allowed`: false if any policy disallows it
    ///
    /// Returns an error if the resulting writable_roots is empty (conflicting constraints).
    pub fn merge(policies: &[SandboxPolicy]) -> Result<SandboxPolicy, SandboxError> {
        if policies.is_empty() {
            return Err(SandboxError::SetupFailed(
                "no policies to merge".to_string(),
            ));
        }
        if policies.len() == 1 {
            return Ok(policies[0].clone());
        }

        // writable_roots: intersection
        let mut writable_set: HashSet<PathBuf> =
            policies[0].writable_roots.iter().cloned().collect();
        for policy in &policies[1..] {
            let other: HashSet<PathBuf> = policy.writable_roots.iter().cloned().collect();
            writable_set = writable_set.intersection(&other).cloned().collect();
        }

        // Empty intersection is a conflict only when at least one policy
        // declared writable roots. If all policies have empty writable_roots,
        // they agree on "no writes allowed".
        let any_has_writable = policies.iter().any(|p| !p.writable_roots.is_empty());
        if writable_set.is_empty() && any_has_writable {
            return Err(SandboxError::SetupFailed(
                "conflicting sandbox policies: no common writable roots".to_string(),
            ));
        }

        // read_only_subpaths: union
        let mut readonly_set: HashSet<PathBuf> = HashSet::new();
        for policy in policies {
            readonly_set.extend(policy.read_only_subpaths.iter().cloned());
        }

        // network_allowed: all must be true
        let network_allowed = policies.iter().all(|p| p.network_allowed);

        let mut writable_roots: Vec<PathBuf> = writable_set.into_iter().collect();
        writable_roots.sort();

        let mut read_only_subpaths: Vec<PathBuf> = readonly_set.into_iter().collect();
        read_only_subpaths.sort();

        Ok(SandboxPolicy {
            writable_roots,
            read_only_subpaths,
            network_allowed,
        })
    }
}

/// Expand `~` at the start of a path to the value of `$HOME`.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    } else if path == "~"
        && let Ok(home) = std::env::var("HOME")
    {
        return home;
    }
    path.to_string()
}

/// Canonicalize a path, returning an error if the path does not exist or cannot be resolved.
///
/// Failing instead of silently falling back prevents TOCTOU attacks where an attacker
/// creates a symlink at a non-existent path after policy creation but before enforcement.
fn canonicalize_path(path: &str) -> Result<PathBuf, SandboxError> {
    let p = PathBuf::from(path);
    p.canonicalize().map_err(|e| {
        SandboxError::SetupFailed(format!("cannot canonicalize path '{}': {}", path, e))
    })
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

impl SandboxPolicy {
    /// Build a `SandboxPolicy` from a `MergedSandboxPolicy` (config layer).
    ///
    /// Converts string paths to `PathBuf`, expands `~`, canonicalizes paths,
    /// and adds protected paths.
    pub fn from_merged(policy: &crate::config::MergedSandboxPolicy) -> Result<Self, SandboxError> {
        Self::build(
            policy.writable.clone(),
            policy.deny.clone(),
            policy.network_allowed,
        )
    }
}

/// An error that can occur during dry-run validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DryRunError {
    /// The command was not found.
    NotFound(String),
    /// Permission was denied to execute the command.
    PermissionDenied(String),
    /// An I/O error occurred.
    Io(String),
}

impl From<ExecError> for DryRunError {
    fn from(err: ExecError) -> Self {
        match err {
            ExecError::NotFound(s) => DryRunError::NotFound(s),
            ExecError::PermissionDenied(s) => DryRunError::PermissionDenied(s),
            ExecError::Io(e) => DryRunError::Io(e.to_string()),
        }
    }
}

impl std::fmt::Display for DryRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DryRunError::NotFound(s) => write!(f, "command not found: {s}"),
            DryRunError::PermissionDenied(s) => write!(f, "permission denied: {s}"),
            DryRunError::Io(s) => write!(f, "io error: {s}"),
        }
    }
}

/// The result of a dry-run validation, containing information about what
/// would happen if the command were executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunResult {
    /// The program name that was validated.
    pub program: String,
    /// The execution mode that would be used.
    pub exec_mode: ExecMode,
    /// Whether the command was found and is executable.
    pub is_valid: bool,
    /// If validation failed, the reason.
    pub error: Option<DryRunError>,
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

    /// Validate a command without executing it, returning structured results.
    fn dry_run(&self, command: &CommandInput, sandbox: Option<&SandboxPolicy>) -> DryRunResult;

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

    fn dry_run(&self, command: &CommandInput, sandbox: Option<&SandboxPolicy>) -> DryRunResult {
        let program = command.program().to_string();
        let exec_mode = self.determine_exec_mode(sandbox, command.is_compound());

        let validation_args: Cow<[String]> = match command {
            CommandInput::Argv(args) => Cow::Borrowed(args),
            CommandInput::Shell(_) => Cow::Owned(vec!["sh".into()]),
        };

        match self.validate(&validation_args) {
            Ok(()) => DryRunResult {
                program,
                exec_mode,
                is_valid: true,
                error: None,
            },
            Err(e) => DryRunResult {
                program,
                exec_mode,
                is_valid: false,
                error: Some(e.into()),
            },
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

    fn stub_sandbox_policy() -> SandboxPolicy {
        SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![PathBuf::from(".git")],
            network_allowed: true,
        }
    }

    #[fixture]
    fn executor() -> ProcessCommandExecutor<StubSandboxExecutor> {
        ProcessCommandExecutor::new_without_sandbox()
    }

    // === ExecMode determination ===

    #[rstest]
    #[case::single_no_sandbox(false, false, ExecMode::TransparentProxy)]
    #[case::single_with_sandbox(true, false, ExecMode::SpawnAndWait)]
    #[case::compound_no_sandbox(false, true, ExecMode::ShellExec)]
    #[case::compound_with_sandbox(true, true, ExecMode::ShellExec)]
    fn determine_exec_mode(
        executor: ProcessCommandExecutor<StubSandboxExecutor>,
        #[case] has_sandbox: bool,
        #[case] is_compound: bool,
        #[case] expected: ExecMode,
    ) {
        let policy = stub_sandbox_policy();
        let sandbox = if has_sandbox { Some(&policy) } else { None };
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
        let policy = stub_sandbox_policy();

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
        let policy = stub_sandbox_policy();

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

    // === Dry-run ===

    #[rstest]
    #[case::argv_existing(
        CommandInput::Argv(vec!["sh".into()]),
        false,
        true,
        "sh",
        ExecMode::TransparentProxy
    )]
    #[case::argv_nonexistent(
        CommandInput::Argv(vec!["__nonexistent_cmd_99__".into()]),
        false,
        false,
        "__nonexistent_cmd_99__",
        ExecMode::TransparentProxy
    )]
    #[case::shell_compound(
        CommandInput::Shell("echo hello".into()),
        false,
        true,
        "sh",
        ExecMode::ShellExec
    )]
    #[case::argv_empty(
        CommandInput::Argv(vec![]),
        false,
        false,
        "",
        ExecMode::TransparentProxy
    )]
    #[case::argv_with_sandbox(
        CommandInput::Argv(vec!["sh".into()]),
        true,
        true,
        "sh",
        ExecMode::SpawnAndWait
    )]
    fn dry_run(
        executor: ProcessCommandExecutor<StubSandboxExecutor>,
        #[case] command: CommandInput,
        #[case] has_sandbox: bool,
        #[case] expected_valid: bool,
        #[case] expected_program: &str,
        #[case] expected_mode: ExecMode,
    ) {
        let policy = stub_sandbox_policy();
        let sandbox = if has_sandbox { Some(&policy) } else { None };
        let result = executor.dry_run(&command, sandbox);

        assert_eq!(result.is_valid, expected_valid);
        assert_eq!(result.program, expected_program);
        if cfg!(unix) {
            assert_eq!(result.exec_mode, expected_mode);
        }
        if expected_valid {
            assert!(result.error.is_none());
        } else {
            let error = result.error.expect("error should be present");
            assert!(
                matches!(error, DryRunError::NotFound(ref s) if s == expected_program),
                "expected NotFound({expected_program:?}), got {error:?}"
            );
        }
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
        let policy = stub_sandbox_policy();

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
        let policy = stub_sandbox_policy();

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
        let policy = stub_sandbox_policy();

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

    // === SandboxPolicy::build ===

    #[rstest]
    fn build_adds_protected_paths() {
        let policy = SandboxPolicy::build(vec!["/tmp".to_string()], vec![], true).unwrap();

        assert!(policy.read_only_subpaths.contains(&PathBuf::from(".git")));
        assert!(
            policy
                .read_only_subpaths
                .contains(&PathBuf::from(".gitmodules"))
        );
        assert!(policy.read_only_subpaths.contains(&PathBuf::from(".runok")));
    }

    #[rstest]
    fn build_deduplicates_protected_paths() {
        let policy =
            SandboxPolicy::build(vec!["/tmp".to_string()], vec![".git".to_string()], true).unwrap();

        let git_count = policy
            .read_only_subpaths
            .iter()
            .filter(|p| *p == &PathBuf::from(".git"))
            .count();
        assert_eq!(git_count, 1);
    }

    #[rstest]
    fn build_expands_tilde_in_writable_roots() {
        let home = std::env::var("HOME").unwrap();
        let policy = SandboxPolicy::build(vec!["~".to_string()], vec![], true).unwrap();

        let expected = PathBuf::from(&home).canonicalize().unwrap();
        assert!(
            policy.writable_roots.iter().any(|p| p == &expected),
            "expected {expected:?} in {:?}",
            policy.writable_roots
        );
    }

    #[rstest]
    fn build_expands_tilde_in_deny_paths() {
        let home = std::env::var("HOME").unwrap();
        let policy = SandboxPolicy::build(vec![], vec!["~/.config".to_string()], true).unwrap();

        // Deny paths are not canonicalized, only tilde-expanded
        let expected = PathBuf::from(format!("{home}/.config"));
        assert!(
            policy.read_only_subpaths.iter().any(|p| p == &expected),
            "expected {expected:?} in {:?}",
            policy.read_only_subpaths
        );
    }

    #[rstest]
    fn build_canonicalizes_existing_paths() {
        let policy = SandboxPolicy::build(vec!["/tmp".to_string()], vec![], true).unwrap();

        // /tmp should be canonicalized (on macOS, /tmp -> /private/tmp)
        let canonical_tmp = PathBuf::from("/tmp")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        assert!(
            policy.writable_roots.contains(&canonical_tmp),
            "expected {canonical_tmp:?} in {:?}",
            policy.writable_roots
        );
    }

    #[rstest]
    fn build_rejects_nonexistent_writable_path() {
        let result =
            SandboxPolicy::build(vec!["/nonexistent_path_12345".to_string()], vec![], true);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot canonicalize path")
        );
    }

    #[rstest]
    #[case::glob_pattern(".env*")]
    #[case::recursive_glob("~/.ssh/**")]
    #[case::nonexistent_path("/nonexistent_readonly_path_12345")]
    fn build_accepts_deny_paths_without_canonicalization(#[case] deny_path: &str) {
        let policy = SandboxPolicy::build(vec![], vec![deny_path.to_string()], true).unwrap();

        let expanded = expand_tilde(deny_path);
        assert!(
            policy
                .read_only_subpaths
                .contains(&PathBuf::from(&expanded)),
            "expected {expanded:?} in {:?}",
            policy.read_only_subpaths
        );
    }

    #[rstest]
    #[case::allowed(true, true)]
    #[case::denied(false, false)]
    fn build_sets_network_allowed(#[case] input: bool, #[case] expected: bool) {
        let policy = SandboxPolicy::build(vec![], vec![], input).unwrap();
        assert_eq!(policy.network_allowed, expected);
    }

    // === SandboxPolicy::merge ===

    #[rstest]
    fn merge_empty_returns_error() {
        let result = SandboxPolicy::merge(&[]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no policies to merge")
        );
    }

    #[rstest]
    fn merge_single_returns_clone() {
        let policy = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home")],
            read_only_subpaths: vec![PathBuf::from(".git")],
            network_allowed: true,
        };
        let merged = SandboxPolicy::merge(std::slice::from_ref(&policy)).unwrap();
        assert_eq!(merged, policy);
    }

    #[rstest]
    fn merge_writable_roots_intersection() {
        let a = SandboxPolicy {
            writable_roots: vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/home"),
                PathBuf::from("/var"),
            ],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let b = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/var")],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let merged = SandboxPolicy::merge(&[a, b]).unwrap();
        assert_eq!(
            merged.writable_roots,
            vec![PathBuf::from("/tmp"), PathBuf::from("/var")]
        );
    }

    #[rstest]
    fn merge_writable_roots_empty_intersection_returns_error() {
        let a = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let b = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/home")],
            read_only_subpaths: vec![],
            network_allowed: true,
        };
        let result = SandboxPolicy::merge(&[a, b]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no common writable roots")
        );
    }

    #[rstest]
    fn merge_both_empty_writable_roots_succeeds() {
        let a = SandboxPolicy {
            writable_roots: vec![],
            read_only_subpaths: vec![PathBuf::from(".git")],
            network_allowed: true,
        };
        let b = SandboxPolicy {
            writable_roots: vec![],
            read_only_subpaths: vec![PathBuf::from(".runok")],
            network_allowed: true,
        };
        let merged = SandboxPolicy::merge(&[a, b]).unwrap();
        assert!(merged.writable_roots.is_empty());
    }

    #[rstest]
    fn merge_read_only_subpaths_union() {
        let a = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![PathBuf::from(".git")],
            network_allowed: true,
        };
        let b = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![PathBuf::from(".runok")],
            network_allowed: true,
        };
        let merged = SandboxPolicy::merge(&[a, b]).unwrap();
        assert_eq!(
            merged.read_only_subpaths,
            vec![PathBuf::from(".git"), PathBuf::from(".runok")]
        );
    }

    #[rstest]
    #[case::both_true(true, true, true)]
    #[case::first_false(false, true, false)]
    #[case::second_false(true, false, false)]
    #[case::both_false(false, false, false)]
    fn merge_network_allowed(#[case] net_a: bool, #[case] net_b: bool, #[case] expected: bool) {
        let a = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![],
            network_allowed: net_a,
        };
        let b = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/tmp")],
            read_only_subpaths: vec![],
            network_allowed: net_b,
        };
        let merged = SandboxPolicy::merge(&[a, b]).unwrap();
        assert_eq!(merged.network_allowed, expected);
    }

    #[rstest]
    fn merge_three_policies_progressive_intersection() {
        let a = SandboxPolicy {
            writable_roots: vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c"),
            ],
            read_only_subpaths: vec![PathBuf::from(".git")],
            network_allowed: true,
        };
        let b = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/a"), PathBuf::from("/b")],
            read_only_subpaths: vec![PathBuf::from(".runok")],
            network_allowed: true,
        };
        let c = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/a"), PathBuf::from("/c")],
            read_only_subpaths: vec![PathBuf::from(".env")],
            network_allowed: false,
        };
        let merged = SandboxPolicy::merge(&[a, b, c]).unwrap();
        assert_eq!(merged.writable_roots, vec![PathBuf::from("/a")]);
        assert_eq!(
            merged.read_only_subpaths,
            vec![
                PathBuf::from(".env"),
                PathBuf::from(".git"),
                PathBuf::from(".runok"),
            ]
        );
        assert!(!merged.network_allowed);
    }

    // === SandboxPolicy::from_merged ===

    #[rstest]
    fn from_merged_converts_config_policy() {
        use crate::config::MergedSandboxPolicy;

        let merged = MergedSandboxPolicy {
            writable: vec!["/tmp".to_string()],
            deny: vec!["/etc/passwd".to_string()],
            network_allowed: true,
        };
        let policy = SandboxPolicy::from_merged(&merged).unwrap();

        let canonical_tmp = PathBuf::from("/tmp")
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        assert!(policy.writable_roots.contains(&canonical_tmp));
        assert!(policy.network_allowed);
        // Protected paths should be auto-added
        assert!(policy.read_only_subpaths.contains(&PathBuf::from(".git")));
        assert!(policy.read_only_subpaths.contains(&PathBuf::from(".runok")));
    }

    #[rstest]
    #[case::network_allowed(true, true)]
    #[case::network_denied(false, false)]
    fn from_merged_network_flag(#[case] input: bool, #[case] expected: bool) {
        use crate::config::MergedSandboxPolicy;

        let merged = MergedSandboxPolicy {
            writable: vec!["/tmp".to_string()],
            deny: vec![],
            network_allowed: input,
        };
        let policy = SandboxPolicy::from_merged(&merged).unwrap();
        assert_eq!(policy.network_allowed, expected);
    }

    // === expand_tilde ===

    #[rstest]
    #[case::tilde_prefix("~/foo", true)]
    #[case::tilde_only("~", true)]
    #[case::no_tilde("/tmp", false)]
    #[case::tilde_in_middle("/home/~user", false)]
    fn expand_tilde_cases(#[case] input: &str, #[case] should_expand: bool) {
        let result = expand_tilde(input);
        if should_expand {
            assert!(
                !result.starts_with('~'),
                "tilde should be expanded: {result}"
            );
        } else {
            assert_eq!(result, input);
        }
    }
}
