mod bwrap;
mod error;
mod landlock_sandbox;
mod policy;
mod seccomp_sandbox;

use std::ffi::CString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use error::SandboxError;
use policy::SandboxPolicy;

/// Linux sandbox helper for runok.
///
/// Applies bubblewrap namespace isolation, landlock filesystem restrictions,
/// and seccomp network filtering before executing a command.
///
/// This binary operates in two stages:
/// - Stage 1 (default): Sets up bubblewrap and re-invokes itself inside the sandbox
/// - Stage 2 (--apply-sandbox-then-exec): Applies landlock + seccomp, then execvp
#[derive(Parser, Debug)]
#[command(name = "runok-linux-sandbox")]
struct Args {
    /// Sandbox policy as JSON string.
    #[arg(long)]
    policy: String,

    /// Working directory for the sandboxed command.
    #[arg(long)]
    cwd: PathBuf,

    /// Stage 2 mode: apply landlock + seccomp, then exec the command.
    /// Used internally when re-invoked inside bubblewrap.
    #[arg(long)]
    apply_sandbox_then_exec: bool,

    /// The command and its arguments to execute.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let policy: SandboxPolicy = match serde_json::from_str(&args.policy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("runok-linux-sandbox: invalid policy JSON: {e}");
            return ExitCode::from(1);
        }
    };

    if args.apply_sandbox_then_exec {
        // Stage 2: apply landlock + seccomp, then exec
        if let Err(e) = run_stage2(&policy, &args.command) {
            eprintln!("runok-linux-sandbox: {e}");
            return ExitCode::from(1);
        }
        // exec_command never returns on success
        unreachable!()
    }

    // Stage 1: set up bubblewrap and re-invoke
    match run_stage1(&policy, &args.cwd, &args.policy, &args.command) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("runok-linux-sandbox: {e}");
            ExitCode::from(1)
        }
    }
}

/// Stage 1: Build bubblewrap arguments and execute bwrap.
fn run_stage1(
    policy: &SandboxPolicy,
    cwd: &std::path::Path,
    policy_json: &str,
    command: &[String],
) -> Result<i32, SandboxError> {
    let helper_binary = std::env::current_exe().map_err(SandboxError::Exec)?;

    let bwrap_args = bwrap::build_bwrap_args(policy, cwd, &helper_binary, policy_json, command);

    let status = std::process::Command::new("bwrap")
        .args(&bwrap_args)
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SandboxError::Bubblewrap(
                    "bubblewrap (bwrap) not found. Install it with your package manager."
                        .to_string(),
                )
            } else {
                SandboxError::Exec(e)
            }
        })?;

    Ok(exit_code_from_status(status))
}

/// Stage 2: Apply landlock and seccomp restrictions, then exec the command.
fn run_stage2(policy: &SandboxPolicy, command: &[String]) -> Result<(), SandboxError> {
    // Apply landlock filesystem restrictions
    landlock_sandbox::apply_landlock(policy)?;

    // Apply seccomp network restrictions
    seccomp_sandbox::apply_seccomp(policy.network_allowed)?;

    // exec the target command
    exec_command(command)
}

/// Extract the exit code from a process exit status.
///
/// If the process was killed by a signal, return 128 + signal number
/// (standard shell convention).
fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

/// Replace the current process with the given command via execvp.
fn exec_command(command: &[String]) -> Result<(), SandboxError> {
    if command.is_empty() {
        return Err(SandboxError::InvalidPolicy("empty command".to_string()));
    }

    let c_args: Vec<CString> = command
        .iter()
        .map(|arg| {
            CString::new(arg.as_bytes()).map_err(|e| {
                SandboxError::InvalidPolicy(format!("argument contains NUL byte: {e}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let c_arg_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // SAFETY: c_arg_ptrs is a null-terminated array of valid C string pointers.
    // The CString values in c_args are alive for the duration of this call.
    unsafe {
        libc::execvp(c_args[0].as_ptr(), c_arg_ptrs.as_ptr());
    }

    // execvp only returns on error
    Err(SandboxError::Exec(std::io::Error::last_os_error()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // === exec_command error paths ===

    #[rstest]
    fn exec_command_rejects_empty_command() {
        let err = exec_command(&[]).unwrap_err();
        assert!(
            matches!(err, SandboxError::InvalidPolicy(_)),
            "empty command should return InvalidPolicy, got: {err}"
        );
    }

    #[rstest]
    fn exec_command_rejects_nul_byte_in_argument() {
        let err = exec_command(&["hello\0world".to_string()]).unwrap_err();
        assert!(
            matches!(err, SandboxError::InvalidPolicy(_)),
            "NUL byte should return InvalidPolicy, got: {err}"
        );
    }

    // === exit_code_from_status ===

    #[rstest]
    #[case::success("true", 0)]
    #[case::failure("false", 1)]
    #[case::exit_42("sh -c 'exit 42'", 42)]
    fn exit_code_from_status_returns_code(#[case] cmd: &str, #[case] expected: i32) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let status = std::process::Command::new(parts[0])
            .args(&parts[1..])
            .status()
            .expect("command should run");
        assert_eq!(exit_code_from_status(status), expected);
    }
}
