mod cli;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{CheckRoute, Cli, Commands, route_check};
use runok::adapter::{self, RunOptions};
use runok::config::{ConfigLoader, DefaultConfigLoader};
#[cfg(target_os = "linux")]
use runok::exec::command_executor::LinuxSandboxExecutor;
use runok::exec::command_executor::{CommandExecutor, ProcessCommandExecutor};

/// Create the appropriate command executor for the current platform.
///
/// On Linux, attempts to find the runok-linux-sandbox helper binary and use
/// the LinuxSandboxExecutor. Falls back to the stub executor if not found.
/// On other platforms, always uses the stub executor.
fn create_executor() -> Box<dyn CommandExecutor> {
    #[cfg(target_os = "linux")]
    {
        match LinuxSandboxExecutor::new() {
            Ok(sandbox) => return Box::new(ProcessCommandExecutor::new(sandbox)),
            Err(_) => {
                // Fall through to stub
            }
        }
    }

    Box::new(ProcessCommandExecutor::new_without_sandbox())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exit_code = run_command(cli.command, &cwd, std::io::stdin());
    ExitCode::from(exit_code as u8)
}

fn run_command(command: Commands, cwd: &std::path::Path, stdin: impl std::io::Read) -> i32 {
    let loader = DefaultConfigLoader::new();

    // Exit code for config errors depends on the subcommand:
    // exec → 1 (general error), check → 2 (input/internal error)
    let config_error_exit_code = match &command {
        Commands::Exec(_) => 1,
        Commands::Check(_) => 2,
    };

    let config = match loader.load(cwd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runok: config error: {e}");
            return config_error_exit_code;
        }
    };

    match command {
        Commands::Exec(args) => {
            let options = RunOptions {
                dry_run: args.dry_run,
                verbose: args.verbose,
            };
            let executor = create_executor();
            let endpoint = runok::adapter::exec_adapter::ExecAdapter::new(
                args.command,
                args.sandbox,
                executor,
            );
            adapter::run_with_options(&endpoint, &config, &options)
        }
        Commands::Check(args) => {
            let options = RunOptions {
                dry_run: args.dry_run,
                verbose: args.verbose,
            };
            match route_check(&args, stdin) {
                Ok(CheckRoute::Single(endpoint)) => {
                    adapter::run_with_options(endpoint.as_ref(), &config, &options)
                }
                Ok(CheckRoute::Multi(adapters)) => {
                    let mut worst_exit = 0;
                    for ep in &adapters {
                        let code = adapter::run_with_options(ep, &config, &options);
                        if code > worst_exit {
                            worst_exit = code;
                        }
                    }
                    worst_exit
                }
                Err(e) => {
                    eprintln!("runok: {e}");
                    2
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cli::CheckArgs;
    use indoc::indoc;
    use rstest::rstest;

    #[rstest]
    fn run_command_check_with_command_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            command: Some("echo hello".into()),
            format: None,
            dry_run: false,
            verbose: false,
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, std::io::empty());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn run_command_check_with_empty_stdin_returns_two() {
        let cmd = Commands::Check(CheckArgs {
            command: None,
            format: None,
            dry_run: false,
            verbose: false,
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, "".as_bytes());
        assert_eq!(exit_code, 2);
    }

    #[rstest]
    fn run_command_check_with_stdin_json_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            command: None,
            format: None,
            dry_run: false,
            verbose: false,
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, r#"{"command": "ls"}"#.as_bytes());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn run_command_check_with_plaintext_stdin_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            command: None,
            format: None,
            dry_run: false,
            verbose: false,
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, "echo hello\n".as_bytes());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn run_command_check_with_multiline_plaintext_stdin_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            command: None,
            format: None,
            dry_run: false,
            verbose: false,
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let input = indoc! {"
            echo hello
            ls -la
        "};
        let exit_code = run_command(cmd, &cwd, input.as_bytes());
        assert_eq!(exit_code, 0);
    }
}
