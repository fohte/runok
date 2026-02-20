mod cli;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Commands, route_check};
use runok::adapter;
use runok::config::{ConfigLoader, DefaultConfigLoader};
use runok::exec::command_executor::ProcessCommandExecutor;

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
            let executor = ProcessCommandExecutor::new_without_sandbox();
            let endpoint = runok::adapter::exec_adapter::ExecAdapter::new(
                args.command,
                args.sandbox,
                Box::new(executor),
            );
            adapter::run(&endpoint, &config)
        }
        Commands::Check(args) => match route_check(&args, stdin) {
            Ok(endpoint) => adapter::run(endpoint.as_ref(), &config),
            Err(e) => {
                eprintln!("runok: {e}");
                2
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cli::CheckArgs;
    use rstest::rstest;

    #[rstest]
    fn run_command_check_with_command_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            command: Some("echo hello".into()),
            format: None,
        });
        let cwd = std::env::current_dir().unwrap();
        let exit_code = run_command(cmd, &cwd, std::io::empty());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn run_command_check_with_invalid_stdin_returns_two() {
        let cmd = Commands::Check(CheckArgs {
            command: None,
            format: None,
        });
        let cwd = std::env::current_dir().unwrap();
        let exit_code = run_command(cmd, &cwd, "not json".as_bytes());
        assert_eq!(exit_code, 2);
    }

    #[rstest]
    fn run_command_check_with_stdin_json_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            command: None,
            format: None,
        });
        let cwd = std::env::current_dir().unwrap();
        let exit_code = run_command(cmd, &cwd, r#"{"command": "ls"}"#.as_bytes());
        assert_eq!(exit_code, 0);
    }
}
