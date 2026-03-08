mod cli;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{AuditArgs, CheckRoute, Cli, Commands, route_check};
use runok::adapter::{self, RunOptions};
use runok::audit::filter::{AuditFilter, TimeSpec};
use runok::audit::reader::AuditReader;
use runok::config::{ActionKind, ConfigLoader, DefaultConfigLoader};
#[cfg(target_os = "linux")]
use runok::exec::command_executor::LinuxSandboxExecutor;
#[cfg(target_os = "macos")]
use runok::exec::command_executor::SandboxExecutor;
use runok::exec::command_executor::{CommandExecutor, ProcessCommandExecutor};
#[cfg(target_os = "macos")]
use runok::exec::macos_sandbox::MacOsSandboxExecutor;

/// Create the appropriate command executor for the current platform.
///
/// On macOS, uses MacOsSandboxExecutor (seatbelt/SBPL via sandbox-exec).
/// On Linux, attempts to find the runok-linux-sandbox helper binary and use
/// the LinuxSandboxExecutor. Falls back to the stub executor if not found.
fn create_executor() -> Box<dyn CommandExecutor> {
    #[cfg(target_os = "macos")]
    {
        let macos_executor = MacOsSandboxExecutor::new();
        if macos_executor.is_supported() {
            return Box::new(ProcessCommandExecutor::new(macos_executor));
        }
    }

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

    #[cfg(feature = "config-schema")]
    if matches!(cli.command, Commands::ConfigSchema) {
        if let Err(e) = runok::config::print_config_schema() {
            eprintln!("runok: failed to generate schema: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exit_code = run_command(cli.command, &cwd, std::io::stdin());
    ExitCode::from(exit_code as u8)
}

fn run_command(command: Commands, cwd: &std::path::Path, stdin: impl std::io::Read) -> i32 {
    let loader = DefaultConfigLoader::new();

    if let Commands::Audit(args) = command {
        return run_audit(args, cwd);
    }

    // Exit code for config errors depends on the subcommand:
    // exec → 1 (general error), check → 2 (input/internal error)
    let config_error_exit_code = match &command {
        Commands::Exec(_) => 1,
        Commands::Check(_) => 2,
        Commands::Audit(_) => unreachable!("handled above"),
        #[cfg(feature = "config-schema")]
        Commands::ConfigSchema => unreachable!("handled in main()"),
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
            let sandbox_defs = config
                .definitions
                .as_ref()
                .and_then(|d| d.sandbox.clone())
                .unwrap_or_default();
            let endpoint = runok::adapter::exec_adapter::ExecAdapter::new(
                args.command,
                args.sandbox,
                executor,
            )
            .with_sandbox_definitions(sandbox_defs);
            adapter::run_with_options(&endpoint, &config, &options)
        }
        Commands::Check(args) => {
            let options = RunOptions {
                dry_run: false,
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
        Commands::Audit(_) => unreachable!("handled above"),
        #[cfg(feature = "config-schema")]
        Commands::ConfigSchema => unreachable!("handled in main()"),
    }
}

fn run_audit(args: AuditArgs, cwd: &std::path::Path) -> i32 {
    let loader = DefaultConfigLoader::new();
    let config = match loader.load(cwd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runok: config error: {e}");
            return 1;
        }
    };

    let audit_config = config.audit.unwrap_or_default();
    let log_dir = PathBuf::from(audit_config.resolved_path());

    let mut filter = AuditFilter::new();
    filter.limit = args.limit;

    if let Some(action_str) = &args.action {
        match action_str.as_str() {
            "allow" => filter.action = Some(ActionKind::Allow),
            "deny" => filter.action = Some(ActionKind::Deny),
            "ask" => filter.action = Some(ActionKind::Ask),
            other => {
                eprintln!("runok: invalid action filter '{other}': expected allow, deny, or ask");
                return 1;
            }
        }
    }

    if let Some(since_str) = &args.since {
        match TimeSpec::parse(since_str) {
            Ok(ts) => filter.since = Some(ts),
            Err(e) => {
                eprintln!("runok: {e}");
                return 1;
            }
        }
    }

    if let Some(until_str) = &args.until {
        match TimeSpec::parse(until_str) {
            Ok(ts) => filter.until = Some(ts),
            Err(e) => {
                eprintln!("runok: {e}");
                return 1;
            }
        }
    }

    filter.command_pattern = args.command;

    let reader = AuditReader::new(log_dir);
    let entries = match reader.read(&filter) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("runok: failed to read audit log: {e}");
            return 1;
        }
    };

    if args.json {
        for entry in &entries {
            match serde_json::to_string(entry) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("runok: serialization error: {e}");
                    return 1;
                }
            }
        }
    } else {
        for entry in &entries {
            let action_str = match &entry.action {
                runok::audit::SerializableAction::Allow => "allow",
                runok::audit::SerializableAction::Deny { .. } => "deny",
                runok::audit::SerializableAction::Ask { .. } => "ask",
                runok::audit::SerializableAction::Default => "default",
            };
            println!("{} [{}] {}", entry.timestamp, action_str, entry.command);
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use cli::{CheckArgs, ExecArgs};
    use indoc::indoc;
    use rstest::rstest;

    #[rstest]
    fn run_command_check_with_command_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            input_format: None,
            output_format: cli::OutputFormat::Text,
            verbose: false,
            command: vec!["echo".into(), "hello".into()],
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, std::io::empty());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn run_command_check_with_empty_stdin_returns_two() {
        let cmd = Commands::Check(CheckArgs {
            input_format: None,
            output_format: cli::OutputFormat::Text,
            verbose: false,
            command: vec![],
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, "".as_bytes());
        assert_eq!(exit_code, 2);
    }

    #[rstest]
    fn run_command_check_with_stdin_json_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            input_format: None,
            output_format: cli::OutputFormat::Text,
            verbose: false,
            command: vec![],
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, r#"{"command": "ls"}"#.as_bytes());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn run_command_check_with_plaintext_stdin_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            input_format: None,
            output_format: cli::OutputFormat::Text,
            verbose: false,
            command: vec![],
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, "echo hello\n".as_bytes());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn create_executor_returns_executor() {
        let executor = create_executor();
        // Verify executor works by validating a known command
        assert!(executor.validate(&["sh".to_string()]).is_ok());
    }

    #[rstest]
    fn run_command_exec_with_dry_run() {
        let cmd = Commands::Exec(ExecArgs {
            command: vec!["echo".into(), "hello".into()],
            sandbox: None,
            dry_run: true,
            verbose: false,
        });
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let exit_code = run_command(cmd, &cwd, std::io::empty());
        assert_eq!(exit_code, 0);
    }

    #[rstest]
    fn run_command_check_with_multiline_plaintext_stdin_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            input_format: None,
            output_format: cli::OutputFormat::Text,
            verbose: false,
            command: vec![],
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
