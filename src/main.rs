mod cli;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{AuditArgs, CheckRoute, Cli, Commands, route_check, validate_no_unknown_flags};
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
/// On Linux, uses LinuxSandboxExecutor (bubblewrap + landlock + seccomp).
/// Falls back to the stub executor if sandbox setup fails.
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
    let raw_args: Vec<String> = std::env::args().collect();

    // Validate unknown flags before clap parsing absorbs them into `command` Vec
    let subcommand_name = raw_args.get(1).map(|s| s.as_str()).unwrap_or("");
    if matches!(subcommand_name, "exec" | "check")
        && let Err(e) = validate_no_unknown_flags(&raw_args, subcommand_name)
    {
        // check uses exit code 2 for errors; exec uses 1
        let code: u8 = if subcommand_name == "check" { 2 } else { 1 };
        eprintln!("runok: {e}");
        return ExitCode::from(code);
    }

    let cli = Cli::parse();

    #[cfg(feature = "config-schema")]
    if matches!(cli.command, Commands::ConfigSchema) {
        if let Err(e) = runok::config::print_config_schema() {
            eprintln!("runok: failed to generate schema: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    // Linux sandbox subcommand runs independently without config
    #[cfg(target_os = "linux")]
    if let Commands::SandboxExec(ref args) = cli.command {
        return run_sandbox_exec(args);
    }

    // Init runs independently without loading config
    if let Commands::Init(ref args) = cli.command {
        return run_init(args);
    }

    // Test runs with its own config loading (no global config)
    if let Commands::Test(ref args) = cli.command {
        return run_test(args);
    }

    // UpdatePresets reads config files directly (not via DefaultConfigLoader)
    if matches!(cli.command, Commands::UpdatePresets) {
        return run_update_presets();
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exit_code = run_command(cli.command, &cwd, std::io::stdin());
    ExitCode::from(exit_code as u8)
}

fn run_test(args: &cli::TestArgs) -> ExitCode {
    use runok::test::{
        TestError, load_test_config, parse_test_cases, report, report_summary, run_tests,
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config_path = args.config.clone().unwrap_or_else(|| cwd.clone());

    let (config, resolved_path) = match load_test_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runok: {e}");
            return ExitCode::from(2);
        }
    };

    let test_cases = parse_test_cases(&config, &resolved_path);
    if test_cases.is_empty() {
        eprintln!("runok: {}", TestError::NoTestCases);
        return ExitCode::from(2);
    }

    let results = run_tests(&config, &test_cases);
    let mut stdout = std::io::stdout();
    report(&results, &mut stdout);
    report_summary(&results, &mut stdout);

    if results.is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_update_presets() -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match runok::update_presets::run(&cwd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("runok: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_init(args: &cli::InitArgs) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let scope = args.scope.as_ref().map(|s| match s {
        cli::InitScope::User => runok::init::InitScope::User,
        cli::InitScope::Project => runok::init::InitScope::Project,
    });
    match runok::init::run_wizard(scope.as_ref(), args.yes, &cwd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("runok: {e}");
            ExitCode::FAILURE
        }
    }
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
        Commands::Test(_) => unreachable!("handled in main()"),
        Commands::Init(_) => unreachable!("handled in main()"),
        Commands::UpdatePresets => unreachable!("handled in main()"),
        #[cfg(feature = "config-schema")]
        Commands::ConfigSchema => unreachable!("handled in main()"),
        #[cfg(target_os = "linux")]
        Commands::SandboxExec(_) => unreachable!("handled in main()"),
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
        Commands::Test(_) => unreachable!("handled in main()"),
        Commands::Init(_) => unreachable!("handled in main()"),
        Commands::UpdatePresets => unreachable!("handled in main()"),
        #[cfg(feature = "config-schema")]
        Commands::ConfigSchema => unreachable!("handled in main()"),
        #[cfg(target_os = "linux")]
        Commands::SandboxExec(_) => unreachable!("handled in main()"),
    }
}

#[cfg(target_os = "linux")]
fn run_sandbox_exec(args: &cli::SandboxExecArgs) -> ExitCode {
    use runok::exec::command_executor::SandboxPolicy;
    use runok::exec::linux_sandbox;

    let policy: SandboxPolicy = match serde_json::from_str(&args.policy) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("runok: invalid sandbox policy JSON: {e}");
            return ExitCode::from(1);
        }
    };

    if args.apply_sandbox_then_exec {
        // Stage 2: apply landlock + seccomp, then exec
        if let Err(e) = linux_sandbox::run_stage2(&policy, &args.command) {
            eprintln!("runok: {e}");
            return ExitCode::from(1);
        }
        // exec_command never returns on success
        unreachable!()
    }

    // Stage 1: set up bubblewrap and re-invoke
    match linux_sandbox::run_stage1(&policy, &args.cwd, &args.policy, &args.command) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("runok: {e}");
            ExitCode::from(1)
        }
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
    let log_dir = audit_config.base_dir();

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
        runok::audit::formatter::print_entries(&entries);
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

    // === Linux sandbox exec ===

    #[cfg(target_os = "linux")]
    #[rstest]
    fn run_sandbox_exec_rejects_invalid_json() {
        let args = cli::SandboxExecArgs {
            policy: "not valid json".to_string(),
            cwd: PathBuf::from("/tmp"),
            apply_sandbox_then_exec: false,
            command: vec!["true".to_string()],
        };
        let exit_code = run_sandbox_exec(&args);
        assert_eq!(exit_code, ExitCode::from(1));
    }
}
