mod cli;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{
    AuditArgs, CheckRoute, Cli, Commands, find_subcommand, route_check, validate_no_unknown_flags,
};
use runok::adapter::{self, RunOptions};
use runok::audit::filter::{AuditFilter, TimeSpec};
use runok::audit::reader::AuditReader;
use runok::config::{ActionKind, ConfigLoader, ConfigSource, DefaultConfigLoader};
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

    // Validate unknown flags before clap parsing absorbs them into `command` Vec.
    // Use `find_subcommand` so that global flags (e.g. `-c config.yml`) placed
    // before the subcommand name do not cause the validation to be skipped,
    // and so the subcommand position survives a `-c` value that happens to
    // match the subcommand name (e.g. `runok -c check check ...`).
    if let Some((subcommand_name, subcommand_pos)) = find_subcommand(&raw_args)
        && matches!(subcommand_name, "exec" | "check")
        && let Err(e) = validate_no_unknown_flags(&raw_args, subcommand_name, subcommand_pos)
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
    if let Commands::Test(ref _args) = cli.command {
        return run_test(cli.config.as_deref());
    }

    // Migrate config files to the latest format
    if let Commands::Migrate(ref args) = cli.command {
        return run_migrate(cli.config.as_deref(), args);
    }

    // UpdatePresets reads config files directly (not via DefaultConfigLoader)
    if matches!(cli.command, Commands::UpdatePresets) {
        return run_update_presets(cli.config.as_deref());
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exit_code = run_command(cli.command, cli.config.as_deref(), &cwd, std::io::stdin());
    ExitCode::from(exit_code as u8)
}

fn run_test(config: Option<&std::path::Path>) -> ExitCode {
    use runok::test::{
        TestError, load_test_config, parse_test_cases, report, report_summary, run_tests,
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config_path = config.map(PathBuf::from).unwrap_or_else(|| cwd.clone());

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

fn run_update_presets(config: Option<&std::path::Path>) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let source = ConfigSource::from_flag(config, &cwd);
    match runok::update_presets::run(&source) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("runok: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_migrate(config: Option<&std::path::Path>, args: &cli::MigrateArgs) -> ExitCode {
    match runok::migrate::run(config, args.yes) {
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

fn run_command(
    command: Commands,
    config_path: Option<&std::path::Path>,
    cwd: &std::path::Path,
    stdin: impl std::io::Read,
) -> i32 {
    if let Commands::Audit(args) = command {
        return run_audit(args, config_path, cwd);
    }

    // Exit code for config errors depends on the subcommand:
    // exec → 1 (general error), check → 2 (input/internal error)
    let config_error_exit_code = match &command {
        Commands::Exec(_) => 1,
        Commands::Check(_) => 2,
        Commands::Audit(_) => unreachable!("handled above"),
        Commands::Test(_) => unreachable!("handled in main()"),
        Commands::Init(_) => unreachable!("handled in main()"),
        Commands::Migrate(_) => unreachable!("handled in main()"),
        Commands::UpdatePresets => unreachable!("handled in main()"),
        #[cfg(feature = "config-schema")]
        Commands::ConfigSchema => unreachable!("handled in main()"),
        #[cfg(target_os = "linux")]
        Commands::SandboxExec(_) => unreachable!("handled in main()"),
    };

    let loader = DefaultConfigLoader::new();
    let source = ConfigSource::from_flag(config_path, cwd);
    let config = match loader.load(&source) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runok: config error: {e}");
            return config_error_exit_code;
        }
    };

    match command {
        Commands::Exec(args) => {
            let options = RunOptions {
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
        Commands::Migrate(_) => unreachable!("handled in main()"),
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

fn run_audit(args: AuditArgs, config_path: Option<&std::path::Path>, cwd: &std::path::Path) -> i32 {
    let loader = DefaultConfigLoader::new();
    let source = ConfigSource::from_flag(config_path, cwd);
    let config = match loader.load(&source) {
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

    if let Some(dir_arg) = args.dir {
        let dir_path = std::path::Path::new(&dir_arg);
        match dir_path.canonicalize() {
            Ok(canonical) => filter.cwd = Some(canonical.to_string_lossy().into_owned()),
            Err(e) => {
                eprintln!("runok: failed to resolve directory path '{}': {e}", dir_arg);
                return 1;
            }
        }
    }

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
    use cli::CheckArgs;
    use indoc::indoc;
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    /// Temp dir holding an empty runok.yml, used as the explicit --config
    /// target so that run_command loads only this file and skips both
    /// global (~/.config/runok/) and project config discovery. Keeps the
    /// tests independent of any config on the developer's machine.
    #[fixture]
    fn empty_config_file() -> (TempDir, PathBuf) {
        let tmp = TempDir::new().expect("create temp dir");
        let path = tmp.path().join("runok.yml");
        std::fs::write(&path, "").expect("write empty config");
        (tmp, path)
    }

    fn check_args_with_command(command: Vec<String>) -> Commands {
        Commands::Check(CheckArgs {
            input_format: None,
            output_format: cli::OutputFormat::Text,
            verbose: false,
            command,
        })
    }

    #[rstest]
    #[case::with_command_arg(check_args_with_command(vec!["echo".into(), "hello".into()]), "".as_bytes(), 0)]
    #[case::stdin_empty(check_args_with_command(vec![]), "".as_bytes(), 2)]
    #[case::stdin_json(check_args_with_command(vec![]), r#"{"command": "ls"}"#.as_bytes(), 0)]
    #[case::stdin_plaintext(check_args_with_command(vec![]), "echo hello\n".as_bytes(), 0)]
    #[case::stdin_multiline(
        check_args_with_command(vec![]),
        indoc! {"
            echo hello
            ls -la
        "}.as_bytes(),
        0
    )]
    fn run_command_check(
        empty_config_file: (TempDir, PathBuf),
        #[case] cmd: Commands,
        #[case] stdin: &[u8],
        #[case] expected_exit: i32,
    ) {
        let (tmp, config_path) = empty_config_file;
        let exit_code = run_command(cmd, Some(&config_path), tmp.path(), stdin);
        assert_eq!(exit_code, expected_exit);
    }

    #[rstest]
    fn create_executor_returns_executor() {
        let executor = create_executor();
        // Verify executor works by validating a known command
        assert!(executor.validate(&["sh".to_string()]).is_ok());
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
