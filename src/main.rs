use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use runok::adapter::check_adapter::{CheckAdapter, CheckInput};
use runok::adapter::exec_adapter::ExecAdapter;
use runok::adapter::hook_adapter::{ClaudeCodeHookAdapter, HookInput};
use runok::adapter::{self, Endpoint};
use runok::config::{ConfigLoader, DefaultConfigLoader};
use runok::exec::command_executor::ProcessCommandExecutor;

#[derive(Parser)]
#[command(name = "runok")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[cfg_attr(test, derive(Debug, PartialEq))]
enum Commands {
    /// Execute a command with permission checks and optional sandboxing
    Exec(ExecArgs),
    /// Check whether a command would be allowed
    Check(CheckArgs),
}

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
struct ExecArgs {
    /// Sandbox preset name
    #[arg(long)]
    sandbox: Option<String>,

    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    command: Vec<String>,
}

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
struct CheckArgs {
    /// Command string to check (skips stdin)
    #[arg(long)]
    command: Option<String>,

    /// Input format: "claude-code-hook" or omit for auto-detection
    #[arg(long)]
    format: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exit_code = run_command(cli.command, &cwd, std::io::stdin());
    ExitCode::from(exit_code as u8)
}

fn run_command(command: Commands, cwd: &std::path::Path, stdin: impl std::io::Read) -> i32 {
    let loader = DefaultConfigLoader::new();
    let config = match loader.load(cwd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runok: config error: {e}");
            return 2;
        }
    };

    match command {
        Commands::Exec(args) => {
            let executor = ProcessCommandExecutor::new_without_sandbox();
            let endpoint = ExecAdapter::new(args.command, args.sandbox, Box::new(executor));
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

/// Route `runok check` to the appropriate adapter based on CLI args and stdin content.
fn route_check(
    args: &CheckArgs,
    mut stdin: impl std::io::Read,
) -> Result<Box<dyn Endpoint>, anyhow::Error> {
    // 1. --command CLI argument → always generic mode (no stdin)
    if let Some(command) = &args.command {
        return Ok(Box::new(CheckAdapter::from_command(command.clone())));
    }

    // 2. Read stdin JSON once
    let mut stdin_input = String::new();
    stdin.read_to_string(&mut stdin_input)?;
    let json_value: serde_json::Value =
        serde_json::from_str(&stdin_input).map_err(|e| anyhow::anyhow!("JSON parse error: {e}"))?;

    // 3. --format is explicitly specified → use that format
    if let Some(format) = &args.format {
        return match format.as_str() {
            "claude-code-hook" => {
                let hook_input: HookInput = serde_json::from_value(json_value)?;
                Ok(Box::new(ClaudeCodeHookAdapter::new(hook_input)))
            }
            unknown => Err(anyhow::anyhow!(
                "Unknown format: '{unknown}'. Valid formats: claude-code-hook"
            )),
        };
    }

    // 4. --format omitted → auto-detect by JSON field presence
    //    HookInput uses #[serde(rename_all = "camelCase")], so the actual JSON key is "toolName"
    if json_value.get("toolName").is_some() {
        let hook_input: HookInput = serde_json::from_value(json_value)?;
        Ok(Box::new(ClaudeCodeHookAdapter::new(hook_input)))
    } else if json_value.get("command").is_some() {
        let check_input: CheckInput = serde_json::from_value(json_value)?;
        Ok(Box::new(CheckAdapter::from_stdin(check_input)))
    } else {
        Err(anyhow::anyhow!(
            "Unknown input format: expected 'toolName' (Claude Code hook) or 'command' (generic) field"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    /// Helper: build CheckArgs for testing
    fn check_args(command: Option<&str>, format: Option<&str>) -> CheckArgs {
        CheckArgs {
            command: command.map(String::from),
            format: format.map(String::from),
        }
    }

    // === route_check: --command flag ===

    #[rstest]
    #[case::simple_command("git status")]
    #[case::command_with_flags("ls -la /tmp")]
    fn route_check_with_command_arg(#[case] cmd: &str) {
        let args = check_args(Some(cmd), None);
        let endpoint = route_check(&args, std::io::empty()).unwrap();
        assert_eq!(endpoint.extract_command().unwrap(), Some(cmd.to_string()));
    }

    // === route_check: stdin auto-detection ===

    #[rstest]
    #[case::claude_code_hook(
        indoc! {r#"
            {
                "toolName": "Bash",
                "sessionId": "s",
                "transcriptPath": "/tmp",
                "cwd": "/tmp",
                "permissionMode": "default",
                "hookEventName": "PreToolUse",
                "toolInput": {"command": "git status"},
                "toolUseId": "123"
            }
        "#},
        Some("git status"),
    )]
    #[case::generic_check(r#"{"command": "git status"}"#, Some("git status"))]
    fn route_check_stdin_auto_detect(
        #[case] stdin_json: &str,
        #[case] expected_command: Option<&str>,
    ) {
        let args = check_args(None, None);
        let endpoint = route_check(&args, stdin_json.as_bytes()).unwrap();
        assert_eq!(
            endpoint.extract_command().unwrap(),
            expected_command.map(String::from)
        );
    }

    #[rstest]
    fn route_check_stdin_unknown_format_returns_error() {
        let args = check_args(None, None);
        let result = route_check(&args, r#"{"unknown_field": "value"}"#.as_bytes());
        match result {
            Err(e) => assert!(
                e.to_string().contains("Unknown input format"),
                "error was: {e}"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[rstest]
    fn route_check_stdin_invalid_json_returns_error() {
        let args = check_args(None, None);
        let result = route_check(&args, "not valid json".as_bytes());
        match result {
            Err(e) => assert!(e.to_string().contains("JSON parse error"), "error was: {e}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[rstest]
    fn route_check_command_flag_takes_precedence_over_stdin() {
        // --command is specified, so stdin content is irrelevant
        let args = check_args(Some("echo hello"), Some("claude-code-hook"));
        let endpoint = route_check(&args, std::io::empty()).unwrap();
        assert_eq!(
            endpoint.extract_command().unwrap(),
            Some("echo hello".to_string())
        );
    }

    // === route_check: --format flag ===

    #[rstest]
    fn route_check_explicit_format_claude_code_hook() {
        let args = check_args(None, Some("claude-code-hook"));
        let stdin_json = indoc! {r#"
            {
                "toolName": "Bash",
                "sessionId": "s",
                "transcriptPath": "/tmp",
                "cwd": "/tmp",
                "permissionMode": "default",
                "hookEventName": "PreToolUse",
                "toolInput": {"command": "ls"},
                "toolUseId": "456"
            }
        "#};
        let endpoint = route_check(&args, stdin_json.as_bytes()).unwrap();
        assert_eq!(endpoint.extract_command().unwrap(), Some("ls".to_string()));
    }

    #[rstest]
    fn route_check_unknown_format_returns_error() {
        let args = check_args(None, Some("invalid-format"));
        let result = route_check(&args, r#"{"command": "ls"}"#.as_bytes());
        match result {
            Err(e) => assert!(
                e.to_string().contains("Unknown format: 'invalid-format'"),
                "error was: {e}"
            ),
            Ok(_) => panic!("expected an error"),
        }
    }

    // === run_command ===

    #[rstest]
    fn run_command_check_with_command_returns_zero() {
        let cmd = Commands::Check(CheckArgs {
            command: Some("echo hello".into()),
            format: None,
        });
        let cwd = std::env::current_dir().unwrap();
        let exit_code = run_command(cmd, &cwd, std::io::empty());
        // Without a config, default action is "ask" → exit 0 (CheckAdapter outputs JSON)
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

    // === CLI argument parsing ===

    #[rstest]
    #[case::exec_simple(
        &["runok", "exec", "--", "git", "status"],
        Commands::Exec(ExecArgs { command: vec!["git".into(), "status".into()], sandbox: None }),
    )]
    #[case::exec_with_sandbox(
        &["runok", "exec", "--sandbox", "strict", "--", "ls"],
        Commands::Exec(ExecArgs { command: vec!["ls".into()], sandbox: Some("strict".into()) }),
    )]
    #[case::check_with_command(
        &["runok", "check", "--command", "git status"],
        Commands::Check(CheckArgs { command: Some("git status".into()), format: None }),
    )]
    #[case::check_with_format(
        &["runok", "check", "--format", "claude-code-hook"],
        Commands::Check(CheckArgs { command: None, format: Some("claude-code-hook".into()) }),
    )]
    #[case::check_with_both(
        &["runok", "check", "--command", "ls", "--format", "claude-code-hook"],
        Commands::Check(CheckArgs { command: Some("ls".into()), format: Some("claude-code-hook".into()) }),
    )]
    fn cli_parsing(#[case] argv: &[&str], #[case] expected: Commands) {
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.command, expected);
    }
}
