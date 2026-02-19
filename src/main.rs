use std::io::Read as _;
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
enum Commands {
    /// Execute a command with permission checks and optional sandboxing
    Exec(ExecArgs),
    /// Check whether a command would be allowed
    Check(CheckArgs),
}

#[derive(clap::Args)]
struct ExecArgs {
    /// Sandbox preset name
    #[arg(long)]
    sandbox: Option<String>,

    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    command: Vec<String>,
}

#[derive(clap::Args)]
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

    let loader = DefaultConfigLoader::new();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = match loader.load(&cwd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("runok: config error: {e}");
            return ExitCode::from(2);
        }
    };

    let exit_code = match cli.command {
        Commands::Exec(args) => {
            let executor = ProcessCommandExecutor::new_without_sandbox();
            let endpoint = ExecAdapter::new(args.command, args.sandbox, Box::new(executor));
            adapter::run(&endpoint, &config)
        }
        Commands::Check(args) => match route_check(&args) {
            Ok(endpoint) => adapter::run(endpoint.as_ref(), &config),
            Err(e) => {
                eprintln!("runok: {e}");
                2
            }
        },
    };

    ExitCode::from(exit_code as u8)
}

/// Route `runok check` to the appropriate adapter based on CLI args and stdin content.
fn route_check(args: &CheckArgs) -> Result<Box<dyn Endpoint>, anyhow::Error> {
    // 1. --command CLI argument → always generic mode (no stdin)
    if let Some(command) = &args.command {
        return Ok(Box::new(CheckAdapter::from_command(command.clone())));
    }

    // 2. Read stdin JSON once
    let stdin_input = read_stdin_to_string()?;
    let json_value: serde_json::Value =
        serde_json::from_str(&stdin_input).map_err(|e| anyhow::anyhow!("JSON parse error: {e}"))?;

    // 3. --format is explicitly specified → use that format
    if let Some(format) = &args.format {
        return match format.as_str() {
            "claude-code-hook" => {
                let hook_input: HookInput = serde_json::from_value(json_value)?;
                Ok(Box::new(ClaudeCodeHookAdapter::new(hook_input)))
            }
            _ => {
                let check_input: CheckInput = serde_json::from_value(json_value)?;
                Ok(Box::new(CheckAdapter::from_stdin(check_input)))
            }
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

fn read_stdin_to_string() -> Result<String, anyhow::Error> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    /// Helper: build CheckArgs for testing
    fn check_args(command: Option<&str>, format: Option<&str>) -> CheckArgs {
        CheckArgs {
            command: command.map(String::from),
            format: format.map(String::from),
        }
    }

    #[rstest]
    #[case::command_arg("git status")]
    #[case::command_arg_with_args("ls -la /tmp")]
    fn route_check_with_command_arg_returns_check_adapter(#[case] cmd: &str) {
        let args = check_args(Some(cmd), None);
        let endpoint = route_check(&args);
        assert!(endpoint.is_ok());
        // Verify the endpoint extracts the correct command
        let ep = endpoint.unwrap();
        let extracted = ep.extract_command().unwrap();
        assert_eq!(extracted, Some(cmd.to_string()));
    }

    // Tests for stdin-based routing require injecting stdin, which is not feasible
    // in unit tests. The auto-detection logic is tested via JSON parsing below.

    #[rstest]
    #[case::has_tool_name(json!({"toolName": "Bash", "sessionId": "s"}), true)]
    #[case::has_command_only(json!({"command": "git status"}), false)]
    fn auto_detect_format(#[case] value: serde_json::Value, #[case] is_hook_format: bool) {
        // Mirrors the auto-detect logic in route_check: HookInput uses camelCase JSON keys
        let detected = value.get("toolName").is_some();
        assert_eq!(detected, is_hook_format);
    }

    #[rstest]
    fn auto_detect_unknown_format_has_no_known_fields() {
        let value = json!({"unknown_field": "value"});
        let has_tool_name = value.get("toolName").is_some();
        let has_command = value.get("command").is_some();
        assert!(!has_tool_name);
        assert!(!has_command);
    }

    #[rstest]
    fn cli_exec_parses_correctly() {
        let cli = Cli::parse_from(["runok", "exec", "--", "git", "status"]);
        match cli.command {
            Commands::Exec(args) => {
                assert_eq!(args.command, vec!["git", "status"]);
                assert!(args.sandbox.is_none());
            }
            _ => panic!("expected Exec subcommand"),
        }
    }

    #[rstest]
    fn cli_exec_with_sandbox_parses_correctly() {
        let cli = Cli::parse_from(["runok", "exec", "--sandbox", "strict", "--", "ls"]);
        match cli.command {
            Commands::Exec(args) => {
                assert_eq!(args.command, vec!["ls"]);
                assert_eq!(args.sandbox.as_deref(), Some("strict"));
            }
            _ => panic!("expected Exec subcommand"),
        }
    }

    #[rstest]
    fn cli_check_with_command_parses_correctly() {
        let cli = Cli::parse_from(["runok", "check", "--command", "git status"]);
        match cli.command {
            Commands::Check(args) => {
                assert_eq!(args.command.as_deref(), Some("git status"));
                assert!(args.format.is_none());
            }
            _ => panic!("expected Check subcommand"),
        }
    }

    #[rstest]
    fn cli_check_with_format_parses_correctly() {
        let cli = Cli::parse_from(["runok", "check", "--format", "claude-code-hook"]);
        match cli.command {
            Commands::Check(args) => {
                assert!(args.command.is_none());
                assert_eq!(args.format.as_deref(), Some("claude-code-hook"));
            }
            _ => panic!("expected Check subcommand"),
        }
    }

    #[rstest]
    fn cli_check_with_both_command_and_format_parses_correctly() {
        let cli = Cli::parse_from([
            "runok",
            "check",
            "--command",
            "ls",
            "--format",
            "claude-code-hook",
        ]);
        match cli.command {
            Commands::Check(args) => {
                assert_eq!(args.command.as_deref(), Some("ls"));
                assert_eq!(args.format.as_deref(), Some("claude-code-hook"));
            }
            _ => panic!("expected Check subcommand"),
        }
    }
}
