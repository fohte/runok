mod route;

use clap::{Parser, Subcommand, ValueEnum};

pub use route::{CheckRoute, route_check};

#[derive(Parser)]
#[command(name = "runok", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Commands {
    /// Execute a command with permission checks and optional sandboxing
    Exec(ExecArgs),
    /// Check whether a command would be allowed
    Check(CheckArgs),
    /// Initialize runok configuration
    Init(InitArgs),
    /// Print the JSON Schema for runok.yml to stdout
    #[cfg(feature = "config-schema")]
    ConfigSchema,

    /// Internal: Linux sandbox execution (stage 1/stage 2)
    #[cfg(target_os = "linux")]
    #[command(name = "__sandbox-exec", hide = true)]
    SandboxExec(SandboxExecArgs),
}

/// Scope for init configuration: user-level or project-level.
#[derive(Clone, ValueEnum)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum InitScope {
    User,
    Project,
}

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct InitArgs {
    /// Configuration scope: "user" for global, "project" for local
    #[arg(long, value_enum)]
    pub scope: Option<InitScope>,

    /// Accept all defaults without prompting
    #[arg(short = 'y', long = "yes")]
    pub yes: bool,
}

#[cfg(target_os = "linux")]
#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct SandboxExecArgs {
    /// Sandbox policy as JSON string.
    #[arg(long)]
    pub policy: String,

    /// Working directory for the sandboxed command.
    #[arg(long)]
    pub cwd: std::path::PathBuf,

    /// Stage 2 mode: apply landlock + seccomp, then exec the command.
    /// Used internally when re-invoked inside bubblewrap.
    #[arg(long)]
    pub apply_sandbox_then_exec: bool,

    /// The command and its arguments to execute.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ExecArgs {
    /// Sandbox preset name
    #[arg(long)]
    pub sandbox: Option<String>,

    /// Show what would happen without executing the command
    #[arg(long)]
    pub dry_run: bool,

    /// Output detailed rule matching information to stderr
    #[arg(long)]
    pub verbose: bool,

    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub command: Vec<String>,
}

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct CheckArgs {
    /// Input format: "claude-code-hook" or omit for auto-detection
    #[arg(long)]
    pub input_format: Option<String>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub output_format: OutputFormat,

    /// Output detailed rule matching information to stderr
    #[arg(long)]
    pub verbose: bool,

    /// Command and arguments to check (skips stdin)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Json,
    Text,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::exec_simple(
        &["runok", "exec", "--", "git", "status"],
        Commands::Exec(ExecArgs { command: vec!["git".into(), "status".into()], sandbox: None, dry_run: false, verbose: false }),
    )]
    #[case::exec_with_sandbox(
        &["runok", "exec", "--sandbox", "strict", "--", "ls"],
        Commands::Exec(ExecArgs { command: vec!["ls".into()], sandbox: Some("strict".into()), dry_run: false, verbose: false }),
    )]
    #[case::exec_with_dry_run(
        &["runok", "exec", "--dry-run", "--", "git", "status"],
        Commands::Exec(ExecArgs { command: vec!["git".into(), "status".into()], sandbox: None, dry_run: true, verbose: false }),
    )]
    #[case::exec_with_verbose(
        &["runok", "exec", "--verbose", "--", "git", "status"],
        Commands::Exec(ExecArgs { command: vec!["git".into(), "status".into()], sandbox: None, dry_run: false, verbose: true }),
    )]
    #[case::exec_with_dry_run_and_verbose(
        &["runok", "exec", "--dry-run", "--verbose", "--", "ls"],
        Commands::Exec(ExecArgs { command: vec!["ls".into()], sandbox: None, dry_run: true, verbose: true }),
    )]
    #[case::check_with_command(
        &["runok", "check", "--", "git", "status"],
        Commands::Check(CheckArgs { input_format: None, output_format: OutputFormat::Text, verbose: false, command: vec!["git".into(), "status".into()] }),
    )]
    #[case::check_with_input_format(
        &["runok", "check", "--input-format", "claude-code-hook"],
        Commands::Check(CheckArgs { input_format: Some("claude-code-hook".into()), output_format: OutputFormat::Text, verbose: false, command: vec![] }),
    )]
    #[case::check_with_output_format_json(
        &["runok", "check", "--output-format", "json", "--", "ls"],
        Commands::Check(CheckArgs { input_format: None, output_format: OutputFormat::Json, verbose: false, command: vec!["ls".into()] }),
    )]
    #[case::check_with_both(
        &["runok", "check", "--input-format", "claude-code-hook", "--", "ls"],
        Commands::Check(CheckArgs { input_format: Some("claude-code-hook".into()), output_format: OutputFormat::Text, verbose: false, command: vec!["ls".into()] }),
    )]
    #[case::check_with_verbose(
        &["runok", "check", "--verbose", "--", "git", "status"],
        Commands::Check(CheckArgs { input_format: None, output_format: OutputFormat::Text, verbose: true, command: vec!["git".into(), "status".into()] }),
    )]
    #[case::init_defaults(
        &["runok", "init"],
        Commands::Init(InitArgs { scope: None, yes: false }),
    )]
    #[case::init_with_scope_user(
        &["runok", "init", "--scope", "user"],
        Commands::Init(InitArgs { scope: Some(InitScope::User), yes: false }),
    )]
    #[case::init_with_scope_project(
        &["runok", "init", "--scope", "project"],
        Commands::Init(InitArgs { scope: Some(InitScope::Project), yes: false }),
    )]
    #[case::init_with_yes(
        &["runok", "init", "-y"],
        Commands::Init(InitArgs { scope: None, yes: true }),
    )]
    #[case::init_with_yes_long(
        &["runok", "init", "--yes"],
        Commands::Init(InitArgs { scope: None, yes: true }),
    )]
    #[case::init_all_flags(
        &["runok", "init", "--scope", "user", "-y"],
        Commands::Init(InitArgs { scope: Some(InitScope::User), yes: true }),
    )]
    fn cli_parsing(#[case] argv: &[&str], #[case] expected: Commands) {
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.command, expected);
    }

    #[rstest]
    #[case::invalid_scope(&["runok", "init", "--scope", "invalid"])]
    fn cli_parsing_errors(#[case] argv: &[&str]) {
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err());
    }
}
