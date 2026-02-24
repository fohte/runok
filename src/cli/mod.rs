mod route;

use clap::{Parser, Subcommand};

pub use route::{CheckRoute, route_check};

#[derive(Parser)]
#[command(name = "runok")]
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
    /// Print the JSON Schema for runok.yml to stdout
    #[cfg(feature = "config-schema")]
    ConfigSchema,
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
    pub format: Option<String>,

    /// Output detailed rule matching information to stderr
    #[arg(long)]
    pub verbose: bool,

    /// Command and arguments to check (skips stdin)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
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
        Commands::Check(CheckArgs { format: None, verbose: false, command: vec!["git".into(), "status".into()] }),
    )]
    #[case::check_with_format(
        &["runok", "check", "--format", "claude-code-hook"],
        Commands::Check(CheckArgs { format: Some("claude-code-hook".into()), verbose: false, command: vec![] }),
    )]
    #[case::check_with_both(
        &["runok", "check", "--format", "claude-code-hook", "--", "ls"],
        Commands::Check(CheckArgs { format: Some("claude-code-hook".into()), verbose: false, command: vec!["ls".into()] }),
    )]
    #[case::check_with_verbose(
        &["runok", "check", "--verbose", "--", "git", "status"],
        Commands::Check(CheckArgs { format: None, verbose: true, command: vec!["git".into(), "status".into()] }),
    )]
    fn cli_parsing(#[case] argv: &[&str], #[case] expected: Commands) {
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.command, expected);
    }
}
