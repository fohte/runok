mod route;

use clap::{Parser, Subcommand};

pub use route::route_check;

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
    /// Command string to check (skips stdin)
    #[arg(long)]
    pub command: Option<String>,

    /// Input format: "claude-code-hook" or omit for auto-detection
    #[arg(long)]
    pub format: Option<String>,

    /// Show what would happen without side effects
    #[arg(long)]
    pub dry_run: bool,

    /// Output detailed rule matching information to stderr
    #[arg(long)]
    pub verbose: bool,
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
        &["runok", "check", "--command", "git status"],
        Commands::Check(CheckArgs { command: Some("git status".into()), format: None, dry_run: false, verbose: false }),
    )]
    #[case::check_with_format(
        &["runok", "check", "--format", "claude-code-hook"],
        Commands::Check(CheckArgs { command: None, format: Some("claude-code-hook".into()), dry_run: false, verbose: false }),
    )]
    #[case::check_with_both(
        &["runok", "check", "--command", "ls", "--format", "claude-code-hook"],
        Commands::Check(CheckArgs { command: Some("ls".into()), format: Some("claude-code-hook".into()), dry_run: false, verbose: false }),
    )]
    #[case::check_with_dry_run(
        &["runok", "check", "--dry-run", "--command", "git status"],
        Commands::Check(CheckArgs { command: Some("git status".into()), format: None, dry_run: true, verbose: false }),
    )]
    #[case::check_with_verbose(
        &["runok", "check", "--verbose", "--command", "git status"],
        Commands::Check(CheckArgs { command: Some("git status".into()), format: None, dry_run: false, verbose: true }),
    )]
    fn cli_parsing(#[case] argv: &[&str], #[case] expected: Commands) {
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.command, expected);
    }
}
