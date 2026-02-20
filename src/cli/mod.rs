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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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
