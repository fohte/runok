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
    /// View audit log entries
    Audit(AuditArgs),
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

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct AuditArgs {
    /// Filter by action kind (allow, deny, ask)
    #[arg(long)]
    pub action: Option<String>,

    /// Show entries since this time (e.g., "1h", "7d", "2026-02-25")
    #[arg(long)]
    pub since: Option<String>,

    /// Show entries until this time (e.g., "1h", "7d", "2026-02-25")
    #[arg(long)]
    pub until: Option<String>,

    /// Filter by command substring
    #[arg(long)]
    pub command: Option<String>,

    /// Maximum number of entries to show
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
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
    #[case::audit_default(
        &["runok", "audit"],
        Commands::Audit(AuditArgs { action: None, since: None, until: None, command: None, limit: 50, json: false }),
    )]
    #[case::audit_with_action(
        &["runok", "audit", "--action", "deny"],
        Commands::Audit(AuditArgs { action: Some("deny".into()), since: None, until: None, command: None, limit: 50, json: false }),
    )]
    #[case::audit_with_since(
        &["runok", "audit", "--since", "1h"],
        Commands::Audit(AuditArgs { action: None, since: Some("1h".into()), until: None, command: None, limit: 50, json: false }),
    )]
    #[case::audit_with_all_options(
        &["runok", "audit", "--action", "allow", "--since", "7d", "--until", "1h", "--command", "git", "--limit", "10", "--json"],
        Commands::Audit(AuditArgs { action: Some("allow".into()), since: Some("7d".into()), until: Some("1h".into()), command: Some("git".into()), limit: 10, json: true }),
    )]
    fn cli_parsing(#[case] argv: &[&str], #[case] expected: Commands) {
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.command, expected);
    }
}
