mod route;
mod validate;

use clap::{Parser, Subcommand, ValueEnum};

pub use route::{CheckRoute, route_check};
pub use validate::{find_subcommand, validate_no_unknown_flags};

#[derive(Parser)]
#[command(name = "runok", version = env!("RUNOK_VERSION"))]
pub struct Cli {
    /// Path to the config file
    #[arg(short = 'c', long, global = true)]
    pub config: Option<std::path::PathBuf>,

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
    /// Run tests defined in the config to verify rules
    Test(TestArgs),
    /// Initialize runok configuration
    Init(InitArgs),
    /// Migrate config files to the latest format
    Migrate(MigrateArgs),
    /// Force-update all remote presets referenced via extends
    UpdatePresets,
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
pub struct MigrateArgs {
    /// Apply all changes without prompting
    #[arg(short = 'y', long = "yes")]
    pub yes: bool,
}

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct TestArgs {}

#[derive(clap::Args)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ExecArgs {
    /// Sandbox preset name
    #[arg(long)]
    pub sandbox: Option<String>,

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

    /// Filter by working directory (includes subdirectories)
    #[arg(long)]
    pub dir: Option<String>,

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
        Commands::Exec(ExecArgs { command: vec!["git".into(), "status".into()], sandbox: None, verbose: false }),
    )]
    #[case::exec_with_sandbox(
        &["runok", "exec", "--sandbox", "strict", "--", "ls"],
        Commands::Exec(ExecArgs { command: vec!["ls".into()], sandbox: Some("strict".into()), verbose: false }),
    )]
    #[case::exec_with_verbose(
        &["runok", "exec", "--verbose", "--", "git", "status"],
        Commands::Exec(ExecArgs { command: vec!["git".into(), "status".into()], sandbox: None, verbose: true }),
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
        Commands::Audit(AuditArgs { action: None, since: None, until: None, command: None, dir: None, limit: 50, json: false }),
    )]
    #[case::audit_with_action(
        &["runok", "audit", "--action", "deny"],
        Commands::Audit(AuditArgs { action: Some("deny".into()), since: None, until: None, command: None, dir: None, limit: 50, json: false }),
    )]
    #[case::audit_with_since(
        &["runok", "audit", "--since", "1h"],
        Commands::Audit(AuditArgs { action: None, since: Some("1h".into()), until: None, command: None, dir: None, limit: 50, json: false }),
    )]
    #[case::audit_with_dir(
        &["runok", "audit", "--dir", "/home/user/project"],
        Commands::Audit(AuditArgs { action: None, since: None, until: None, command: None, dir: Some("/home/user/project".into()), limit: 50, json: false }),
    )]
    #[case::audit_with_all_options(
        &["runok", "audit", "--action", "allow", "--since", "7d", "--until", "1h", "--command", "git", "--limit", "10", "--json"],
        Commands::Audit(AuditArgs { action: Some("allow".into()), since: Some("7d".into()), until: Some("1h".into()), command: Some("git".into()), dir: None, limit: 10, json: true }),
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
    #[case::migrate_default(
        &["runok", "migrate"],
        Commands::Migrate(MigrateArgs { yes: false }),
    )]
    #[case::migrate_with_yes(
        &["runok", "migrate", "-y"],
        Commands::Migrate(MigrateArgs { yes: true }),
    )]
    #[case::test_default(
        &["runok", "test"],
        Commands::Test(TestArgs {}),
    )]
    #[case::update_presets(
        &["runok", "update-presets"],
        Commands::UpdatePresets,
    )]
    fn cli_parsing(#[case] argv: &[&str], #[case] expected: Commands) {
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.command, expected);
    }

    #[rstest]
    #[case::config_before_subcommand(
        &["runok", "-c", "path/to/config.yml", "test"],
        Some(std::path::PathBuf::from("path/to/config.yml")),
    )]
    #[case::config_long_before_subcommand(
        &["runok", "--config", "path/to/config.yml", "check", "--", "ls"],
        Some(std::path::PathBuf::from("path/to/config.yml")),
    )]
    #[case::config_after_subcommand(
        &["runok", "test", "-c", "path/to/config.yml"],
        Some(std::path::PathBuf::from("path/to/config.yml")),
    )]
    #[case::config_after_migrate(
        &["runok", "migrate", "-c", "path/to/config.yml"],
        Some(std::path::PathBuf::from("path/to/config.yml")),
    )]
    #[case::no_config(
        &["runok", "test"],
        None,
    )]
    fn cli_global_config_flag(#[case] argv: &[&str], #[case] expected: Option<std::path::PathBuf>) {
        let cli = Cli::parse_from(argv);
        assert_eq!(cli.config, expected);
    }

    #[rstest]
    #[case::invalid_scope(&["runok", "init", "--scope", "invalid"])]
    fn cli_parsing_errors(#[case] argv: &[&str]) {
        let result = Cli::try_parse_from(argv);
        assert!(result.is_err());
    }
}
