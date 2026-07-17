use super::MigrateError;

/// A migration that rewrites a config file's contents to follow a newer
/// schema.
///
/// Migrations are applied to a file in registry order, each consuming the
/// previous migration's approved output. Implementations must be
/// idempotent: applying `migrate` to its own output must return `None`.
pub trait Migration {
    /// Stable identifier used in diagnostics (e.g. `"sandbox-fs"`).
    fn id(&self) -> &'static str;

    /// One-line description shown alongside diff previews.
    fn description(&self) -> &'static str;

    /// The set of files this migration applies to.
    fn target(&self) -> MigrationTarget;

    /// Returns the migrated content, or `None` if `content` needs no change.
    fn migrate(&self, content: &str) -> Result<Option<String>, MigrateError>;
}

/// The set of files a migration applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationTarget {
    /// runok config files reachable via local `extends`.
    ConfigChain,
    /// Claude Code's `.claude/settings.json`, at the user and project scopes.
    ClaudeCodeSettings,
}
