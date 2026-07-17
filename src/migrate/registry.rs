use super::claude_code_hook::ClaudeCodeHookMigration;
use super::migration::Migration;
use super::quote_optional_marker::QuoteOptionalMarkerMigration;
use super::sandbox_fs::SandboxFsMigration;

/// All registered migrations, in application order.
pub fn all() -> Vec<Box<dyn Migration>> {
    vec![
        Box::new(SandboxFsMigration),
        Box::new(QuoteOptionalMarkerMigration),
        Box::new(ClaudeCodeHookMigration),
    ]
}
