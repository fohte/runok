use super::migration::Migration;
use super::sandbox_fs::SandboxFsMigration;

/// All registered migrations, in application order.
pub fn all() -> Vec<Box<dyn Migration>> {
    vec![Box::new(SandboxFsMigration)]
}
