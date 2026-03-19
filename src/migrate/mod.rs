mod sandbox_fs;

use std::path::Path;

use crate::config::DefaultConfigLoader;

/// Run migration on all discovered config files (or a specific file if given).
pub fn run(config_path: Option<&Path>) -> Result<(), MigrateError> {
    let paths = match config_path {
        Some(p) => vec![p.to_path_buf()],
        None => {
            let cwd = std::env::current_dir().map_err(MigrateError::Io)?;
            DefaultConfigLoader::new().find_config_paths(&cwd)
        }
    };

    if paths.is_empty() {
        eprintln!("runok: no config files found");
        return Ok(());
    }

    let mut migrated_count = 0;

    for path in &paths {
        let original = std::fs::read_to_string(path).map_err(MigrateError::Io)?;
        let migrated = sandbox_fs::migrate_sandbox_fs(&original);

        if migrated != original {
            std::fs::write(path, &migrated).map_err(MigrateError::Io)?;
            eprintln!("migrated: {}", path.display());
            migrated_count += 1;
        } else {
            eprintln!("no changes: {}", path.display());
        }
    }

    if migrated_count > 0 {
        eprintln!(
            "\n{migrated_count} file{} updated.",
            if migrated_count == 1 { "" } else { "s" }
        );
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
}
