mod sandbox_fs;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use similar::ChangeTag;

use crate::config::preset_remote::{PresetReference, parse_preset_reference};
use crate::config::{DefaultConfigLoader, parse_config};
use crate::init::prompt::{AutoYesPrompter, DialoguerPrompter, Prompter};

/// Run migration on all discovered config files (or a specific file if given).
///
/// When `yes` is false, shows a diff preview and asks for confirmation before
/// writing changes. When `yes` is true, applies changes without prompting.
pub fn run(config_path: Option<&Path>, yes: bool) -> Result<(), MigrateError> {
    let root_paths = match config_path {
        Some(p) => vec![p.to_path_buf()],
        None => {
            let cwd = std::env::current_dir().map_err(MigrateError::Io)?;
            DefaultConfigLoader::new().find_config_paths(&cwd)
        }
    };

    if root_paths.is_empty() {
        eprintln!("runok: no config files found");
        return Ok(());
    }

    // Collect all paths including local extends targets
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for path in &root_paths {
        collect_with_local_extends(path, &mut paths, &mut seen);
    }

    let prompter: Box<dyn Prompter> = if yes {
        Box::new(AutoYesPrompter)
    } else {
        Box::new(DialoguerPrompter)
    };

    let mut migrated_count = 0;

    for path in &paths {
        let original = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warning: cannot read {}: {e}", path.display());
                continue;
            }
        };
        let migrated = sandbox_fs::migrate_sandbox_fs(&original);

        if migrated == original {
            continue;
        }

        // Show diff preview
        let path_display = path.display().to_string();
        eprintln!("\x1b[1mMigrate {path_display}\x1b[0m");
        eprintln!();
        print_diff(&path_display, &original, &migrated);
        eprintln!();

        let approved = prompter
            .confirm("Apply these changes?", true)
            .map_err(|e| MigrateError::Io(std::io::Error::other(e)))?;

        if approved {
            std::fs::write(path, &migrated).map_err(MigrateError::Io)?;
            eprintln!("migrated: {}", path.display());
            migrated_count += 1;
        } else {
            eprintln!("skipped: {}", path.display());
        }
    }

    if migrated_count > 0 {
        eprintln!(
            "\n{migrated_count} file{} updated.",
            if migrated_count == 1 { "" } else { "s" }
        );
    } else {
        eprintln!("Already up to date.");
    }

    Ok(())
}

/// Collect a config file path and recursively collect local extends targets.
fn collect_with_local_extends(path: &Path, out: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>) {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(canonical.clone()) {
        return;
    }
    out.push(path.to_path_buf());

    // Parse the config to find extends references
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(config) = parse_config(&content) else {
        return;
    };

    let Some(extends) = config.extends else {
        return;
    };

    let base_dir = path.parent().unwrap_or(Path::new("."));
    for reference in &extends {
        // Only follow local file references, not remote (github:, https://, etc.)
        if let Ok(PresetReference::Local(local_path)) = parse_preset_reference(reference) {
            let resolved = base_dir.join(local_path);
            if resolved.exists() {
                collect_with_local_extends(&resolved, out, seen);
            }
        }
    }
}

/// Print a colored unified-style diff between two strings.
fn print_diff(filename: &str, before: &str, after: &str) {
    let diff = similar::TextDiff::from_lines(before, after);

    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    let (prefix_a, prefix_b) = if filename.starts_with('/') {
        ("--- ", "+++ ")
    } else {
        ("--- a/", "+++ b/")
    };
    eprintln!("{RED}{prefix_a}{filename}{RESET}");
    eprintln!("{GREEN}{prefix_b}{filename}{RESET}");

    for group in diff.grouped_ops(3) {
        let first = &group[0];
        let last = &group[group.len() - 1];
        let old_start = first.old_range().start + 1;
        let old_len = last.old_range().end - first.old_range().start;
        let new_start = first.new_range().start + 1;
        let new_len = last.new_range().end - first.new_range().start;
        eprintln!("{CYAN}@@ -{old_start},{old_len} +{new_start},{new_len} @@{RESET}");
        for op in &group {
            for change in diff.iter_changes(op) {
                let (sign, color) = match change.tag() {
                    ChangeTag::Delete => ("-", RED),
                    ChangeTag::Insert => ("+", GREEN),
                    ChangeTag::Equal => (" ", ""),
                };
                eprint!("{color}{sign}{change}{RESET}");
                if change.missing_newline() {
                    eprintln!();
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
}
