use std::path::{Path, PathBuf};

use super::super::error::InitError;
use super::super::prompt::Prompter;
use super::super::{claude_code, config_gen};
use super::preview::{
    normalize_json, preview_register_hook, preview_remove_permissions, print_diff,
};

/// Result of setting up a single scope.
pub(super) struct ScopeResult {
    pub config_path: Option<PathBuf>,
    pub hook_registered: bool,
    pub converted_rules: Option<String>,
    pub permissions_removed: bool,
}

/// Whether to register the runok hook in settings.json.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HookPolicy {
    /// Register hook (user scope).
    Register,
    /// Never register hook (project scope — shared config should not
    /// assume all contributors use runok).
    Skip,
}

/// Set up configuration for a given scope (user or project).
///
/// `hook_policy` controls whether the runok hook is registered in settings.json.
/// `migration_default` controls the default answer for the migration prompt
/// (true for user scope, false for project scope).
pub(super) fn setup_scope(
    config_dir: &Path,
    claude_dir: Option<&Path>,
    prompter: &dyn Prompter,
    hook_policy: HookPolicy,
    migration_default: bool,
) -> Result<ScopeResult, InitError> {
    let mut converted_rules = None;
    let mut approved = false;
    let mut has_any_change = false;
    let mut has_rules = false;
    let mut has_hook_change = false;

    if let Some(cd) = claude_dir
        && cd.exists()
    {
        // Read current settings.json
        let settings_path = cd.join("settings.json");
        let original_content = if settings_path.exists() {
            normalize_json(&std::fs::read_to_string(&settings_path)?)?
        } else {
            String::new()
        };

        // Determine what changes are needed
        let (allow, deny) = claude_code::read_permissions(cd)?;
        let has_permissions = !allow.is_empty() || !deny.is_empty();

        if has_permissions {
            let conversion = claude_code::convert_permissions(&allow, &deny);
            if !conversion.rules.is_empty() {
                let should_migrate = prompter.confirm(
                    "Migrate Claude Code Bash permissions to runok rules?",
                    migration_default,
                )?;
                if should_migrate {
                    converted_rules = Some(conversion.rules.clone());
                    has_rules = true;
                }
            }
        }

        // Build the preview (only compute hook if policy allows)
        let after_permissions = if has_rules {
            preview_remove_permissions(&original_content)?
        } else {
            original_content.clone()
        };

        if hook_policy == HookPolicy::Register {
            let hook_preview = preview_register_hook(&after_permissions)?;
            has_hook_change = hook_preview.is_some();
        }

        has_any_change = has_rules || has_hook_change;

        if has_any_change {
            let settings_path_display = settings_path.display();
            let config_path = config_dir.join("runok.yml");
            let config_path_display = config_path.display();

            eprintln!(
                "\x1b[1mDetected Claude Code configuration in {settings_path_display}\x1b[0m"
            );
            eprintln!();

            // Show all diffs together
            if has_rules {
                eprintln!("\x1b[1mRemove Bash permissions from {settings_path_display}\x1b[0m");
                eprintln!();
                print_diff(
                    &settings_path_display.to_string(),
                    &original_content,
                    &after_permissions,
                );
                eprintln!();

                let config_content = config_gen::build_config_content(converted_rules.as_deref());
                let existing_config = if config_path.exists() {
                    std::fs::read_to_string(&config_path)?
                } else {
                    String::new()
                };
                let verb = if config_path.exists() {
                    "Update"
                } else {
                    "Create"
                };
                eprintln!("\x1b[1m{verb} {config_path_display} with converted rules\x1b[0m");
                eprintln!();
                print_diff(
                    &config_path_display.to_string(),
                    &existing_config,
                    &config_content,
                );
                eprintln!();
            }

            if has_hook_change {
                let hook_preview = preview_register_hook(&after_permissions)?;
                eprintln!("\x1b[1mRegister runok hook in {settings_path_display}\x1b[0m");
                eprintln!();
                if let Some(ref after_hook) = hook_preview {
                    print_diff(
                        &settings_path_display.to_string(),
                        &after_permissions,
                        after_hook,
                    );
                }
                eprintln!();
            }

            approved = prompter.confirm("Apply these changes?", true)?;
            if !approved {
                converted_rules = None;
            }
        }
    }

    // Apply changes only when the user approved the batch
    let permissions_removed = if approved && has_rules {
        claude_dir
            .map(claude_code::remove_permissions)
            .transpose()?
            .unwrap_or(false)
    } else {
        false
    };

    let hook_registered = if approved && has_hook_change {
        claude_dir
            .map(claude_code::register_hook)
            .transpose()?
            .unwrap_or(false)
    } else {
        false
    };

    // Create config file:
    // - If user approved changes with rules: config includes converted rules
    // - If no Claude Code changes were needed: boilerplate config only
    // - If user declined: no config created
    let config_path = if has_any_change && !approved {
        None
    } else {
        let content = config_gen::build_config_content(converted_rules.as_deref());
        Some(config_gen::write_config(config_dir, &content)?)
    };

    Ok(ScopeResult {
        config_path,
        hook_registered,
        converted_rules,
        permissions_removed,
    })
}
