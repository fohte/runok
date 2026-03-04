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

/// Set up configuration for a given scope (user or project).
pub(super) fn setup_scope(
    config_dir: &Path,
    claude_dir: Option<&Path>,
    prompter: &dyn Prompter,
    force: bool,
) -> Result<ScopeResult, InitError> {
    let mut converted_rules = None;
    let mut hook_registered = false;
    let mut permissions_removed = false;
    let mut config_declined = false;

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
        let mut has_rules = false;

        if has_permissions {
            let conversion = claude_code::convert_permissions(&allow, &deny);
            if !conversion.rules.is_empty() {
                converted_rules = Some(conversion.rules.clone());
                has_rules = true;
            }
        }

        // Build the preview
        let after_permissions = if has_rules {
            preview_remove_permissions(&original_content)?
        } else {
            original_content.clone()
        };
        let hook_preview = preview_register_hook(&after_permissions)?;
        let has_hook_change = hook_preview.is_some();

        // ANSI codes for step headers
        const BOLD: &str = "\x1b[1m";
        const CYAN: &str = "\x1b[36m";
        const RESET: &str = "\x1b[0m";

        let settings_path_display = settings_path.display();
        let config_path = config_dir.join("runok.yml");
        let config_path_display = config_path.display();

        let mut step = 1;
        let total_steps = usize::from(has_rules) * 2 + usize::from(has_hook_change);

        if has_rules {
            // Step: remove permissions from settings.json
            eprintln!(
                "{CYAN}[{step}/{total_steps}]{RESET} {BOLD}Remove Bash permissions from {settings_path_display}{RESET}"
            );
            eprintln!();
            print_diff(
                &settings_path_display.to_string(),
                &original_content,
                &after_permissions,
            );
            eprintln!();

            let should_apply = prompter.confirm("Apply this change?", true)?;
            if should_apply {
                permissions_removed = claude_code::remove_permissions(cd)?;
            }
            step += 1;
            eprintln!();

            // Step: create runok.yml with converted rules
            let config_content = config_gen::build_config_content(converted_rules.as_deref());

            eprintln!(
                "{CYAN}[{step}/{total_steps}]{RESET} {BOLD}Create {config_path_display} with converted rules{RESET}"
            );
            eprintln!();
            print_diff(&config_path_display.to_string(), "", &config_content);
            eprintln!();

            let should_apply = prompter.confirm("Apply this change?", true)?;
            if !should_apply {
                // User declined: skip creating runok.yml entirely
                converted_rules = None;
                config_declined = true;
            }
            step += 1;
            eprintln!();
        }

        if has_hook_change {
            eprintln!(
                "{CYAN}[{step}/{total_steps}]{RESET} {BOLD}Register runok hook in {settings_path_display}{RESET}"
            );
            eprintln!();
            if let Some(ref after_hook) = hook_preview {
                print_diff(
                    &settings_path_display.to_string(),
                    &after_permissions,
                    after_hook,
                );
            }
            eprintln!();

            let should_apply = prompter.confirm("Apply this change?", true)?;
            if should_apply {
                hook_registered = claude_code::register_hook(cd)?;
            }
        }
    }

    let config_path = if config_declined {
        None
    } else {
        let content = config_gen::build_config_content(converted_rules.as_deref());
        Some(config_gen::write_config(config_dir, &content, force)?)
    };

    Ok(ScopeResult {
        config_path,
        hook_registered,
        converted_rules,
        permissions_removed,
    })
}
