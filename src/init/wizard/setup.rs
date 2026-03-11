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
    /// Number of other PreToolUse entries that also match Bash.
    pub conflicting_hook_count: usize,
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
    let mut detected_claude_config = false;
    let mut has_rules = false;
    let mut has_hook_change = false;
    let mut detected_conflict_count: usize = 0;

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

        // Determine what changes are available
        let (allow, deny) = claude_code::read_permissions(cd)?;
        let has_permissions = !allow.is_empty() || !deny.is_empty();
        let has_migratable_rules = if has_permissions {
            let conversion = claude_code::convert_permissions(&allow, &deny);
            !conversion.rules.is_empty()
        } else {
            false
        };

        // Check if hook registration would change anything
        let would_add_hook = if hook_policy == HookPolicy::Register {
            preview_register_hook(&original_content)?.is_some()
        } else {
            false
        };

        // Only show "Detected" and ask migration if there's something to do
        if has_migratable_rules || would_add_hook {
            detected_claude_config = true;
            let settings_path_display = settings_path.display();
            eprintln!(
                "\x1b[1mDetected Claude Code configuration in {settings_path_display}\x1b[0m"
            );
            eprintln!();

            // Ask whether to migrate Bash permissions
            if has_migratable_rules {
                let conversion = claude_code::convert_permissions(&allow, &deny);
                let should_migrate = prompter.confirm(
                    "Migrate Claude Code Bash permissions to runok rules?",
                    migration_default,
                )?;
                if should_migrate {
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

            if hook_policy == HookPolicy::Register {
                let hook_preview = preview_register_hook(&after_permissions)?;
                has_hook_change = hook_preview.is_some();
            }

            let config_path = config_dir.join("runok.yml");
            let config_path_display = config_path.display();

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
            }

            // Always show runok.yml creation/update diff
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
            eprintln!("\x1b[1m{verb} {config_path_display}\x1b[0m");
            eprintln!();
            print_diff(
                &config_path_display.to_string(),
                &existing_config,
                &config_content,
            );
            eprintln!();

            // Determine the final settings.json content (after hook registration)
            // for both the diff preview and the conflicting-hook check.
            let after_hook_content = if has_hook_change {
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
                hook_preview.unwrap_or(after_permissions.clone())
            } else {
                after_permissions.clone()
            };

            // Show warning about conflicting hooks before the confirmation prompt
            // so the user can make an informed decision.
            if hook_policy == HookPolicy::Register {
                detected_conflict_count = count_conflicting_hooks_in_json(&after_hook_content)?;
                if detected_conflict_count > 0 {
                    print_conflicting_hooks_warning(detected_conflict_count);
                    eprintln!();
                }
            }

            approved = prompter.confirm("Apply these changes?", true)?;
            if !approved {
                converted_rules = None;
            }
        }
    }

    // When no changes were proposed (hook already registered, no migratable
    // rules), the detected_claude_config block is skipped entirely.  We still
    // need to check for conflicting hooks in the existing settings.json so the
    // user is informed even when runok init has nothing else to do.
    let conflicting_hook_count = if !detected_claude_config && hook_policy == HookPolicy::Register {
        let count = detect_conflicting_hook_count(claude_dir)?;
        if count > 0 {
            print_conflicting_hooks_warning(count);
        }
        count
    } else {
        detected_conflict_count
    };

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
    // - User approved changes in "Detected" block: create with converted rules
    // - No Claude Code config detected: create boilerplate (ask if file exists)
    // - User declined all changes: skip (don't create silently)
    let config_path = if approved {
        let content = config_gen::build_config_content(converted_rules.as_deref());
        Some(config_gen::write_config(config_dir, &content)?)
    } else if !detected_claude_config {
        let config_path = config_dir.join("runok.yml");
        if config_path.exists() {
            let overwrite = prompter.confirm("runok.yml already exists. Overwrite?", false)?;
            if overwrite {
                let content = config_gen::build_config_content(None);
                Some(config_gen::write_config(config_dir, &content)?)
            } else {
                None
            }
        } else {
            let content = config_gen::build_config_content(None);
            Some(config_gen::write_config(config_dir, &content)?)
        }
    } else {
        None
    };

    Ok(ScopeResult {
        config_path,
        hook_registered,
        converted_rules,
        permissions_removed,
        conflicting_hook_count,
    })
}

/// Count conflicting hooks from a JSON string (for preview-phase checks).
fn count_conflicting_hooks_in_json(json_content: &str) -> Result<usize, InitError> {
    if json_content.is_empty() {
        return Ok(0);
    }
    let root: serde_json::Value = serde_json::from_str(json_content)?;
    let arr = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array());
    match arr {
        Some(entries) => Ok(claude_code::detect_conflicting_hooks(entries).len()),
        None => Ok(0),
    }
}

/// Read settings.json and count PreToolUse entries that conflict with the
/// runok hook (i.e. other entries that also match Bash).
fn detect_conflicting_hook_count(claude_dir: Option<&Path>) -> Result<usize, InitError> {
    let Some(cd) = claude_dir else {
        return Ok(0);
    };
    let settings_path = cd.join("settings.json");
    if !settings_path.exists() {
        return Ok(0);
    }
    let content = std::fs::read_to_string(&settings_path)?;
    let root: serde_json::Value = serde_json::from_str(&content)?;
    let arr = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array());
    match arr {
        Some(entries) => Ok(claude_code::detect_conflicting_hooks(entries).len()),
        None => Ok(0),
    }
}

fn print_conflicting_hooks_warning(count: usize) {
    const YELLOW: &str = "\x1b[33m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";

    let noun = if count == 1 { "entry" } else { "entries" };
    eprintln!();
    eprintln!(
        "{YELLOW}{BOLD}Warning:{RESET}{YELLOW} Found {count} other PreToolUse {noun} matching Bash in settings.json.{RESET}"
    );
    eprintln!();
    eprintln!(
        "Due to a known Claude Code issue (https://github.com/anthropics/claude-code/issues/15897),"
    );
    eprintln!("runok's sandbox may not work when multiple PreToolUse hooks match Bash.");
    eprintln!("Commands that should be sandboxed could run without any restrictions.");
    eprintln!();
    eprintln!("To fix this, merge all Bash-matching hooks into a single PreToolUse entry.");
    eprintln!(
        "See https://runok.fohte.net/getting-started/claude-code/#avoid-multiple-bash-matching-hooks"
    );
}
