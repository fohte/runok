use std::path::Path;

use super::super::codex;
use super::super::error::InitError;
use super::super::prompt::Prompter;
use super::preview::{normalize_json, preview_register_codex_hook, print_diff};

/// Result of setting up Codex hook registration.
pub(super) struct CodexScopeResult {
    pub hook_registered: bool,
}

/// Register the runok hook in Codex's hooks.json.
///
/// If Codex isn't installed (`$CODEX_HOME`/`~/.codex` doesn't exist), this is
/// a silent no-op: no prompts, no directory creation, no file writes. If the
/// hook is already registered for both events, this is also a silent no-op.
pub(super) fn setup_codex_scope(
    home_dir: &Path,
    prompter: &dyn Prompter,
) -> Result<CodexScopeResult, InitError> {
    let codex_home = codex::resolve_codex_home(home_dir);
    if !codex_home.exists() {
        return Ok(CodexScopeResult {
            hook_registered: false,
        });
    }

    let hooks_path = codex_home.join("hooks.json");
    let raw_content = if hooks_path.exists() {
        std::fs::read_to_string(&hooks_path)?
    } else {
        String::new()
    };
    let content = if raw_content.is_empty() {
        raw_content
    } else {
        normalize_json(&raw_content)?
    };

    let Some(after) = preview_register_codex_hook(&content)? else {
        return Ok(CodexScopeResult {
            hook_registered: false,
        });
    };

    let hooks_path_display = hooks_path.display();
    eprintln!("\x1b[1mDetected Codex configuration in {hooks_path_display}\x1b[0m");
    eprintln!();
    print_diff(&hooks_path_display.to_string(), &content, &after);
    eprintln!();

    let approved = prompter.confirm("Register runok hook in Codex hooks.json?", true)?;
    if !approved {
        return Ok(CodexScopeResult {
            hook_registered: false,
        });
    }

    let hook_registered = codex::register_hook(&codex_home)?;
    Ok(CodexScopeResult { hook_registered })
}
