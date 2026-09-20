use std::path::Path;

use super::super::codex;
use super::super::error::InitError;
use super::super::prompt::Prompter;
use super::preview::{
    normalize_json, preview_register_codex_exec_policy, preview_register_codex_hook, print_diff,
};

/// Result of setting up Codex hook registration.
pub(super) struct CodexScopeResult {
    pub hook_registered: bool,
    pub exec_policy_registered: bool,
}

/// Register the runok hook and exec policy in the Codex configuration.
///
/// If Codex isn't installed (`codex_home` doesn't exist), this is a silent
/// no-op: no prompts, no directory creation, no file writes. If the hook is
/// already registered for both events, this is also a silent no-op.
pub(super) fn setup_codex_scope(
    codex_home: &Path,
    prompter: &dyn Prompter,
) -> Result<CodexScopeResult, InitError> {
    if !codex_home.exists() {
        return Ok(CodexScopeResult {
            hook_registered: false,
            exec_policy_registered: false,
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
    let rules_path = codex_home.join(codex::EXEC_POLICY_PATH);
    let rules_content = if rules_path.exists() {
        std::fs::read_to_string(&rules_path)?
    } else {
        String::new()
    };

    let after_hooks = preview_register_codex_hook(&content)?;
    let after_rules = preview_register_codex_exec_policy(&rules_content);
    if after_hooks.is_none() && after_rules.is_none() {
        return Ok(CodexScopeResult {
            hook_registered: false,
            exec_policy_registered: false,
        });
    }

    let hooks_path_display = hooks_path.display();
    eprintln!("\x1b[1mDetected Codex configuration in {hooks_path_display}\x1b[0m");
    eprintln!();
    if let Some(ref after) = after_hooks {
        print_diff(&hooks_path_display.to_string(), &content, after);
        eprintln!();
    }
    if let Some(ref after) = after_rules {
        let rules_path_display = rules_path.display();
        print_diff(&rules_path_display.to_string(), &rules_content, after);
        eprintln!();
    }

    let approved = prompter.confirm(
        "Register runok hook and exec policy in Codex configuration?",
        true,
    )?;
    if !approved {
        return Ok(CodexScopeResult {
            hook_registered: false,
            exec_policy_registered: false,
        });
    }

    let hook_registered = after_hooks.is_some() && codex::register_hook(codex_home)?;
    let exec_policy_registered = after_rules.is_some() && codex::register_exec_policy(codex_home)?;
    Ok(CodexScopeResult {
        hook_registered,
        exec_policy_registered,
    })
}
