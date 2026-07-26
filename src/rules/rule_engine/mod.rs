use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{ActionKind, Config, MergedSandboxPolicy};
use crate::rules::RuleError;
use crate::rules::command_parser::{
    FunctionCallInfo, PipeInfo, RedirectInfo, extract_commands_with_metadata,
};

mod command_resolver;
mod compound;
mod dispatch;
mod flag_schema;
mod function;
mod require_command_in_path;
mod simple_eval;
mod wrapper;

pub use command_resolver::{
    CommandResolution, CommandResolver, ProcessCommandResolver, StubCommandResolver,
};
pub use compound::{default_action, evaluate_compound};

use dispatch::evaluate_command_inner;
use require_command_in_path::command_contains_source_like;

/// Context for rule evaluation, providing environment variables and
/// working directory for `when` clause evaluation.
pub struct EvalContext {
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
    /// PATH-dependent command lookup, injected so tests can substitute a
    /// deterministic stub instead of depending on the host's `$PATH`.
    pub resolver: Arc<dyn CommandResolver>,
}

impl EvalContext {
    /// Build an `EvalContext` from the current process environment.
    pub fn from_env() -> Self {
        Self {
            env: std::env::vars().collect(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            resolver: Arc::new(ProcessCommandResolver::new()),
        }
    }
}

/// Information about a single rule match, used for verbose logging.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatchInfo {
    /// The action kind of the matched rule (allow, deny, ask).
    pub action_kind: ActionKind,
    /// The pattern string that matched.
    pub pattern: String,
    /// Tokens captured by wildcards (`*`) in the pattern.
    pub matched_tokens: Vec<String>,
}

/// Result of rule evaluation: an action and an optional sandbox preset name.
#[derive(Debug, PartialEq)]
pub struct EvalResult {
    pub action: Action,
    /// Sandbox preset name from the matched rule, or `None` to fall back to `defaults.sandbox`.
    pub sandbox_preset: Option<String>,
    /// Details of all rules that matched, for verbose logging.
    pub matched_rules: Vec<RuleMatchInfo>,
    /// Names of aliases applied while resolving the command, in order.
    /// Empty when no alias rewrite fired.
    pub alias_chain: Vec<String>,
    /// Unresolved command name, present only when
    /// `experimental.require_command_in_path` decided `action` (deny or
    /// ask) rather than a matched rule or `default_action`.
    pub require_command_in_path: Option<String>,
}

/// Per-sub-command evaluation detail, for verbose logging.
#[derive(Debug, PartialEq)]
pub struct SubCommandDetail {
    pub command: String,
    pub action: Action,
    pub matched_rules: Vec<RuleMatchInfo>,
}

/// Result of compound command evaluation: an action and an optional merged
/// sandbox policy built from all sub-commands' sandbox presets.
#[derive(Debug, PartialEq)]
pub struct CompoundEvalResult {
    pub action: Action,
    pub sandbox_policy: Option<MergedSandboxPolicy>,
    /// Per-sub-command evaluation results for audit logging.
    pub sub_results: Vec<EvalResult>,
    /// Per-sub-command evaluation details, for verbose logging.
    pub sub_command_details: Vec<SubCommandDetail>,
}

/// The action determined by rule evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Deny(DenyResponse),
    Ask(Option<String>),
}

/// Details included when a command is denied.
#[derive(Debug, Clone, PartialEq)]
pub struct DenyResponse {
    pub message: Option<String>,
    pub fix_suggestion: Option<String>,
    pub matched_rule: String,
}

/// Evaluate a command against all rules in the config, returning the most
/// restrictive matching action (Explicit Deny Wins).
///
/// If the command matches a wrapper pattern from `definitions.wrappers`,
/// the inner command is extracted and evaluated recursively.
pub fn evaluate_command(
    config: &Config,
    command: &str,
    context: &EvalContext,
) -> Result<EvalResult, RuleError> {
    let source_like_present = command_contains_source_like(command);

    // For single commands, extract redirect/pipe metadata so that `when`
    // clauses referencing `redirects` or `pipe` work correctly.
    // Compound commands (multiple extracted commands) are left to the
    // compound guard inside evaluate_command_inner.
    if let Ok(extracted) = extract_commands_with_metadata(command)
        && extracted.len() == 1
    {
        let first = &extracted[0];
        return evaluate_command_inner(
            config,
            &first.command,
            context,
            0,
            &first.redirects,
            &first.pipe,
            &first.loop_kind,
            first.function_call.as_ref(),
            &[],
            source_like_present,
        );
    }
    evaluate_command_inner(
        config,
        command,
        context,
        0,
        &[],
        &PipeInfo::default(),
        "",
        None,
        &[],
        source_like_present,
    )
}

/// Like `evaluate_command`, but with pre-extracted redirect, pipe, and
/// function-call metadata.
///
/// Use this when the caller has already parsed the original command for
/// redirect/pipe information (e.g., the adapter extracts metadata from the
/// original input before stripping redirects for pattern matching).
pub fn evaluate_command_with_metadata(
    config: &Config,
    command: &str,
    context: &EvalContext,
    redirects: &[RedirectInfo],
    pipe: &PipeInfo,
    loop_kind: &str,
    function_call: Option<&FunctionCallInfo>,
) -> Result<EvalResult, RuleError> {
    evaluate_command_inner(
        config,
        command,
        context,
        0,
        redirects,
        pipe,
        loop_kind,
        function_call,
        &[],
        command_contains_source_like(command),
    )
}

/// Shared test fixtures used by `compound::tests`, `dispatch::tests`,
/// `simple_eval::tests`, and `wrapper::tests`.
#[cfg(test)]
mod test_support {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use rstest::fixture;

    use crate::config::{Config, RuleEntry};

    use super::{EvalContext, StubCommandResolver};

    #[fixture]
    pub(super) fn empty_context() -> EvalContext {
        EvalContext {
            env: HashMap::new(),
            cwd: PathBuf::from("/tmp"),
            resolver: Arc::new(StubCommandResolver),
        }
    }

    pub(super) fn make_config(rules: Vec<RuleEntry>) -> Config {
        Config {
            rules: Some(rules),
            ..Default::default()
        }
    }

    pub(super) fn allow_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            allow: Some(pattern.to_string()),
            deny: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
            tests: None,
        }
    }

    pub(super) fn deny_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            deny: Some(pattern.to_string()),
            allow: None,
            ask: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
            tests: None,
        }
    }

    pub(super) fn ask_rule(pattern: &str) -> RuleEntry {
        RuleEntry {
            ask: Some(pattern.to_string()),
            allow: None,
            deny: None,
            when: None,
            message: None,
            fix_suggestion: None,
            sandbox: None,
            tests: None,
        }
    }
}
