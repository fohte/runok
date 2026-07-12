use crate::rules::command_parser::redirect::{
    collect_substitutions_recursive, extract_env_assignment, extract_redirect_info,
    is_quoted_heredoc,
};
use crate::rules::command_parser::tokenizer::{dequote_node, expand_argument_tokens};
use crate::rules::command_parser::var_env::{VarEnv, poison_bare_name, record_variable_assignment};
use crate::rules::command_parser::{
    EnvAssignment, ExtractedCommand, PipeInfo, RedirectInfo, shell_quote_join,
};

use super::collect_commands;

/// `command` node: strip leading variable_assignment children
/// (environment variable prefixes like `FOO=bar echo hello`), strip
/// redirect children (herestring_redirect, etc. that tree-sitter
/// attaches directly to a command node), extract nested
/// command_substitution / subshell nodes, and emit the remaining text.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_command(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    var_env: &mut VarEnv,
    poison: bool,
) {
    let mut cmd_redirects = redirects.to_vec();
    let mut env: Vec<EnvAssignment> = Vec::new();
    let mut argv: Vec<String> = Vec::new();
    let mut expanded_any = false;
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            continue;
        }
        if node.field_name_for_child(i as u32) == Some("redirect") {
            // Extract redirect info from command-level redirects
            if let Some(info) = extract_redirect_info(child, source) {
                cmd_redirects.push(info);
            }
            // Recurse into redirect children for nested
            // substitutions (e.g. `cat <<< $(secret_cmd)`).
            // HEREDOCs with a quoted delimiter are literal in
            // bash, so skip body recursion to avoid scanning
            // user prose as if it were shell syntax.
            if !(child.kind() == "heredoc_redirect" && is_quoted_heredoc(child, source)) {
                collect_substitutions_recursive(child, source, commands, var_env, poison);
            }
        } else {
            match child.kind() {
                // A subshell argument (e.g. `time (ls | tail -40)`)
                // or a command substitution (e.g. `echo $(ls foo)`)
                // runs in its own process, so sub-commands must be
                // extracted without inheriting the outer pipe /
                // redirect context. `loop_kind` is preserved because
                // a subshell is still lexically inside any enclosing
                // loop (`while x; do echo $(sleep 1); done` keeps
                // `sleep` in the `"while"` loop). The outer command
                // text is still emitted below and handled by the
                // self-reference filter in `evaluate_command_inner`.
                "command_substitution" | "subshell" => {
                    collect_commands(
                        child,
                        source,
                        commands,
                        &PipeInfo::default(),
                        &[],
                        loop_kind,
                        var_env,
                        poison,
                    );
                    if let Some(token) = dequote_node(child, source) {
                        argv.push(token);
                    }
                }
                "variable_assignment" => {
                    if let Some(assignment) = extract_env_assignment(child, source) {
                        env.push(assignment);
                    }
                    collect_substitutions_recursive(child, source, commands, var_env, poison);
                }
                // Recurse into other child nodes (e.g. string,
                // concatenation) to find nested command_substitution
                // nodes (e.g. `curl -u "user:$(secret_cmd)" url`). gitleaks:allow
                // Also resolve any bare `$X` / `${X}` this child
                // carries against `var_env`, which may expand it
                // into zero, one, or several argv tokens.
                _ => {
                    collect_substitutions_recursive(child, source, commands, var_env, poison);
                    if let Some((tokens, changed)) = expand_argument_tokens(child, source, var_env)
                    {
                        if changed {
                            expanded_any = true;
                        }
                        argv.extend(tokens);
                    }
                }
            }
        }
    }
    // Build command text excluding variable_assignment and redirect children.
    // Redirects (e.g. herestring_redirect) attached directly to a command
    // node use the field name "redirect".
    let parts: Vec<&str> = (0..node.child_count())
        .filter_map(|i| {
            let child = node.child(i as u32)?;
            if !child.is_named() {
                return None;
            }
            if child.kind() == "variable_assignment" {
                return None;
            }
            if node.field_name_for_child(i as u32) == Some("redirect") {
                return None;
            }
            let text = &source[child.start_byte()..child.end_byte()];
            std::str::from_utf8(text).ok()
        })
        .collect();
    let raw_text = parts.join(" ");
    let raw_text = raw_text.trim();
    // Only rebuild the command text from the (possibly expanded)
    // argv when an expansion actually happened, so a command with
    // no resolvable variables is emitted byte-for-byte as before.
    let (text, original_command) = if expanded_any {
        match shell_quote_join(&argv) {
            Ok(rebuilt) => (rebuilt, Some(raw_text.to_string())),
            Err(_) => (raw_text.to_string(), None),
        }
    } else {
        (raw_text.to_string(), None)
    };
    if !text.is_empty() {
        commands.push(ExtractedCommand {
            command: text,
            env,
            argv,
            redirects: cmd_redirects,
            pipe: pipe_info.clone(),
            loop_kind: loop_kind.to_string(),
            original_command,
        });
    }
}

/// `declaration_command` (`export FOO=bar`, `declare -x FOO`, `readonly
/// FOO`, `local FOO=bar`, `typeset FOO`) and `unset_command` (`unset
/// FOO`, `unsetenv FOO`) are shell builtins that tree-sitter-bash emits
/// as their own node kinds. They have no environment prefix and no
/// redirect field children, so the structure is simpler than `command`:
/// emit the keyword + each argument (variable_assignment kept verbatim
/// as `KEY=VALUE`) as argv, and the source text as the command string.
/// A `variable_assignment` argument is recorded into `var_env` like a
/// top-level assignment; a bare name (`export FOO`, `unset FOO`) is
/// always poisoned since its current/former value is not statically
/// known.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_declaration_or_unset(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    redirects: &[RedirectInfo],
    pipe_info: &PipeInfo,
    loop_kind: &str,
    var_env: &mut VarEnv,
    poison: bool,
) {
    let mut argv: Vec<String> = Vec::new();
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            if argv.is_empty()
                && let Some(text) = source.get(child.start_byte()..child.end_byte())
                && let Ok(text) = std::str::from_utf8(text)
            {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    argv.push(trimmed.to_string());
                }
            }
            continue;
        }
        match child.kind() {
            "variable_assignment" => {
                if let Some(text) = source.get(child.start_byte()..child.end_byte())
                    && let Ok(text) = std::str::from_utf8(text)
                {
                    argv.push(text.to_string());
                }
                record_variable_assignment(child, source, var_env, poison);
                collect_substitutions_recursive(child, source, commands, var_env, poison);
            }
            "variable_name" => {
                poison_bare_name(child, source, var_env);
                collect_substitutions_recursive(child, source, commands, var_env, poison);
                if let Some(token) = dequote_node(child, source) {
                    argv.push(token);
                }
            }
            _ => {
                collect_substitutions_recursive(child, source, commands, var_env, poison);
                if let Some(token) = dequote_node(child, source) {
                    argv.push(token);
                }
            }
        }
    }
    let text = &source[node.start_byte()..node.end_byte()];
    let text = std::str::from_utf8(text).unwrap_or("").trim();
    if !text.is_empty() {
        commands.push(ExtractedCommand {
            command: text.to_string(),
            env: Vec::new(),
            argv,
            redirects: redirects.to_vec(),
            pipe: pipe_info.clone(),
            loop_kind: loop_kind.to_string(),
            original_command: None,
        });
    }
}
