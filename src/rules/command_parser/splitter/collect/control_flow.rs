use crate::rules::command_parser::function_table::FunctionTable;
use crate::rules::command_parser::redirect::{
    collect_substitutions_recursive, detect_while_or_until,
};
use crate::rules::command_parser::var_env::VarEnv;
use crate::rules::command_parser::{ExtractedCommand, PipeInfo, RedirectInfo};

use super::collect_commands;

/// `if_statement`: the `condition` field runs unconditionally exactly
/// once whenever the if_statement itself is reached, so it keeps
/// whatever poison state the caller passed in. Everything else (the
/// then-body, `elif_clause`s, `else_clause`) only runs conditionally, so
/// it is always poisoned regardless of the caller's state.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_if_statement(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    var_env: &mut VarEnv,
    function_table: &mut FunctionTable,
    poison: bool,
) {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            continue;
        }
        let is_condition = node.field_name_for_child(i as u32) == Some("condition");
        let child_poison = if is_condition { poison } else { true };
        collect_commands(
            child,
            source,
            commands,
            pipe_info,
            redirects,
            loop_kind,
            var_env,
            function_table,
            child_poison,
        );
    }
}

/// `elif_clause` / `else_clause`: unlike if_statement's own condition, an
/// elif's condition only runs if every preceding condition was false,
/// and an else body only runs if every condition was false — both are
/// always conditional, so force poison regardless of the caller's
/// state.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_elif_or_else(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    var_env: &mut VarEnv,
    function_table: &mut FunctionTable,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_commands(
            child,
            source,
            commands,
            pipe_info,
            redirects,
            loop_kind,
            var_env,
            function_table,
            true,
        );
    }
}

/// `while_statement` covers both `while` and `until` in tree-sitter-bash.
/// The leading anonymous token (`while` or `until`) distinguishes them;
/// it sets `loop_kind` for the condition, body, and any nested commands.
/// A nested loop further down overrides this (nearest parent wins). The
/// condition may re-run every iteration and the body may run zero, one,
/// or many times, so both are always poisoned.
pub(super) fn handle_while_statement(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    var_env: &mut VarEnv,
    function_table: &mut FunctionTable,
) {
    let kind = detect_while_or_until(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_commands(
            child,
            source,
            commands,
            pipe_info,
            redirects,
            kind,
            var_env,
            function_table,
            true,
        );
    }
}

/// `for_statement`: recurse into body (`do_group`) for loop-body
/// commands, and into value-list items to find nested command
/// substitutions. The body runs inside the loop (`loop_kind = "for"`);
/// value-list substitutions run once before the loop body, so they keep
/// `loop_kind = ""` whether the substitution is bare (`$(cmd)`) or
/// quoted (`"$(cmd)"`).
///
/// The loop variable itself is always poisoned: even when the
/// for_statement runs unconditionally, its value changes every
/// iteration, so no single static value describes it. The loop body
/// always runs poisoned (it may execute zero, one, or many times); the
/// value list runs exactly once whenever the for_statement is reached,
/// so it keeps the caller's poison state.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_for_statement(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    var_env: &mut VarEnv,
    function_table: &mut FunctionTable,
    poison: bool,
) {
    if let Some(var_node) = node.child_by_field_name("variable")
        && let Some(bytes) = source.get(var_node.start_byte()..var_node.end_byte())
        && let Ok(name) = std::str::from_utf8(bytes)
    {
        var_env.poison(name.to_string());
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "do_group" => {
                collect_commands(
                    child,
                    source,
                    commands,
                    pipe_info,
                    redirects,
                    "for",
                    var_env,
                    function_table,
                    true,
                );
            }
            "command_substitution" | "process_substitution" => {
                collect_commands(
                    child,
                    source,
                    commands,
                    &PipeInfo::default(),
                    &[],
                    "",
                    var_env,
                    function_table,
                    poison,
                );
            }
            _ => {
                collect_substitutions_recursive(
                    child,
                    source,
                    commands,
                    var_env,
                    function_table,
                    poison,
                );
            }
        }
    }
}

/// `case_statement`: recurse into each `case_item`, and search the
/// match value for nested command substitutions (e.g. `case $(cmd) in
/// ...`). The match value uses field name "value" and may be a
/// command_substitution node directly. Each case_item body is
/// conditional (only the matching branch runs), so it is always
/// poisoned; the match value runs exactly once whenever the
/// case_statement is reached, so it keeps the caller's poison state.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_case_statement(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    var_env: &mut VarEnv,
    function_table: &mut FunctionTable,
    poison: bool,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "case_item" => {
                collect_commands(
                    child,
                    source,
                    commands,
                    pipe_info,
                    redirects,
                    loop_kind,
                    var_env,
                    function_table,
                    true,
                );
            }
            "command_substitution" => {
                collect_commands(
                    child,
                    source,
                    commands,
                    pipe_info,
                    redirects,
                    loop_kind,
                    var_env,
                    function_table,
                    poison,
                );
            }
            _ => {
                collect_substitutions_recursive(
                    child,
                    source,
                    commands,
                    var_env,
                    function_table,
                    poison,
                );
            }
        }
    }
}

/// `case_item`: recurse into body commands, and search pattern values
/// for nested command substitutions (e.g. `case $x in "$(cmd)") ...`).
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_case_item(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    var_env: &mut VarEnv,
    function_table: &mut FunctionTable,
    poison: bool,
) {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            continue;
        }
        if node.field_name_for_child(i as u32) == Some("value") {
            collect_substitutions_recursive(
                child,
                source,
                commands,
                var_env,
                function_table,
                poison,
            );
        } else {
            collect_commands(
                child,
                source,
                commands,
                pipe_info,
                redirects,
                loop_kind,
                var_env,
                function_table,
                true,
            );
        }
    }
}
