mod control_flow;
mod redirected;
mod simple_command;

use control_flow::{
    handle_case_item, handle_case_statement, handle_elif_or_else, handle_for_statement,
    handle_if_statement, handle_while_statement,
};
use redirected::handle_redirected_statement;
use simple_command::{handle_command, handle_declaration_or_unset};

use crate::rules::command_parser::function_table::FunctionTable;
use crate::rules::command_parser::redirect::collect_substitutions_recursive;
use crate::rules::command_parser::var_env::{VarEnv, record_variable_assignment};
use crate::rules::command_parser::{ExtractedCommand, PipeInfo, RedirectInfo};

/// Recursively walk the tree-sitter AST and collect individual command strings.
///
/// Compound constructs (pipeline, list, subshell, control structures) are split
/// into their constituent commands. Conditions and value lists are also recursed
/// into so that commands within them (including command substitutions) are extracted.
///
/// `pipe_info` carries the current pipeline position context.
/// `redirects` carries redirect info inherited from a parent `redirected_statement`.
/// `loop_kind` carries the kind of shell loop (`"while"`, `"until"`, `"for"`,
/// or `""`) that immediately encloses the current node. Nested loops surface
/// the nearest enclosing kind. Subshells propagate the kind unchanged.
/// `var_env` tracks statically-resolvable variable assignments seen so far in
/// this walk. `function_table` tracks `name() { ... }` definitions seen so
/// far, so a later `command` node whose name matches gets annotated with a
/// [`crate::rules::command_parser::FunctionCallInfo`] for `rule_engine` to
/// resolve. `poison` is `true` when the current node sits inside a
/// conditional or loop body (an `if`/`case`/`for`/`while`/`until` body), where
/// an assignment may run zero, one, or many times, so it must be recorded as
/// unresolvable rather than by its own static-ness.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(in crate::rules::command_parser) fn collect_commands(
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
    match node.kind() {
        // Transparent containers: recurse into all named children.
        // Skips anonymous tokens like `;`, `(`, `)`, `do`, `done`, `then`,
        // `fi`, `esac`, keywords, etc.
        "program" | "do_group" | "compound_statement" | "negated_command" => {
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
                    poison,
                );
            }
        }
        // subshell / command_substitution / process_substitution fork a
        // child shell: an assignment or function definition inside is
        // visible to the rest of that same construct, but never
        // propagates back out once it exits. Recurse against scratch
        // clones of `var_env` / `function_table` (reads see everything
        // the parent has recorded so far) and discard them afterward,
        // instead of mutating the caller's state directly.
        "subshell" | "command_substitution" | "process_substitution" => {
            let mut child_env = var_env.clone();
            let mut child_functions = function_table.clone();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(
                    child,
                    source,
                    commands,
                    pipe_info,
                    redirects,
                    loop_kind,
                    &mut child_env,
                    &mut child_functions,
                    poison,
                );
            }
        }
        // list: tree-sitter-bash uses this node kind exclusively for
        // `&&` / `||` (a plain `;` sequence never produces a `list` node —
        // each statement is just a direct sibling of its enclosing
        // container). The right-hand side only runs if the left side's
        // exit status permits it — true for both operators — so it is
        // always poisoned regardless of the caller's state; the left
        // side runs unconditionally whenever this node is reached, so it
        // keeps the caller's poison state.
        "list" => {
            let children: Vec<_> = {
                let mut cursor = node.walk();
                node.named_children(&mut cursor).collect()
            };
            for (i, child) in children.iter().enumerate() {
                let child_poison = if i == 0 { poison } else { true };
                collect_commands(
                    *child,
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
        "if_statement" => {
            handle_if_statement(
                node,
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
        "elif_clause" | "else_clause" => {
            handle_elif_or_else(
                node,
                source,
                commands,
                pipe_info,
                redirects,
                loop_kind,
                var_env,
                function_table,
            );
        }
        "while_statement" => {
            handle_while_statement(
                node,
                source,
                commands,
                pipe_info,
                redirects,
                var_env,
                function_table,
            );
        }
        // pipeline: compute pipe position for each child command.
        "pipeline" => {
            let children: Vec<_> = {
                let mut cursor = node.walk();
                node.named_children(&mut cursor).collect()
            };
            let len = children.len();
            for (i, child) in children.iter().enumerate() {
                let child_pipe = PipeInfo {
                    stdin: pipe_info.stdin || i > 0,
                    stdout: pipe_info.stdout || i < len - 1,
                };
                collect_commands(
                    *child,
                    source,
                    commands,
                    &child_pipe,
                    redirects,
                    loop_kind,
                    var_env,
                    function_table,
                    poison,
                );
            }
        }
        "for_statement" => {
            handle_for_statement(
                node,
                source,
                commands,
                pipe_info,
                redirects,
                var_env,
                function_table,
                poison,
            );
        }
        "case_statement" => {
            handle_case_statement(
                node,
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
        "case_item" => {
            handle_case_item(
                node,
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
        "redirected_statement" => {
            handle_redirected_statement(
                node,
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
        // comment: skip shell comments (e.g. `# description`)
        "comment" => {}
        // variable_assignment: transparent container — skip the assignment itself
        // and recursively find command_substitution / process_substitution nodes
        // anywhere in the subtree (they may be nested inside string nodes when
        // the value is quoted, e.g. X="$(cmd)"). Also record the assignment
        // into `var_env` so a later `$X` in the same command string can
        // resolve to a statically known value.
        "variable_assignment" => {
            record_variable_assignment(node, source, var_env, poison);
            collect_substitutions_recursive(
                node,
                source,
                commands,
                var_env,
                function_table,
                poison,
            );
        }
        // function_definition: register the name/body into the *outer*
        // `function_table` (unconditionally, regardless of `poison` --
        // over-registering a function that might not actually be defined
        // at call time is always safe: it just means evaluating code
        // that, if it never really executes, could not have been
        // dangerous either) so a later `command` node can be recognized
        // as a call to it, then recurse into the body. The body is not
        // executed at definition time, so it must not read or write the
        // enclosing `var_env` -- a fresh, throwaway one keeps every
        // expansion inside verbatim without leaking any `local`/
        // assignment the body makes back out to the caller. Unlike
        // variable *values*, which one call to `f` cannot assume are the
        // same on the next call, a function name being defined is a
        // static, lexical fact once its `function_definition` has been
        // walked -- so `function_table` uses the same clone-and-discard
        // scoping as a subshell (reads see every function defined so far
        // in the *outer* scope, including `f` itself; nested definitions
        // the body makes are not visible outside it). This lets the
        // unconditional definition-time pass resolve a call to an
        // earlier-defined function (`g() { ... }; f() { g; }`) instead of
        // leaving it as an unknown command that would otherwise drag the
        // merged result down to `defaults.action`.
        "function_definition" => {
            if let Some(name_node) = node.child_by_field_name("name")
                && let Some(body) = node.child_by_field_name("body")
                && let Some(name) = node_text(name_node, source)
                && let Some(body_text) = node_text(body, source)
            {
                function_table.define(name, body_text);
            }
            if let Some(body) = node.child_by_field_name("body") {
                let mut inert_env = VarEnv::new();
                let mut visible_functions = function_table.clone();
                collect_commands(
                    body,
                    source,
                    commands,
                    pipe_info,
                    redirects,
                    loop_kind,
                    &mut inert_env,
                    &mut visible_functions,
                    poison,
                );
            }
        }
        "command" => {
            handle_command(
                node,
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
        "declaration_command" | "unset_command" => {
            handle_declaration_or_unset(
                node,
                source,
                commands,
                redirects,
                pipe_info,
                loop_kind,
                var_env,
                function_table,
                poison,
            );
        }
        // Leaf command nodes — extract the source text, and recurse into
        // all child nodes to find nested command substitutions.
        _ => {
            collect_substitutions_recursive(
                node,
                source,
                commands,
                var_env,
                function_table,
                poison,
            );
            let text = &source[node.start_byte()..node.end_byte()];
            let text = std::str::from_utf8(text).unwrap_or("").trim();
            if !text.is_empty() {
                commands.push(ExtractedCommand {
                    command: text.to_string(),
                    env: Vec::new(),
                    argv: Vec::new(),
                    redirects: redirects.to_vec(),
                    pipe: pipe_info.clone(),
                    loop_kind: loop_kind.to_string(),
                    original_command: None,
                    function_call: None,
                });
            }
        }
    }
}

fn node_text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let bytes = source.get(node.start_byte()..node.end_byte())?;
    Some(std::str::from_utf8(bytes).ok()?.to_string())
}
