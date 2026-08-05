use crate::rules::command_parser::function_table::FunctionTable;
use crate::rules::command_parser::redirect::{collect_substitutions_recursive, is_quoted_heredoc};
use crate::rules::command_parser::var_env::{VarEnv, record_variable_assignment};
use crate::rules::command_parser::{ExtractedCommand, PipeInfo, RedirectInfo};

use super::collect_commands;

/// `command` node matched by
/// [`crate::rules::command_parser::splitter::misparse::is_assignment_redirect_misparse`]:
/// a bare `assignment redirect` prefix that tree-sitter-bash 0.25.1
/// fails to parse as a complete simple command (see that function's
/// docs for the two AST shapes this handles).
///
/// Persists each `variable_assignment` into `var_env` like a top-level
/// assignment -- NOT like `handle_command`'s ephemeral env-prefix
/// treatment -- since there is no command here for it to prefix;
/// `TS=foo 2>/dev/null; echo $TS` must resolve `$TS`. In the
/// swallowed-continuation shape, hands the folded-in tail off to
/// [`extract_swallowed_tail`] to be re-extracted as its own statement.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_assignment_redirect_misparse(
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
    let mut last_separator: Option<&str> = None;
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if node.field_name_for_child(i as u32) == Some("redirect") {
            // No command is ever emitted for the assignment-only part,
            // so there is nothing to attach `RedirectInfo` to here --
            // just recurse for nested substitutions, same as
            // `handle_command`. HEREDOCs with a quoted delimiter are
            // literal in bash, so skip body recursion for those.
            if !(child.kind() == "heredoc_redirect" && is_quoted_heredoc(child, source)) {
                collect_substitutions_recursive(
                    child,
                    source,
                    commands,
                    var_env,
                    function_table,
                    poison,
                );
            }
            continue;
        }
        if !child.is_named() {
            continue;
        }
        match child.kind() {
            "variable_assignment" => {
                record_variable_assignment(child, source, var_env, poison);
                collect_substitutions_recursive(
                    child,
                    source,
                    commands,
                    var_env,
                    function_table,
                    poison,
                );
            }
            "ERROR" => {
                last_separator = child.utf8_text(source).ok().map(str::trim);
            }
            // By grammar field ordering, `name` always precedes
            // `argument`, so the first child that is none of
            // redirect/unnamed/variable_assignment/ERROR is always the
            // `name` field's `command_name` node.
            _ => {
                let is_terminal = child.kind() == "command_name"
                    && child.child(0).is_some_and(|c| c.is_missing());
                if is_terminal {
                    // Nothing follows the assignment(s)/redirect(s);
                    // the assignments are already recorded above.
                    return;
                }
                let tail_bytes = &source[child.start_byte()..node.end_byte()];
                if let Ok(tail_text) = std::str::from_utf8(tail_bytes) {
                    extract_swallowed_tail(
                        tail_text.trim(),
                        commands,
                        pipe_info,
                        redirects,
                        loop_kind,
                        var_env,
                        function_table,
                        poison,
                        last_separator,
                    );
                }
                return;
            }
        }
    }
}

/// Re-parse the text tree-sitter folded into `node`'s `name`/`argument`
/// fields (the "swallowed continuation" shape) as an independent
/// statement, and feed it through the normal [`collect_commands`] walk.
/// `separator` is the swallowed operator's own source text (`;`, `&`,
/// `&&`, `||`, `|`, or `None` for the top-level/no-separator case) and
/// determines how the tail's pipe/poison context is derived:
///
/// - `|` continues a pipeline: the tail reads from the pipe.
/// - `&&` / `||` poisons the tail, mirroring how `collect_commands`'s
///   `"list"` arm always poisons a list's right-hand side.
/// - `;` / `&` / no separator: a plain sibling statement, so
///   `pipe_info`/`poison` propagate unchanged (mirrors how transparent
///   containers like `program` pass context through to every child).
///
/// Silently drops the tail (pushes nothing) if it fails to parse or
/// still has an error of its own after reparsing, rather than risk
/// emitting a garbled command. The only way a tail could itself contain
/// an unexplained error is a second, nested `assignment redirect`
/// misparse with nothing after it -- but tree-sitter already folds any
/// *directly* chained `assignment redirect ;` groups into the *same*
/// enclosing `command` node (see the module docs on
/// `is_assignment_redirect_misparse`), so that shape never reaches here
/// as a tail in the first place; this fallback exists only for
/// hypothetical parse errors unrelated to this bug.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
fn extract_swallowed_tail(
    tail_text: &str,
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    var_env: &mut VarEnv,
    function_table: &mut FunctionTable,
    poison: bool,
    separator: Option<&str>,
) {
    if tail_text.is_empty() {
        return;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(tail_text, None) else {
        return;
    };
    let root = tree.root_node();
    if root.has_error() {
        return;
    }

    let (tail_pipe, tail_poison) = match separator {
        Some("|") => (
            PipeInfo {
                stdin: true,
                stdout: pipe_info.stdout,
            },
            poison,
        ),
        Some("&&") | Some("||") => (pipe_info.clone(), true),
        _ => (pipe_info.clone(), poison),
    };

    collect_commands(
        root,
        tail_text.as_bytes(),
        commands,
        &tail_pipe,
        redirects,
        loop_kind,
        var_env,
        function_table,
        tail_poison,
    );
}
