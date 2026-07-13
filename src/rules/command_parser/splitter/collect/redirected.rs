use crate::rules::command_parser::function_table::FunctionTable;
use crate::rules::command_parser::redirect::{
    collect_heredoc_redirect_substitutions, collect_substitutions_recursive, extract_redirect_info,
    find_heredoc_continuation, is_quoted_heredoc,
};
use crate::rules::command_parser::var_env::VarEnv;
use crate::rules::command_parser::{ExtractedCommand, PipeInfo, RedirectInfo};

use super::collect_commands;

/// `redirected_statement`: extract redirect info, then recurse into the
/// body. Redirect target paths are left to the OS-level sandbox to
/// enforce. Also recurse into redirect children to extract nested
/// commands (e.g. process substitutions: `cmd > >(nested_cmd)`).
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var/function tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(super) fn handle_redirected_statement(
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
    let mut all_redirects = redirects.to_vec();
    // First pass: extract redirect metadata only
    for i in 0..node.child_count() {
        if node.field_name_for_child(i as u32) == Some("redirect")
            && let Some(child) = node.child(i as u32)
            && let Some(info) = extract_redirect_info(child, source)
        {
            all_redirects.push(info);
        }
    }
    // tree-sitter-bash represents `cat <<EOF | other ...\nbody\nEOF`
    // by attaching the trailing `pipeline` / `&&` / `||` arm as a
    // CHILD of the `heredoc_redirect` instead of wrapping the
    // whole thing in an outer pipeline / list. Detect that here
    // so the body and the swallowed continuation are emitted with
    // the right pipe_info — otherwise the trailing arm silently
    // disappears and `cat <<EOF | rm -rf /` would slip past
    // `cat *` allow rules.
    let continuation = find_heredoc_continuation(node);
    let body = node.child_by_field_name("body");
    match (&continuation, body) {
        // No swallowed continuation: behave like a plain
        // redirected statement.
        (None, Some(body)) => {
            collect_commands(
                body,
                source,
                commands,
                pipe_info,
                &all_redirects,
                loop_kind,
                var_env,
                function_table,
                poison,
            );
        }
        // Swallowed continuation: synthesize the outer
        // pipeline `[body, *pipe_stages]` and emit each stage
        // with the same per-stage pipe accounting as the
        // regular `pipeline` arm. Heredoc-attached redirects
        // belong to body alone; remaining stages keep the
        // outer redirect set.
        //
        // List arms (`&&` / `||` trailing the pipeline) are
        // pipe boundaries: `b` in `cat <<EOF | a && b` does
        // not read stdin from the pipe even when the whole
        // group is, so `arm_pipe.stdin` is forced to `false`.
        // The outer `pipe_info.stdout` still propagates so
        // an enclosing `(...) | succ` keeps stdout=true on
        // every arm.
        (Some(continuation), Some(body)) => {
            let mut stages: Vec<tree_sitter::Node> =
                Vec::with_capacity(continuation.pipe_stages.len() + 1);
            stages.push(body);
            stages.extend(continuation.pipe_stages.iter().copied());
            let len = stages.len();
            for (i, stage) in stages.iter().enumerate() {
                let stage_pipe = PipeInfo {
                    stdin: pipe_info.stdin || i > 0,
                    stdout: pipe_info.stdout || i < len - 1,
                };
                let stage_redirects: &[RedirectInfo] =
                    if i == 0 { &all_redirects } else { redirects };
                collect_commands(
                    *stage,
                    source,
                    commands,
                    &stage_pipe,
                    stage_redirects,
                    loop_kind,
                    var_env,
                    function_table,
                    poison,
                );
            }
            let arm_pipe = PipeInfo {
                stdin: false,
                stdout: pipe_info.stdout,
            };
            // These are the swallowed `&&` / `||` continuation of
            // the pipeline above, same as a plain `list` node's
            // right-hand side: always poisoned, since they only
            // run if the pipeline's exit status permits it.
            for arm in &continuation.list_arms {
                collect_commands(
                    *arm,
                    source,
                    commands,
                    &arm_pipe,
                    redirects,
                    loop_kind,
                    var_env,
                    function_table,
                    true,
                );
            }
        }
        // body field missing — defensive only; tree-sitter
        // always emits one for `redirected_statement`.
        (_, None) => {}
    }
    // Second pass: recurse into redirect children for nested
    // substitutions (e.g. `cmd > >(nested)`). HEREDOCs with a
    // quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) are
    // literal — bash does not expand `$VAR`/`$(...)` inside the
    // body — so skip them to avoid false positives where the
    // body text accidentally looks like shell syntax.
    //
    // Also skip the swallowed pipeline / `right`-field children
    // already emitted via `find_heredoc_continuation` above —
    // re-walking them would double-count `command_substitution`
    // nodes inside the trailing arm.
    for i in 0..node.child_count() {
        if node.field_name_for_child(i as u32) == Some("redirect")
            && let Some(child) = node.child(i as u32)
        {
            if child.kind() == "heredoc_redirect" && is_quoted_heredoc(child, source) {
                continue;
            }
            if child.kind() == "heredoc_redirect" {
                collect_heredoc_redirect_substitutions(
                    child,
                    source,
                    commands,
                    var_env,
                    function_table,
                    poison,
                );
            } else {
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
