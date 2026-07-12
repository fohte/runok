use crate::rules::command_parser::redirect::{
    collect_heredoc_redirect_substitutions, collect_substitutions_recursive, detect_while_or_until,
    extract_env_assignment, extract_redirect_info, find_heredoc_continuation, is_quoted_heredoc,
};
use crate::rules::command_parser::tokenizer::{dequote_node, expand_argument_tokens};
use crate::rules::command_parser::var_env::{VarEnv, poison_bare_name, record_variable_assignment};
use crate::rules::command_parser::{
    EnvAssignment, ExtractedCommand, PipeInfo, RedirectInfo, shell_quote_join,
};

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
/// this walk. `poison` is `true` when the current node sits inside a
/// conditional or loop body (an `if`/`case`/`for`/`while`/`until` body), where
/// an assignment may run zero, one, or many times, so it must be recorded as
/// unresolvable rather than by its own static-ness.
#[expect(
    clippy::too_many_arguments,
    reason = "each parameter carries independent AST-walk context (pipe/redirect/loop position, var tracking); grouping them into a struct would obscure the per-recursion-site overrides this function relies on"
)]
pub(in crate::rules::command_parser) fn collect_commands(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
    var_env: &mut VarEnv,
    poison: bool,
) {
    match node.kind() {
        // Transparent containers (except pipeline): recurse into all named children.
        // Skips anonymous tokens like `;`, `&&`, `||`, `(`, `)`,
        // `do`, `done`, `then`, `fi`, `esac`, keywords, etc.
        "program"
        | "list"
        | "subshell"
        | "do_group"
        | "compound_statement"
        | "command_substitution"
        | "process_substitution"
        | "negated_command" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(
                    child, source, commands, pipe_info, redirects, loop_kind, var_env, poison,
                );
            }
        }
        // if_statement: the `condition` field runs unconditionally exactly
        // once whenever the if_statement itself is reached, so it keeps
        // whatever poison state the caller passed in. Everything else
        // (the then-body, `elif_clause`s, `else_clause`) only runs
        // conditionally, so it is always poisoned regardless of the
        // caller's state.
        "if_statement" => {
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
                    child_poison,
                );
            }
        }
        // elif_clause / else_clause: unlike if_statement's own condition,
        // an elif's condition only runs if every preceding
        // condition was false, and an else body only runs if every
        // condition was false — both are always conditional, so force
        // poison regardless of the caller's state.
        "elif_clause" | "else_clause" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(
                    child, source, commands, pipe_info, redirects, loop_kind, var_env, true,
                );
            }
        }
        // while_statement covers both `while` and `until` in tree-sitter-bash.
        // The leading anonymous token (`while` or `until`) distinguishes them;
        // it sets `loop_kind` for the condition, body, and any nested commands.
        // A nested loop further down overrides this (nearest parent wins).
        // The condition may re-run every iteration and the body may run zero,
        // one, or many times, so both are always poisoned.
        "while_statement" => {
            let kind = detect_while_or_until(node, source);
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(
                    child, source, commands, pipe_info, redirects, kind, var_env, true,
                );
            }
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
                    poison,
                );
            }
        }
        // for_statement: recurse into body (do_group) for loop-body commands,
        // and into value-list items to find nested command substitutions.
        // The body runs inside the loop (`loop_kind = "for"`); value-list
        // substitutions run once before the loop body, so they keep
        // `loop_kind = ""` whether the substitution is bare (`$(cmd)`) or
        // quoted (`"$(cmd)"`).
        //
        // The loop variable itself is always poisoned: even when the
        // for_statement runs unconditionally, its value changes every
        // iteration, so no single static value describes it. The loop
        // body always runs poisoned (it may execute zero, one, or many
        // times); the value list runs exactly once whenever the
        // for_statement is reached, so it keeps the caller's poison state.
        "for_statement" => {
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
                            child, source, commands, pipe_info, redirects, "for", var_env, true,
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
                            poison,
                        );
                    }
                    _ => {
                        collect_substitutions_recursive(child, source, commands, var_env, poison);
                    }
                }
            }
        }
        // case_statement: recurse into each case_item, and search the match
        // value for nested command substitutions (e.g. `case $(cmd) in ...`).
        // The match value uses field name "value" and may be a
        // command_substitution node directly. Each case_item body is
        // conditional (only the matching branch runs), so it is always
        // poisoned; the match value runs exactly once whenever the
        // case_statement is reached, so it keeps the caller's poison state.
        "case_statement" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "case_item" => {
                        collect_commands(
                            child, source, commands, pipe_info, redirects, loop_kind, var_env, true,
                        );
                    }
                    "command_substitution" => {
                        collect_commands(
                            child, source, commands, pipe_info, redirects, loop_kind, var_env,
                            poison,
                        );
                    }
                    _ => {
                        collect_substitutions_recursive(child, source, commands, var_env, poison);
                    }
                }
            }
        }
        // case_item: recurse into body commands, and search pattern values
        // for nested command substitutions (e.g. `case $x in "$(cmd)") ...`).
        "case_item" => {
            for i in 0..node.child_count() {
                let Some(child) = node.child(i as u32) else {
                    continue;
                };
                if !child.is_named() {
                    continue;
                }
                if node.field_name_for_child(i as u32) == Some("value") {
                    collect_substitutions_recursive(child, source, commands, var_env, poison);
                } else {
                    collect_commands(
                        child, source, commands, pipe_info, redirects, loop_kind, var_env, true,
                    );
                }
            }
        }
        // redirected_statement: extract redirect info, then recurse into the body.
        // Redirect target paths are left to the OS-level sandbox to enforce.
        // Also recurse into redirect children to extract nested commands
        // (e.g. process substitutions: `cmd > >(nested_cmd)`).
        "redirected_statement" => {
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
                            poison,
                        );
                    }
                    let arm_pipe = PipeInfo {
                        stdin: false,
                        stdout: pipe_info.stdout,
                    };
                    for arm in &continuation.list_arms {
                        collect_commands(
                            *arm, source, commands, &arm_pipe, redirects, loop_kind, var_env,
                            poison,
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
                            child, source, commands, var_env, poison,
                        );
                    } else {
                        collect_substitutions_recursive(child, source, commands, var_env, poison);
                    }
                }
            }
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
            collect_substitutions_recursive(node, source, commands, var_env, poison);
        }
        // function_definition: recurse into body. The body is not executed
        // at definition time, so it must not read or write the enclosing
        // `var_env` — a fresh, throwaway one keeps every expansion inside
        // verbatim (as before this feature existed) without leaking any
        // `local`/assignment the body makes back out to the caller.
        "function_definition" => {
            if let Some(body) = node.child_by_field_name("body") {
                let mut inert = VarEnv::new();
                collect_commands(
                    body, source, commands, pipe_info, redirects, loop_kind, &mut inert, poison,
                );
            }
        }
        // command node: strip leading variable_assignment children
        // (environment variable prefixes like `FOO=bar echo hello`), strip
        // redirect children (herestring_redirect, etc. that tree-sitter
        // attaches directly to a command node), extract nested
        // command_substitution / subshell nodes, and emit the remaining text.
        "command" => {
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
                            collect_substitutions_recursive(
                                child, source, commands, var_env, poison,
                            );
                        }
                        // Recurse into other child nodes (e.g. string,
                        // concatenation) to find nested command_substitution
                        // nodes (e.g. `curl -u "user:$(secret_cmd)" url`). gitleaks:allow
                        // Also resolve any bare `$X` / `${X}` this child
                        // carries against `var_env`, which may expand it
                        // into zero, one, or several argv tokens.
                        _ => {
                            collect_substitutions_recursive(
                                child, source, commands, var_env, poison,
                            );
                            if let Some((tokens, changed)) =
                                expand_argument_tokens(child, source, var_env)
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
        // declaration_command (`export FOO=bar`, `declare -x FOO`,
        // `readonly FOO`, `local FOO=bar`, `typeset FOO`) and
        // unset_command (`unset FOO`, `unsetenv FOO`) are shell
        // builtins that tree-sitter-bash emits as their own node
        // kinds. They have no environment prefix and no redirect
        // field children, so the structure is simpler than `command`:
        // emit the keyword + each argument (variable_assignment kept
        // verbatim as `KEY=VALUE`) as argv, and the source text as
        // the command string. A `variable_assignment` argument is
        // recorded into `var_env` like a top-level assignment; a bare
        // name (`export FOO`, `unset FOO`) is always poisoned since its
        // current/former value is not statically known.
        "declaration_command" | "unset_command" => {
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
        // Leaf command nodes — extract the source text, and recurse into
        // all child nodes to find nested command substitutions.
        _ => {
            collect_substitutions_recursive(node, source, commands, var_env, poison);
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
                });
            }
        }
    }
}
