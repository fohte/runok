use crate::rules::CommandParseError;

use super::redirect::{
    collect_heredoc_redirect_substitutions, collect_substitutions_recursive, detect_while_or_until,
    extract_env_assignment, extract_redirect_info, find_heredoc_continuation, is_quoted_heredoc,
};
use super::tokenizer::dequote_node;
use super::{EnvAssignment, ExtractedCommand, PipeInfo, RedirectInfo};

/// Extract individual command strings from a potentially compound shell input.
///
/// Splits on pipelines (`|`), logical operators (`&&`, `||`), and semicolons (`;`).
/// Uses tree-sitter-bash to correctly handle quoting and nesting.
/// Returns `SyntaxError` if the input contains parse errors.
pub fn extract_commands(input: &str) -> Result<Vec<String>, CommandParseError> {
    Ok(extract_commands_with_metadata(input)?
        .into_iter()
        .map(|ec| ec.command)
        .collect())
}

/// Extract individual commands with redirect and pipe metadata.
///
/// Like `extract_commands`, but each command includes information about
/// attached redirects and pipeline position.
pub fn extract_commands_with_metadata(
    input: &str,
) -> Result<Vec<ExtractedCommand>, CommandParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    // Workaround for tree-sitter-bash misparses of reserved-word prefixes
    // (`time <compound>`, `! <compound>`, ...). See
    // `strip_misparsed_compound_prefix`.
    if let Some(rest) = strip_misparsed_compound_prefix(trimmed) {
        return extract_commands_with_metadata(rest);
    }

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|_| CommandParseError::SyntaxError)?;

    let tree = parser
        .parse(trimmed, None)
        .ok_or(CommandParseError::SyntaxError)?;

    let root = tree.root_node();

    if root.has_error() {
        return Err(CommandParseError::SyntaxError);
    }

    let mut commands = Vec::new();
    collect_commands(
        root,
        trimmed.as_bytes(),
        &mut commands,
        &PipeInfo::default(),
        &[],
        "",
    );

    Ok(commands)
}

/// Detect a tree-sitter-bash misparse triggered by a reserved-word prefix on a
/// compound statement (`time for ...; do ...; done`, `! while ...; do ...; done`,
/// future bash reserved words that take a pipeline of compounds, ...) and
/// strip the offending prefix so the inner compound parses correctly.
///
/// The detection is symptom-based rather than keyword-based: when tree-sitter
/// splits the input into multiple top-level `program` children and any
/// non-leading child begins with a compound continuation token (`do`, `done`,
/// `then`, `fi`, `elif`, `else`, `esac`, `}`), the input was misparsed. These
/// tokens are never the start of a valid simple-command statement, so their
/// appearance at the top level of a `program` is the signature of a
/// reserved-word prefix that tree-sitter failed to recognize.
///
/// When the symptom is present, the function drops the first whitespace-
/// delimited token from the input and recurses; multi-token prefixes such as
/// `time -p` get peeled off one token per recursion until the symptom is gone.
fn strip_misparsed_compound_prefix(input: &str) -> Option<&str> {
    if !has_misparsed_compound_symptom(input) {
        return None;
    }
    let stripped = strip_first_token(input)?;
    Some(strip_misparsed_compound_prefix(stripped).unwrap_or(stripped))
}

fn has_misparsed_compound_symptom(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let Some(tree) = parser.parse(trimmed, None) else {
        return false;
    };
    let root = tree.root_node();
    if root.has_error() {
        return false;
    }
    let mut cursor = root.walk();
    let children: Vec<_> = root.named_children(&mut cursor).collect();
    if children.len() < 2 {
        return false;
    }
    let source = trimmed.as_bytes();
    children
        .iter()
        .skip(1)
        .any(|child| starts_with_compound_continuation(*child, source))
}

/// Whether the source text covered by `node` begins with a token that can
/// only appear as the continuation of a compound statement, not as the start
/// of a simple command.
fn starts_with_compound_continuation(node: tree_sitter::Node, source: &[u8]) -> bool {
    const KEYWORDS: &[&str] = &["do", "done", "then", "fi", "elif", "else", "esac"];
    let Ok(text) = std::str::from_utf8(&source[node.start_byte()..node.end_byte()]) else {
        return false;
    };
    let text = text.trim_start();
    if text.starts_with('}') {
        return true;
    }
    KEYWORDS.iter().any(|kw| {
        let Some(rest) = text.strip_prefix(*kw) else {
            return false;
        };
        // The keyword must end on a non-word boundary so user-named commands
        // like `do_thing` / `done_task` are not misclassified.
        match rest.chars().next() {
            None => true,
            Some(c) => !c.is_alphanumeric() && c != '_',
        }
    })
}

/// Strip the first whitespace-delimited token from `input`, returning the
/// remainder with leading space/tab run trimmed (newlines are preserved so
/// a token followed by a newline does not silently join with the next line).
fn strip_first_token(input: &str) -> Option<&str> {
    let trimmed = input.trim_start();
    let end = trimmed.find(|c: char| c.is_ascii_whitespace())?;
    let rest = &trimmed[end..];
    Some(rest.trim_start_matches([' ', '\t']))
}

/// Split a multi-line shell input into top-level command strings.
///
/// Unlike [`extract_commands_with_metadata`], this function only splits at
/// **top-level command boundaries** — newlines, `;`, and `&` between
/// statements at the `program` root. Compound commands joined by `&&`,
/// `||`, or `|` are kept as a single string (the caller — typically the
/// rule engine — will split those further).
///
/// HEREDOC bodies, quoted strings spanning multiple lines, and backslash
/// line continuations are kept intact because tree-sitter-bash represents
/// them as a single AST node.
///
/// Returns `SyntaxError` if tree-sitter-bash cannot parse the input, and
/// `EmptyCommand` if the input is empty or whitespace-only.
pub fn split_top_level_commands(input: &str) -> Result<Vec<String>, CommandParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    // See `strip_misparsed_compound_prefix`.
    if let Some(rest) = strip_misparsed_compound_prefix(trimmed) {
        return split_top_level_commands(rest);
    }

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|_| CommandParseError::SyntaxError)?;

    let tree = parser
        .parse(trimmed, None)
        .ok_or(CommandParseError::SyntaxError)?;

    let root = tree.root_node();

    if root.has_error() {
        return Err(CommandParseError::SyntaxError);
    }

    let source = trimmed.as_bytes();
    let mut commands = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        // tree-sitter-bash exposes `#...` lines as `comment` siblings of
        // top-level commands; bash treats them as no-ops, so drop them here.
        if child.kind() == "comment" {
            continue;
        }
        if let Ok(text) = child.utf8_text(source) {
            let text = text.trim();
            if !text.is_empty() {
                commands.push(text.to_string());
            }
        }
    }

    if commands.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    Ok(commands)
}

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
pub(super) fn collect_commands(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
    loop_kind: &str,
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
        | "else_clause"
        | "command_substitution"
        | "process_substitution"
        | "if_statement"
        | "elif_clause"
        | "negated_command" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(child, source, commands, pipe_info, redirects, loop_kind);
            }
        }
        // while_statement covers both `while` and `until` in tree-sitter-bash.
        // The leading anonymous token (`while` or `until`) distinguishes them;
        // it sets `loop_kind` for the condition, body, and any nested commands.
        // A nested loop further down overrides this (nearest parent wins).
        "while_statement" => {
            let kind = detect_while_or_until(node, source);
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(child, source, commands, pipe_info, redirects, kind);
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
                collect_commands(*child, source, commands, &child_pipe, redirects, loop_kind);
            }
        }
        // for_statement: recurse into body (do_group) for loop-body commands,
        // and into value-list items to find nested command substitutions.
        // The body runs inside the loop (`loop_kind = "for"`); value-list
        // substitutions run once before the loop body, so they keep
        // `loop_kind = ""` whether the substitution is bare (`$(cmd)`) or
        // quoted (`"$(cmd)"`).
        "for_statement" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "do_group" => {
                        collect_commands(child, source, commands, pipe_info, redirects, "for");
                    }
                    "command_substitution" | "process_substitution" => {
                        collect_commands(child, source, commands, &PipeInfo::default(), &[], "");
                    }
                    _ => {
                        collect_substitutions_recursive(child, source, commands);
                    }
                }
            }
        }
        // case_statement: recurse into each case_item, and search the match
        // value for nested command substitutions (e.g. `case $(cmd) in ...`).
        // The match value uses field name "value" and may be a
        // command_substitution node directly.
        "case_statement" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "case_item" => {
                        collect_commands(child, source, commands, pipe_info, redirects, loop_kind);
                    }
                    "command_substitution" => {
                        collect_commands(child, source, commands, pipe_info, redirects, loop_kind);
                    }
                    _ => {
                        collect_substitutions_recursive(child, source, commands);
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
                    collect_substitutions_recursive(child, source, commands);
                } else {
                    collect_commands(child, source, commands, pipe_info, redirects, loop_kind);
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
                    collect_commands(body, source, commands, pipe_info, &all_redirects, loop_kind);
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
                        );
                    }
                    let arm_pipe = PipeInfo {
                        stdin: false,
                        stdout: pipe_info.stdout,
                    };
                    for arm in &continuation.list_arms {
                        collect_commands(*arm, source, commands, &arm_pipe, redirects, loop_kind);
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
                        collect_heredoc_redirect_substitutions(child, source, commands);
                    } else {
                        collect_substitutions_recursive(child, source, commands);
                    }
                }
            }
        }
        // comment: skip shell comments (e.g. `# description`)
        "comment" => {}
        // variable_assignment: transparent container — skip the assignment itself
        // and recursively find command_substitution / process_substitution nodes
        // anywhere in the subtree (they may be nested inside string nodes when
        // the value is quoted, e.g. X="$(cmd)").
        "variable_assignment" => {
            collect_substitutions_recursive(node, source, commands);
        }
        // function_definition: recurse into body
        "function_definition" => {
            if let Some(body) = node.child_by_field_name("body") {
                collect_commands(body, source, commands, pipe_info, redirects, loop_kind);
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
                        collect_substitutions_recursive(child, source, commands);
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
                            );
                            if let Some(token) = dequote_node(child, source) {
                                argv.push(token);
                            }
                        }
                        "variable_assignment" => {
                            if let Some(assignment) = extract_env_assignment(child, source) {
                                env.push(assignment);
                            }
                            collect_substitutions_recursive(child, source, commands);
                        }
                        // Recurse into other child nodes (e.g. string,
                        // concatenation) to find nested command_substitution
                        // nodes (e.g. `curl -u "user:$(secret_cmd)" url`).
                        _ => {
                            collect_substitutions_recursive(child, source, commands);
                            if let Some(token) = dequote_node(child, source) {
                                argv.push(token);
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
            let text = parts.join(" ");
            let text = text.trim();
            if !text.is_empty() {
                commands.push(ExtractedCommand {
                    command: text.to_string(),
                    env,
                    argv,
                    redirects: cmd_redirects,
                    pipe: pipe_info.clone(),
                    loop_kind: loop_kind.to_string(),
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
        // the command string.
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
                        collect_substitutions_recursive(child, source, commands);
                    }
                    _ => {
                        collect_substitutions_recursive(child, source, commands);
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
                });
            }
        }
        // Leaf command nodes — extract the source text, and recurse into
        // all child nodes to find nested command substitutions.
        _ => {
            collect_substitutions_recursive(node, source, commands);
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
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

    // ========================================
    // extract_commands: compound commands
    // ========================================

    #[rstest]
    #[case::single("echo hello", vec!["echo hello"])]
    #[case::pipeline("echo hello | grep world", vec!["echo hello", "grep world"])]
    #[case::and("cmd1 && cmd2", vec!["cmd1", "cmd2"])]
    #[case::or("cmd1 || cmd2", vec!["cmd1", "cmd2"])]
    #[case::semicolon("cmd1 ; cmd2", vec!["cmd1", "cmd2"])]
    #[case::mixed_operators("curl url | jq '.data' && rm tmp.json", vec!["curl url", "jq '.data'", "rm tmp.json"])]
    #[case::logical_chain("cmd1 && cmd2 || cmd3", vec!["cmd1", "cmd2", "cmd3"])]
    #[case::quotes_preserved(r#"echo "hello | world" && grep test"#, vec![r#"echo "hello | world""#, "grep test"])]
    fn extract_compound_commands(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: subshell
    // ========================================

    #[rstest]
    #[case::in_pipeline("(cmd1 && cmd2) | cmd3", vec!["cmd1", "cmd2", "cmd3"])]
    #[case::in_logical_chain("(cmd1 ; cmd2) && cmd3", vec!["cmd1", "cmd2", "cmd3"])]
    // `((...))` is arithmetic expansion in bash, so we use
    // `(... | (...))` to test genuine subshell nesting.
    #[case::deeply_nested("(cmd1 | (cmd2 ; cmd3)) && cmd4", vec!["cmd1", "cmd2", "cmd3", "cmd4"])]
    fn extract_subshell(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: special constructs
    // ========================================

    #[rstest]
    #[case::process_substitution("diff <(cmd1) <(cmd2)", vec!["diff <(cmd1) <(cmd2)"])]
    fn extract_special_constructs(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: HEREDOC
    //
    // For all delimiter forms (`<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`)
    // the body command is `cat` and the redirect carries the body
    // text. Quoted delimiters (`'EOF'`/`"EOF"`/`\EOF`) make the body
    // literal in bash — `$(cmd)` and friends do NOT expand — so runok
    // must not extract apparent substitutions from inside them. The
    // unquoted form (`<<EOF`) does expand, so a `$(secret)` in the
    // body is a real command and gets extracted.
    // ========================================

    #[test]
    fn extract_heredoc_unquoted_delimiter_keeps_body_command() {
        let input = indoc! {"
            cat <<EOF
            hello
            EOF
        "}
        .trim_end();
        let result = extract_commands(input).unwrap();
        // heredoc is a redirected_statement; only the body command is extracted
        assert_eq!(result, vec!["cat"]);
    }

    #[rstest]
    #[case::single_quoted_delimiter(indoc! {"
        cat <<'EOF'
        $(secret_cmd)
        EOF
    "})]
    #[case::double_quoted_delimiter(indoc! {r#"
        cat <<"EOF"
        $(secret_cmd)
        EOF
    "#})]
    #[case::backslash_quoted_delimiter(indoc! {r"
        cat <<\EOF
        $(secret_cmd)
        EOF
    "})]
    // `<<-` strips leading tabs; the quoting rule is still determined
    // by the delimiter token itself, so a tab-stripping single-quoted
    // delimiter must also be treated as literal.
    #[case::tab_strip_single_quoted_delimiter(indoc! {"
        cat <<-'EOF'
        \t$(secret_cmd)
        \tEOF
    "})]
    // bash treats the body as literal whenever ANY part of the
    // delimiter is quoted, not just the leading character. `<<E\OF`
    // is the same as `<<\EOF` for this purpose: the backslash quotes
    // the next character and that's enough to disable expansion.
    #[case::mid_backslash_quoted_delimiter(indoc! {r"
        cat <<E\OF
        $(secret_cmd)
        EOF
    "})]
    fn extract_heredoc_quoted_delimiter_skips_body_substitutions(#[case] input: &str) {
        let trimmed = input.trim_end();
        let result = extract_commands(trimmed).unwrap();
        // Quoted delimiter ⇒ literal body ⇒ `$(secret_cmd)` is inert
        // text, so only `cat` is extracted.
        assert_eq!(result, vec!["cat"]);
    }

    #[test]
    fn extract_heredoc_unquoted_delimiter_extracts_body_substitution() {
        let input = indoc! {"
            cat <<EOF
            $(secret_cmd)
            EOF
        "}
        .trim_end();
        let result = extract_commands(input).unwrap();
        // Unquoted delimiter ⇒ bash interpolates the body, so the
        // `$(secret_cmd)` gets pulled out for separate evaluation.
        // collect_commands emits the body command before scanning
        // redirect children, so `cat` comes first.
        assert_eq!(result, vec!["cat", "secret_cmd"]);
    }

    // Regression test for `git commit -m "$(cat <<'EOF' ... EOF)"` —
    // a Claude Code `/commit` skill workflow that previously failed
    // with `unclosed quote` because the inner self-tokenizer scanned
    // the literal HEREDOC body as if it were shell syntax.
    #[test]
    fn extract_heredoc_inside_command_substitution_inside_double_quotes() {
        let input = indoc! {"
            git add path && git commit -m \"$(cat <<'EOF'
            subject

            body line 1 with 'apostrophes' inside
            EOF
            )\"
        "}
        .trim_end();
        let result = extract_commands(input).unwrap();
        // git add ... && git commit ... extracts to two top-level
        // commands, plus the inner `cat` from the command substitution.
        let third = indoc! {"
            git commit -m \"$(cat <<'EOF'
            subject

            body line 1 with 'apostrophes' inside
            EOF
            )\""}
        .trim_end();
        assert_eq!(result, vec!["git add path", "cat", third]);
    }

    // ========================================
    // extract_commands: HEREDOC inside compound expressions
    //
    // tree-sitter-bash represents `cat <<EOF | other ...\nbody\nEOF` by
    // attaching the trailing `pipeline` / `&&` / `||` arm as a CHILD of
    // the `heredoc_redirect` node, instead of wrapping the whole thing
    // in an outer pipeline. The body and continuation must be re-stitched
    // into the synthesized outer pipeline so every sub-command surfaces
    // to the rule engine with the right pipe metadata.
    // ========================================

    // Each delimiter form (`<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`,
    // `<<-EOF`) and each compound operator (`|`, `&&`, `||`) goes
    // through the same `find_heredoc_continuation` codepath, so a
    // single rstest matrix covers the variants. The `<<\EOF` case
    // exercises `is_quoted_heredoc`'s backslash detection.
    #[rstest]
    #[case::pipe_unquoted(
        indoc! {"
            cat <<EOF | kubectl apply -f -
            apiVersion: v1
            EOF
        "},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_single_quoted_delimiter(
        indoc! {"
            cat <<'EOF' | kubectl apply -f -
            apiVersion: v1
            EOF
        "},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_double_quoted_delimiter(
        indoc! {r#"
            cat <<"EOF" | kubectl apply -f -
            apiVersion: v1
            EOF
        "#},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_backslash_quoted_delimiter(
        indoc! {r"
            cat <<\EOF | kubectl apply -f -
            apiVersion: v1
            EOF
        "},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_tab_strip(
        indoc! {"
            cat <<-EOF | tee out
            \tbody
            \tEOF
        "},
        vec!["cat", "tee out"],
    )]
    #[case::pipe_multiple_stages(
        indoc! {"
            cat <<EOF | kubectl apply -f - | tee out
            body
            EOF
        "},
        vec!["cat", "kubectl apply -f -", "tee out"],
    )]
    #[case::and_chain(
        indoc! {"
            cat <<EOF && echo done
            body
            EOF
        "},
        vec!["cat", "echo done"],
    )]
    #[case::or_chain(
        indoc! {"
            cat <<EOF || echo nope
            body
            EOF
        "},
        vec!["cat", "echo nope"],
    )]
    fn extract_heredoc_in_compound(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input.trim_end()).unwrap();
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        assert_eq!(result, expected);
    }

    // tree-sitter-bash 0.25.1 produces an ERROR node for `;` / `&`
    // after a heredoc start, so runok surfaces these as SyntaxError
    // rather than dropping the trailing arm. Pinned to detect parser
    // version drift.
    #[rstest]
    #[case::semicolon_after_heredoc(indoc! {"
        cat <<EOF ; echo after
        body
        EOF
    "})]
    #[case::ampersand_after_heredoc(indoc! {"
        cat <<EOF & echo after
        body
        EOF
    "})]
    fn extract_heredoc_with_semicolon_or_ampersand_is_syntax_error(#[case] input: &str) {
        let err = extract_commands(input.trim_end()).unwrap_err();
        assert!(
            matches!(err, CommandParseError::SyntaxError),
            "expected SyntaxError, got {:?}",
            err
        );
    }

    // Per-stage pipe metadata. `extract_commands` discards `pipe`,
    // so these cases pin `extract_commands_with_metadata` directly.
    // Important for any future `when: pipe.stdout == false` rule that
    // would silently misfire if a middle stage lost a flag, or if a
    // logical-list right-hand side got reinterpreted as a pipe stage.
    #[rstest]
    #[case::three_stage_pipeline(
        indoc! {"
            cat <<EOF | kubectl apply -f - | tee out
            body
            EOF
        "},
        vec![
            ("cat",                PipeInfo { stdin: false, stdout: true  }),
            ("kubectl apply -f -", PipeInfo { stdin: true,  stdout: true  }),
            ("tee out",            PipeInfo { stdin: true,  stdout: false }),
        ],
    )]
    // `cat <<EOF && a | b`: tree-sitter exposes `a | b` as the
    // `right`-fielded pipeline. body and right are list siblings (no
    // pipe), `a` is the head of the right-hand pipeline.
    #[case::and_with_right_pipeline(
        indoc! {"
            cat <<EOF && a | b
            body
            EOF
        "},
        vec![
            ("cat", PipeInfo { stdin: false, stdout: false }),
            ("a",   PipeInfo { stdin: false, stdout: true  }),
            ("b",   PipeInfo { stdin: true,  stdout: false }),
        ],
    )]
    // `cat <<EOF | tee out && echo done`: heredoc holds an un-fielded
    // pipeline whose stages are `[tee out, list[..., echo done]]`.
    // The list stage must be processed as a list, NOT inherit
    // `stdin = true` from the synthesized outer pipeline.
    #[case::pipe_then_and_chain(
        indoc! {"
            cat <<EOF | tee out && echo done
            body
            EOF
        "},
        vec![
            ("cat",       PipeInfo { stdin: false, stdout: true  }),
            ("tee out",   PipeInfo { stdin: true,  stdout: false }),
            ("echo done", PipeInfo { stdin: false, stdout: false }),
        ],
    )]
    // `cat <<EOF | a | b && c || d`: the multi-pipe + multi-list
    // chain stress-tests the recursive `list` split. Bash's
    // `|` > `&&` precedence means `(cat | a | b) && c || d`.
    #[case::pipe_chain_then_list_chain(
        indoc! {"
            cat <<EOF | a | b && c || d
            body
            EOF
        "},
        vec![
            ("cat", PipeInfo { stdin: false, stdout: true  }),
            ("a",   PipeInfo { stdin: true,  stdout: true  }),
            ("b",   PipeInfo { stdin: true,  stdout: false }),
            ("c",   PipeInfo { stdin: false, stdout: false }),
            ("d",   PipeInfo { stdin: false, stdout: false }),
        ],
    )]
    // `a | cat <<EOF && b`: the heredoc body is the pipeline
    // `a | cat`, and `b` is the `&&` arm. `&&` is a pipe boundary,
    // so `b.stdin` must be `false` even though it sits next to a
    // pipe segment in the source.
    #[case::heredoc_pipe_in_body_with_and_arm(
        indoc! {"
            a | cat <<EOF && b
            body
            EOF
        "},
        vec![
            ("a",   PipeInfo { stdin: false, stdout: true  }),
            ("cat", PipeInfo { stdin: true,  stdout: false }),
            ("b",   PipeInfo { stdin: false, stdout: false }),
        ],
    )]
    fn extract_heredoc_pipe_metadata(#[case] input: &str, #[case] expected: Vec<(&str, PipeInfo)>) {
        let cmds = extract_commands_with_metadata(input.trim_end()).unwrap();
        let actual: Vec<(&str, PipeInfo)> = cmds
            .iter()
            .map(|c| (c.command.as_str(), c.pipe.clone()))
            .collect();
        assert_eq!(actual, expected);
    }

    // tree-sitter-bash 0.25.1 produces an ERROR node when a second
    // `<<` follows the first heredoc on the same pipeline, so runok
    // surfaces SyntaxError instead of silently dropping arms. Pinned
    // to detect parser version drift.
    #[test]
    fn extract_two_heredocs_in_pipeline_is_syntax_error() {
        let input = indoc! {"
            cat <<EOF | cat <<EOF2 | tee out
            body1
            EOF
            body2
            EOF2
        "}
        .trim_end();
        let err = extract_commands(input).unwrap_err();
        assert!(
            matches!(err, CommandParseError::SyntaxError),
            "expected SyntaxError, got {:?}",
            err
        );
    }

    // The trailing arm may itself be a compound expression. All of
    // its sub-commands need to surface so deny rules can match them.
    #[test]
    fn extract_heredoc_pipe_then_and_chain() {
        let input = indoc! {"
            cat <<EOF | tee out && echo done
            body
            EOF
        "}
        .trim_end();
        let result = extract_commands(input).unwrap();
        assert_eq!(result, vec!["cat", "tee out", "echo done"]);
    }

    // Heredoc on the right-hand side of a pipeline is the "easy"
    // case (tree-sitter wraps the pipeline naturally). Pin it down
    // so the fix for the left-hand case does not regress it.
    #[test]
    fn extract_pipeline_into_heredoc() {
        let input = indoc! {"
            echo foo | cat <<EOF
            body
            EOF
        "}
        .trim_end();
        let result = extract_commands(input).unwrap();
        assert_eq!(result, vec!["echo foo", "cat"]);
    }

    // Heredoc inside a control-flow body must still surface every
    // pipeline stage to the outer command list.
    #[rstest]
    #[case::if_body(
        indoc! {"
            if true; then
              cat <<EOF | tee out
            body
            EOF
            fi
        "},
        vec!["true", "cat", "tee out"],
    )]
    #[case::while_body(
        indoc! {"
            while true; do
              cat <<EOF | tee out
            body
            EOF
            done
        "},
        vec!["true", "cat", "tee out"],
    )]
    #[case::for_body(
        indoc! {"
            for x in a b; do
              cat <<EOF | tee out
            body
            EOF
            done
        "},
        vec!["cat", "tee out"],
    )]
    fn extract_heredoc_pipe_inside_control_flow(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input.trim_end()).unwrap();
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: redirected statements
    // ========================================

    #[rstest]
    #[case::stdout_to_file("echo hello > file.txt", vec!["echo hello"])]
    #[case::append_to_file("echo hello >> file.txt", vec!["echo hello"])]
    #[case::stdin_from_file("cat < input.txt", vec!["cat"])]
    #[case::stderr_to_devnull("cmd 2> /dev/null", vec!["cmd"])]
    #[case::stdout_and_stderr("cmd > out.txt 2>&1", vec!["cmd"])]
    #[case::fd_redirect_only("echo hello 2>&1", vec!["echo hello"])]
    #[case::devnull_redirect("curl url > /dev/null", vec!["curl url"])]
    #[case::herestring("cat <<< hello", vec!["cat"])]
    #[case::redirect_with_pipeline(
        "echo hello 2>&1 | grep world",
        vec!["echo hello", "grep world"],
    )]
    #[case::redirect_with_list(
        "echo hello > file.txt && cat file.txt",
        vec!["echo hello", "cat file.txt"],
    )]
    #[case::redirect_in_compound(
        r#"X="test" && echo "$X" 2>&1"#,
        vec![r#"echo "$X""#],
    )]
    #[case::process_substitution_in_redirect(
        "cmd > >(nested_cmd)",
        vec!["cmd", "nested_cmd"],
    )]
    #[case::command_substitution_in_redirect(
        "cmd > $(echo /tmp/file)",
        vec!["cmd", "echo /tmp/file"],
    )]
    #[case::command_substitution_in_herestring(
        "cat <<< $(secret_cmd)",
        vec!["secret_cmd", "cat"],
    )]
    fn extract_redirected_statements(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: comments
    // ========================================

    #[rstest]
    #[case::comment_before_command(
        "# description\ngh api -X GET /repos",
        vec!["gh api -X GET /repos"],
    )]
    #[case::comment_before_pipeline(
        "# list agents\ngh api -X GET /repos | jq '.name'",
        vec!["gh api -X GET /repos", "jq '.name'"],
    )]
    #[case::comment_only("# just a comment", vec![])]
    #[case::inline_comment_after_semicolon(
        "echo hello; # trailing comment",
        vec!["echo hello"],
    )]
    fn extract_comments(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: whitespace handling
    // ========================================

    #[rstest]
    #[case::extra_whitespace("  cmd1   &&   cmd2  ", vec!["cmd1", "cmd2"])]
    #[case::with_subshell("  cmd1   &&   cmd2  | ( cmd3 )  ", vec!["cmd1", "cmd2", "cmd3"])]
    fn extract_commands_whitespace(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: control structures
    // ========================================

    #[rstest]
    #[case::for_simple("for i in 1 2 3; do echo $i; done", vec!["echo $i"])]
    #[case::for_multiple_cmds("for f in *.txt; do cat $f && rm $f; done", vec!["cat $f", "rm $f"])]
    #[case::for_cmd_substitution("for f in $(find . -name '*.txt'); do echo $f; done", vec!["find . -name '*.txt'", "echo $f"])]
    #[case::for_backtick_substitution("for f in `ls`; do cat $f; done", vec!["ls", "cat $f"])]
    #[case::while_simple("while true; do echo hello; done", vec!["true", "echo hello"])]
    #[case::while_pipeline("while read line; do echo $line | grep foo; done", vec!["read line", "echo $line", "grep foo"])]
    #[case::if_then("if true; then echo yes; fi", vec!["true", "echo yes"])]
    #[case::if_then_else("if true; then echo yes; else echo no; fi", vec!["true", "echo yes", "echo no"])]
    #[case::if_elif_else("if true; then echo a; elif false; then echo b; else echo c; fi", vec!["true", "echo a", "false", "echo b", "echo c"])]
    #[case::for_quoted_cmd_sub_in_value(
        r#"for i in "$(dangerous_cmd)"; do echo $i; done"#,
        vec!["dangerous_cmd", "echo $i"],
    )]
    #[case::case_cmd_sub_in_match_value(
        "case $(dangerous_cmd) in a) echo a;; esac",
        vec!["dangerous_cmd", "echo a"],
    )]
    #[case::case_cmd_sub_in_pattern(
        r#"case $x in "$(dangerous_cmd)") echo a;; esac"#,
        vec!["dangerous_cmd", "echo a"],
    )]
    #[case::case_statement("case $x in a) echo a;; b) echo b;; esac", vec!["echo a", "echo b"])]
    #[case::compound_statement("{ echo a; echo b; }", vec!["echo a", "echo b"])]
    #[case::function_def("f() { echo hello; }", vec!["echo hello"])]
    #[case::negated_command("! echo hello", vec!["echo hello"])]
    #[case::negated_command_in_if(
        "if ! grep -q test /dev/null; then echo no; fi",
        vec!["grep -q test /dev/null", "echo no"],
    )]
    #[case::negated_pipeline_in_subshell("! (echo a | grep a)", vec!["echo a", "grep a"])]
    fn extract_control_structures(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: nested control structures
    // ========================================

    #[rstest]
    #[case::for_in_if("for i in 1 2; do if true; then echo $i; fi; done", vec!["true", "echo $i"])]
    #[case::if_in_for("if true; then for i in a b; do echo $i; done; fi", vec!["true", "echo $i"])]
    fn extract_nested_control_structures(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands_with_metadata: loop_kind
    //
    // Surfaces the enclosing-loop kind on every sub-command so CEL
    // `when` clauses can deny `sleep` polling loops via
    // `shell.loop_kind in ["while", "until"]`.
    // ========================================

    #[rstest]
    #[case::no_loop("sleep 5", vec![("sleep 5", "")])]
    #[case::until_body(
        "until ready; do sleep 1; done",
        vec![("ready", "until"), ("sleep 1", "until")],
    )]
    #[case::while_body(
        "while alive; do sleep 1; done",
        vec![("alive", "while"), ("sleep 1", "while")],
    )]
    #[case::for_body(
        "for i in 1 2 3; do echo $i; done",
        vec![("echo $i", "for")],
    )]
    #[case::nested_until_in_for(
        "for x in a b; do until y; do sleep 1; done; done",
        vec![("y", "until"), ("sleep 1", "until")],
    )]
    #[case::subshell_wraps_loop(
        "(while x; do sleep 1; done)",
        vec![("x", "while"), ("sleep 1", "while")],
    )]
    #[case::pipeline_inside_loop(
        "while alive; do gh pr checks 1 | grep -q ok; done",
        vec![("alive", "while"), ("gh pr checks 1", "while"), ("grep -q ok", "while")],
    )]
    #[case::loop_followed_by_outside(
        "while alive; do sleep 1; done; echo done",
        vec![("alive", "while"), ("sleep 1", "while"), ("echo done", "")],
    )]
    // For-value-list substitutions run once before the loop body in bash, so
    // they keep `loop_kind == ""` regardless of whether the substitution is
    // bare or quoted — quoting shouldn't change rule-matching semantics.
    #[case::for_value_substitution_bare(
        "for i in $(seed); do echo $i; done",
        vec![("seed", ""), ("echo $i", "for")],
    )]
    #[case::for_value_substitution_quoted(
        r#"for i in "$(seed)"; do echo $i; done"#,
        vec![("seed", ""), ("echo $i", "for")],
    )]
    fn extract_loop_kind(#[case] input: &str, #[case] expected: Vec<(&str, &str)>) {
        let result = extract_commands_with_metadata(input).unwrap();
        let actual: Vec<(&str, &str)> = result
            .iter()
            .map(|ec| (ec.command.as_str(), ec.loop_kind.as_str()))
            .collect();
        assert_eq!(actual, expected);
    }

    // ========================================
    // extract_commands: control structures with pipeline/list
    // ========================================

    #[rstest]
    #[case::list_with_for("echo start && for i in 1 2; do echo $i; done", vec!["echo start", "echo $i"])]
    #[case::for_piped("for i in 1 2; do echo $i; done | grep 1", vec!["echo $i", "grep 1"])]
    #[case::cmd_sub_in_command("echo $(dangerous_cmd)", vec!["dangerous_cmd", "echo $(dangerous_cmd)"])]
    #[case::backtick_in_command("echo `dangerous_cmd`", vec!["dangerous_cmd", "echo `dangerous_cmd`"])]
    #[case::cmd_sub_in_quoted_string(
        r#"curl -u "user:$(secret_cmd)" https://example.com"#,
        vec!["secret_cmd", r#"curl -u "user:$(secret_cmd)" https://example.com"#],
    )]
    #[case::cmd_sub_in_concatenation(
        "curl -H Authorization:$(cat token) url",
        vec!["cat token", "curl -H Authorization:$(cat token) url"],
    )]
    #[case::cmd_sub_in_single_quotes(
        "echo '$(dangerous_cmd)'",
        vec!["echo '$(dangerous_cmd)'"],
    )]
    #[case::backtick_sub_in_quoted_string(
        r#"curl -u "user:`secret_cmd`" https://example.com"#,
        vec!["secret_cmd", r#"curl -u "user:`secret_cmd`" https://example.com"#],
    )]
    #[case::docker_env_with_cmd_sub(
        r#"docker run -e TOKEN="$(cat /tmp/secret)" nginx"#,
        vec!["cat /tmp/secret", r#"docker run -e TOKEN="$(cat /tmp/secret)" nginx"#],
    )]
    fn extract_control_with_operators(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: variable assignments
    // ========================================

    #[rstest]
    #[case::assignment_then_command("X=1 && echo hello", vec!["echo hello"])]
    #[case::assignment_with_cmd_substitution("X=$(echo test)", vec!["echo test"])]
    #[case::assignment_with_cmd_substitution_and_command(
        "X=$(rm -rf /) && echo hello",
        vec!["rm -rf /", "echo hello"]
    )]
    #[case::multiple_assignments("A=1 && B=2 && echo done", vec!["echo done"])]
    #[case::assignment_with_backtick_substitution("X=`ls`", vec!["ls"])]
    #[case::quoted_cmd_substitution(r#"X="$(echo test)""#, vec!["echo test"])]
    #[case::quoted_backtick_substitution(r#"X="`ls`""#, vec!["ls"])]
    #[case::process_substitution_in_assignment("X=<(cat file)", vec!["cat file"])]
    fn extract_variable_assignments(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn extract_bare_variable_assignment_returns_empty() {
        // A bare variable assignment (no command substitution) produces no commands.
        let result = extract_commands("X=1").unwrap();
        assert!(result.is_empty());
    }

    // ========================================
    // extract_commands: env-prefix commands (VAR=value cmd args)
    // ========================================

    #[rstest]
    #[case::single_env_prefix("FOO=bar echo hello", vec!["echo hello"])]
    #[case::multiple_env_prefixes("FOO=bar BAZ=qux echo hello", vec!["echo hello"])]
    #[case::env_prefix_with_flags("FOO=bar curl -X POST https://example.com", vec!["curl -X POST https://example.com"])]
    #[case::env_prefix_with_pipeline("FOO=bar echo hello | grep hello", vec!["echo hello", "grep hello"])]
    #[case::env_prefix_with_cmd_substitution(
        "FOO=$(echo bar) echo hello",
        vec!["echo bar", "echo hello"]
    )]
    // `env FOO=bar echo hello`: tree-sitter treats `env` as the command name
    // and `FOO=bar` as a regular argument (word node), not a variable_assignment.
    // The entire text is preserved as a single command for wrapper evaluation.
    #[case::env_cmd_with_var_arg(
        "env FOO=bar echo hello",
        vec!["env FOO=bar echo hello"]
    )]
    fn extract_env_prefix_commands(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: declaration_command / unset_command builtins
    //
    // These shell builtins live alongside `command` in tree-sitter-bash
    // and must flow through extraction (not be dropped or treated as
    // env-prefix variable_assignments) so callers can evaluate rules
    // against them inside pipelines / lists / subshells.
    // ========================================

    #[rstest]
    #[case::standalone_export("export FOO=bar", vec!["export FOO=bar"])]
    #[case::standalone_unset("unset FOO", vec!["unset FOO"])]
    #[case::declare_in_pipeline(
        "declare -x FOO=bar | grep FOO",
        vec!["declare -x FOO=bar", "grep FOO"]
    )]
    #[case::export_in_and_list(
        "echo before && export FOO=bar && echo after",
        vec!["echo before", "export FOO=bar", "echo after"]
    )]
    #[case::unset_in_subshell(
        "(unset FOO && echo done)",
        vec!["unset FOO", "echo done"]
    )]
    fn extract_declaration_and_unset_commands(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: error cases
    // ========================================

    #[rstest]
    #[case::empty("", CommandParseError::EmptyCommand)]
    #[case::syntax_error("&&", CommandParseError::SyntaxError)]
    fn extract_commands_errors(#[case] input: &str, #[case] expected: CommandParseError) {
        let result = extract_commands(input);
        assert_eq!(
            std::mem::discriminant(&result.unwrap_err()),
            std::mem::discriminant(&expected),
        );
    }

    // ========================================
    // extract_commands_with_metadata: redirects
    // ========================================

    #[rstest]
    #[case::output_redirect(
        "echo hello > /tmp/log.txt",
        vec![RedirectInfo {
            redirect_type: "output".to_string(),
            operator: ">".to_string(),
            target: "/tmp/log.txt".to_string(),
            descriptor: None,
        }],
        PipeInfo { stdin: false, stdout: false },
    )]
    #[case::append_redirect(
        "echo hello >> /tmp/log.txt",
        vec![RedirectInfo {
            redirect_type: "output".to_string(),
            operator: ">>".to_string(),
            target: "/tmp/log.txt".to_string(),
            descriptor: None,
        }],
        PipeInfo { stdin: false, stdout: false },
    )]
    #[case::dup_redirect_2_to_1(
        "echo hello 2>&1",
        vec![RedirectInfo {
            redirect_type: "dup".to_string(),
            operator: ">&".to_string(),
            target: "1".to_string(),
            descriptor: Some(2),
        }],
        PipeInfo { stdin: false, stdout: false },
    )]
    #[case::input_redirect(
        "cat < input.txt",
        vec![RedirectInfo {
            redirect_type: "input".to_string(),
            operator: "<".to_string(),
            target: "input.txt".to_string(),
            descriptor: None,
        }],
        PipeInfo { stdin: false, stdout: false },
    )]
    #[case::herestring_redirect(
        "cat <<< 'hello'",
        vec![RedirectInfo {
            redirect_type: "input".to_string(),
            operator: "<<<".to_string(),
            target: "'hello'".to_string(),
            descriptor: None,
        }],
        PipeInfo { stdin: false, stdout: false },
    )]
    #[case::ampersand_redirect(
        "echo hello &>/dev/null",
        vec![RedirectInfo {
            redirect_type: "output".to_string(),
            operator: "&>".to_string(),
            target: "/dev/null".to_string(),
            descriptor: None,
        }],
        PipeInfo { stdin: false, stdout: false },
    )]
    #[case::clobber_redirect(
        "echo hello >| /tmp/log.txt",
        vec![RedirectInfo {
            redirect_type: "output".to_string(),
            operator: ">|".to_string(),
            target: "/tmp/log.txt".to_string(),
            descriptor: None,
        }],
        PipeInfo { stdin: false, stdout: false },
    )]
    fn extract_commands_metadata_single(
        #[case] input: &str,
        #[case] expected_redirects: Vec<RedirectInfo>,
        #[case] expected_pipe: PipeInfo,
    ) {
        let commands = extract_commands_with_metadata(input).unwrap();
        assert_eq!(commands.len(), 1, "expected 1 command for input: {}", input);
        assert_eq!(commands[0].redirects, expected_redirects);
        assert_eq!(commands[0].pipe, expected_pipe);
    }

    // ========================================
    // extract_commands_with_metadata: pipeline position
    // ========================================

    #[rstest]
    #[case::simple_command("echo hello", vec![
        PipeInfo { stdin: false, stdout: false },
    ])]
    #[case::two_stage_pipeline("echo hello | grep foo", vec![
        PipeInfo { stdin: false, stdout: true },
        PipeInfo { stdin: true, stdout: false },
    ])]
    #[case::three_stage_pipeline("echo hello | grep foo | wc -l", vec![
        PipeInfo { stdin: false, stdout: true },
        PipeInfo { stdin: true, stdout: true },
        PipeInfo { stdin: true, stdout: false },
    ])]
    #[case::nested_pipeline_in_subshell("cmd1 | (cmd2 | cmd3)", vec![
        PipeInfo { stdin: false, stdout: true },
        PipeInfo { stdin: true, stdout: true },
        PipeInfo { stdin: true, stdout: false },
    ])]
    fn extract_commands_metadata_pipelines(
        #[case] input: &str,
        #[case] expected_pipes: Vec<PipeInfo>,
    ) {
        let commands = extract_commands_with_metadata(input).unwrap();
        assert_eq!(
            commands.len(),
            expected_pipes.len(),
            "command count mismatch for: {}",
            input
        );
        for (i, expected_pipe) in expected_pipes.iter().enumerate() {
            assert_eq!(
                commands[i].pipe, *expected_pipe,
                "PipeInfo mismatch for command #{} in: {}",
                i, input
            );
            assert!(
                commands[i].redirects.is_empty(),
                "redirects should be empty for command #{} in: {}",
                i,
                input
            );
        }
    }

    // ========================================
    // extract_commands_with_metadata: env / argv
    // ========================================

    fn env(name: &str, value: Option<&str>) -> EnvAssignment {
        EnvAssignment {
            name: name.to_owned(),
            value: value.map(|v| v.to_owned()),
        }
    }

    #[rstest]
    #[case::no_prefix(
        "helmfile template",
        vec![],
        vec!["helmfile", "template"],
    )]
    #[case::single_env_prefix(
        "FOO=x helmfile template",
        vec![env("FOO", Some("x"))],
        vec!["helmfile", "template"],
    )]
    #[case::multiple_env_prefix(
        "FOO=x BAR=y helmfile -l name=alloy template",
        vec![env("FOO", Some("x")), env("BAR", Some("y"))],
        vec!["helmfile", "-l", "name=alloy", "template"],
    )]
    #[case::env_with_dquoted_value(
        r#"FOO="hello world" cmd"#,
        vec![env("FOO", Some("hello world"))],
        vec!["cmd"],
    )]
    #[case::env_with_squoted_value(
        "FOO='hello world' cmd",
        vec![env("FOO", Some("hello world"))],
        vec!["cmd"],
    )]
    fn extract_commands_metadata_env_argv_single(
        #[case] input: &str,
        #[case] expected_env: Vec<EnvAssignment>,
        #[case] expected_argv: Vec<&str>,
    ) {
        let commands = extract_commands_with_metadata(input).unwrap();
        assert_eq!(commands.len(), 1, "expected single command for: {}", input);
        assert_eq!(commands[0].env, expected_env, "env mismatch for: {}", input);
        assert_eq!(
            commands[0].argv, expected_argv,
            "argv mismatch for: {}",
            input
        );
    }

    #[rstest]
    fn extract_commands_metadata_env_with_command_substitution() {
        // Command substitutions in env values are kept verbatim with
        // their delimiters so audit consumers can recognise them.
        let commands = extract_commands_with_metadata(r#"DATE=$(date) cmd run"#).unwrap();
        // The command substitution is hoisted as its own ExtractedCommand
        // (see collect_substitutions_recursive), so we expect two entries.
        let main = commands
            .iter()
            .find(|c| c.command.starts_with("cmd"))
            .expect("main command should be present");
        assert_eq!(main.env, vec![env("DATE", Some("$(date)"))]);
        assert_eq!(main.argv, vec!["cmd", "run"]);
    }

    #[rstest]
    #[case::export_assignment(
        "export FOO=bar",
        vec!["export", "FOO=bar"],
    )]
    #[case::declare_flag_assignment(
        "declare -x FOO=bar",
        vec!["declare", "-x", "FOO=bar"],
    )]
    #[case::unset_multiple(
        "unset FOO BAR",
        vec!["unset", "FOO", "BAR"],
    )]
    fn extract_commands_metadata_declaration_and_unset_argv(
        #[case] input: &str,
        #[case] expected_argv: Vec<&str>,
    ) {
        let commands = extract_commands_with_metadata(input).unwrap();
        assert_eq!(commands.len(), 1, "expected single command for: {}", input);
        assert!(
            commands[0].env.is_empty(),
            "builtins do not carry env-prefix assignments: {}",
            input
        );
        assert_eq!(
            commands[0].argv, expected_argv,
            "argv mismatch for: {}",
            input
        );
    }

    #[rstest]
    fn extract_commands_metadata_redirect_does_not_appear_in_argv() {
        let commands = extract_commands_with_metadata("echo hello > /tmp/out 2>&1").unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].argv, vec!["echo", "hello"]);
        assert_eq!(commands[0].env, Vec::<EnvAssignment>::new());
        assert_eq!(commands[0].redirects.len(), 2);
    }

    #[rstest]
    fn extract_commands_metadata_compound_per_branch_argv() {
        let commands = extract_commands_with_metadata("FOO=x echo hi && BAR=y cat /tmp/f").unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].env, vec![env("FOO", Some("x"))]);
        assert_eq!(commands[0].argv, vec!["echo", "hi"]);
        assert_eq!(commands[1].env, vec![env("BAR", Some("y"))]);
        assert_eq!(commands[1].argv, vec!["cat", "/tmp/f"]);
    }

    #[rstest]
    fn extract_commands_metadata_pipeline_argv_per_stage() {
        let commands = extract_commands_with_metadata("echo hello | grep foo").unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].argv, vec!["echo", "hello"]);
        assert_eq!(
            commands[0].pipe,
            PipeInfo {
                stdin: false,
                stdout: true
            }
        );
        assert_eq!(commands[1].argv, vec!["grep", "foo"]);
        assert_eq!(
            commands[1].pipe,
            PipeInfo {
                stdin: true,
                stdout: false
            }
        );
    }

    // ========================================
    // split_top_level_commands
    //
    // Splits at top-level statement boundaries (newline, `;`, `&`) only.
    // Compound commands joined by `&&`/`||`/`|` and constructs that span
    // multiple lines (HEREDOC, multi-line strings, `\` continuations) are
    // kept as a single string.
    // ========================================

    #[rstest]
    #[case::single_line("git status", vec!["git status"])]
    #[case::three_separate_lines(
        indoc! {"
            git status
            ls -la
            echo hello
        "},
        vec!["git status", "ls -la", "echo hello"],
    )]
    #[case::semicolon_separator("foo; bar", vec!["foo", "bar"])]
    #[case::ampersand_background("foo & bar", vec!["foo", "bar"])]
    #[case::and_or_kept_together(
        "foo && bar || baz",
        vec!["foo && bar || baz"],
    )]
    #[case::pipeline_kept_together(
        "echo hello | grep foo",
        vec!["echo hello | grep foo"],
    )]
    #[case::backslash_line_continuation(
        indoc! {"
            echo \\
              hello \\
              world
        "},
        vec!["echo \\\n  hello \\\n  world"],
    )]
    #[case::heredoc_inside_command_substitution(
        indoc! {"
            git add foo && git commit -m \"$(cat <<'EOF'
            subject
            body
            EOF
            )\"
        "},
        vec![indoc! {"
            git add foo && git commit -m \"$(cat <<'EOF'
            subject
            body
            EOF
            )\""}],
    )]
    #[case::multiline_double_quoted_string(
        indoc! {r#"
            echo "line one
            line two"
        "#},
        vec!["echo \"line one\nline two\""],
    )]
    #[case::skips_blank_lines(
        indoc! {"
            git status

            ls -la
        "},
        vec!["git status", "ls -la"],
    )]
    #[case::skips_comment_only_line(
        indoc! {"
            # a standalone comment
            git status
        "},
        vec!["git status"],
    )]
    #[case::skips_comment_between_commands(
        indoc! {"
            git status
            # comment in the middle
            ls -la
        "},
        vec!["git status", "ls -la"],
    )]
    #[case::trailing_inline_comment_terminated_by_newline(
        indoc! {"
            git status # trailing comment
            ls -la
        "},
        vec!["git status", "ls -la"],
    )]
    #[case::pipelines_split_around_comment_line(
        indoc! {"
            ls -la | grep foo | head -1
            # divider
            cat bar | wc -l
        "},
        vec!["ls -la | grep foo | head -1", "cat bar | wc -l"],
    )]
    // tree-sitter-bash misparses reserved-word prefixes on compound statements
    // (`time for ...; do ...; done`, `! while ...`, etc.) into multiple
    // top-level statements. The parser detects the symptom (a non-leading
    // `program` child that starts with `do`/`done`/`then`/`fi`/`elif`/`else`/
    // `esac`/`}`) and strips the offending prefix so the compound stays whole.
    #[case::time_for_loop(
        "time for i in 1 2 3; do echo $i; done",
        vec!["for i in 1 2 3; do echo $i; done"],
    )]
    #[case::time_dash_p_for_loop(
        "time -p for i in 1 2 3; do echo $i; done",
        vec!["for i in 1 2 3; do echo $i; done"],
    )]
    #[case::time_while_loop(
        "time while true; do echo hi; done",
        vec!["while true; do echo hi; done"],
    )]
    #[case::time_until_loop(
        "time until false; do echo hi; done",
        vec!["until false; do echo hi; done"],
    )]
    #[case::time_if_block(
        "time if true; then echo y; fi",
        vec!["if true; then echo y; fi"],
    )]
    #[case::time_brace_group(
        "time { echo hi; }",
        vec!["{ echo hi; }"],
    )]
    #[case::time_time_for_loop(
        "time time for i in 1 2; do echo $i; done",
        vec!["for i in 1 2; do echo $i; done"],
    )]
    // `!` is another reserved-word prefix tree-sitter misparses when it
    // precedes a compound (the leading `negated_command` only captures the
    // `for`-header and the `do`/`done` get split off as separate statements).
    #[case::bang_for_loop(
        "! for i in 1 2; do echo $i; done",
        vec!["for i in 1 2; do echo $i; done"],
    )]
    // Symptom-based detection: any leading prefix that causes tree-sitter to
    // split the compound apart is peeled off, not just literal `time` / `!`.
    #[case::arbitrary_prefix_compound(
        "foo for i in 1 2; do echo $i; done",
        vec!["for i in 1 2; do echo $i; done"],
    )]
    // Simple commands parse cleanly with no symptom, so the prefix stays.
    #[case::time_simple_command_kept(
        "time ls -la",
        vec!["time ls -la"],
    )]
    // tree-sitter parses `time (...)` as a single `command` node whose argument
    // is the subshell, so the symptom never triggers and the wrapper layer
    // captures the input as-is.
    #[case::time_subshell_kept(
        "time (echo hi; echo bye)",
        vec!["time (echo hi; echo bye)"],
    )]
    #[case::time_dash_p_simple_command_kept(
        "time -p ls -la",
        vec!["time -p ls -la"],
    )]
    fn split_top_level_commands_cases(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = split_top_level_commands(input).unwrap();
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::empty("", CommandParseError::EmptyCommand)]
    #[case::whitespace_only("   \n\n  ", CommandParseError::EmptyCommand)]
    #[case::only_comments(
        indoc! {"
            # one
            # two
        "},
        CommandParseError::EmptyCommand,
    )]
    #[case::unclosed_quote("echo \"unterminated", CommandParseError::SyntaxError)]
    #[case::unclosed_heredoc(
        indoc! {"
            cat <<EOF
            no terminator here
        "},
        CommandParseError::SyntaxError,
    )]
    fn split_top_level_commands_errors(#[case] input: &str, #[case] expected: CommandParseError) {
        let err = split_top_level_commands(input).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&expected),
        );
    }
}
