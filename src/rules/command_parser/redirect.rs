use super::splitter::collect_commands;
use super::tokenizer::dequote_node;
use super::{EnvAssignment, ExtractedCommand, PipeInfo, RedirectInfo};

/// Inspect a `while_statement` node and return `"until"` if the leading
/// anonymous token is `until`, otherwise `"while"`. tree-sitter-bash uses a
/// single `while_statement` kind to represent both constructs, distinguished
/// only by which keyword leads the node.
pub(super) fn detect_while_or_until(node: tree_sitter::Node, source: &[u8]) -> &'static str {
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if child.is_named() {
            continue;
        }
        if let Some(bytes) = source.get(child.start_byte()..child.end_byte())
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            match text.trim() {
                "until" => return "until",
                "while" => return "while",
                _ => continue,
            }
        }
    }
    // Unreachable in practice: tree-sitter-bash always emits one of the
    // two keywords. Stay inside the loop sentinel set to keep callers
    // safe if the grammar shape ever shifts.
    "while"
}

/// Decode a `variable_assignment` AST node (`KEY=VALUE`,
/// `KEY="$(cmd)"`, `KEY=`) into a structured assignment.
///
/// `dequote_node` is reused for the value half so quoting is resolved
/// the same way as for argv tokens (raw strings pass through; double
/// quotes are decoded; command substitutions are kept verbatim with
/// their delimiters so a downstream consumer can still see `$(...)`).
pub(super) fn extract_env_assignment(
    node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<EnvAssignment> {
    let name_node = node.child_by_field_name("name")?;
    let name_bytes = source.get(name_node.start_byte()..name_node.end_byte())?;
    let name = std::str::from_utf8(name_bytes).ok()?.to_string();
    let value = node
        .child_by_field_name("value")
        .and_then(|v| dequote_node(v, source));
    Some(EnvAssignment { name, value })
}

/// Classify a redirect operator into "input", "output", or "dup".
fn classify_redirect(operator: &str) -> &'static str {
    match operator {
        ">" | ">>" | ">|" | "&>" | "&>>" => "output",
        "<" | "<<<" | "<<" | "<<-" => "input",
        ">&" | "<&" => "dup",
        _ => "output",
    }
}

/// Extract redirect information from a tree-sitter redirect node.
///
/// Handles `file_redirect`, `heredoc_redirect`, and `herestring_redirect` nodes.
pub(super) fn extract_redirect_info(
    node: tree_sitter::Node,
    source: &[u8],
) -> Option<RedirectInfo> {
    match node.kind() {
        "file_redirect" => {
            // Extract the operator from anonymous children
            let mut operator = String::new();
            let mut descriptor: Option<i64> = None;
            let mut target = String::new();

            for i in 0..node.child_count() {
                let child = node.child(i as u32)?;
                if child.kind() == "file_descriptor" {
                    let bytes = source.get(child.start_byte()..child.end_byte())?;
                    let text = std::str::from_utf8(bytes).ok()?;
                    descriptor = text.parse::<i64>().ok();
                } else if !child.is_named() {
                    // Anonymous node = operator token (>, >>, <, >&, <&, &>, &>>, >|)
                    let bytes = source.get(child.start_byte()..child.end_byte())?;
                    let text = std::str::from_utf8(bytes).ok()?;
                    operator = text.to_string();
                } else if node.field_name_for_child(i as u32) == Some("destination") {
                    let bytes = source.get(child.start_byte()..child.end_byte())?;
                    let text = std::str::from_utf8(bytes).ok()?;
                    target = text.to_string();
                }
            }

            if operator.is_empty() {
                return None;
            }

            Some(RedirectInfo {
                redirect_type: classify_redirect(&operator).to_string(),
                operator,
                target,
                descriptor,
            })
        }
        "herestring_redirect" => {
            // <<< 'content'
            let mut target = String::new();
            for i in 0..node.child_count() {
                let child = node.child(i as u32)?;
                if child.is_named() {
                    let bytes = source.get(child.start_byte()..child.end_byte())?;
                    let text = std::str::from_utf8(bytes).ok()?;
                    target = text.to_string();
                    break;
                }
            }
            Some(RedirectInfo {
                redirect_type: "input".to_string(),
                operator: "<<<".to_string(),
                target,
                descriptor: None,
            })
        }
        "heredoc_redirect" => {
            // << or <<-
            let mut operator = "<<".to_string();
            for i in 0..node.child_count() {
                let child = node.child(i as u32)?;
                if !child.is_named() {
                    let bytes = source.get(child.start_byte()..child.end_byte())?;
                    let text = std::str::from_utf8(bytes).ok()?;
                    if text == "<<-" || text == "<<" {
                        operator = text.to_string();
                    }
                }
            }
            Some(RedirectInfo {
                redirect_type: "input".to_string(),
                operator,
                target: String::new(),
                descriptor: None,
            })
        }
        _ => None,
    }
}

/// What follows the `<<DELIM` / `<<-DELIM` part of a `heredoc_redirect`,
/// when tree-sitter-bash has folded a trailing pipeline / `&&` / `||`
/// arm into the redirect's children.
///
/// `pipe_stages` are commands that join the body in the synthesized
/// outer pipeline (`body | pipe_stages[0] | pipe_stages[1] | ...`).
/// `list_arms` are statements joined to that pipeline by `&&` / `||`,
/// with no pipe relationship to the body — `collect_commands` is
/// responsible for re-deriving their internal pipe metadata.
///
/// `cat <<EOF && x` / `cat <<EOF || x` populates `list_arms` only.
/// `cat <<EOF | a | b` populates `pipe_stages` only.
/// `cat <<EOF | a | b && c || d` populates both: pipe_stages = [a, b],
/// list_arms = [c, d]. Bash's `|` > `&&` precedence means `a | b` is
/// the pipe target and `c` / `d` are independent.
///
/// `;` / `&` after a heredoc and two heredocs in one pipeline are
/// known tree-sitter-bash 0.25.1 parse errors — they never reach this
/// helper; the caller surfaces them as `SyntaxError` upstream.
pub(super) struct HeredocContinuation<'tree> {
    pub(super) pipe_stages: Vec<tree_sitter::Node<'tree>>,
    pub(super) list_arms: Vec<tree_sitter::Node<'tree>>,
}

impl<'tree> HeredocContinuation<'tree> {
    fn is_empty(&self) -> bool {
        self.pipe_stages.is_empty() && self.list_arms.is_empty()
    }
}

/// Inspect a `redirected_statement` for a "swallowed" trailing arm of
/// a pipeline / `&&` / `||` that tree-sitter-bash mis-attaches as a
/// child of the inner `heredoc_redirect`.
///
/// Returns `None` when the redirected statement has no heredoc
/// continuation — i.e. for the well-formed cases that already worked
/// (no heredoc, heredoc with no trailing operator, heredoc on the
/// right of a pipe).
pub(super) fn find_heredoc_continuation<'tree>(
    redirected_statement: tree_sitter::Node<'tree>,
) -> Option<HeredocContinuation<'tree>> {
    for i in 0..redirected_statement.child_count() {
        if redirected_statement.field_name_for_child(i as u32) != Some("redirect") {
            continue;
        }
        let Some(child) = redirected_statement.child(i as u32) else {
            continue;
        };
        if child.kind() != "heredoc_redirect" {
            continue;
        }
        let cont = extract_heredoc_continuation(child);
        if cont.is_empty() {
            return None;
        }
        return Some(cont);
    }
    None
}

/// Walk a `heredoc_redirect` node and split its trailing arm into
/// pipe stages and list arms.
///
/// `&&` / `||` on the heredoc directly (no preceding `|`) populates
/// `list_arms` via the `right` field. `|` populates an un-fielded
/// `pipeline` child whose stages may themselves contain a `list`
/// (from a `&& x` / `|| y` continuation): bash's `|` > `&&` precedence
/// means the list's leftmost descendant is the actual pipe target,
/// and subsequent list operands are independent arms.
fn extract_heredoc_continuation<'tree>(
    heredoc: tree_sitter::Node<'tree>,
) -> HeredocContinuation<'tree> {
    let mut pipe_stages: Vec<tree_sitter::Node<'tree>> = Vec::new();
    let mut list_arms: Vec<tree_sitter::Node<'tree>> = Vec::new();

    for i in 0..heredoc.child_count() {
        let Some(child) = heredoc.child(i as u32) else {
            continue;
        };
        let field = heredoc.field_name_for_child(i as u32);
        if field == Some("right") {
            list_arms.push(child);
        } else if field.is_none() && child.kind() == "pipeline" {
            let mut cursor = child.walk();
            for stage in child.named_children(&mut cursor) {
                split_pipe_stage(stage, &mut pipe_stages, &mut list_arms);
            }
        }
    }

    HeredocContinuation {
        pipe_stages,
        list_arms,
    }
}

/// Walk a pipeline-stage node, classifying it as either a real pipe
/// stage or a `list` whose first element extends the pipe and whose
/// remaining operands are list arms.
fn split_pipe_stage<'tree>(
    node: tree_sitter::Node<'tree>,
    pipe_stages: &mut Vec<tree_sitter::Node<'tree>>,
    list_arms: &mut Vec<tree_sitter::Node<'tree>>,
) {
    if node.kind() != "list" {
        pipe_stages.push(node);
        return;
    }
    let mut cursor = node.walk();
    let mut named_iter = node.named_children(&mut cursor);
    let Some(first) = named_iter.next() else {
        return;
    };
    // `list` is left-recursive in tree-sitter-bash, so the first
    // named child is itself the deeper continuation of the pipe.
    split_pipe_stage(first, pipe_stages, list_arms);
    for arm in named_iter {
        list_arms.push(arm);
    }
}

/// Like `collect_substitutions_recursive`, but tailored for an
/// unquoted `heredoc_redirect`: skip swallowed pipeline / `right`-field
/// children (those have already been emitted as proper sub-commands by
/// the caller) and only scan the actual `heredoc_body` for `$(...)` /
/// `` `...` `` substitutions.
pub(super) fn collect_heredoc_redirect_substitutions(
    heredoc: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
) {
    for i in 0..heredoc.child_count() {
        let Some(child) = heredoc.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            continue;
        }
        // Already emitted via the continuation handling.
        if child.kind() == "pipeline" {
            continue;
        }
        if heredoc.field_name_for_child(i as u32) == Some("right") {
            continue;
        }
        collect_substitutions_recursive(child, source, commands);
    }
}

/// Check whether a `heredoc_redirect` node uses a quoted delimiter.
///
/// Bash treats the HEREDOC body as literal whenever **any** part of
/// the delimiter is quoted — `<<'EOF'`, `<<"EOF"`, `<<\EOF`,
/// `<<EO'F'`, and `<<E\OF` all disable `$VAR` / `$(...)` / `` `...` ``
/// expansion inside the body. Detect that by scanning the
/// `heredoc_start` text for any `'`, `"`, or `\`. Identifiers used as
/// HEREDOC delimiters cannot legally contain those characters, so
/// finding one is unambiguous evidence that the delimiter is
/// (partially) quoted.
pub(super) fn is_quoted_heredoc(heredoc_redirect: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    for i in 0..heredoc_redirect.child_count() {
        let Some(child) = heredoc_redirect.child(i as u32) else {
            continue;
        };
        if child.kind() != "heredoc_start" {
            continue;
        }
        let Some(text) = source.get(child.start_byte()..child.end_byte()) else {
            return false;
        };
        return text.iter().any(|&b| matches!(b, b'\'' | b'"' | b'\\'));
    }
    false
}

/// Recursively walk a subtree to find `command_substitution` and
/// `process_substitution` nodes, then hand them off to `collect_commands`.
/// Used by `variable_assignment` to reach substitutions nested inside
/// `string` nodes (e.g. `X="$(cmd)"`).
pub(super) fn collect_substitutions_recursive(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            // Substitutions reached through this helper appear in
            // for-value lists, case-pattern values, or variable
            // assignments — all of which run outside any enclosing
            // loop body, so loop_kind resets to "".
            "command_substitution" | "process_substitution" => {
                collect_commands(child, source, commands, &PipeInfo::default(), &[], "");
            }
            _ => {
                collect_substitutions_recursive(child, source, commands);
            }
        }
    }
}
