use crate::rules::command_parser::var_env::{VarEnv, VarValue};

use super::dequote::{dequote_node, dequote_node_with};

/// Resolve one child of a `command` node (the command name or an
/// argument position) into zero or more tokens, applying variable
/// expansion via `var_env` where possible.
///
/// A bare, unquoted, top-level `$X` / `${X}` that resolves to a tracked
/// [`VarValue::Literal`] is split on whitespace, mirroring bash's default
/// `IFS` word-splitting (an all-whitespace or empty value contributes no
/// tokens at all). Every other shape -- including a resolved expansion
/// embedded inside a quoted string or a concatenation -- yields exactly
/// one token. A `$X` / `${X}` that isn't in `var_env`, or that carries an
/// operator (`${X:-default}`), falls back to the plain verbatim token
/// exactly as [`dequote_node`] would produce.
///
/// Returns `(tokens, expanded)`, where `expanded` is `true` only when at
/// least one substitution actually happened, so callers can tell whether
/// the reconstructed command text differs from the original source.
pub(in crate::rules::command_parser) fn expand_argument_tokens(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    var_env: &VarEnv,
) -> Option<(Vec<String>, bool)> {
    match node.kind() {
        "command_name" => expand_argument_tokens(node.named_child(0)?, source, var_env),
        "simple_expansion" | "expansion" => {
            if let Some(value) = resolve_literal(node, source, var_env) {
                let tokens: Vec<String> = value.split_whitespace().map(str::to_string).collect();
                return Some((tokens, true));
            }
            Some((vec![dequote_node(node, source)?], false))
        }
        _ => {
            let verbatim = dequote_node(node, source)?;
            let resolved = dequote_node_with(node, source, Some(var_env))?;
            let expanded = resolved != verbatim;
            Some((vec![resolved], expanded))
        }
    }
}

/// Resolve a `simple_expansion` (`$X`) or bare `expansion` (`${X}`) node
/// against `var_env`, returning its literal value. Returns `None` when
/// the variable isn't tracked (absent or [`VarValue::Poisoned`]), or when
/// the expansion isn't a bare variable reference (an operator like
/// `${X:-default}`, an array subscript, a special variable like `$?`).
pub(in crate::rules::command_parser) fn resolve_literal(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    var_env: &VarEnv,
) -> Option<String> {
    let name = expansion_var_name(node, source)?;
    match var_env.get(&name) {
        Some(VarValue::Literal(value)) => Some(value.clone()),
        _ => None,
    }
}

/// Extract the variable name from a bare `simple_expansion` (`$X`) or
/// `expansion` (`${X}`) node. Returns `None` for anything that isn't a
/// plain variable reference: `expansion` nodes with an `operator` field
/// (`${X:-default}`, `${X#pattern}`, ...), or a referenced name that
/// isn't a plain `variable_name` (special variables like `$?` / `$@`,
/// array subscripts).
fn expansion_var_name(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "simple_expansion" => {
            let name_node = node.named_child(0)?;
            if name_node.kind() != "variable_name" {
                return None;
            }
            node_text(name_node, source)
        }
        "expansion" => {
            let mut name_node = None;
            for i in 0..node.child_count() {
                let child = node.child(i as u32)?;
                if node.field_name_for_child(i as u32) == Some("operator") {
                    return None;
                }
                if child.is_named() {
                    if name_node.is_some() {
                        return None;
                    }
                    name_node = Some(child);
                }
            }
            let name_node = name_node?;
            if name_node.kind() != "variable_name" {
                return None;
            }
            node_text(name_node, source)
        }
        _ => None,
    }
}

fn node_text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let bytes = source.get(node.start_byte()..node.end_byte())?;
    Some(std::str::from_utf8(bytes).ok()?.to_string())
}
