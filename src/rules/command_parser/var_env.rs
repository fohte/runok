use std::collections::HashMap;

use super::tokenizer::dequote_node;

/// Tracks shell variable assignments seen so far while walking a single
/// command string, so that a later `$X` / `${X}` expansion can resolve to
/// a statically known value.
///
/// Scoped to one [`super::extract_commands_with_metadata`] call: a fresh
/// `VarEnv` is created per top-level parse and never persisted across
/// separate command strings.
#[derive(Debug, Default)]
pub(in crate::rules::command_parser) struct VarEnv {
    values: HashMap<String, VarValue>,
}

/// The state tracked for a single variable name.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::rules::command_parser) enum VarValue {
    /// A statically known value.
    Literal(String),
    /// Assigned, but not statically resolvable (a dynamic value, an
    /// array-element assignment, or a reassignment inside a conditional
    /// or loop body). Once poisoned, a name stays poisoned for the rest
    /// of the walk -- this prevents a stale `Literal` recorded before a
    /// dynamic reassignment (`X=1; X=$(date); $X`) from being reused.
    Poisoned,
}

impl VarEnv {
    pub(in crate::rules::command_parser) fn new() -> Self {
        Self::default()
    }

    pub(in crate::rules::command_parser) fn get(&self, name: &str) -> Option<&VarValue> {
        self.values.get(name)
    }

    fn set_literal(&mut self, name: String, value: String) {
        self.values.insert(name, VarValue::Literal(value));
    }

    pub(in crate::rules::command_parser) fn poison(&mut self, name: String) {
        self.values.insert(name, VarValue::Poisoned);
    }
}

/// Record a top-level `variable_assignment` node (`X=1`) or a
/// `variable_assignment` child of a `declaration_command`
/// (`export X=1`) into `var_env`.
///
/// `poison` forces the assignment to be recorded as
/// [`VarValue::Poisoned`] regardless of whether the value itself is
/// static -- used when the assignment sits inside a conditional or loop
/// body, where it may run zero, one, or many times.
pub(in crate::rules::command_parser) fn record_variable_assignment(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    var_env: &mut VarEnv,
    poison: bool,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    // Array-element assignment (`arr[0]=x`): not a scalar Literal, and it
    // also invalidates any scalar Literal already recorded for `arr`, so
    // poison the base name rather than leaving it untouched.
    if name_node.kind() == "subscript" {
        if let Some(base) = name_node
            .child_by_field_name("name")
            .and_then(|n| node_text(n, source))
        {
            var_env.poison(base);
        }
        return;
    }

    if name_node.kind() != "variable_name" {
        return;
    }
    let Some(name) = node_text(name_node, source) else {
        return;
    };

    if poison {
        var_env.poison(name);
        return;
    }

    // No `value` field means the bare `X=` form (bash assigns the empty
    // string), which is still a well-defined static value.
    let literal = match node.child_by_field_name("value") {
        Some(value_node) => static_value(value_node, source),
        None => Some(String::new()),
    };

    match literal {
        Some(value) => var_env.set_literal(name, value),
        None => var_env.poison(name),
    }
}

/// Record a bare identifier argument of a `declaration_command`
/// (`export FOO`) or `unset_command` (`unset FOO`) as
/// [`VarValue::Poisoned`]: the current value (for a bare `export`) or
/// the absence of one (for `unset`) is not statically known.
pub(in crate::rules::command_parser) fn poison_bare_name(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    var_env: &mut VarEnv,
) {
    if let Some(name) = node_text(node, source) {
        var_env.poison(name);
    }
}

/// Whether `node` (a `variable_assignment`'s `value` field, or a piece
/// of a `concatenation`) is one of the static shapes runok can resolve
/// without executing anything: a bare word, a raw (single-quoted)
/// string, a double-quoted string with no interpolation, or a
/// concatenation of those. Command substitutions, backticks, process
/// substitutions, arithmetic expansions, and variable expansions all
/// return `None` (not statically resolvable).
fn static_value(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "word" | "raw_string" => dequote_node(node, source),
        "string" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "string_content" {
                    return None;
                }
            }
            dequote_node(node, source)
        }
        "concatenation" => {
            let mut out = String::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                out.push_str(&static_value(child, source)?);
            }
            Some(out)
        }
        _ => None,
    }
}

fn node_text(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let bytes = source.get(node.start_byte()..node.end_byte())?;
    Some(std::str::from_utf8(bytes).ok()?.to_string())
}
