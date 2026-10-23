use super::redirect::is_quoted_heredoc;

/// Return whether a runnable shell fragment expands a variable from its shell
/// state. `None` means tree-sitter-bash could not parse the fragment safely.
pub(crate) fn contains_shell_state_expansion(fragment: &str) -> Option<bool> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .ok()?;

    let tree = parser.parse(fragment, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut found = false;
    collect_shell_state_expansions(root, fragment.as_bytes(), false, &mut found);
    Some(found)
}

fn collect_shell_state_expansions(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    inside_arithmetic_expansion: bool,
    found: &mut bool,
) {
    if *found || (node.kind() == "heredoc_redirect" && is_quoted_heredoc(node, source)) {
        return;
    }

    let inside_arithmetic_expansion =
        inside_arithmetic_expansion || node.kind() == "arithmetic_expansion";
    if matches!(node.kind(), "simple_expansion" | "expansion")
        || (inside_arithmetic_expansion && node.kind() == "variable_name")
    {
        *found = true;
        return;
    }

    for index in 0..node.child_count() {
        if let Some(child) = node.child(index as u32) {
            collect_shell_state_expansions(child, source, inside_arithmetic_expansion, found);
        }
    }
}
