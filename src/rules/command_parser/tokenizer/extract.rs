use crate::rules::CommandParseError;

use super::dequote::dequote_node;

/// Extract tokens from a regular `command` node: command name, then
/// each positional argument or grouping child. Skips
/// `variable_assignment` prefixes and `redirect` field children, both
/// of which are tracked elsewhere and must not appear in the token
/// stream used for pattern matching.
pub(super) fn tokens_from_command(
    command_node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Result<Vec<String>, CommandParseError> {
    let mut tokens: Vec<String> = Vec::new();
    for i in 0..command_node.child_count() {
        let Some(child) = command_node.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            continue;
        }
        if child.kind() == "variable_assignment" {
            continue;
        }
        if command_node.field_name_for_child(i as u32) == Some("redirect") {
            continue;
        }
        let token = dequote_node(child, source).ok_or(CommandParseError::SyntaxError)?;
        tokens.push(token);
    }
    Ok(tokens)
}

/// Extract tokens from a `declaration_command` (`export FOO=bar`,
/// `declare -x FOO`, `readonly FOO=bar`, `local FOO=bar`,
/// `typeset FOO`) or an `unset_command` (`unset FOO`, `unsetenv FOO`).
///
/// The leading keyword (`export`/`declare`/`readonly`/`local`/`typeset`/
/// `unset`/`unsetenv`) is an anonymous child in tree-sitter-bash but is
/// the head of the command for runok's pattern matching purposes, so
/// it's emitted as the first token. Subsequent named children are
/// emitted one token per child:
///
/// - `variable_assignment` (e.g. `FOO=bar`) is preserved as the source
///   text of the whole assignment, so `allow: 'export *'` can match
///   `["export", "FOO=bar"]`. Unlike a regular `command`, the
///   assignment here is the argument, not an environment prefix.
/// - Any other named child (`word`, `string`, `raw_string`,
///   `concatenation`, ...) goes through `dequote_node` like a regular
///   argument.
pub(super) fn tokens_from_declaration_command(
    node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Result<Vec<String>, CommandParseError> {
    let mut tokens: Vec<String> = Vec::new();
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            // The leading keyword (`export`, `declare`, ...) is an
            // anonymous child. There is exactly one anonymous child
            // per `declaration_command` / `unset_command`, and it's
            // always the first.
            if !tokens.is_empty() {
                continue;
            }
            let text = source
                .get(child.start_byte()..child.end_byte())
                .ok_or(CommandParseError::SyntaxError)?;
            let text = std::str::from_utf8(text)
                .map_err(|_| CommandParseError::SyntaxError)?
                .trim();
            if !text.is_empty() {
                tokens.push(text.to_string());
            }
            continue;
        }
        if child.kind() == "variable_assignment" {
            // Keep `KEY=VALUE` as a single token verbatim so rule
            // patterns can match the assignment shape literally.
            let text = source
                .get(child.start_byte()..child.end_byte())
                .ok_or(CommandParseError::SyntaxError)?;
            let text = std::str::from_utf8(text).map_err(|_| CommandParseError::SyntaxError)?;
            tokens.push(text.to_string());
            continue;
        }
        let token = dequote_node(child, source).ok_or(CommandParseError::SyntaxError)?;
        tokens.push(token);
    }
    Ok(tokens)
}

/// Extract tokens from a `test_command` node (`[ ... ]` or `[[ ... ]]`).
///
/// The opening (`[`/`[[`) and closing (`]`/`]]`) delimiters are
/// anonymous in tree-sitter-bash but participate in literal matching
/// (rules like `[ *` rely on `[` being a separate token). Argument
/// children — `unary_expression`, `binary_expression`, `word`,
/// `string`, etc. — are flattened into individual tokens so a pattern
/// like `[ -f * ]` can match `[ -f file ]`.
pub(super) fn tokens_from_test_command(
    node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Result<Vec<String>, CommandParseError> {
    let mut tokens: Vec<String> = Vec::new();
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if !child.is_named() {
            // The bracket delimiters are anonymous; pull their text in.
            let text = source
                .get(child.start_byte()..child.end_byte())
                .ok_or(CommandParseError::SyntaxError)?;
            let text = std::str::from_utf8(text)
                .map_err(|_| CommandParseError::SyntaxError)?
                .trim();
            if !text.is_empty() {
                tokens.push(text.to_string());
            }
            continue;
        }
        flatten_test_expression(child, source, &mut tokens)?;
    }
    Ok(tokens)
}

/// Recursively flatten a `test_command` expression subtree into its
/// individual tokens (operators and operands), so that `[ -f file ]`
/// emits `["[", "-f", "file", "]"]` regardless of how tree-sitter
/// groups the operator and operand into a `unary_expression` node.
fn flatten_test_expression(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    tokens: &mut Vec<String>,
) -> Result<(), CommandParseError> {
    match node.kind() {
        "unary_expression"
        | "binary_expression"
        | "parenthesized_expression"
        | "negated_expression" => {
            for i in 0..node.child_count() {
                let Some(child) = node.child(i as u32) else {
                    continue;
                };
                if child.is_named() {
                    flatten_test_expression(child, source, tokens)?;
                } else {
                    let text = source
                        .get(child.start_byte()..child.end_byte())
                        .ok_or(CommandParseError::SyntaxError)?;
                    let text = std::str::from_utf8(text)
                        .map_err(|_| CommandParseError::SyntaxError)?
                        .trim();
                    if !text.is_empty() {
                        tokens.push(text.to_string());
                    }
                }
            }
        }
        _ => {
            tokens.push(dequote_node(node, source).ok_or(CommandParseError::SyntaxError)?);
        }
    }
    Ok(())
}
