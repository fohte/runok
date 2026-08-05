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
pub(super) fn strip_misparsed_compound_prefix(input: &str) -> Option<&str> {
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

/// Whether `node` is a `command` node produced by the tree-sitter-bash
/// 0.25.1 misparse of a bare `assignment redirect` prefix with no
/// command name -- e.g. `TS=foo 2>/dev/null`. This is a complete,
/// valid POSIX simple command (both `bash -n` and `zsh -n` accept it),
/// but the `command` grammar rule requires a `command_name`, so
/// tree-sitter produces one of two malformed shapes instead of a clean
/// parse:
///
/// - **Terminal**: nothing follows the assignment(s)/redirect(s) (or
///   what follows can't continue as a command name, e.g. a keyword
///   like `fi`). tree-sitter emits a `command_name` field whose sole
///   child is a zero-width MISSING `word`, with no `ERROR` child:
///   `TS=foo 2>/dev/null` parses as `(command (variable_assignment ...)
///   redirect: (file_redirect ...) name: (command_name (MISSING word)))`.
/// - **Swallowed continuation**: the assignment/redirect is immediately
///   followed by a statement/pipe separator (`;`, `&`, `&&`, `||`, `|`)
///   and then a real statement. tree-sitter recovers by inserting an
///   `ERROR` node for the separator and folding the *next* statement's
///   tokens into the *same* malformed node's `name`/`argument` fields:
///   `TS=foo 2>/dev/null; echo hi` parses as `(command
///   (variable_assignment ...) redirect: (...) (ERROR) name:
///   (command_name (word)) argument: (word))` -- two logically separate
///   statements folded into one AST node. Chained bare assignments
///   before the real tail repeat the same
///   `variable_assignment`/`redirect`/`ERROR` group.
///
/// A well-formed command that happens to carry both an assignment and a
/// redirect (`FOO=bar cat <<< hello`) has a real, non-missing
/// `command_name` and no `ERROR` child, so it matches neither shape. A
/// genuinely dangling operator with nothing after it (`TS=foo
/// 2>/dev/null &&`) gets swallowed into the *enclosing* `ERROR` node
/// instead of staying inside a `command` node, so it never reaches this
/// function as a `command` kind at all -- it stays a real
/// `SyntaxError` via [`all_errors_explained`].
pub(super) fn is_assignment_redirect_misparse(node: tree_sitter::Node) -> bool {
    if node.kind() != "command" {
        return false;
    }
    let mut has_assignment = false;
    let mut has_redirect = false;
    let mut has_error = false;
    let mut name_field_missing: Option<bool> = None;
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if node.field_name_for_child(i as u32) == Some("redirect") {
            has_redirect = true;
            continue;
        }
        if !child.is_named() {
            continue;
        }
        match child.kind() {
            "variable_assignment" => has_assignment = true,
            _ if child.is_error() => has_error = true,
            _ if node.field_name_for_child(i as u32) == Some("name") => {
                name_field_missing = Some(child.child(0).is_some_and(|c| c.is_missing()));
            }
            _ => {}
        }
    }
    has_assignment
        && has_redirect
        && matches!(
            (has_error, name_field_missing),
            (false, Some(true)) | (true, Some(false))
        )
}

/// Whether every `ERROR`/MISSING node anywhere in `root`'s subtree is
/// explained by [`is_assignment_redirect_misparse`] on its enclosing
/// `command` node, so callers can walk the tree instead of bailing out
/// with `SyntaxError`. Doesn't affect nodes already handled by
/// [`strip_misparsed_compound_prefix`] -- that workaround runs as a
/// separate text-level pre-pass before the tree checked here is even
/// parsed.
pub(super) fn all_errors_explained(node: tree_sitter::Node) -> bool {
    if node.is_error() {
        return node.parent().is_some_and(is_assignment_redirect_misparse);
    }
    if node.is_missing() {
        return node.kind() == "word"
            && node.parent().is_some_and(|p| p.kind() == "command_name")
            && node
                .parent()
                .and_then(|p| p.parent())
                .is_some_and(is_assignment_redirect_misparse);
    }
    for i in 0..node.child_count() {
        let Some(child) = node.child(i as u32) else {
            continue;
        };
        if !all_errors_explained(child) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    /// Depth-first search for the first node of `kind` in the tree.
    fn find_first<'a>(node: tree_sitter::Node<'a>, kind: &str) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        for i in 0..node.child_count() {
            let child = node.child(i as u32)?;
            if let Some(found) = find_first(child, kind) {
                return Some(found);
            }
        }
        None
    }

    #[rstest]
    #[case::terminal("TS=foo 2>/dev/null", true)]
    #[case::swallowed_semicolon("TS=foo 2>/dev/null; echo hi", true)]
    #[case::chained_double_assignment_swallow(
        "TS=foo 2>/dev/null; TS2=bar 2>/dev/null; echo hi",
        true
    )]
    #[case::swallowed_pipe("TS=foo 2>/dev/null | cat", true)]
    #[case::swallowed_and("TS=foo 2>/dev/null && echo hi", true)]
    #[case::swallowed_or("TS=foo 2>/dev/null || echo hi", true)]
    #[case::swallowed_ampersand("TS=foo 2>/dev/null & echo hi", true)]
    #[case::well_formed_assignment_and_redirect_not_triggered("FOO=bar cat <<< hello", false)]
    fn is_assignment_redirect_misparse_cases(#[case] input: &str, #[case] expected: bool) {
        let tree = parse(input);
        let command = find_first(tree.root_node(), "command").expect("input has a `command` node");
        assert_eq!(is_assignment_redirect_misparse(command), expected);
    }

    #[rstest]
    #[case::terminal("TS=foo 2>/dev/null", true)]
    #[case::swallowed_semicolon("TS=foo 2>/dev/null; echo hi", true)]
    #[case::chained_double_assignment_swallow(
        "TS=foo 2>/dev/null; TS2=bar 2>/dev/null; echo hi",
        true
    )]
    #[case::swallowed_pipe("TS=foo 2>/dev/null | cat", true)]
    #[case::swallowed_and("TS=foo 2>/dev/null && echo hi", true)]
    #[case::swallowed_or("TS=foo 2>/dev/null || echo hi", true)]
    #[case::swallowed_ampersand("TS=foo 2>/dev/null & echo hi", true)]
    #[case::env_prefix_command_unaffected("FOO=bar echo hi 2>&1", true)]
    #[case::dangling_and_with_nothing_after_stays_syntax_error("TS=foo 2>/dev/null &&", false)]
    fn all_errors_explained_cases(#[case] input: &str, #[case] expected: bool) {
        let tree = parse(input);
        assert_eq!(all_errors_explained(tree.root_node()), expected);
    }
}
