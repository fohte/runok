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
