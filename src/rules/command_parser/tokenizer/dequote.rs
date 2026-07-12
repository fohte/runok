use crate::rules::command_parser::var_env::VarEnv;

use super::expand::resolve_literal;

/// Decode a tree-sitter-bash argument node into the literal token value
/// shell semantics would produce, with one exception: shell groupings
/// (`subshell`, `command_substitution`, `process_substitution`) are
/// preserved verbatim with their delimiters so wrapper-pattern matching
/// can capture them as a single placeholder token.
///
/// Specifically:
/// - `string` (double-quoted): surrounding `"` are dropped, double-quote
///   escape sequences (`\\`, `\"`, `\$`, `` \` ``, line continuation
///   `\<newline>`) are processed; unknown escapes preserve the backslash
///   to match shell behaviour. Interpolations (`$X`, `${X}`, `$(...)`,
///   `` `...` ``) are kept as their source text, since runok matches
///   tokens literally and the inner commands have already been extracted
///   for separate evaluation by `collect_commands`.
/// - `raw_string` (single-quoted): outer `'` are dropped, contents are
///   passed through verbatim (no escape processing).
/// - `concatenation`: each child piece is decoded and concatenated into
///   one token (e.g. `"a"'b'c` → `abc`).
/// - `ansi_c_string`/`translated_string`: kept verbatim with delimiters.
///   runok does not need to interpret ANSI-C escapes for matching.
/// - `subshell`/`command_substitution`/`process_substitution`: kept
///   verbatim with delimiters.
/// - Other leaf-like nodes (`command_name`, `word`, `number`,
///   `simple_expansion`, `expansion`, ...): kept verbatim.
pub(in crate::rules::command_parser) fn dequote_node(
    node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<String> {
    dequote_node_with(node, source, None)
}

/// Like [`dequote_node`], but when `var_env` is given, a bare `$X` /
/// `${X}` — whether it is the whole node or an interpolation nested
/// inside a `string` / `concatenation` — resolves to its tracked literal
/// value instead of staying verbatim. Passing `None` reproduces
/// [`dequote_node`] exactly.
pub(in crate::rules::command_parser) fn dequote_node_with(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    var_env: Option<&VarEnv>,
) -> Option<String> {
    match node.kind() {
        // Shell groupings: keep the whole node text including delimiters
        // so wrapper patterns can capture them as a single token.
        "subshell" | "command_substitution" | "process_substitution" => {
            let text = source.get(node.start_byte()..node.end_byte())?;
            Some(std::str::from_utf8(text).ok()?.to_string())
        }
        // Double-quoted: walk children, drop the anonymous `"` boundary
        // tokens, decode `string_content` (with shell escape rules), and
        // pass interpolation children through verbatim (or resolved,
        // when `var_env` is given and the interpolation is a bare
        // variable reference).
        "string" => {
            let mut out = String::new();
            for i in 0..node.child_count() {
                let child = node.child(i as u32)?;
                if !child.is_named() {
                    // Anonymous children of `string` are the surrounding
                    // `"` quotes; skip them.
                    continue;
                }
                if child.kind() == "string_content" {
                    let text = source.get(child.start_byte()..child.end_byte())?;
                    let text = std::str::from_utf8(text).ok()?;
                    out.push_str(&decode_double_quote_escapes(text));
                } else if let Some(value) =
                    var_env.and_then(|env| resolve_literal(child, source, env))
                {
                    out.push_str(&value);
                } else {
                    // Interpolations stay as source text so wrapper
                    // patterns like `bash -c <cmd>` see `$(secret)`
                    // intact; the inner commands are already extracted
                    // for separate evaluation by `collect_commands`.
                    let text = source.get(child.start_byte()..child.end_byte())?;
                    out.push_str(std::str::from_utf8(text).ok()?);
                }
            }
            Some(out)
        }
        // Single-quoted: strip the outer `'` and pass contents through.
        "raw_string" => {
            let text = source.get(node.start_byte()..node.end_byte())?;
            let text = std::str::from_utf8(text).ok()?;
            // `raw_string` is always `'...'`; a 2-byte node is `''`.
            let inner = text
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(text);
            Some(inner.to_string())
        }
        // Adjacent quoted/unquoted pieces (`"a"'b'c`) glue into one token.
        "concatenation" => {
            let mut out = String::new();
            for i in 0..node.child_count() {
                let child = node.child(i as u32)?;
                if !child.is_named() {
                    continue;
                }
                out.push_str(&dequote_node_with(child, source, var_env)?);
            }
            Some(out)
        }
        // ANSI-C strings (`$'...'`) and translated strings (`$"..."`)
        // are kept verbatim: runok does not interpret them, and shell
        // rules treat them as one word.
        "ansi_c_string" | "translated_string" => {
            let text = source.get(node.start_byte()..node.end_byte())?;
            Some(std::str::from_utf8(text).ok()?.to_string())
        }
        // `word` covers unquoted argument tokens, including those
        // that absorbed backslash-escaped whitespace at the parser
        // level (`hello\ world` becomes one `word`). Apply the shell
        // outside-quote escape rule — `\<c>` reduces to `<c>`,
        // `\<newline>` is line continuation — so that adjacent
        // literal characters look the way bash would tokenise them
        // (`'it'\''s'` → `it's`).
        "word" => {
            let text = source.get(node.start_byte()..node.end_byte())?;
            let text = std::str::from_utf8(text).ok()?;
            Some(decode_unquoted_escapes(text))
        }
        // `command_name` wraps the first word of a command. It always
        // has exactly one named child holding the actual content
        // (`word`, `string`, `raw_string`, `concatenation`, ...), so
        // recurse into that child to keep the same dequoting rules
        // that apply to argument tokens. Without this, a quoted
        // command name like `"echo" hello` or `'rm' -rf /` would come
        // back with the surrounding quotes still attached, breaking
        // pattern matching against `echo *` / `rm *`.
        "command_name" => dequote_node_with(node.named_child(0)?, source, var_env),
        // `simple_expansion` (`$X`) / `expansion` (`${X}`): resolve to
        // the tracked literal value when `var_env` is given and the
        // reference is a bare variable (no operator, no array
        // subscript); otherwise fall through to the verbatim leaf case.
        "simple_expansion" | "expansion" => {
            if let Some(value) = var_env.and_then(|env| resolve_literal(node, source, env)) {
                return Some(value);
            }
            let text = source.get(node.start_byte()..node.end_byte())?;
            Some(std::str::from_utf8(text).ok()?.to_string())
        }
        // Other leaf-like nodes (`number`, ...): take the raw source
        // text. runok matches tokens literally, so no further
        // processing is needed.
        _ => {
            let text = source.get(node.start_byte()..node.end_byte())?;
            Some(std::str::from_utf8(text).ok()?.to_string())
        }
    }
}

/// Apply the shell's outside-quote backslash-escape rules:
/// - `\<c>` reduces to `<c>` (a literal character).
/// - `\<newline>` is a line continuation and disappears.
/// - A trailing `\` with no following character is dropped.
fn decode_unquoted_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\n') => {} // line continuation
            Some(other) => out.push(other),
            None => {} // trailing backslash dropped
        }
    }
    out
}

/// Apply the shell's double-quote backslash-escape rules to the text
/// inside a `string_content` node:
/// - `\\`, `\"`, `\$`, `` \` `` reduce to the second character.
/// - `\<newline>` is a line continuation and disappears.
/// - Any other `\<c>` keeps the backslash, matching `bash`.
fn decode_double_quote_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(next @ ('\\' | '"' | '$' | '`')) => out.push(next),
            Some('\n') => {} // line continuation
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}
