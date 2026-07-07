use std::collections::HashMap;

use crate::rules::CommandParseError;

use super::{FlagSchema, ParsedCommand};

/// Parse a command string into a structured `ParsedCommand`.
///
/// Uses `FlagSchema` to determine whether a flag consumes the next token
/// as its value. Unknown flags are treated as boolean (no value).
/// Tokens containing `=` (e.g., `-Denv=prod`, `--word-diff=color`) are
/// split into flag name and value at the first `=`.
///
/// Combined short flags (`-am`) are not split into individual flags.
/// Rules match tokens literally ("What You See Is How It Parses"),
/// so `-m` in a rule won't match `-am` in the input.
///
/// Tokenization is performed by walking the tree-sitter-bash AST. Shell
/// groupings (`(subshell)`, `$(command substitution)`, `` `...` ``) are
/// kept as single tokens with their delimiters intact, so wrapper
/// patterns like `time <cmd>` capture the whole grouping. Quoted
/// arguments come back with the surrounding quotes stripped and shell
/// double-quote escapes resolved.
///
/// Returns `SyntaxError` if tree-sitter-bash cannot parse the input as a
/// single top-level command (pipelines, `&&`/`||`/`;`, control
/// structures, parse errors) — those inputs are expected to be split
/// upstream by [`extract_commands_with_metadata`](super::extract_commands_with_metadata).
pub fn parse_command(input: &str, schema: &FlagSchema) -> Result<ParsedCommand, CommandParseError> {
    let raw_tokens = tokenize_command(input)?;
    let command = raw_tokens[0].clone();

    let mut flags = HashMap::new();
    let mut args = Vec::new();
    let mut i = 1;

    while i < raw_tokens.len() {
        let token = &raw_tokens[i];

        if let Some(eq_pos) = token.find('=') {
            // Handle `=`-joined flags like `-Denv=prod` or `--word-diff=color`
            let flag_part = &token[..eq_pos];
            if flag_part.starts_with('-') {
                let value_part = &token[eq_pos + 1..];
                flags.insert(flag_part.to_string(), Some(value_part.to_string()));
                i += 1;
                continue;
            }
        }

        if token.starts_with('-') {
            if schema.value_flags.contains(token.as_str()) {
                // Flag takes a value: consume the next token
                let value = raw_tokens.get(i + 1).cloned();
                flags.insert(token.clone(), value);
                i += 2;
            } else {
                // Boolean flag (no value)
                flags.insert(token.clone(), None);
                i += 1;
            }
        } else {
            args.push(token.clone());
            i += 1;
        }
    }

    Ok(ParsedCommand {
        command,
        flags,
        args,
        raw_tokens,
    })
}

/// Tokenize a command string into a list of raw tokens by walking the
/// tree-sitter-bash AST.
///
/// Each named child of the top-level `command` (or `test_command`) node
/// becomes one token, with shell quoting resolved (a
/// `string`/`raw_string`/`concatenation` argument comes out without its
/// surrounding quotes; double-quote escapes for `\\`, `\"`, `\$`,
/// `` \` ``, line continuation `\<newline>` are processed) but
/// groupings (`(subshell)`, `$(command substitution)`, `` `...` ``,
/// `<(...)`/`>(...)`) preserved verbatim with their delimiters intact,
/// so wrapper patterns like `time <cmd>` see them as a single token.
/// Prefix `variable_assignment`s (`FOO=bar cmd`) and `redirect` fields
/// are skipped — they are tracked as redirect metadata or stripped
/// upstream and do not participate in flag/arg matching.
///
/// When tree-sitter-bash cannot make sense of the input (e.g. flag
/// values containing unbalanced shell metacharacters like
/// `-f query=mutation{...}` for `gh api graphql`), falls back to
/// `shlex::split` for a POSIX-style word split. This keeps real-world
/// command inputs working without dragging back the previous
/// character-level tokenizer that was easily fooled by HEREDOC bodies.
///
/// Returns:
/// - `EmptyCommand` for empty / whitespace-only input.
/// - `SyntaxError` when neither tree-sitter-bash nor `shlex` can
///   produce a token stream (e.g. truly unclosed quotes, pipelines /
///   lists / control flow that callers were expected to split first).
pub fn tokenize_command(input: &str) -> Result<Vec<String>, CommandParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    match tokenize_via_ast(trimmed) {
        AstTokenizeOutcome::Tokens(tokens) => Ok(tokens),
        AstTokenizeOutcome::ParseError => {
            // Fallback: tree-sitter-bash gave up on this input (most
            // often because a flag value contains shell metacharacters
            // that aren't quoted in a way bash itself would accept,
            // e.g. `gh api graphql -f query=mutation{createIssue(...)}`).
            // `shlex::split` gives us POSIX word-split semantics without
            // the original tokenizer's habit of mis-reading literal
            // HEREDOC bodies as live shell.
            if let Some(tokens) = shlex::split(trimmed)
                && !tokens.is_empty()
            {
                return Ok(tokens);
            }
            Err(CommandParseError::SyntaxError)
        }
        AstTokenizeOutcome::NotASingleCommand => Err(CommandParseError::SyntaxError),
    }
}

/// Outcome of trying to tokenise `input` via tree-sitter-bash. We
/// distinguish "tree-sitter parsed it but it isn't a single command"
/// (pipelines, `&&`, control flow — callers should have split it
/// first) from "tree-sitter couldn't parse it at all" (where a relaxed
/// shlex fallback is the right move). Without this split the fallback
/// would silently swallow pipelines and feed `["ls", "|", "tail"]`
/// into pattern matching as if they were a single command.
enum AstTokenizeOutcome {
    Tokens(Vec<String>),
    ParseError,
    NotASingleCommand,
}

/// Walk `input` with tree-sitter-bash and classify the outcome:
/// - `Tokens(...)` if it resolves to a single top-level `command` or
///   `test_command` (possibly wrapped in
///   `program`/`list`/`redirected_statement`).
/// - `NotASingleCommand` if tree-sitter parsed it cleanly but the
///   result is something else (pipeline, list, control flow). Those
///   should have been split upstream.
/// - `ParseError` if tree-sitter could not parse the input at all
///   (treated as a candidate for the shlex fallback).
fn tokenize_via_ast(input: &str) -> AstTokenizeOutcome {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return AstTokenizeOutcome::ParseError;
    }
    let Some(tree) = parser.parse(input, None) else {
        return AstTokenizeOutcome::ParseError;
    };
    let root = tree.root_node();
    if root.has_error() {
        return AstTokenizeOutcome::ParseError;
    }

    let Some(command_node) = find_single_command_node(root) else {
        return AstTokenizeOutcome::NotASingleCommand;
    };
    let source = input.as_bytes();

    let tokens_result = match command_node.kind() {
        "test_command" => tokens_from_test_command(command_node, source),
        "declaration_command" | "unset_command" => {
            tokens_from_declaration_command(command_node, source)
        }
        _ => tokens_from_command(command_node, source),
    };

    match tokens_result {
        Ok(tokens) if !tokens.is_empty() => AstTokenizeOutcome::Tokens(tokens),
        _ => AstTokenizeOutcome::NotASingleCommand,
    }
}

/// Extract tokens from a regular `command` node: command name, then
/// each positional argument or grouping child. Skips
/// `variable_assignment` prefixes and `redirect` field children, both
/// of which are tracked elsewhere and must not appear in the token
/// stream used for pattern matching.
fn tokens_from_command(
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
fn tokens_from_declaration_command(
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
fn tokens_from_test_command(
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
pub(super) fn dequote_node(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        // Shell groupings: keep the whole node text including delimiters
        // so wrapper patterns can capture them as a single token.
        "subshell" | "command_substitution" | "process_substitution" => {
            let text = source.get(node.start_byte()..node.end_byte())?;
            Some(std::str::from_utf8(text).ok()?.to_string())
        }
        // Double-quoted: walk children, drop the anonymous `"` boundary
        // tokens, decode `string_content` (with shell escape rules), and
        // pass interpolation children through verbatim.
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
                out.push_str(&dequote_node(child, source)?);
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
        "command_name" => dequote_node(node.named_child(0)?, source),
        // Other leaf-like nodes (`number`, `simple_expansion`,
        // `expansion`, ...): take the raw source text. runok matches
        // tokens literally, so no further processing is needed.
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

/// Descend through transparent containers (`program`, `list`,
/// `redirected_statement`) looking for a single `command` node.
///
/// Distinguishes "a command, possibly wrapped in a few pass-through
/// nodes" from "anything more structured" (pipelines, `&&`/`||`/`;`,
/// control flow). Only the former is a valid input for [`tokenize_command`];
/// for everything else callers must split first via
/// [`extract_commands_with_metadata`](super::extract_commands_with_metadata).
fn find_single_command_node(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    match node.kind() {
        // A regular shell command (`echo hello`, `git -C foo log`, ...).
        "command" => Some(node),
        // A bracket test command (`[ -f file ]`, `[[ -f file ]]`).
        // runok matches these with literal `[`/`]` tokens, so they
        // need to flow through tokenisation just like a `command`.
        "test_command" => Some(node),
        // Shell builtins that tree-sitter-bash parses as their own
        // node kinds: `declare`/`typeset`/`export`/`readonly`/`local`
        // are `declaration_command`, and `unset`/`unsetenv` are
        // `unset_command`. Users want to allowlist these (e.g.
        // `allow: 'export *'`), so they need to flow through
        // tokenisation like a regular `command`.
        "declaration_command" | "unset_command" => Some(node),
        "program" | "list" => {
            let mut cursor = node.walk();
            let named: Vec<_> = node.named_children(&mut cursor).collect();
            if named.len() != 1 {
                return None;
            }
            find_single_command_node(named[0])
        }
        "redirected_statement" => {
            let body = node.child_by_field_name("body")?;
            find_single_command_node(body)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use rstest::rstest;

    // ========================================
    // tokenize_command: simple commands
    // ========================================

    #[rstest]
    #[case::single_arg("echo hello", vec!["echo", "hello"])]
    #[case::no_args("git status", vec!["git", "status"])]
    #[case::flags_and_path("ls -la /tmp", vec!["ls", "-la", "/tmp"])]
    #[case::single_word("ls", vec!["ls"])]
    // Quoted command names must come back without their quotes — bash
    // treats `"echo"` and `echo` identically as command names, and
    // runok rules like `echo *` should match either form.
    #[case::dquoted_command_name(r#""echo" hello"#, vec!["echo", "hello"])]
    #[case::squoted_command_name("'echo' hello", vec!["echo", "hello"])]
    fn tokenize_command_simple(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::leading_and_trailing("  echo   hello  ", vec!["echo", "hello"])]
    #[case::tabs("git\t\tstatus", vec!["git", "status"])]
    fn tokenize_command_extra_whitespace(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: single-quoted strings
    // raw_strings pass contents through verbatim, no escape processing.
    // ========================================

    #[rstest]
    #[case::with_space("echo 'hello world'", vec!["echo", "hello world"])]
    // `'it'\''s'` is the bash idiom for embedding a single quote in a
    // single-quoted string: raw_string + word(`\'`) + raw_string.
    // The middle word's backslash escape decodes to `'`.
    #[case::embedded_quote("echo 'it'\\''s'", vec!["echo", "it's"])]
    #[case::backslash_inside_raw("echo 'no \\escapes'", vec!["echo", "no \\escapes"])]
    #[case::empty_with_arg("echo '' arg", vec!["echo", "", "arg"])]
    fn tokenize_command_single_quotes(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: double-quoted strings
    // string_content has shell escape rules applied (`\\`, `\"`, `\$`,
    // `` \` ``, `\<newline>`); unknown escapes keep the backslash.
    // ========================================

    #[rstest]
    #[case::space_inside(r#"echo "hello world""#, vec!["echo", "hello world"])]
    #[case::escaped_dquote(r#"echo "with \"quotes\"""#, vec!["echo", r#"with "quotes""#])]
    #[case::escaped_backslash(r#"echo "back\\slash""#, vec!["echo", "back\\slash"])]
    // Unknown escape: bash preserves the backslash.
    #[case::unknown_escape(r#"echo "\j""#, vec!["echo", "\\j"])]
    // Known escape `\$` becomes `$`.
    #[case::escaped_dollar(r#"echo "a\$b""#, vec!["echo", "a$b"])]
    #[case::empty_with_arg(r#"echo "" arg"#, vec!["echo", "", "arg"])]
    fn tokenize_command_double_quotes(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: outside-quote backslash escapes
    // tree-sitter-bash collapses `a\ b` into a single `word` node;
    // `decode_unquoted_escapes` then resolves `\<c>` → `<c>`.
    // ========================================

    #[rstest]
    #[case::space_escape("echo hello\\ world", vec!["echo", "hello world"])]
    #[case::quote_escape("echo test\\\"quote", vec!["echo", "test\"quote"])]
    fn tokenize_command_outside_escapes(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: mixed and concatenated quoting
    // ========================================

    #[rstest]
    #[case::dquote_arg(
        r#"curl -X POST -H "Content-Type: application/json" https://example.com"#,
        vec!["curl", "-X", "POST", "-H", "Content-Type: application/json", "https://example.com"]
    )]
    #[case::squote_arg(
        "git commit -m 'initial commit'",
        vec!["git", "commit", "-m", "initial commit"]
    )]
    // Adjacent quoted/unquoted pieces glue into one token.
    #[case::concatenated(
        r#"echo "hello"' world'"#,
        vec!["echo", "hello world"]
    )]
    fn tokenize_command_mixed_quoting(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: shell groupings as a single token
    //
    // `subshell`, `command_substitution`, and `process_substitution`
    // come out as one token each with their delimiters intact, so
    // wrapper patterns like `time <cmd>` capture the whole grouping as
    // a single placeholder.
    // ========================================

    #[rstest]
    #[case::bare_subshell("time (ls)", vec!["time", "(ls)"])]
    #[case::subshell_pipeline(
        "time (ls | tail -40)",
        vec!["time", "(ls | tail -40)"]
    )]
    #[case::subshell_multi_arg(
        "time (lefthook run pre-commit 2>&1 | tail -40)",
        vec!["time", "(lefthook run pre-commit 2>&1 | tail -40)"]
    )]
    #[case::nested_subshell("time (a | (b && c))", vec!["time", "(a | (b && c))"])]
    #[case::dollar_substitution(
        "echo $(date -u)",
        vec!["echo", "$(date -u)"]
    )]
    #[case::backtick_substitution(
        "echo `date -u`",
        vec!["echo", "`date -u`"]
    )]
    #[case::process_substitution(
        "diff <(ls a) <(ls b)",
        vec!["diff", "<(ls a)", "<(ls b)"]
    )]
    fn tokenize_command_groupings(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: flags with = syntax
    // ========================================

    #[rstest]
    #[case::short_dkey("java -Denv=prod", vec!["java", "-Denv=prod"])]
    #[case::long_eq("git diff --word-diff=color", vec!["git", "diff", "--word-diff=color"])]
    fn tokenize_command_equals_flags(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: declaration_command / unset_command builtins
    //
    // tree-sitter-bash gives `export`/`declare`/`typeset`/`readonly`/
    // `local` their own `declaration_command` node (with an anonymous
    // keyword child) and `unset`/`unsetenv` their own `unset_command`
    // node. The keyword is emitted as the first token; argument
    // children are emitted one token each, with `variable_assignment`
    // (`KEY=VALUE`) preserved verbatim as a single token so rule
    // patterns like `allow: 'export *'` can match against them.
    // ========================================

    #[rstest]
    #[case::export_assignment("export FOO=bar", vec!["export", "FOO=bar"])]
    #[case::export_bare_name("export FOO", vec!["export", "FOO"])]
    #[case::export_flag("export -p", vec!["export", "-p"])]
    #[case::export_flag_with_arg("export -f myfunc", vec!["export", "-f", "myfunc"])]
    #[case::export_multiple("export FOO=bar BAZ=qux", vec!["export", "FOO=bar", "BAZ=qux"])]
    #[case::declare_flag_assignment("declare -x FOO=bar", vec!["declare", "-x", "FOO=bar"])]
    #[case::readonly_assignment("readonly FOO=bar", vec!["readonly", "FOO=bar"])]
    #[case::local_assignment("local FOO=bar", vec!["local", "FOO=bar"])]
    #[case::typeset_assignment("typeset FOO=bar", vec!["typeset", "FOO=bar"])]
    #[case::unset_single("unset FOO", vec!["unset", "FOO"])]
    #[case::unset_multiple("unset FOO BAR BAZ", vec!["unset", "FOO", "BAR", "BAZ"])]
    #[case::unsetenv_single("unsetenv FOO", vec!["unsetenv", "FOO"])]
    #[case::export_quoted_value(
        r#"export FOO="hello world""#,
        vec!["export", r#"FOO="hello world""#]
    )]
    fn tokenize_command_builtins(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize_command(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize_command: error cases
    //
    // Empty / whitespace-only input is `EmptyCommand`; everything that
    // tree-sitter-bash refuses (unclosed quotes, lone operators,
    // pipelines/lists/control flow that aren't a single command,
    // trailing backslash, ...) is `SyntaxError`. Compound input is
    // expected to be split upstream by `extract_commands_with_metadata`.
    // ========================================

    #[rstest]
    #[case::empty("", CommandParseError::EmptyCommand)]
    #[case::whitespace("   ", CommandParseError::EmptyCommand)]
    // `\\\n` / `\\` / `echo \\` / `echo "hello` look incomplete to
    // tree-sitter. shlex also can't recover them (unclosed quote,
    // dangling backslash), so they end as `SyntaxError`.
    #[case::lone_continuation("\\\n", CommandParseError::SyntaxError)]
    #[case::unclosed_squote("echo 'hello", CommandParseError::SyntaxError)]
    #[case::unclosed_dquote(r#"echo "hello"#, CommandParseError::SyntaxError)]
    // Compound input is the caller's responsibility — these are valid
    // bash but resolve to a `pipeline`/`list`, not a single `command`.
    #[case::pipeline("ls | tail -40", CommandParseError::SyntaxError)]
    #[case::and_list("ls && rm foo", CommandParseError::SyntaxError)]
    fn tokenize_command_errors(#[case] input: &str, #[case] expected: CommandParseError) {
        let result = tokenize_command(input);
        assert_eq!(
            std::mem::discriminant(&result.unwrap_err()),
            std::mem::discriminant(&expected),
        );
    }

    // ========================================
    // parse_command: no schema (default) — unknown flags are boolean
    // ========================================

    #[rstest]
    // simple commands without flags
    #[case::no_flags("git status", "git", &[], &["status"])]
    #[case::multiple_args("cp src.txt dst.txt", "cp", &[], &["src.txt", "dst.txt"])]
    // boolean flags (unknown → boolean)
    #[case::short_combined("rm -rf /tmp/test", "rm", &[("-rf", None)], &["/tmp/test"])]
    #[case::long_flag("git push --force origin main", "git", &[("--force", None)], &["push", "origin", "main"])]
    // equals-joined flags
    #[case::eq_short("java -Denv=prod Main", "java", &[("-Denv", Some("prod"))], &["Main"])]
    #[case::eq_long("git diff --word-diff=color file.txt", "git", &[("--word-diff", Some("color"))], &["diff", "file.txt"])]
    // equals in non-flag token → positional arg
    #[case::eq_non_flag("echo key=value", "echo", &[], &["key=value"])]
    fn parse_command_default_schema(
        #[case] input: &str,
        #[case] expected_cmd: &str,
        #[case] expected_flags: &[(&str, Option<&str>)],
        #[case] expected_args: &[&str],
    ) {
        let schema = FlagSchema::default();
        let result = parse_command(input, &schema).unwrap();
        assert_eq!(result.command, expected_cmd);
        assert_eq!(result.args, expected_args);
        assert_eq!(result.flags.len(), expected_flags.len());
        for &(flag, value) in expected_flags {
            assert_eq!(
                result.flags.get(flag),
                Some(&value.map(String::from)),
                "flag {flag}"
            );
        }
    }

    // ========================================
    // parse_command: with schema — value flags consume next token
    // ========================================

    #[rstest]
    // short value flag
    #[case::short(
        "curl -X POST https://example.com",
        &["-X"],
        "curl", &[("-X", Some("POST"))], &["https://example.com"],
    )]
    // long value flag
    #[case::long(
        "curl --request GET https://example.com",
        &["--request"],
        "curl", &[("--request", Some("GET"))], &["https://example.com"],
    )]
    // value flag at end with no following token
    #[case::at_end(
        "git commit -m",
        &["-m"],
        "git", &[("-m", None)], &["commit"],
    )]
    // separate boolean flag + value flag: `-a -m "msg"` keeps them distinct
    #[case::separate_bool_and_value(
        r#"git commit -a -m "initial commit""#,
        &["-m"],
        "git", &[("-a", None), ("-m", Some("initial commit"))], &["commit"],
    )]
    // combined short flags `-am` is treated as a single unknown flag token;
    // runok does not split combined short flags (by design: "What You See
    // Is How It Parses" — the rule `-m` won't match `-am`)
    #[case::combined_short_flags(
        r#"git commit -am "initial commit""#,
        &["-m"],
        "git", &[("-am", None)], &["commit", "initial commit"],
    )]
    // argument order independence: flag before arg
    #[case::order_flag_first(
        "curl -X POST https://example.com",
        &["-X"],
        "curl", &[("-X", Some("POST"))], &["https://example.com"],
    )]
    // argument order independence: flag after arg
    #[case::order_flag_last(
        "curl https://example.com -X POST",
        &["-X"],
        "curl", &[("-X", Some("POST"))], &["https://example.com"],
    )]
    fn parse_command_with_schema(
        #[case] input: &str,
        #[case] value_flags: &[&str],
        #[case] expected_cmd: &str,
        #[case] expected_flags: &[(&str, Option<&str>)],
        #[case] expected_args: &[&str],
    ) {
        let schema = FlagSchema {
            value_flags: value_flags.iter().map(|s| s.to_string()).collect(),
        };
        let result = parse_command(input, &schema).unwrap();
        assert_eq!(result.command, expected_cmd);
        assert_eq!(result.args, expected_args);
        assert_eq!(result.flags.len(), expected_flags.len());
        for &(flag, value) in expected_flags {
            assert_eq!(
                result.flags.get(flag),
                Some(&value.map(String::from)),
                "flag {flag}"
            );
        }
    }

    // ========================================
    // parse_command: multiple value flags
    // ========================================

    #[test]
    fn parse_command_mixed_flags_and_args() {
        let schema = FlagSchema {
            value_flags: ["-H", "-X"].iter().map(|s| s.to_string()).collect(),
        };
        let result = parse_command(
            r#"curl -X POST -H "Content-Type: application/json" https://example.com"#,
            &schema,
        )
        .unwrap();
        assert_eq!(result.command, "curl");
        assert_eq!(result.flags.get("-X"), Some(&Some("POST".to_string())));
        assert_eq!(
            result.flags.get("-H"),
            Some(&Some("Content-Type: application/json".to_string()))
        );
        assert_eq!(result.args, vec!["https://example.com"]);
    }

    // ========================================
    // parse_command: error cases
    // ========================================

    #[test]
    fn parse_command_empty_input() {
        let schema = FlagSchema::default();
        let result = parse_command("", &schema);
        assert!(matches!(result, Err(CommandParseError::EmptyCommand)));
    }

    // ========================================
    // parse_command: raw_tokens preserved
    // ========================================

    #[test]
    fn parse_command_raw_tokens_preserved() {
        let schema = FlagSchema {
            value_flags: HashSet::from(["-X".to_string()]),
        };
        let result = parse_command("curl -X POST https://example.com", &schema).unwrap();
        assert_eq!(
            result.raw_tokens,
            vec!["curl", "-X", "POST", "https://example.com"]
        );
    }
}
