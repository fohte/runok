use std::collections::{HashMap, HashSet};

use crate::rules::CommandParseError;

/// Schema describing which flags take values vs. are boolean-only.
///
/// Derived from rule patterns (Policy-Derived Schema): if a rule writes
/// `deny: "curl -X POST"`, then `-X` is inferred to take a value.
/// Flags not listed in `value_flags` are treated as boolean (no value).
#[derive(Debug, Default)]
pub struct FlagSchema {
    /// Flags known to take a following value (e.g., `-X`, `--request`).
    pub value_flags: HashSet<String>,
}

/// A parsed command with structured flag and argument information.
#[derive(Debug, PartialEq)]
pub struct ParsedCommand {
    /// The command name (first token).
    pub command: String,
    /// Flags and their optional values. Boolean flags have `None`.
    /// For `=`-joined tokens like `-Dkey=value`, the key is the flag name
    /// and the value is the part after `=`.
    ///
    /// Duplicate flags are last-wins (HashMap semantics). This is acceptable
    /// because the matching engine uses `raw_tokens` for pattern matching,
    /// not this map. This map is for structured access in `when` expressions.
    pub flags: HashMap<String, Option<String>>,
    /// Positional arguments (non-flag tokens after the command name).
    pub args: Vec<String>,
    /// The original raw tokens from tokenization.
    pub raw_tokens: Vec<String>,
}

/// Information about a single redirect operator attached to a command.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectInfo {
    /// Redirect category: "input", "output", or "dup".
    pub redirect_type: String,
    /// The redirect operator (e.g., ">", ">>", "<", "<<<", ">&", "<&", "&>", "&>>", ">|").
    pub operator: String,
    /// The redirect target (e.g., "/dev/null", "&1", "file.txt").
    pub target: String,
    /// File descriptor number, if explicitly specified (e.g., `2` in `2>`).
    pub descriptor: Option<i64>,
}

/// Information about a command's position in a pipeline.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PipeInfo {
    /// Whether stdin comes from a preceding pipe.
    pub stdin: bool,
    /// Whether stdout feeds into a following pipe.
    pub stdout: bool,
}

/// A `KEY=VALUE` environment variable assignment that prefixes a
/// command (e.g. `FOO=bar BAZ=qux helmfile template`).
#[derive(Debug, Clone, PartialEq)]
pub struct EnvAssignment {
    /// Variable name.
    pub name: String,
    /// Variable value with shell quotes resolved. `None` when bash
    /// permits the bare form `FOO= cmd` (clear the variable).
    pub value: Option<String>,
}

/// A command extracted from a compound shell expression, with metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedCommand {
    /// The command string (redirects stripped, as before).
    pub command: String,
    /// Inline environment variable assignments that prefixed the
    /// command (`FOO=bar cmd ...`). Empty when the command had no
    /// such prefix or when the AST shape made them unattributable
    /// (e.g. process substitutions emitted as standalone commands).
    pub env: Vec<EnvAssignment>,
    /// The command + argument tokens with shell quoting resolved
    /// (env prefix, redirects, and HEREDOC bodies excluded). Empty
    /// when the AST surfaced a non-`command` node — currently only
    /// the leaf-text fallback in `collect_commands` — so callers
    /// must treat the empty case as "argv unavailable" rather than
    /// "argv had no tokens".
    pub argv: Vec<String>,
    /// Redirect operators that were attached to this command.
    pub redirects: Vec<RedirectInfo>,
    /// Pipeline position information.
    pub pipe: PipeInfo,
}

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
/// upstream by [`extract_commands_with_metadata`].
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
fn dequote_node(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
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
/// [`extract_commands_with_metadata`].
fn find_single_command_node(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    match node.kind() {
        // A regular shell command (`echo hello`, `git -C foo log`, ...).
        "command" => Some(node),
        // A bracket test command (`[ -f file ]`, `[[ -f file ]]`).
        // runok matches these with literal `[`/`]` tokens, so they
        // need to flow through tokenisation just like a `command`.
        "test_command" => Some(node),
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
    );

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
fn collect_commands(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
    pipe_info: &PipeInfo,
    redirects: &[RedirectInfo],
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
        | "while_statement"
        | "if_statement"
        | "elif_clause"
        | "negated_command" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(child, source, commands, pipe_info, redirects);
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
                collect_commands(*child, source, commands, &child_pipe, redirects);
            }
        }
        // for_statement: recurse into body (do_group) and any command_substitution
        // nodes in the value list. Literal values (number, word, etc.) are skipped.
        "for_statement" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "do_group" | "command_substitution" => {
                        collect_commands(child, source, commands, pipe_info, redirects);
                    }
                    // Recurse into value list items (e.g. string nodes)
                    // to find nested command substitutions like
                    // `for i in "$(cmd)"; do ...`.
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
                        collect_commands(child, source, commands, pipe_info, redirects);
                    }
                    "command_substitution" => {
                        collect_commands(child, source, commands, pipe_info, redirects);
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
                    collect_commands(child, source, commands, pipe_info, redirects);
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
            // Process body first (preserves original command ordering)
            if let Some(body) = node.child_by_field_name("body") {
                collect_commands(body, source, commands, pipe_info, &all_redirects);
            }
            // Second pass: recurse into redirect children for nested
            // substitutions (e.g. `cmd > >(nested)`). HEREDOCs with a
            // quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) are
            // literal — bash does not expand `$VAR`/`$(...)` inside the
            // body — so skip them to avoid false positives where the
            // body text accidentally looks like shell syntax.
            for i in 0..node.child_count() {
                if node.field_name_for_child(i as u32) == Some("redirect")
                    && let Some(child) = node.child(i as u32)
                {
                    if child.kind() == "heredoc_redirect" && is_quoted_heredoc(child, source) {
                        continue;
                    }
                    collect_substitutions_recursive(child, source, commands);
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
                collect_commands(body, source, commands, pipe_info, redirects);
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
                        // redirect context. The outer command text is still
                        // emitted below and handled by the self-reference
                        // filter in `evaluate_command_inner`.
                        "command_substitution" | "subshell" => {
                            collect_commands(child, source, commands, &PipeInfo::default(), &[]);
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
                });
            }
        }
    }
}

/// Decode a `variable_assignment` AST node (`KEY=VALUE`,
/// `KEY="$(cmd)"`, `KEY=`) into a structured assignment.
///
/// `dequote_node` is reused for the value half so quoting is resolved
/// the same way as for argv tokens (raw strings pass through; double
/// quotes are decoded; command substitutions are kept verbatim with
/// their delimiters so a downstream consumer can still see `$(...)`).
fn extract_env_assignment(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<EnvAssignment> {
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
fn extract_redirect_info(node: tree_sitter::Node, source: &[u8]) -> Option<RedirectInfo> {
    match node.kind() {
        "file_redirect" => {
            // Extract the operator from anonymous children
            let mut operator = String::new();
            let mut descriptor: Option<i64> = None;
            let mut target = String::new();

            for i in 0..node.child_count() {
                let child = node.child(i as u32)?;
                if child.kind() == "file_descriptor" {
                    let text =
                        std::str::from_utf8(&source[child.start_byte()..child.end_byte()]).ok()?;
                    descriptor = text.parse::<i64>().ok();
                } else if !child.is_named() {
                    // Anonymous node = operator token (>, >>, <, >&, <&, &>, &>>, >|)
                    let text =
                        std::str::from_utf8(&source[child.start_byte()..child.end_byte()]).ok()?;
                    operator = text.to_string();
                } else if node.field_name_for_child(i as u32) == Some("destination") {
                    let text =
                        std::str::from_utf8(&source[child.start_byte()..child.end_byte()]).ok()?;
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
                    let text =
                        std::str::from_utf8(&source[child.start_byte()..child.end_byte()]).ok()?;
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
                    let text =
                        std::str::from_utf8(&source[child.start_byte()..child.end_byte()]).ok()?;
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
fn is_quoted_heredoc(heredoc_redirect: tree_sitter::Node<'_>, source: &[u8]) -> bool {
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
fn collect_substitutions_recursive(
    node: tree_sitter::Node,
    source: &[u8],
    commands: &mut Vec<ExtractedCommand>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command_substitution" | "process_substitution" => {
                collect_commands(child, source, commands, &PipeInfo::default(), &[]);
            }
            _ => {
                collect_substitutions_recursive(child, source, commands);
            }
        }
    }
}

/// Join tokens into a shell-safe string by quoting tokens that contain
/// spaces or shell metacharacters. Tokens without special characters are
/// emitted verbatim.
///
/// Returns an error if any token contains a NUL byte (which cannot be
/// represented in shell syntax).
pub fn shell_quote_join(tokens: &[String]) -> Result<String, shlex::QuoteError> {
    shlex::try_join(tokens.iter().map(|s| s.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
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

    // ========================================
    // shell_quote_join
    // ========================================

    #[rstest]
    #[case::simple(&["echo", "hello"], "echo hello")]
    #[case::space_in_token(&["echo", "hello world"], "echo 'hello world'")]
    #[case::empty_token(&["echo", ""], "echo ''")]
    #[case::single_quote_in_token(&["echo", "it's"], "echo \"it's\"")]
    #[case::flags_and_paths(&["rm", "-rf", "/tmp/dir"], "rm -rf /tmp/dir")]
    #[case::single_token(&["ls"], "ls")]
    fn shell_quote_join_cases(#[case] tokens: &[&str], #[case] expected: &str) {
        let owned: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
        assert_eq!(shell_quote_join(&owned).unwrap(), expected);
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
}
