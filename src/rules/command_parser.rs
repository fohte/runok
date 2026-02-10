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
pub fn parse_command(input: &str, schema: &FlagSchema) -> Result<ParsedCommand, CommandParseError> {
    let raw_tokens = tokenize(input)?;
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

/// Tokenize a command string into a list of raw tokens.
///
/// Handles:
/// - Whitespace-delimited splitting
/// - Single-quoted strings (no escape processing inside)
/// - Double-quoted strings (backslash escapes for `\`, `"`, `$`, `` ` ``, newline;
///   unknown escapes preserve the backslash to match shell behavior)
/// - Backslash escapes outside of quotes
/// - Empty quoted strings (`""`, `''`) are preserved as empty tokens
pub fn tokenize(input: &str) -> Result<Vec<String>, CommandParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut has_token = false;
    let mut chars = trimmed.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            // Whitespace outside quotes: emit current token
            c if c.is_ascii_whitespace() => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
                chars.next();
            }
            // Single quote: consume until closing quote, no escape processing
            '\'' => {
                has_token = true;
                chars.next(); // consume opening quote
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => current.push(c),
                        None => return Err(CommandParseError::UnclosedQuote),
                    }
                }
            }
            // Double quote: consume with escape processing
            '"' => {
                has_token = true;
                chars.next(); // consume opening quote
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c @ ('"' | '\\' | '$' | '`')) => current.push(c),
                            Some('\n') => {} // line continuation
                            // Unknown escape: preserve backslash (match shell behavior)
                            Some(c) => {
                                current.push('\\');
                                current.push(c);
                            }
                            None => return Err(CommandParseError::UnclosedQuote),
                        },
                        Some(c) => current.push(c),
                        None => return Err(CommandParseError::UnclosedQuote),
                    }
                }
            }
            // Backslash escape outside quotes
            '\\' => {
                chars.next(); // consume backslash
                match chars.next() {
                    Some('\n') => {} // line continuation
                    Some(c) => {
                        has_token = true;
                        current.push(c);
                    }
                    None => {} // trailing backslash is ignored
                }
            }
            // Regular character
            _ => {
                has_token = true;
                current.push(ch);
                chars.next();
            }
        }
    }

    if has_token {
        tokens.push(current);
    }

    if tokens.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    Ok(tokens)
}

/// Extract individual command strings from a potentially compound shell input.
///
/// Splits on pipelines (`|`), logical operators (`&&`, `||`), and semicolons (`;`).
/// Uses tree-sitter-bash to correctly handle quoting and nesting.
/// Returns `SyntaxError` if the input contains parse errors.
pub fn extract_commands(input: &str) -> Result<Vec<String>, CommandParseError> {
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
    collect_commands(root, trimmed.as_bytes(), &mut commands);

    if commands.is_empty() {
        return Err(CommandParseError::SyntaxError);
    }

    Ok(commands)
}

/// Recursively walk the tree-sitter AST and collect individual command strings.
///
/// Top-level compound constructs (pipeline, list with &&/||/;) are split into
/// their constituent commands. Everything else is preserved as-is.
fn collect_commands(node: tree_sitter::Node, source: &[u8], commands: &mut Vec<String>) {
    match node.kind() {
        // `program` is the root — recurse into named children only
        // (skips anonymous nodes like `;`)
        "program" | "pipeline" | "list" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_commands(child, source, commands);
            }
        }
        // Leaf command nodes — extract the source text
        _ => {
            let text = &source[node.start_byte()..node.end_byte()];
            let text = std::str::from_utf8(text).unwrap_or("").trim();
            if !text.is_empty() {
                commands.push(text.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ========================================
    // tokenize: simple commands
    // ========================================

    #[rstest]
    #[case("echo hello", vec!["echo", "hello"])]
    #[case("git status", vec!["git", "status"])]
    #[case("ls -la /tmp", vec!["ls", "-la", "/tmp"])]
    fn tokenize_simple_commands(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case("  echo   hello  ", vec!["echo", "hello"])]
    #[case("git\t\tstatus", vec!["git", "status"])]
    fn tokenize_extra_whitespace(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn tokenize_single_command() {
        let result = tokenize("ls").unwrap();
        assert_eq!(result, vec!["ls"]);
    }

    // ========================================
    // tokenize: single-quoted strings
    // ========================================

    #[rstest]
    #[case("echo 'hello world'", vec!["echo", "hello world"])]
    #[case("echo 'it'\\''s'", vec!["echo", "it's"])]
    #[case("echo 'no \\escapes'", vec!["echo", "no \\escapes"])]
    fn tokenize_single_quotes(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize: double-quoted strings
    // ========================================

    #[rstest]
    #[case(r#"echo "hello world""#, vec!["echo", "hello world"])]
    #[case(r#"echo "with \"quotes\"""#, vec!["echo", r#"with "quotes""#])]
    #[case(r#"echo "back\\slash""#, vec!["echo", "back\\slash"])]
    fn tokenize_double_quotes(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize: unknown escape sequences in double quotes
    // ========================================

    #[test]
    fn tokenize_double_quote_unknown_escape_preserves_backslash() {
        // Shell behavior: "\j" -> "\j" (backslash preserved for unknown escapes)
        let result = tokenize(r#"echo "\j""#).unwrap();
        assert_eq!(result, vec!["echo", "\\j"]);
    }

    #[test]
    fn tokenize_double_quote_known_escapes_preserved() {
        // Known escapes: \\, \", \$, \` are processed
        let result = tokenize(r#"echo "a\$b""#).unwrap();
        assert_eq!(result, vec!["echo", "a$b"]);
    }

    // ========================================
    // tokenize: escape sequences (outside quotes)
    // ========================================

    #[rstest]
    #[case("echo hello\\ world", vec!["echo", "hello world"])]
    #[case("echo test\\\"quote", vec!["echo", "test\"quote"])]
    fn tokenize_escapes(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn tokenize_trailing_backslash_ignored() {
        // Trailing backslash at end of input should not produce a spurious empty token
        let result = tokenize("echo \\").unwrap();
        assert_eq!(result, vec!["echo"]);
    }

    // ========================================
    // tokenize: mixed quoting
    // ========================================

    #[rstest]
    #[case(
        r#"curl -X POST -H "Content-Type: application/json" https://example.com"#,
        vec!["curl", "-X", "POST", "-H", "Content-Type: application/json", "https://example.com"]
    )]
    #[case(
        "git commit -m 'initial commit'",
        vec!["git", "commit", "-m", "initial commit"]
    )]
    fn tokenize_mixed_quoting(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // tokenize: concatenated quoting
    // ========================================

    #[test]
    fn tokenize_concatenated_quotes() {
        // e.g., echo "hello"' world' -> "hello world"
        let result = tokenize(r#"echo "hello"' world'"#).unwrap();
        assert_eq!(result, vec!["echo", "hello world"]);
    }

    // ========================================
    // tokenize: empty quoted strings
    // ========================================

    #[test]
    fn tokenize_empty_double_quotes() {
        let result = tokenize(r#"echo "" arg"#).unwrap();
        assert_eq!(result, vec!["echo", "", "arg"]);
    }

    #[test]
    fn tokenize_empty_single_quotes() {
        let result = tokenize("echo '' arg").unwrap();
        assert_eq!(result, vec!["echo", "", "arg"]);
    }

    // ========================================
    // tokenize: error cases
    // ========================================

    #[rstest]
    #[case("", CommandParseError::EmptyCommand)]
    #[case("   ", CommandParseError::EmptyCommand)]
    #[case("\\", CommandParseError::EmptyCommand)]
    #[case("\\\n", CommandParseError::EmptyCommand)]
    #[case("echo 'hello", CommandParseError::UnclosedQuote)]
    #[case::unclosed_double_quote(r#"echo "hello"#, CommandParseError::UnclosedQuote)]
    fn tokenize_errors(#[case] input: &str, #[case] expected: CommandParseError) {
        let result = tokenize(input);
        assert_eq!(
            std::mem::discriminant(&result.unwrap_err()),
            std::mem::discriminant(&expected),
        );
    }

    // ========================================
    // tokenize: flags with = syntax
    // ========================================

    #[rstest]
    #[case("java -Denv=prod", vec!["java", "-Denv=prod"])]
    #[case("git diff --word-diff=color", vec!["git", "diff", "--word-diff=color"])]
    fn tokenize_equals_flags(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = tokenize(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands: basic
    // ========================================

    #[test]
    fn extract_single_command() {
        let result = extract_commands("echo hello").unwrap();
        assert_eq!(result, vec!["echo hello"]);
    }

    #[rstest]
    #[case("echo hello | grep world", vec!["echo hello", "grep world"])]
    #[case("cmd1 && cmd2", vec!["cmd1", "cmd2"])]
    #[case("cmd1 || cmd2", vec!["cmd1", "cmd2"])]
    #[case("cmd1 ; cmd2", vec!["cmd1", "cmd2"])]
    fn extract_compound_commands(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn extract_mixed_operators() {
        let result = extract_commands("curl url | jq '.data' && rm tmp.json").unwrap();
        assert_eq!(result, vec!["curl url", "jq '.data'", "rm tmp.json"]);
    }

    #[test]
    fn extract_commands_empty_input() {
        let result = extract_commands("");
        assert!(matches!(result, Err(CommandParseError::EmptyCommand)));
    }

    // ========================================
    // extract_commands: syntax errors
    // ========================================

    #[test]
    fn extract_commands_syntax_error() {
        let result = extract_commands("&&");
        assert!(matches!(result, Err(CommandParseError::SyntaxError)));
    }

    // ========================================
    // extract_commands: quoting preserved in compound
    // ========================================

    #[test]
    fn extract_commands_with_quotes() {
        let result = extract_commands(r#"echo "hello | world" && grep test"#).unwrap();
        assert_eq!(result, vec![r#"echo "hello | world""#, "grep test"]);
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
