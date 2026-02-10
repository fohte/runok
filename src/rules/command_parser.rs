use crate::rules::CommandParseError;

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
                has_token = true;
                chars.next(); // consume backslash
                match chars.next() {
                    Some('\n') => {} // line continuation
                    Some(c) => current.push(c),
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

    #[test]
    fn tokenize_empty_input() {
        let result = tokenize("");
        assert!(matches!(result, Err(CommandParseError::EmptyCommand)));
    }

    #[test]
    fn tokenize_whitespace_only() {
        let result = tokenize("   ");
        assert!(matches!(result, Err(CommandParseError::EmptyCommand)));
    }

    #[test]
    fn tokenize_unclosed_single_quote() {
        let result = tokenize("echo 'hello");
        assert!(matches!(result, Err(CommandParseError::UnclosedQuote)));
    }

    #[test]
    fn tokenize_unclosed_double_quote() {
        let result = tokenize(r#"echo "hello"#);
        assert!(matches!(result, Err(CommandParseError::UnclosedQuote)));
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
}
