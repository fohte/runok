mod collect;
mod misparse;

pub(super) use collect::collect_commands;
use misparse::strip_misparsed_compound_prefix;

use crate::rules::CommandParseError;

#[cfg(test)]
use super::EnvAssignment;
use super::function_table::FunctionTable;
use super::var_env::VarEnv;
use super::{ExtractedCommand, FunctionCallInfo, PipeInfo, RedirectInfo};

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
    extract_commands_with_context(
        input,
        VarEnv::new(),
        FunctionTable::new(),
        &[],
        &PipeInfo::default(),
        "",
    )
}

/// Re-extract a resolved function call's body: binds the call's own
/// arguments to `$1`..`$N` / `$@` / `$*` / `$#` on top of the variable
/// environment captured at the call site, then extracts it with the
/// call site's function table, redirects, pipe position, and loop kind
/// inherited -- so a nested call inside the body also resolves
/// (`g() { git push; }; f() { g; }; f`), and none of the call site's
/// context is lost by re-parsing the body in isolation (e.g. `f() {
/// git push; }; f > /path` keeps the redirect on the body's `git
/// push`, and `curl ... | f` keeps the body's commands aware they are
/// reading from a pipe).
pub(crate) fn resolve_function_call_body(
    call_info: &FunctionCallInfo,
    body: &str,
    redirects: &[RedirectInfo],
    pipe: &PipeInfo,
    loop_kind: &str,
) -> Result<Vec<ExtractedCommand>, CommandParseError> {
    let mut var_env = call_info.var_env.clone();
    var_env.bind_positional_params(&call_info.call_args);
    extract_commands_with_context(
        body,
        var_env,
        call_info.function_table.clone(),
        redirects,
        pipe,
        loop_kind,
    )
}

/// Like [`extract_commands_with_metadata`], but seeds the walk with a
/// pre-populated variable environment, function table, and
/// redirect/pipe/loop-kind context instead of always starting fresh.
/// Use [`resolve_function_call_body`] rather than calling this directly
/// to re-extract a function call's body.
fn extract_commands_with_context(
    input: &str,
    mut var_env: VarEnv,
    mut function_table: FunctionTable,
    redirects: &[RedirectInfo],
    pipe: &PipeInfo,
    loop_kind: &str,
) -> Result<Vec<ExtractedCommand>, CommandParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    // Workaround for tree-sitter-bash misparses of reserved-word prefixes
    // (`time <compound>`, `! <compound>`, ...). See
    // `strip_misparsed_compound_prefix`.
    if let Some(rest) = strip_misparsed_compound_prefix(trimmed) {
        return extract_commands_with_context(
            rest,
            var_env,
            function_table,
            redirects,
            pipe,
            loop_kind,
        );
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
        pipe,
        redirects,
        loop_kind,
        &mut var_env,
        &mut function_table,
        false,
    );

    Ok(commands)
}

/// Split a multi-line shell input into top-level command strings.
///
/// Unlike [`extract_commands_with_metadata`], this function only splits at
/// **top-level command boundaries** — newlines, `;`, and `&` between
/// statements at the `program` root. Compound commands joined by `&&`,
/// `||`, or `|` are kept as a single string (the caller — typically the
/// rule engine — will split those further).
///
/// HEREDOC bodies, quoted strings spanning multiple lines, and backslash
/// line continuations are kept intact because tree-sitter-bash represents
/// them as a single AST node.
///
/// Returns `SyntaxError` if tree-sitter-bash cannot parse the input, and
/// `EmptyCommand` if the input is empty or whitespace-only.
pub fn split_top_level_commands(input: &str) -> Result<Vec<String>, CommandParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    // See `strip_misparsed_compound_prefix`.
    if let Some(rest) = strip_misparsed_compound_prefix(trimmed) {
        return split_top_level_commands(rest);
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

    let source = trimmed.as_bytes();
    let mut commands = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        // tree-sitter-bash exposes `#...` lines as `comment` siblings of
        // top-level commands; bash treats them as no-ops, so drop them here.
        if child.kind() == "comment" {
            continue;
        }
        if let Ok(text) = child.utf8_text(source) {
            let text = text.trim();
            if !text.is_empty() {
                commands.push(text.to_string());
            }
        }
    }

    if commands.is_empty() {
        return Err(CommandParseError::EmptyCommand);
    }

    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::super::var_env::VarValue;
    use super::*;
    use indoc::indoc;
    use rstest::rstest;

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
    // extract_commands: HEREDOC inside compound expressions
    //
    // tree-sitter-bash represents `cat <<EOF | other ...\nbody\nEOF` by
    // attaching the trailing `pipeline` / `&&` / `||` arm as a CHILD of
    // the `heredoc_redirect` node, instead of wrapping the whole thing
    // in an outer pipeline. The body and continuation must be re-stitched
    // into the synthesized outer pipeline so every sub-command surfaces
    // to the rule engine with the right pipe metadata.
    // ========================================

    // Each delimiter form (`<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`,
    // `<<-EOF`) and each compound operator (`|`, `&&`, `||`) goes
    // through the same `find_heredoc_continuation` codepath, so a
    // single rstest matrix covers the variants. The `<<\EOF` case
    // exercises `is_quoted_heredoc`'s backslash detection.
    #[rstest]
    #[case::pipe_unquoted(
        indoc! {"
            cat <<EOF | kubectl apply -f -
            apiVersion: v1
            EOF
        "},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_single_quoted_delimiter(
        indoc! {"
            cat <<'EOF' | kubectl apply -f -
            apiVersion: v1
            EOF
        "},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_double_quoted_delimiter(
        indoc! {r#"
            cat <<"EOF" | kubectl apply -f -
            apiVersion: v1
            EOF
        "#},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_backslash_quoted_delimiter(
        indoc! {r"
            cat <<\EOF | kubectl apply -f -
            apiVersion: v1
            EOF
        "},
        vec!["cat", "kubectl apply -f -"],
    )]
    #[case::pipe_tab_strip(
        indoc! {"
            cat <<-EOF | tee out
            \tbody
            \tEOF
        "},
        vec!["cat", "tee out"],
    )]
    #[case::pipe_multiple_stages(
        indoc! {"
            cat <<EOF | kubectl apply -f - | tee out
            body
            EOF
        "},
        vec!["cat", "kubectl apply -f -", "tee out"],
    )]
    #[case::and_chain(
        indoc! {"
            cat <<EOF && echo done
            body
            EOF
        "},
        vec!["cat", "echo done"],
    )]
    #[case::or_chain(
        indoc! {"
            cat <<EOF || echo nope
            body
            EOF
        "},
        vec!["cat", "echo nope"],
    )]
    fn extract_heredoc_in_compound(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input.trim_end()).unwrap();
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        assert_eq!(result, expected);
    }

    // tree-sitter-bash 0.25.1 produces an ERROR node for `;` / `&`
    // after a heredoc start, so runok surfaces these as SyntaxError
    // rather than dropping the trailing arm. Pinned to detect parser
    // version drift.
    #[rstest]
    #[case::semicolon_after_heredoc(indoc! {"
        cat <<EOF ; echo after
        body
        EOF
    "})]
    #[case::ampersand_after_heredoc(indoc! {"
        cat <<EOF & echo after
        body
        EOF
    "})]
    fn extract_heredoc_with_semicolon_or_ampersand_is_syntax_error(#[case] input: &str) {
        let err = extract_commands(input.trim_end()).unwrap_err();
        assert!(
            matches!(err, CommandParseError::SyntaxError),
            "expected SyntaxError, got {:?}",
            err
        );
    }

    // Per-stage pipe metadata. `extract_commands` discards `pipe`,
    // so these cases pin `extract_commands_with_metadata` directly.
    // Important for any future `when: pipe.stdout == false` rule that
    // would silently misfire if a middle stage lost a flag, or if a
    // logical-list right-hand side got reinterpreted as a pipe stage.
    #[rstest]
    #[case::three_stage_pipeline(
        indoc! {"
            cat <<EOF | kubectl apply -f - | tee out
            body
            EOF
        "},
        vec![
            ("cat",                PipeInfo { stdin: false, stdout: true  }),
            ("kubectl apply -f -", PipeInfo { stdin: true,  stdout: true  }),
            ("tee out",            PipeInfo { stdin: true,  stdout: false }),
        ],
    )]
    // `cat <<EOF && a | b`: tree-sitter exposes `a | b` as the
    // `right`-fielded pipeline. body and right are list siblings (no
    // pipe), `a` is the head of the right-hand pipeline.
    #[case::and_with_right_pipeline(
        indoc! {"
            cat <<EOF && a | b
            body
            EOF
        "},
        vec![
            ("cat", PipeInfo { stdin: false, stdout: false }),
            ("a",   PipeInfo { stdin: false, stdout: true  }),
            ("b",   PipeInfo { stdin: true,  stdout: false }),
        ],
    )]
    // `cat <<EOF | tee out && echo done`: heredoc holds an un-fielded
    // pipeline whose stages are `[tee out, list[..., echo done]]`.
    // The list stage must be processed as a list, NOT inherit
    // `stdin = true` from the synthesized outer pipeline.
    #[case::pipe_then_and_chain(
        indoc! {"
            cat <<EOF | tee out && echo done
            body
            EOF
        "},
        vec![
            ("cat",       PipeInfo { stdin: false, stdout: true  }),
            ("tee out",   PipeInfo { stdin: true,  stdout: false }),
            ("echo done", PipeInfo { stdin: false, stdout: false }),
        ],
    )]
    // `cat <<EOF | a | b && c || d`: the multi-pipe + multi-list
    // chain stress-tests the recursive `list` split. Bash's
    // `|` > `&&` precedence means `(cat | a | b) && c || d`.
    #[case::pipe_chain_then_list_chain(
        indoc! {"
            cat <<EOF | a | b && c || d
            body
            EOF
        "},
        vec![
            ("cat", PipeInfo { stdin: false, stdout: true  }),
            ("a",   PipeInfo { stdin: true,  stdout: true  }),
            ("b",   PipeInfo { stdin: true,  stdout: false }),
            ("c",   PipeInfo { stdin: false, stdout: false }),
            ("d",   PipeInfo { stdin: false, stdout: false }),
        ],
    )]
    // `a | cat <<EOF && b`: the heredoc body is the pipeline
    // `a | cat`, and `b` is the `&&` arm. `&&` is a pipe boundary,
    // so `b.stdin` must be `false` even though it sits next to a
    // pipe segment in the source.
    #[case::heredoc_pipe_in_body_with_and_arm(
        indoc! {"
            a | cat <<EOF && b
            body
            EOF
        "},
        vec![
            ("a",   PipeInfo { stdin: false, stdout: true  }),
            ("cat", PipeInfo { stdin: true,  stdout: false }),
            ("b",   PipeInfo { stdin: false, stdout: false }),
        ],
    )]
    fn extract_heredoc_pipe_metadata(#[case] input: &str, #[case] expected: Vec<(&str, PipeInfo)>) {
        let cmds = extract_commands_with_metadata(input.trim_end()).unwrap();
        let actual: Vec<(&str, PipeInfo)> = cmds
            .iter()
            .map(|c| (c.command.as_str(), c.pipe.clone()))
            .collect();
        assert_eq!(actual, expected);
    }

    // tree-sitter-bash 0.25.1 produces an ERROR node when a second
    // `<<` follows the first heredoc on the same pipeline, so runok
    // surfaces SyntaxError instead of silently dropping arms. Pinned
    // to detect parser version drift.
    #[test]
    fn extract_two_heredocs_in_pipeline_is_syntax_error() {
        let input = indoc! {"
            cat <<EOF | cat <<EOF2 | tee out
            body1
            EOF
            body2
            EOF2
        "}
        .trim_end();
        let err = extract_commands(input).unwrap_err();
        assert!(
            matches!(err, CommandParseError::SyntaxError),
            "expected SyntaxError, got {:?}",
            err
        );
    }

    // The trailing arm may itself be a compound expression. All of
    // its sub-commands need to surface so deny rules can match them.
    #[test]
    fn extract_heredoc_pipe_then_and_chain() {
        let input = indoc! {"
            cat <<EOF | tee out && echo done
            body
            EOF
        "}
        .trim_end();
        let result = extract_commands(input).unwrap();
        assert_eq!(result, vec!["cat", "tee out", "echo done"]);
    }

    // Heredoc on the right-hand side of a pipeline is the "easy"
    // case (tree-sitter wraps the pipeline naturally). Pin it down
    // so the fix for the left-hand case does not regress it.
    #[test]
    fn extract_pipeline_into_heredoc() {
        let input = indoc! {"
            echo foo | cat <<EOF
            body
            EOF
        "}
        .trim_end();
        let result = extract_commands(input).unwrap();
        assert_eq!(result, vec!["echo foo", "cat"]);
    }

    // Heredoc inside a control-flow body must still surface every
    // pipeline stage to the outer command list.
    #[rstest]
    #[case::if_body(
        indoc! {"
            if true; then
              cat <<EOF | tee out
            body
            EOF
            fi
        "},
        vec!["true", "cat", "tee out"],
    )]
    #[case::while_body(
        indoc! {"
            while true; do
              cat <<EOF | tee out
            body
            EOF
            done
        "},
        vec!["true", "cat", "tee out"],
    )]
    #[case::for_body(
        indoc! {"
            for x in a b; do
              cat <<EOF | tee out
            body
            EOF
            done
        "},
        vec!["cat", "tee out"],
    )]
    fn extract_heredoc_pipe_inside_control_flow(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = extract_commands(input.trim_end()).unwrap();
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        assert_eq!(result, expected);
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
    // `$X` resolves to the literal value assigned by `X="test"`; the
    // redirect is still stripped, which is this case's original intent.
    #[case::redirect_in_compound(
        r#"X="test" && echo "$X" 2>&1"#,
        vec!["echo test"],
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
    // extract_commands_with_metadata: loop_kind
    //
    // Surfaces the enclosing-loop kind on every sub-command so CEL
    // `when` clauses can deny `sleep` polling loops via
    // `shell.loop_kind in ["while", "until"]`.
    // ========================================

    #[rstest]
    #[case::no_loop("sleep 5", vec![("sleep 5", "")])]
    #[case::until_body(
        "until ready; do sleep 1; done",
        vec![("ready", "until"), ("sleep 1", "until")],
    )]
    #[case::while_body(
        "while alive; do sleep 1; done",
        vec![("alive", "while"), ("sleep 1", "while")],
    )]
    #[case::for_body(
        "for i in 1 2 3; do echo $i; done",
        vec![("echo $i", "for")],
    )]
    #[case::nested_until_in_for(
        "for x in a b; do until y; do sleep 1; done; done",
        vec![("y", "until"), ("sleep 1", "until")],
    )]
    #[case::subshell_wraps_loop(
        "(while x; do sleep 1; done)",
        vec![("x", "while"), ("sleep 1", "while")],
    )]
    #[case::pipeline_inside_loop(
        "while alive; do gh pr checks 1 | grep -q ok; done",
        vec![("alive", "while"), ("gh pr checks 1", "while"), ("grep -q ok", "while")],
    )]
    #[case::loop_followed_by_outside(
        "while alive; do sleep 1; done; echo done",
        vec![("alive", "while"), ("sleep 1", "while"), ("echo done", "")],
    )]
    // For-value-list substitutions run once before the loop body in bash, so
    // they keep `loop_kind == ""` regardless of whether the substitution is
    // bare or quoted — quoting shouldn't change rule-matching semantics.
    #[case::for_value_substitution_bare(
        "for i in $(seed); do echo $i; done",
        vec![("seed", ""), ("echo $i", "for")],
    )]
    #[case::for_value_substitution_quoted(
        r#"for i in "$(seed)"; do echo $i; done"#,
        vec![("seed", ""), ("echo $i", "for")],
    )]
    fn extract_loop_kind(#[case] input: &str, #[case] expected: Vec<(&str, &str)>) {
        let result = extract_commands_with_metadata(input).unwrap();
        let actual: Vec<(&str, &str)> = result
            .iter()
            .map(|ec| (ec.command.as_str(), ec.loop_kind.as_str()))
            .collect();
        assert_eq!(actual, expected);
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
    // extract_commands: declaration_command / unset_command builtins
    //
    // These shell builtins live alongside `command` in tree-sitter-bash
    // and must flow through extraction (not be dropped or treated as
    // env-prefix variable_assignments) so callers can evaluate rules
    // against them inside pipelines / lists / subshells.
    // ========================================

    #[rstest]
    #[case::standalone_export("export FOO=bar", vec!["export FOO=bar"])]
    #[case::standalone_unset("unset FOO", vec!["unset FOO"])]
    #[case::declare_in_pipeline(
        "declare -x FOO=bar | grep FOO",
        vec!["declare -x FOO=bar", "grep FOO"]
    )]
    #[case::export_in_and_list(
        "echo before && export FOO=bar && echo after",
        vec!["echo before", "export FOO=bar", "echo after"]
    )]
    #[case::unset_in_subshell(
        "(unset FOO && echo done)",
        vec!["unset FOO", "echo done"]
    )]
    fn extract_declaration_and_unset_commands(#[case] input: &str, #[case] expected: Vec<&str>) {
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
    #[case::export_assignment(
        "export FOO=bar",
        vec!["export", "FOO=bar"],
    )]
    #[case::declare_flag_assignment(
        "declare -x FOO=bar",
        vec!["declare", "-x", "FOO=bar"],
    )]
    #[case::unset_multiple(
        "unset FOO BAR",
        vec!["unset", "FOO", "BAR"],
    )]
    fn extract_commands_metadata_declaration_and_unset_argv(
        #[case] input: &str,
        #[case] expected_argv: Vec<&str>,
    ) {
        let commands = extract_commands_with_metadata(input).unwrap();
        assert_eq!(commands.len(), 1, "expected single command for: {}", input);
        assert!(
            commands[0].env.is_empty(),
            "builtins do not carry env-prefix assignments: {}",
            input
        );
        assert_eq!(
            commands[0].argv, expected_argv,
            "argv mismatch for: {}",
            input
        );
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

    // ========================================
    // split_top_level_commands
    //
    // Splits at top-level statement boundaries (newline, `;`, `&`) only.
    // Compound commands joined by `&&`/`||`/`|` and constructs that span
    // multiple lines (HEREDOC, multi-line strings, `\` continuations) are
    // kept as a single string.
    // ========================================

    #[rstest]
    #[case::single_line("git status", vec!["git status"])]
    #[case::three_separate_lines(
        indoc! {"
            git status
            ls -la
            echo hello
        "},
        vec!["git status", "ls -la", "echo hello"],
    )]
    #[case::semicolon_separator("foo; bar", vec!["foo", "bar"])]
    #[case::ampersand_background("foo & bar", vec!["foo", "bar"])]
    #[case::and_or_kept_together(
        "foo && bar || baz",
        vec!["foo && bar || baz"],
    )]
    #[case::pipeline_kept_together(
        "echo hello | grep foo",
        vec!["echo hello | grep foo"],
    )]
    #[case::backslash_line_continuation(
        indoc! {"
            echo \\
              hello \\
              world
        "},
        vec!["echo \\\n  hello \\\n  world"],
    )]
    #[case::heredoc_inside_command_substitution(
        indoc! {"
            git add foo && git commit -m \"$(cat <<'EOF'
            subject
            body
            EOF
            )\"
        "},
        vec![indoc! {"
            git add foo && git commit -m \"$(cat <<'EOF'
            subject
            body
            EOF
            )\""}],
    )]
    #[case::multiline_double_quoted_string(
        indoc! {r#"
            echo "line one
            line two"
        "#},
        vec!["echo \"line one\nline two\""],
    )]
    #[case::skips_blank_lines(
        indoc! {"
            git status

            ls -la
        "},
        vec!["git status", "ls -la"],
    )]
    #[case::skips_comment_only_line(
        indoc! {"
            # a standalone comment
            git status
        "},
        vec!["git status"],
    )]
    #[case::skips_comment_between_commands(
        indoc! {"
            git status
            # comment in the middle
            ls -la
        "},
        vec!["git status", "ls -la"],
    )]
    #[case::trailing_inline_comment_terminated_by_newline(
        indoc! {"
            git status # trailing comment
            ls -la
        "},
        vec!["git status", "ls -la"],
    )]
    #[case::pipelines_split_around_comment_line(
        indoc! {"
            ls -la | grep foo | head -1
            # divider
            cat bar | wc -l
        "},
        vec!["ls -la | grep foo | head -1", "cat bar | wc -l"],
    )]
    // tree-sitter-bash misparses reserved-word prefixes on compound statements
    // (`time for ...; do ...; done`, `! while ...`, etc.) into multiple
    // top-level statements. The parser detects the symptom (a non-leading
    // `program` child that starts with `do`/`done`/`then`/`fi`/`elif`/`else`/
    // `esac`/`}`) and strips the offending prefix so the compound stays whole.
    #[case::time_for_loop(
        "time for i in 1 2 3; do echo $i; done",
        vec!["for i in 1 2 3; do echo $i; done"],
    )]
    #[case::time_dash_p_for_loop(
        "time -p for i in 1 2 3; do echo $i; done",
        vec!["for i in 1 2 3; do echo $i; done"],
    )]
    #[case::time_while_loop(
        "time while true; do echo hi; done",
        vec!["while true; do echo hi; done"],
    )]
    #[case::time_until_loop(
        "time until false; do echo hi; done",
        vec!["until false; do echo hi; done"],
    )]
    #[case::time_if_block(
        "time if true; then echo y; fi",
        vec!["if true; then echo y; fi"],
    )]
    #[case::time_brace_group(
        "time { echo hi; }",
        vec!["{ echo hi; }"],
    )]
    #[case::time_time_for_loop(
        "time time for i in 1 2; do echo $i; done",
        vec!["for i in 1 2; do echo $i; done"],
    )]
    // `!` is another reserved-word prefix tree-sitter misparses when it
    // precedes a compound (the leading `negated_command` only captures the
    // `for`-header and the `do`/`done` get split off as separate statements).
    #[case::bang_for_loop(
        "! for i in 1 2; do echo $i; done",
        vec!["for i in 1 2; do echo $i; done"],
    )]
    // Symptom-based detection: any leading prefix that causes tree-sitter to
    // split the compound apart is peeled off, not just literal `time` / `!`.
    #[case::arbitrary_prefix_compound(
        "foo for i in 1 2; do echo $i; done",
        vec!["for i in 1 2; do echo $i; done"],
    )]
    // Simple commands parse cleanly with no symptom, so the prefix stays.
    #[case::time_simple_command_kept(
        "time ls -la",
        vec!["time ls -la"],
    )]
    // tree-sitter parses `time (...)` as a single `command` node whose argument
    // is the subshell, so the symptom never triggers and the wrapper layer
    // captures the input as-is.
    #[case::time_subshell_kept(
        "time (echo hi; echo bye)",
        vec!["time (echo hi; echo bye)"],
    )]
    #[case::time_dash_p_simple_command_kept(
        "time -p ls -la",
        vec!["time -p ls -la"],
    )]
    fn split_top_level_commands_cases(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = split_top_level_commands(input).unwrap();
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::empty("", CommandParseError::EmptyCommand)]
    #[case::whitespace_only("   \n\n  ", CommandParseError::EmptyCommand)]
    #[case::only_comments(
        indoc! {"
            # one
            # two
        "},
        CommandParseError::EmptyCommand,
    )]
    #[case::unclosed_quote("echo \"unterminated", CommandParseError::SyntaxError)]
    #[case::unclosed_heredoc(
        indoc! {"
            cat <<EOF
            no terminator here
        "},
        CommandParseError::SyntaxError,
    )]
    fn split_top_level_commands_errors(#[case] input: &str, #[case] expected: CommandParseError) {
        let err = split_top_level_commands(input).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&expected),
        );
    }

    // ========================================
    // extract_commands_with_metadata: variable resolution
    //
    // A static, single-value `variable_assignment` (`X=1`) is tracked so a
    // later bare `$X` / `${X}` in the same command string resolves to its
    // value: `command` becomes the expanded text and `original_command`
    // holds the verbatim source. Anything not statically resolvable —
    // dynamic values, reassignment inside a conditional/loop, array
    // subscripts, bare `export`/`unset`, a definition-time function body —
    // is recorded as poisoned, and expansion falls back to the verbatim
    // `$X` (`original_command: None`).
    // ========================================

    fn no_expansion(command: &str, argv: &[&str]) -> ExtractedCommand {
        ExtractedCommand {
            command: command.to_string(),
            env: vec![],
            argv: argv.iter().map(|s| s.to_string()).collect(),
            redirects: vec![],
            pipe: PipeInfo::default(),
            loop_kind: String::new(),
            original_command: None,
            function_call: None,
        }
    }

    #[rstest]
    fn variable_resolution_numeric_value_resolves() {
        // A purely-numeric value parses as a `number` node (distinct
        // from `word` in tree-sitter-bash), so it needs its own static
        // check; regression test for that gap.
        let result = extract_commands_with_metadata("X=1; echo $X").unwrap();
        assert_eq!(
            result,
            vec![ExtractedCommand {
                command: "echo 1".to_string(),
                env: vec![],
                argv: vec!["echo".to_string(), "1".to_string()],
                redirects: vec![],
                pipe: PipeInfo::default(),
                loop_kind: String::new(),
                original_command: Some("echo $X".to_string()),
                function_call: None,
            }]
        );
    }

    #[rstest]
    #[case::subshell_reassignment_does_not_leak("X=1; (X=2); echo $X")]
    #[case::command_substitution_reassignment_does_not_leak("X=1; Y=$(X=2); echo $X")]
    fn variable_resolution_subshell_scope_is_isolated(#[case] input: &str) {
        // A subshell / command substitution forks: an assignment inside
        // it (here, the inner `X=2`, itself a bare assignment that
        // contributes no `ExtractedCommand` of its own) must never
        // overwrite the value the parent scope resolves `$X` to
        // afterward -- `echo $X` must still expand from the outer
        // `X=1`, not the shadowed `X=2`.
        let result = extract_commands_with_metadata(input).unwrap();
        assert_eq!(
            result,
            vec![ExtractedCommand {
                command: "echo 1".to_string(),
                env: vec![],
                argv: vec!["echo".to_string(), "1".to_string()],
                redirects: vec![],
                pipe: PipeInfo::default(),
                loop_kind: String::new(),
                original_command: Some("echo $X".to_string()),
                function_call: None,
            }]
        );
    }

    #[rstest]
    #[case::and_then_reassignment_is_poisoned(
        "X=1; false && X=2; echo $X",
        vec![no_expansion("false", &["false"]), no_expansion("echo $X", &["echo", "$X"])],
    )]
    #[case::or_then_reassignment_is_poisoned(
        "X=1; true || X=2; echo $X",
        vec![no_expansion("true", &["true"]), no_expansion("echo $X", &["echo", "$X"])],
    )]
    fn variable_resolution_list_right_hand_side_is_poisoned(
        #[case] input: &str,
        #[case] expected: Vec<ExtractedCommand>,
    ) {
        // `X=2` on the right of `&&` / `||` may or may not run depending
        // on the left side's exit status, so it must poison `X` rather
        // than being trusted as an unconditional Literal -- regardless
        // of which operand actually executes at runtime.
        let result = extract_commands_with_metadata(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    // A literal value containing a space is word-split like bash's
    // default IFS would: `$X` alone expands to two argv tokens, and the
    // command name becomes `git` (not the unknown `git status`).
    #[case::bare_expansion_becomes_two_tokens(
        r#"X="git status"; $X"#,
        ExtractedCommand {
            command: "git status".to_string(),
            env: vec![],
            argv: vec!["git".to_string(), "status".to_string()],
            redirects: vec![],
            pipe: PipeInfo::default(),
            loop_kind: String::new(),
            original_command: Some("$X".to_string()),
            function_call: None,
        },
    )]
    #[case::command_name_position(
        "X=rm; $X -rf /",
        ExtractedCommand {
            command: "rm -rf /".to_string(),
            env: vec![],
            argv: vec!["rm".to_string(), "-rf".to_string(), "/".to_string()],
            redirects: vec![],
            pipe: PipeInfo::default(),
            loop_kind: String::new(),
            original_command: Some("$X -rf /".to_string()),
            function_call: None,
        },
    )]
    // Motivating case: a flag value smuggled through a variable no
    // longer evades a `deny: 'git push --force*'` rule.
    #[case::flag_value(
        "F=--force; git push $F",
        ExtractedCommand {
            command: "git push --force".to_string(),
            env: vec![],
            argv: vec!["git".to_string(), "push".to_string(), "--force".to_string()],
            redirects: vec![],
            pipe: PipeInfo::default(),
            loop_kind: String::new(),
            original_command: Some("git push $F".to_string()),
            function_call: None,
        },
    )]
    // `"$X"` is one quoted argument: no IFS splitting, so the whole
    // command collapses to the single (unknown) command name `git
    // status`, matching real bash semantics.
    #[case::quoted_value_stays_one_token(
        r#"X="git status"; "$X""#,
        ExtractedCommand {
            command: "'git status'".to_string(),
            env: vec![],
            argv: vec!["git status".to_string()],
            redirects: vec![],
            pipe: PipeInfo::default(),
            loop_kind: String::new(),
            original_command: Some(r#""$X""#.to_string()),
            function_call: None,
        },
    )]
    fn variable_resolution_resolves_static_value(
        #[case] input: &str,
        #[case] expected: ExtractedCommand,
    ) {
        assert_eq!(
            extract_commands_with_metadata(input).unwrap(),
            vec![expected]
        );
    }

    #[rstest]
    #[case::dynamic_command_substitution_value(
        "X=$(cat f); $X",
        vec![no_expansion("cat f", &["cat", "f"]), no_expansion("$X", &["$X"])],
    )]
    #[case::reassigned_via_command_substitution(
        "X=1; X=$(date); echo $X",
        vec![no_expansion("date", &["date"]), no_expansion("echo $X", &["echo", "$X"])],
    )]
    #[case::operator_expansion_not_resolved(
        "X=default; echo ${X:-fallback}",
        vec![no_expansion("echo ${X:-fallback}", &["echo", "${X:-fallback}"])],
    )]
    #[case::conditional_assignment_stays_poisoned(
        "if true; then X=rm; fi; $X /",
        vec![no_expansion("true", &["true"]), no_expansion("$X /", &["$X", "/"])],
    )]
    #[case::array_subscript_assignment_poisons_base_name(
        "X=1; X[0]=2; echo $X",
        vec![no_expansion("echo $X", &["echo", "$X"])],
    )]
    #[case::function_body_assignment_does_not_leak(
        "f() { local X=1; }; echo $X",
        vec![no_expansion("local X=1", &["local", "X=1"]), no_expansion("echo $X", &["echo", "$X"])],
    )]
    #[case::declaration_command_bare_name_poisons(
        "X=1; export X; echo $X",
        vec![no_expansion("export X", &["export", "X"]), no_expansion("echo $X", &["echo", "$X"])],
    )]
    #[case::unset_command_poisons(
        "X=1; unset X; echo $X",
        vec![no_expansion("unset X", &["unset", "X"]), no_expansion("echo $X", &["echo", "$X"])],
    )]
    fn variable_resolution_falls_back_to_verbatim(
        #[case] input: &str,
        #[case] expected: Vec<ExtractedCommand>,
    ) {
        let result = extract_commands_with_metadata(input).unwrap();
        assert_eq!(result, expected);
    }

    // ========================================
    // extract_commands_with_metadata: function call annotation
    // ========================================

    #[test]
    fn function_call_annotates_command_matching_earlier_definition() {
        let result = extract_commands_with_metadata("f() { git push; }; f").unwrap();
        let call = result
            .iter()
            .find(|ec| ec.command == "f")
            .expect("call site extracted");
        let call_info = call.function_call.as_ref().expect("annotated as a call");
        assert_eq!(
            (
                call_info.function_name.as_str(),
                call_info.bodies.as_slice(),
                call_info.call_args.as_slice(),
            ),
            ("f", ["{ git push; }".to_string()].as_slice(), [].as_slice()),
        );
    }

    #[test]
    fn function_call_captures_resolved_call_args() {
        let result = extract_commands_with_metadata("f() { git push $1; }; f --force").unwrap();
        let call = result
            .iter()
            .find(|ec| ec.function_call.is_some())
            .expect("call site extracted");
        let call_info = call.function_call.as_ref().unwrap();
        assert_eq!(call_info.call_args, vec!["--force".to_string()]);
    }

    #[test]
    fn function_call_not_annotated_before_definition() {
        // `f` runs before `f() { ... }` is reached in program order, so
        // real bash would fail with "command not found" -- it must stay
        // an unannotated, unknown command.
        let result = extract_commands_with_metadata("f; f() { git push; }").unwrap();
        let call = result
            .iter()
            .find(|ec| ec.command == "f")
            .expect("call site extracted");
        assert_eq!(call.function_call, None);
    }

    #[test]
    fn function_call_snapshot_includes_earlier_defined_functions() {
        // `f`'s call-site function-table snapshot must contain `g` too,
        // so rule_engine can resolve the nested `g;` call when it
        // re-extracts `f`'s body.
        let result = extract_commands_with_metadata("g() { git push; }; f() { g; }; f").unwrap();
        let call = result
            .iter()
            .find(|ec| ec.command == "f")
            .expect("call site extracted");
        let call_info = call.function_call.as_ref().unwrap();
        assert_eq!(
            call_info.function_table.lookup("g"),
            Some(["{ git push; }".to_string()].as_slice())
        );
    }

    #[test]
    fn function_call_multiple_definitions_accumulate_bodies() {
        let result = extract_commands_with_metadata(
            "if true; then f() { echo a; }; else f() { echo b; }; fi; f",
        )
        .unwrap();
        let call = result
            .iter()
            .find(|ec| ec.command == "f")
            .expect("call site extracted");
        let call_info = call.function_call.as_ref().unwrap();
        assert_eq!(
            call_info.bodies,
            vec!["{ echo a; }".to_string(), "{ echo b; }".to_string()]
        );
    }

    #[test]
    fn function_call_carries_call_site_var_env_snapshot() {
        let result = extract_commands_with_metadata("X=--force; f() { git push; }; f").unwrap();
        let call = result
            .iter()
            .find(|ec| ec.command == "f")
            .expect("call site extracted");
        let call_info = call.function_call.as_ref().unwrap();
        let mut env = call_info.var_env.clone();
        env.bind_positional_params(&[]);
        assert_eq!(
            env.get("X"),
            Some(&VarValue::Literal("--force".to_string()))
        );
    }
}
