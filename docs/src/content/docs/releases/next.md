---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Highlights

### Breaking: quoted-delimiter HEREDOCs are no longer scanned for nested commands ([#330](https://github.com/fohte/runok/pull/330))

Previously, runok recursed into the body of every HEREDOC looking for command substitutions (`$(...)`, `` `...` ``) to evaluate as separate sub-commands, regardless of whether the delimiter was quoted. This did not match bash semantics: `<<'EOF'`, `<<"EOF"`, and `<<\EOF` make the body literal, so a `$(secret_cmd)` inside the body is text, not a real command. Scanning it caused false `ask`/`deny` decisions on commit messages and similar prose that happened to look like shell.

```sh
# Before: `secret_cmd` was extracted from the body and evaluated.
# After: the body is literal, only `cat` is extracted.
cat <<'EOF'
$(secret_cmd)
EOF
```

Unquoted HEREDOCs (`<<EOF`) keep the existing behaviour — bash does expand the body, so runok still extracts substitutions from it.

**What should I do?**

If you previously relied on runok scanning a quoted-HEREDOC body (for example, a rule that fired because `$(rm -rf /)` inside `<<'EOF'` matched a `deny` rule), update the rule to target the actual command instead. Quoted heredocs are inert in bash, so this can only have hidden real commands behind a literal-looking surface — those should be written as ordinary command substitutions, not buried inside a literal heredoc.

## Bug Fixes

### `git commit -m "$(cat <<'EOF' ... EOF)"` no longer fails with `unclosed quote` ([#330](https://github.com/fohte/runok/pull/330))

Commit-message workflows that pipe a HEREDOC through `cat` inside a double-quoted command substitution — for example, the Claude Code `/commit` skill — were rejected with `command parse error: unclosed quote`. The character-level tokenizer used to fall back behind the AST walk treated the HEREDOC body as live shell, hit a stray quote inside the prose, and bailed out. The tokenizer is now AST-only: quotes are resolved per AST node, so a HEREDOC body is handled as the literal redirect target it is and never re-scanned as shell syntax.

```sh
# Before: command parse error: unclosed quote
# After: matches the existing `git [-C *] commit -m *` rule and
#        evaluates to allow.
git add path && git commit -m "$(cat <<'EOF'
subject

body line 1 with 'apostrophes' inside
EOF
)"
```

### Quoted command names match the same rules as their unquoted form ([#330](https://github.com/fohte/runok/pull/330))

`"echo" hello` (or `'echo' hello`) used to tokenise with the surrounding quotes still attached to the command name (`["\"echo\"", "hello"]`), so a rule like `allow: 'echo *'` would not fire. Quotes are now stripped from the command name as well as from arguments, matching how bash itself treats them.

### `runok check` stdin splits on shell statement boundaries, not raw newlines ([#332](https://github.com/fohte/runok/pull/332))

Plaintext stdin into `runok check` was previously split into one command per line, which broke any input that legitimately spans multiple lines: HEREDOCs, multi-line quoted strings, and `\` line continuations all got chopped up and rejected. The splitter now uses tree-sitter-bash to find top-level statement boundaries, so multi-line constructs are kept together while genuinely separate commands (newline, `;`, `&` between top-level statements) are still evaluated independently. `&&`, `||`, and `|` keep their existing behaviour — they are part of one compound command and are split further by the rule engine.

```sh
# Before: each line evaluated separately; the inner heredoc body and the
#         closing `)"` were nonsense on their own.
# After: this is one command, matched against your `git commit` rules.
cat <<'OUTER' | runok check
git add path && git commit -m "$(cat <<'EOF'
subject
body
EOF
)"
OUTER

# Multi-command scripts still split into independent commands:
cat <<'OUTER' | runok check
git status
ls -la
echo hello
OUTER
```

If stdin cannot be parsed as shell (for example, an unclosed quote), `runok check` now exits with `stdin parse error: failed to parse stdin as shell input` instead of trying to recover by treating each line independently.

## Library API changes

These changes only affect code that imports `runok` as a Rust library. The CLI and `runok.yml` authoring are unaffected.

### Breaking: `CommandParseError::UnclosedQuote` removed ([#330](https://github.com/fohte/runok/pull/330))

The `UnclosedQuote` variant is gone. Inputs that the previous character-level tokenizer rejected as `UnclosedQuote` are now reported as `CommandParseError::SyntaxError`, alongside everything else tree-sitter-bash refuses.

**What should I do?**

If you have a `match` arm on `CommandParseError::UnclosedQuote`, fold it into the `SyntaxError` arm:

```rust
// Before
match err {
    CommandParseError::UnclosedQuote => /* ... */,
    CommandParseError::SyntaxError => /* ... */,
    CommandParseError::EmptyCommand => /* ... */,
}

// After
match err {
    CommandParseError::SyntaxError => /* ... */,
    CommandParseError::EmptyCommand => /* ... */,
}
```

### Breaking: bare `FOO=bar` and trailing-`\` inputs now report `SyntaxError` ([#330](https://github.com/fohte/runok/pull/330))

The previous tokenizer accepted a few inputs that bash itself does not consider a complete command:

- A bare `VAR=value` assignment (no command following it) used to tokenise as `["VAR=value"]`.
- A trailing backslash (`echo \`) used to silently drop the backslash.

Both now return `CommandParseError::SyntaxError`. tree-sitter-bash flags them as parse errors, and the shlex fallback also rejects them. End-to-end command evaluation is unaffected for ordinary inputs because compound input is split first by `extract_commands_with_metadata`, which still extracts substitutions out of `VAR=$(cmd)`-style assignments before tokenisation runs.

**What should I do?**

If you have integrations that fed `parse_command` raw assignment-only strings, wrap them in a real command (`true VAR=value`) or switch to evaluating via `evaluate_command` / `extract_commands_with_metadata`, which already handle assignments.
