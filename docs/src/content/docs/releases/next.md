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

### Breaking: audit log JSON consolidates rule + parse data into `command_evaluations` ([#333](https://github.com/fohte/runok/pull/333))

The audit log entry shape changes so single and compound commands share one schema. The top-level `matched_rules` and `sub_evaluations` keys are removed; their contents move into a new `command_evaluations` array — one entry per shell command extracted from the input (`"primary"` for non-compound inputs, one `"compound"` entry per branch for `a && b` / `a | b` / etc.). Each entry now also carries the shell-level parse result (`env`, `argv`, `redirects`, `pipe`) alongside `action` and `matched_rules`.

See [Audit Log JSON Schema -- `command_evaluations`](/cli/audit-log-schema/#command_evaluations) for the full schema and field reference.

## New Features

### New reference page for the `runok audit --json` schema ([#338](https://github.com/fohte/runok/pull/338))

`runok audit --json` now has a dedicated field-by-field reference: [Audit Log JSON Schema](/cli/audit-log-schema/). It documents every top-level key (`timestamp`, `command`, `action`, `sandbox_preset`, `default_action`, `metadata`, `command_evaluations`), every nested object (`Action`, `Metadata`, `CommandEvaluation`, `RuleMatch`, `EnvVar`, `Redirect`, `Pipe`), every enum value, and every "omitted when empty" condition — so writing `jq` queries no longer requires reading the runok source. The `runok audit` page now links to it instead of duplicating a partial schema.

### New `fs.*` CEL functions for filesystem checks in `when` clauses ([#341](https://github.com/fohte/runok/pull/341))

`when` expressions can now read the live filesystem through three new functions:

| Function           | Description                                    |
| ------------------ | ---------------------------------------------- |
| `fs.exists(path)`  | `true` if the path exists (symlinks followed). |
| `fs.is_file(path)` | `true` if the path is a regular file.          |
| `fs.is_dir(path)`  | `true` if the path is a directory.             |

Empty-string paths return `false`; broken symlinks return `false` from all three; permission errors (e.g. `EACCES`) surface as evaluation errors rather than being folded into `false`. Typical use case: gating a rule on a marker file written by a separate tool.

```yaml
rules:
  - allow: 'git commit *'
    when: "fs.exists('/tmp/runok-precommit-ok')"
  - ask: 'git commit *'
```

See [Filesystem functions](/rule-evaluation/when-clause/#filesystem-functions) for the full behaviour reference.

### New `os` CEL variable for OS-conditional `when` clauses ([#336](https://github.com/fohte/runok/pull/336))

`when` expressions now expose an `os` string equal to Rust's [`std::env::consts::OS`](https://doc.rust-lang.org/std/env/consts/constant.OS.html) — `"macos"`, `"linux"`, `"windows"`, `"freebsd"`, etc. This lets a single config branch on the host operating system, which previously was not possible: shell built-ins like `OSTYPE` are not exported to child processes, so they don't appear in `env`.

```yaml
rules:
  # macOS ships BSD sed; steer to GNU sed (gsed)
  - deny: 'sed *'
    when: "os == 'macos'"
    message: 'Use gsed (GNU sed) on macOS'
  - allow: 'gsed *'
  - allow: 'sed *'
    when: "os == 'linux'"
```

See [When Clauses](/rule-evaluation/when-clause/#os--host-operating-system) for details.

### `definitions.vars` gains a new `pattern` type for reusable command-prefix patterns ([#334](https://github.com/fohte/runok/pull/334))

`definitions.vars[<name>].type` now accepts `pattern` in addition to `literal` and `path`. A pattern-typed variable's values are parsed as rule-pattern fragments and inlined wherever `<var:name>` appears. This is purpose-built for naming a base CLI plus its global flags once, and reusing it across every rule that should accept that prefix.

```yaml
definitions:
  vars:
    kubectl:
      type: pattern
      values:
        - 'kubectl [-n|--namespace *] [--context *] [--cluster *] [--user *] [--kubeconfig *]'

rules:
  - allow: '<var:kubectl> get|describe|logs *'
  - allow: '<var:kubectl> top node|pod|nodes|pods *'
  - allow: '<var:kubectl> auth can-i|whoami *'
```

Each rule above accepts the kubectl prefix with any combination of the listed global flags (including the `--flag=value` form), so `kubectl --kubeconfig ~/.kube/work --context prod get pods -A` and the bare `kubectl get pods` are both allowed by the first rule.

Pattern-typed values support the full rule-pattern syntax (alternation `|`, wildcard `*`, optional groups `[...]`, literals, etc.), but cannot nest other placeholders (`<cmd>`, `<opts>`, `<vars>`, `<var:...>`, `<path:...>`, `<flag:...>`) and cannot themselves be placed inside an optional group at a rule call site (`[<var:name>]`). Both restrictions are reported at config validation time.

See [Variable References (`<var:name>`)](/pattern-syntax/placeholders/#variable-references-varname) and [`definitions.vars`](/configuration/schema/#definitionsvars) for details.

## Bug Fixes

### `runok test` no longer evaluates inline tests from any preset reached via a remote ancestor ([#339](https://github.com/fohte/runok/pull/339))

The strip introduced in [#227](https://github.com/fohte/runok/pull/227) only removed inline `tests` and the top-level `tests:` block from the outermost remote preset. Any preset reached transitively through a local-path `extends` inside that remote (the layout used by `runok-presets/base`, which extends `./readonly-unix.yml`, `./readonly-git.yml`, etc.) kept its preset-authored tests, and they were re-evaluated under the downstream user's overrides — typically failing as `expected allow, got deny` when the user denied something the preset allows.

`runok test` now strips inline tests and top-level `tests:` from every preset reached via a remote ancestor in the `extends` chain, regardless of whether each child reference is remote or local. Tests in the user's own config and in presets the user extends directly via a local path are unaffected.

### `runok audit --json` no longer panics when the downstream pipe closes early ([#337](https://github.com/fohte/runok/pull/337))

Piping `runok audit --json` into `head`, `jq -c`, or any consumer that may close stdout before runok has finished writing now exits silently instead of panicking with `failed printing to stdout: Broken pipe (os error 32)`. runok now restores the default SIGPIPE handler at startup on Unix, so the process terminates on EPIPE the same way `yes | head` does. Other commands that print to stdout (for example `runok config-schema`) benefit from the same fix.

```sh
# Before: prints one JSON line, then a Rust panic + backtrace on stderr.
# After: prints one JSON line and exits silently.
runok audit --json | head -1
```

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
