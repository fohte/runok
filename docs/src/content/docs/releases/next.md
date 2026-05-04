---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Highlights

### Breaking: parent command text now uses placeholders for command substitutions

Compound commands that pass a heredoc through a command substitution — most commonly `git commit -m "$(cat <<'EOF' ... EOF)"` produced by Claude Code's `/commit` flow — used to fall back to `defaults.action` because the heredoc body's bytes were folded into the parent command's text and re-tokenized, raising `unclosed quote` whenever the body contained a `'` or `"`.

The parent command text now collapses each command substitution to its opening/closing markers (`$(...)` → `$()`, backtick form → empty backticks), so the body never reaches the parent tokenizer. The substitution body is still extracted as its own sub-command and evaluated independently.

Quoted-delimiter heredocs (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) are also now treated as literal text, matching bash semantics: any `$(...)` inside a quoted-delimiter body is no longer extracted as a command substitution.

**What should I do?**

Rules that did not reference the inside of `$(...)` (e.g. `'git commit -m *'`) are unaffected — `$()` still tokenizes as a single argument and matches a `*` slot.

Rules that did embed a sub-pattern inside the substitution must be split into two rules: one for the parent (using the empty placeholder) and one for the inner command (matched independently as a sub-command).

```yaml title="runok.yml"
# Before: relied on the substitution body being visible in the parent text
rules:
  - allow: 'echo $(secret_lookup *)'

# After: parent matches the placeholder; the inner command is matched as its own sub-command
rules:
  - allow: 'echo $()'
  - allow: 'secret_lookup *'
```

## Bug Fixes

### `runok check --input-format claude-code-hook` no longer blocks Claude Code on runok-side failures

In hook mode, the following runok-side failures now exit with code `1` instead of `2`: config load errors, rule pattern parse errors, unknown-flag errors, stdin JSON parse errors, and `HookInput` schema mismatches. Previously, any of these would cause every Bash tool call in Claude Code to be blocked, because Claude Code treats exit `2` from a `PreToolUse` hook as a blocking error. Exit `1` is the documented non-blocking failure mode and lets Claude Code fall back to its normal permission flow until the underlying issue is fixed.

Direct CLI usage (`runok check` without `--input-format claude-code-hook`) is unchanged.

See [`runok check` exit codes](/cli/check/) for details.

## New Features

### Global `--config` / `-c` flag ([#315](https://github.com/fohte/runok/pull/315))

All subcommands now accept a `-c` / `--config` flag to load a specific config file instead of the default config discovery (global + project). The flag can appear before or after the subcommand name.

```sh
runok check -c readonly-gh.yml -- gh api graphql
runok -c custom.yml exec -- npm test
runok test -c my-rules.yml
```

This replaces the previous per-subcommand `--config` flags on `runok test` and `runok migrate`. The flag now works identically on all subcommands including `check` and `exec`.

See [Global Flags](/cli/overview/#global-flags) for details.
