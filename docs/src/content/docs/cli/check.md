---
title: runok check
description: Check whether a command would be allowed by runok rules without executing it.
sidebar:
  order: 2
---

`runok check` evaluates a command against your runok rules and reports the decision — without actually running the command. Useful for previewing what runok would do, or for integrating with external tools like [Claude Code hooks](/getting-started/claude-code/).

## Usage

```sh
runok check [options] -- <command> [arguments...]
```

Any unrecognized flag before `--` is rejected with an error to prevent typos from being silently absorbed into the command arguments.

When no command arguments are given, runok reads from stdin instead. The input format is auto-detected: JSON objects are parsed by field (`tool_name` for Claude Code hooks, `command` for generic checks), and anything else is treated as plaintext shell input.

Plaintext stdin is split into individual commands at top-level shell statement boundaries (newlines, `;`, and `&` between top-level statements). Constructs that legitimately span multiple lines — HEREDOCs, multi-line quoted strings, and `\` line continuations — are kept together as a single command. Compound commands joined by `&&`, `||`, or `|` also stay together (the rule engine splits those further internally). Stdin that cannot be parsed as shell exits with `stdin parse error`.

Use `--input-format claude-code-hook` to force Claude Code hook parsing.

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags).

### `--input-format <format>`

Input format for stdin. Currently supports `claude-code-hook`. When omitted, the format is auto-detected from the stdin content. Has no effect when command arguments are provided.

### `--output-format <format>` [default: `text`]

Output format. Available values:

- `text` — Human-readable single line (e.g., `deny: reason (suggestion: fix)`)
- `json` — Machine-readable JSON object with `decision`, `reason`, `fix_suggestion`, and `sandbox` fields. Fields with no value are omitted.

### `--verbose`

Output detailed rule matching information to stderr.

## Examples

Check a single command:

```sh
runok check -- git push --force
# deny: Blocked to prevent rewriting remote history (suggestion: git push)
```

Check with JSON output:

```sh
runok check --output-format json -- rm -rf /
```

```json
{
  "decision": "deny",
  "reason": "Do not delete root",
  "fix_suggestion": "rm -rf ./build"
}
```

Read commands from stdin (split at shell statement boundaries):

```sh
printf "git push\nnpm publish\n" | runok check
# allow
# deny: Publishing is not allowed
```

Multi-line constructs are evaluated as a single command:

```sh
cat <<'OUTER' | runok check
git add path && git commit -m "$(cat <<'EOF'
subject
body
EOF
)"
OUTER
# allow
```

Read from stdin as JSON:

```sh
echo '{"command":"git push"}' | runok check
# allow
```

Force Claude Code hook format:

```sh
cat hook-input.json | runok check --input-format claude-code-hook
# allow [sandbox: default]
```

## Exit codes

| Code | Meaning                                                         |
| ---- | --------------------------------------------------------------- |
| `0`  | Evaluation completed successfully (regardless of the decision). |
| `2`  | An error occurred (config error, JSON parse error, etc.).       |

The exit code reflects whether the check itself succeeded, not the permission decision. A `deny` result still returns exit code `0`. Use `--output-format json` to programmatically inspect the decision.

When checking multiple commands (multi-line stdin), the exit code is the highest value across all evaluations.

### Hook mode (`--input-format claude-code-hook`)

The hook input's `hook_event_name` field selects what runok does:

- **`PreToolUse`** (or absent): evaluate the command against the rules and print the permission decision, as described above.
- **`PostToolUse`**: no rule evaluation. runok records an `ask_resolution` record in the audit log when the tool call corresponds to an `ask` decision it made at PreToolUse time (i.e. the user approved the permission dialog). Nothing is written to stdout, and once the event is dispatched the exit code is always `0` — the command has already run, so failures must not disturb the session. The hook-mode failures listed below (config load errors, input parse errors) happen before the event is dispatched and exit `1` as usual. See [tracking ask approvals](/getting-started/claude-code/#track-ask-approvals-optional).

In hook mode, the following runok-side failures exit with code `1` instead of `2`:

- Config load errors (YAML syntax errors, etc.)
- Rule pattern parse errors caught during evaluation
- Unknown-flag errors for `runok check`
- Stdin JSON parse errors
- `HookInput` schema mismatches (e.g. when Claude Code adds a new required field)

Claude Code treats exit `2` from a `PreToolUse` hook as a blocking error, so any of these would otherwise block every Bash tool call until runok or the config catches up. Exit `1` is the documented non-blocking failure mode that lets Claude Code fall back to its normal permission flow.

Direct CLI usage (without `--input-format claude-code-hook`) is unchanged and still exits `2` on errors.
