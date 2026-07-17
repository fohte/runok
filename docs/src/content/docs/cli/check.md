---
title: runok check
description: Check whether a command would be allowed by runok rules without executing it.
sidebar:
  order: 2
---

`runok check` evaluates a command against your runok rules and reports the decision — without actually running the command. Useful for previewing what runok would do, for CI, or for scripting.

:::note[Looking for the Claude Code hook integration?]
Use [`runok hook`](/cli/hook/) instead. `check --input-format claude-code-hook` still works for backward compatibility, but it's deprecated in favor of a dedicated command — see [Migrating from `runok check --input-format claude-code-hook`](/cli/hook/#migrating-from-runok-check---input-format-claude-code-hook).
:::

## Usage

```sh
runok check [options] -- <command> [arguments...]
```

Any unrecognized flag before `--` is rejected with an error to prevent typos from being silently absorbed into the command arguments.

When no command arguments are given, runok reads from stdin instead. The input format is auto-detected: JSON objects are parsed by field (`tool_name` for the deprecated Claude Code hook mode, `command` for generic checks), and anything else is treated as plaintext shell input.

Plaintext stdin is split into individual commands at top-level shell statement boundaries (newlines, `;`, and `&` between top-level statements). Constructs that legitimately span multiple lines — HEREDOCs, multi-line quoted strings, and `\` line continuations — are kept together as a single command. Compound commands joined by `&&`, `||`, or `|` also stay together (the rule engine splits those further internally). Stdin that cannot be parsed as shell exits with `stdin parse error`.

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags).

### `--input-format <format>`

Input format for stdin. Currently supports `claude-code-hook` (deprecated, use [`runok hook`](/cli/hook/) instead). When omitted, the format is auto-detected from the stdin content. Has no effect when command arguments are provided.

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

Force the deprecated Claude Code hook format (use [`runok hook`](/cli/hook/) for new setups):

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

### Hook mode (`--input-format claude-code-hook`) [deprecated]

`--input-format claude-code-hook` shares [`runok hook`](/cli/hook/#event-dispatch)'s `PreToolUse`/`PostToolUse` dispatch, response format, and non-blocking (`exit 1` instead of `2`) error handling — see that page for the full reference. One difference remains for backward compatibility: this mode predates the "any other event is a no-op" behavior `runok hook` added, so a `hook_event_name` other than `PreToolUse`/`PostToolUse` still falls through to rule evaluation here instead of being ignored.

It's kept working for existing `settings.json` registrations, but new setups should use `runok hook` directly; `check` is documented above as a read-only evaluation command, which the `PostToolUse` audit write contradicts. Every invocation prints a deprecation warning to stderr (stdout is left untouched, since it carries the hook response). Run [`runok migrate`](/cli/migrate/#claude-code-legacy-hook-command) to rewrite an existing `settings.json` registration to `runok hook --agent claude-code`.

Direct CLI usage (without `--input-format claude-code-hook`) is unaffected and still exits `2` on errors.
