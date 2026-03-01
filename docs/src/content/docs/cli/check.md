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

When no command arguments are given, runok reads from stdin instead. The input format is auto-detected: JSON objects are parsed by field (`tool_name` for Claude Code hooks, `command` for generic checks), and anything else is treated as plaintext with one command per line.

Use `--input-format claude-code-hook` to force Claude Code hook parsing.

## Flags

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

Read commands from stdin (one per line):

```sh
printf "git push\nnpm publish\n" | runok check
# allow
# deny: Publishing is not allowed
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
