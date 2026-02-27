---
title: runok check
description: Check whether a command would be allowed by runok rules without executing it.
sidebar:
  order: 2
---

`runok check` evaluates a command against your runok rules and reports the decision — without actually running the command.

## Usage

```sh
# Pass command as arguments
runok check <command> [arguments...]

# Read from stdin (plaintext)
echo "git push" | runok check

# Read from stdin (JSON)
echo '{"command":"git push"}' | runok check

# Multiple commands (one per line)
printf "git push\nnpm publish\n" | runok check
```

## Flags

| Flag                       | Description                                                                   |
| -------------------------- | ----------------------------------------------------------------------------- |
| `--input-format <format>`  | Input format. Currently supports `claude-code-hook`. Omit for auto-detection. |
| `--output-format <format>` | Output format: `text` (default) or `json`.                                    |
| `--verbose`                | Output detailed rule matching information to stderr.                          |

## Input formats

### Command-line arguments

When arguments are provided after `runok check`, they are used directly as the command to evaluate. Stdin is not read.

```sh
runok check git push --force
```

### Stdin auto-detection

When no command arguments are given, runok reads from stdin and auto-detects the format:

1. **JSON object with `tool_name` field** — Treated as a Claude Code hook input (`claude-code-hook` format). Only `Bash` tool events are evaluated; other tools are skipped.
2. **JSON object with `command` field** — Treated as a generic check input.
3. **Non-JSON or non-object JSON** — Treated as plaintext. Each line is evaluated as a separate command (empty lines and whitespace are trimmed/skipped).

Use `--input-format claude-code-hook` to force Claude Code hook parsing. If `--input-format` is specified but stdin is not valid JSON, a parse error is returned.

### Plaintext mode

In plaintext mode, each non-empty line is evaluated as a separate command:

- A single line produces a single check result.
- Multiple lines produce multiple check results, and the exit code is the highest (worst) among them.

## Output formats

### Text (default)

```
allow
```

```
deny: Do not delete root (suggestion: rm -rf ./build)
```

The text format includes the decision, optional reason, and optional fix suggestion.

### JSON

```json
{
  "decision": "deny",
  "reason": "Do not delete root",
  "fix_suggestion": "rm -rf ./build"
}
```

Fields with no value (`reason`, `fix_suggestion`, `sandbox`) are omitted from the JSON output.

When a sandbox is configured for the matched rule:

```json
{
  "decision": "allow",
  "sandbox": {
    "preset": "strict",
    "writable_roots": ["/tmp"],
    "network_allowed": false
  }
}
```

## Exit codes

| Code | Meaning                                                         |
| ---- | --------------------------------------------------------------- |
| `0`  | Evaluation completed successfully (regardless of the decision). |
| `2`  | An error occurred (config error, JSON parse error, etc.).       |

The exit code reflects whether the check itself succeeded, not the permission decision. A `deny` result still returns exit code `0`. Use `--output-format json` to programmatically inspect the decision.

When checking multiple commands (multi-line plaintext), the exit code is the highest value across all evaluations.
