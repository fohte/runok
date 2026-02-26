---
title: runok exec
description: Execute a command with permission checks and optional sandboxing.
sidebar:
  order: 3
---

`runok exec` evaluates a command against your runok rules and, if allowed, executes it — optionally within a sandbox.

## Usage

```sh
runok exec [options] -- <command> [arguments...]
```

The `--` separator is recommended to distinguish runok flags from the command's own flags.

## Flags

| Flag                 | Description                                                                       |
| -------------------- | --------------------------------------------------------------------------------- |
| `--sandbox <preset>` | Apply a named sandbox preset from your runok configuration.                       |
| `--dry-run`          | Show what would happen without executing the command. Always exits with code `0`. |
| `--verbose`          | Output detailed rule matching information to stderr.                              |

## Command input

- **Single argument** — Interpreted as a shell command (passed to the shell for execution).
- **Multiple arguments** — Interpreted as an argv array (executed directly without shell interpretation).

```sh
# Shell command (single argument)
runok exec -- 'echo hello && echo world'

# Argv (multiple arguments)
runok exec -- echo hello
```

## Behavior by decision

### Allow

The command is executed. If a sandbox is configured (via rule or `--sandbox`), the command runs within the sandbox. The exit code is the command's own exit code.

### Deny

The command is not executed. A message is printed to stderr:

```
runok: denied: <matched_rule>
  reason: <message>
  suggestion: <fix_suggestion>
```

The `reason` and `suggestion` lines are only shown when `message` or `fix_suggestion` are configured in the matching rule. See [Denial feedback](/cli/denial-feedback/) for details.

### Ask

Treated as deny in exec mode — the command is not executed.

## Dry-run mode

With `--dry-run`, runok evaluates the command against rules and prints diagnostic information to stderr, but does not execute anything. The exit code is always `0`.

## Exit codes

| Code | Meaning                                                        |
| ---- | -------------------------------------------------------------- |
| _N_  | Command's own exit code (on successful execution).             |
| `1`  | An error occurred (config error, sandbox setup failure, etc.). |
| `3`  | Command was denied or requires confirmation (ask).             |
