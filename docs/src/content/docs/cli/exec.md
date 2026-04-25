---
title: runok exec
description: Execute a command with permission checks and optional sandboxing.
sidebar:
  order: 3
---

`runok exec` evaluates a command against your runok rules and, if allowed, executes it — [optionally within a sandbox](/sandbox/overview/). If the command is denied (or requires confirmation), it is not executed and exit code `3` is returned.

## Usage

```sh
runok exec [options] -- <command> [arguments...]
```

The `--` separator distinguishes runok flags from the command's own flags. Any unrecognized flag before `--` is rejected with an error to prevent typos from being silently absorbed into the command arguments.

A single argument after `--` is interpreted as a shell command (passed to the shell). Multiple arguments are interpreted as an argv array (executed directly).

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags).

### `--sandbox <preset>`

Apply a named [sandbox preset](/sandbox/overview/) from your runok configuration. Overrides any sandbox defined in the matching rule.

### `--verbose`

Output detailed rule matching information to stderr.

## Examples

Execute a command with permission checks:

```sh
runok exec -- npm test
```

Execute with a sandbox preset:

```sh
runok exec --sandbox strict -- npm install
```

Run a shell expression (single argument, passed to shell):

```sh
runok exec -- 'echo hello && echo world'
```

## Exit codes

| Code | Meaning                                                        |
| ---- | -------------------------------------------------------------- |
| _N_  | Command's own exit code (on successful execution).             |
| `1`  | An error occurred (config error, sandbox setup failure, etc.). |
| `3`  | Command was denied or requires confirmation (ask).             |

## Related

- [`runok check`](/cli/check/) -- Evaluate commands without executing them.
- [Sandbox](/sandbox/overview/) -- Configure sandbox presets.
- [Denial Feedback](/configuration/denial-feedback/) -- Configure feedback for denied commands.
