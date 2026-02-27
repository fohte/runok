---
title: runok exec
description: Execute a command with permission checks and optional sandboxing.
sidebar:
  order: 3
---

`runok exec` evaluates a command against your runok rules and, if allowed, executes it — optionally within a sandbox. If the command is denied (or requires confirmation), it is not executed and exit code `3` is returned.

## Usage

```sh
runok exec [options] -- <command> [arguments...]
```

The `--` separator distinguishes runok flags from the command's own flags.

A single argument after `--` is interpreted as a shell command (passed to the shell). Multiple arguments are interpreted as an argv array (executed directly).

## Flags

### `--sandbox <preset>`

Apply a named sandbox preset from your runok configuration. Overrides any sandbox defined in the matching rule.

### `--dry-run`

Show what would happen without executing the command. Prints diagnostic information to stderr and always exits with code `0`.

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

Preview what would happen without executing:

```sh
runok exec --dry-run -- git push --force
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
