---
title: runok audit
description: View and filter audit log entries.
sidebar:
  order: 5
---

`runok audit` displays recorded audit log entries. Every `exec` and hook evaluation is logged automatically (unless disabled), and this subcommand lets you query those entries by time range, action, or command pattern.

## Usage

```sh
runok audit [options]
```

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags). The audit log directory is read from the loaded config's `audit.path`.

### `--action <allow|deny|ask>`

Filter entries by the evaluation result.

### `--since <timespec>`

Show only entries after the given time. Accepts relative durations (`30m`, `1h`, `7d`) or absolute timestamps (`2026-03-01`, `2026-03-01T12:00:00Z`).

### `--until <timespec>`

Show only entries before the given time. Same format as `--since`.

### `--command <pattern>`

Filter entries whose command string contains the given substring.

### `--dir <path>`

Filter entries by working directory. Only shows entries executed in the given directory or its subdirectories. The path is resolved to its canonical (absolute, symlink-resolved) form before matching.

### `--limit <n>`

Maximum number of entries to display.

**Default:** `50`

### `--json`

Output entries as JSON (one object per line). Useful for piping into `jq` or other tools.

## Examples

Show the last 50 audit log entries (default):

```sh
runok audit
```

Show denied commands from the last hour:

```sh
runok audit --action deny --since 1h
```

Show entries for `git` commands in JSON format:

```sh
runok audit --command git --json
```

Show entries from a specific date range with a custom limit:

```sh
runok audit --since 2026-03-01 --until 2026-03-07 --limit 100
```

## Output format

In text mode (default), the output adapts to the terminal:

- **TTY** (interactive terminal): a column-aligned table with colored action labels. Commands are truncated to fit the terminal width. Entries are sorted oldest-first so the most recent entry appears at the bottom.

```
TIMESTAMP            ACTION   COMMAND
2026-03-13 19:30:00  allow    git status
2026-03-13 19:31:00  deny     rm -rf /
```

- **Non-TTY** (piped): tab-separated values without colors or truncation, suitable for further processing.

Timestamps are displayed in local time in both modes.

In JSON mode (`--json`), each entry is a complete JSON object containing the command, action, matched rules, sandbox preset, metadata, sub-evaluations (for compound commands), and the shell-level parse result (`parsed`).

### `parsed` field

Single (non-compound) entries carry a top-level `parsed` field with runok's tokenisation result, so audit consumers can filter on the real binary without re-implementing shell parsing in `jq`. Compound entries omit the top-level `parsed`; each `sub_evaluations[]` entry carries its own `parsed` instead.

```json
{
  "command": "FOO=x helmfile -l name=alloy template",
  "parsed": {
    "env": [{ "name": "FOO", "value": "x" }],
    "argv": ["helmfile", "-l", "name=alloy", "template"]
  }
}
```

Fields:

- `env` -- Inline `KEY=VALUE` prefix. `value` is `null` for the bare `KEY= cmd` form. Omitted when empty.
- `argv` -- Command name plus arguments, with shell quotes resolved. `argv[0]` is the binary as written. Omitted when shell parsing could not produce an argv.
- `redirects` -- Redirect operators (`> file`, `2>&1`, `<<<` here-strings, `<<` here-docs, etc.). Each entry has `redirect_type` (`input`/`output`/`dup`), `operator` (the bare operator token; the here-doc delimiter and body are not captured), `target` (file or fd reference; empty for `<<` / `<<-`), and optional `descriptor`. Omitted when empty.
- `pipe` -- `{stdin, stdout}` flags indicating pipeline position. Omitted when both are `false`.

The whole `parsed` object itself is omitted when runok could not parse the input (e.g. unbalanced quotes); audit consumers can fall back to the raw `command` string.

Identifying the binary across compound or pipelined inputs (the original motivation for this field) becomes a one-liner:

```sh
runok audit --json | jq 'select(.parsed.argv[0] == "helmfile" or (.sub_evaluations // [])[].parsed.argv[0] == "helmfile")'
```

Per-CLI shaping (resolving `binary` vs `subcommand`, normalising `mise` shims, classifying `-n` as boolean vs value-taking) is intentionally left to the consumer because those rules differ per CLI.

## Configuration

Audit logging is configured in the **global** `runok.yml` only. Audit settings in project or local override configs are ignored. See [Configuration Schema](/configuration/schema/#audit) for the full reference.

```yaml title="~/.config/runok/runok.yml"
audit:
  enabled: true
  path: ~/.local/share/runok/
  rotation:
    retention_days: 7
```

## Log storage

Audit entries are stored as JSONL files partitioned by date (`audit-YYYY-MM-DD.jsonl`) in the configured directory. Files are written with append-mode and file locking, so concurrent runok invocations are safe.

Old log files are automatically removed based on `rotation.retention_days`.

## Related

- [Configuration Schema — `audit`](/configuration/schema/#audit) -- Full audit config reference.
- [`runok exec`](/cli/exec/) -- Commands evaluated via `exec` are logged.
