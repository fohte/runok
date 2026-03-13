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

### `--action <allow|deny|ask>`

Filter entries by the evaluation result.

### `--since <timespec>`

Show only entries after the given time. Accepts relative durations (`30m`, `1h`, `7d`) or absolute timestamps (`2026-03-01`, `2026-03-01T12:00:00Z`).

### `--until <timespec>`

Show only entries before the given time. Same format as `--since`.

### `--command <pattern>`

Filter entries whose command string contains the given substring.

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

In text mode (default), each entry is printed as:

```
2026-03-13T10:30:00Z [allow] git status
2026-03-13T10:31:00Z [deny] rm -rf /
```

In JSON mode (`--json`), each entry is a complete JSON object containing the command, action, matched rules, sandbox preset, metadata, and sub-evaluations (for compound commands).

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
