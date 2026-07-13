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

Maximum number of records to display. In JSON mode, decision entries and `ask_resolution` records count toward the same limit.

**Default:** `50`

### `--json`

Output entries as JSON (one object per line). Useful for piping into `jq` or other tools.

### `--recheck`

Re-evaluate each displayed entry's `command` against the config currently in effect, and annotate the output with the result. This is an **annotation, not a filter** -- it never changes which entries are shown, and composes freely with `--action`, `--since`, `--dir`, and the other filters above.

An audit entry's recorded `action` and `matched_rules` are a snapshot from when the entry was decided. If rules were added, removed, or edited since then, the recorded snapshot no longer reflects how the command would be evaluated today. `--recheck` answers "what would happen now?" without requiring you to re-run the command.

Config is loaded from each entry's own `metadata.cwd` (the same global-plus-project discovery every other runok subcommand uses), so entries from different projects are re-evaluated against their own config. Entries with no recorded `cwd`, or whose config fails to load, are still shown (fail-open) with the recheck result marked as an error rather than being silently dropped.

The `env` used for `when`-clause evaluation is the _current_ process environment, not a snapshot from when the entry was decided -- the audit log does not record one. Rules whose `when` clause reads `env.*` may re-evaluate differently than they did at decision time.

In TTY and non-TTY text mode, `--recheck` adds a NOW column next to ACTION, showing the current result: `allow`, `deny`, `ask`, `ask-def` for an `ask` resolved purely via `defaults.action` fallback rather than an explicit rule, or `error` when the entry could not be re-evaluated (see above). In JSON mode, each entry gets a `recheck` object -- see [`recheck`](/cli/audit-log-schema/#recheck) for the full field reference.

A common use of `--recheck` is finding `ask` entries that are still `ask` today, to decide which ones are worth turning into an `allow` rule:

```sh
runok audit --action ask --recheck --json \
  | jq 'select(.recheck.action.type == "ask")'
```

Narrow further to asks resolved purely via `defaults.action` fallback (no explicit `ask` rule matched):

```sh
runok audit --action ask --recheck --json \
  | jq 'select(.recheck.command_evaluations | any(.matched_rules == null))'
```

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

Show `ask` entries alongside how they would evaluate against the current config:

```sh
runok audit --action ask --recheck
```

## Output format

In text mode (default), the output adapts to the terminal:

- **TTY** (interactive terminal): a column-aligned table with colored action labels. Commands are truncated to fit the terminal width. Entries are sorted oldest-first so the most recent entry appears at the bottom.

```
TIMESTAMP            ACTION   COMMAND
2026-03-13 19:30:00  allow    git status
2026-03-13 19:31:00  deny     rm -rf /
2026-03-13 19:32:00  ask ✓    terraform apply
```

- **Non-TTY** (piped): tab-separated values without colors or truncation, suitable for further processing.

Timestamps are displayed in local time in both modes.

An `ask` entry whose approval was recorded (see [tracking ask approvals](/getting-started/claude-code/#track-ask-approvals-optional)) is shown as `ask ✓` in both modes. An unmarked `ask` means "denied or not yet decided" — denials cannot be observed. With `--recheck` (see above), both text modes gain a NOW column showing the current re-evaluation result.

In JSON mode (`--json`), each line is a complete JSON object: decision entries and `ask_resolution` records (when ask-approval tracking is enabled) are emitted as-is, merged into one timestamp-ordered stream. Every `ask` decision entry additionally carries an `approved` boolean (the same join used for `ask ✓` in text mode, so consumers do not have to re-implement the `ask_resolution` correlation logic); non-`ask` entries omit the field. With `--recheck`, every decision entry additionally carries a `recheck` object with the current re-evaluation result. Neither field is part of the on-disk audit-log schema -- both are computed only for this command's output. The full field-by-field reference -- including every enum value and every "omitted when empty" condition -- lives on a dedicated page: see [Audit Log JSON Schema](/cli/audit-log-schema/).

The most common shape worth knowing here: each entry exposes a `command_evaluations` array with one entry per shell command extracted from the input. Single inputs produce one entry, compound (`a && b`) and pipelined (`a | b`) inputs produce one per branch in source order, and inputs with no runnable command (comment-only, parse failure) produce an empty array. Each entry carries the rule-evaluation result (`action`, `matched_rules`) and the shell-level parse result (`env`, `argv`, `redirects`, `pipe`) side by side, so audit consumers can filter on the actual binary in one `jq` line:

```sh
runok audit --json | jq 'select(.command_evaluations[].argv[0] == "helmfile")'
```

See [`command_evaluations`](/cli/audit-log-schema/#command_evaluations) for the full per-entry field reference.

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

- [Audit Log JSON Schema](/cli/audit-log-schema/) -- Field-by-field reference for `runok audit --json` output.
- [Configuration Schema — `audit`](/configuration/schema/#audit) -- Full audit config reference.
- [`runok exec`](/cli/exec/) -- Commands evaluated via `exec` are logged.
