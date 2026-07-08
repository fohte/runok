---
title: runok pending-asks
description: Show ask commands from the audit log that are still resolved via defaults.action fallback under the current config.
sidebar:
  order: 10
---

`runok pending-asks` scans the audit log for `ask` decisions and re-evaluates each one against your **current** config. Only commands still falling back to `defaults.action` are shown -- ones already covered by an explicit `allow`/`deny` rule, or by an explicit `ask` rule you wrote on purpose, are excluded. Matching entries are grouped by their exact command string, so you can see at a glance which commands are asked (and approved) often enough to be worth turning into a rule.

## Usage

```sh
runok pending-asks [options]
```

## How a command counts as "pending"

For each `ask` entry in the audit log, `runok pending-asks`:

1. Loads the config that would apply from that entry's recorded working directory (the same global-plus-project discovery `runok check`/`runok exec` use), caching one load per distinct directory.
2. Re-evaluates the entry's raw command against that config.
3. Keeps the entry only if the result is still `ask` **and** no rule explicitly matched -- i.e. the decision came from `defaults.action`, not from a rule someone already added.

An entry whose result now resolves to `allow` or `deny`, or that matches an explicit `ask:` rule, is dropped: a rule already exists for it, so it isn't a candidate anymore.

An entry whose working directory is missing from the log, or whose config fails to load (e.g. a deleted worktree), cannot be re-evaluated. It is kept as pending rather than silently dropped -- hiding a command that may still need attention is worse than showing one that has already been resolved.

`when` clauses that read `env.*` are evaluated against the **current** process environment, not a historical snapshot -- the audit log only records the inline `KEY=VALUE` prefix of a command, not the full environment at ask time. Adding an `env`-dependent rule can therefore change how past entries re-evaluate depending on the environment `runok pending-asks` runs in.

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags). Only used to locate the audit log directory (`audit.path`); per-entry re-evaluation always uses each entry's own working directory for config discovery.

### `--since <timespec>`

Only consider `ask` entries after the given time. Accepts relative durations (`30m`, `1h`, `7d`) or absolute timestamps (`2026-03-01`, `2026-03-01T12:00:00Z`).

### `--until <timespec>`

Only consider `ask` entries before the given time. Same format as `--since`.

### `--command <pattern>`

Only consider entries whose command string contains the given substring.

### `--dir <path>`

Only consider entries recorded in the given working directory or its subdirectories. The path is resolved to its canonical (absolute, symlink-resolved) form before matching.

### `--limit <n>`

Maximum number of command groups to display, applied after grouping (not to the number of raw audit entries scanned).

**Default:** `50`

### `--json`

Output one JSON object per group (JSONL), suitable for piping into `jq` or into a tool that proposes rule changes.

## Examples

Show the top 50 pending ask commands (default):

```sh
runok pending-asks
```

Show pending commands asked in the last week, as JSON:

```sh
runok pending-asks --since 7d --json
```

Show pending `terraform` commands from a specific project:

```sh
runok pending-asks --command terraform --dir ~/projects/infra
```

## Output format

In text mode (default), the output adapts to the terminal:

- **TTY**: a column-aligned table, sorted by ask count (descending, then command ascending). Commands are truncated to fit the terminal width.

```
ASK_COUNT  APPROVED  FIRST_SEEN           LAST_SEEN            COMMAND
5          4         2026-06-20 09:00:00  2026-07-08 10:30:00  terraform apply
2          0         2026-07-01 14:00:00  2026-07-05 11:00:00  gh api -X POST repos/org/repo/dispatches
```

- **Non-TTY** (piped): tab-separated values, suitable for further processing.

In JSON mode (`--json`), each line is one group object:

```json
{
  "command": "terraform apply",
  "ask_count": 5,
  "approved_count": 4,
  "first_seen": "2026-06-20T09:00:00Z",
  "last_seen": "2026-07-08T10:30:00Z",
  "cwds": ["/home/user/projects/infra"]
}
```

| Field                      | Description                                                                                                                              |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `command`                  | The raw command string shared by every entry in the group.                                                                               |
| `ask_count`                | Number of `ask` decision entries for this command.                                                                                       |
| `approved_count`           | Of those, how many were approved by the user (see [tracking ask approvals](/getting-started/claude-code/#track-ask-approvals-optional)). |
| `first_seen` / `last_seen` | Timestamps (UTC) of the oldest and newest entry in the group.                                                                            |
| `cwds`                     | Distinct working directories the command was asked from, in first-seen order.                                                            |

`runok pending-asks` only reports the raw command strings and their counts -- it does not suggest a wildcard pattern, sandbox preset, or rule syntax. Deciding which pattern to `allow` (and how narrowly) is a judgment call left to the reader or to a downstream tool that consumes `--json`.

## Related

- [`runok audit`](/cli/audit/) -- View and filter raw audit log entries.
- [Audit Log JSON Schema](/cli/audit-log-schema/) -- Field-by-field reference for audit entries, including `ask_resolution` records.
- [Rule Evaluation](/rule-evaluation/overview/) -- How `defaults.action` and explicit rules interact.
