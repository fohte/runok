---
title: Audit Log JSON Schema
description: Field reference for runok audit --json output.
sidebar:
  order: 6
---

This page is the field-by-field reference for the JSON objects produced by [`runok audit --json`](/cli/audit/#--json) (one object per line, JSONL). Use it to write `jq` queries against audit logs without reading the runok source.

The output contains two record types, distinguished by the `kind` field:

- **Decision entries** ([Top-Level Object](#top-level-object)) have no `kind` field. One is written per evaluation.
- **Ask resolution records** ([Ask Resolution Record](#ask-resolution-record)) have `kind: "ask_resolution"`. One is written when the user approves an `ask` decision in the agent's permission dialog (requires the opt-in PostToolUse hook).

`jq` queries that only want decision entries can filter with `select(.kind == null)`.

## Top-Level Object

Every decision-entry line of `runok audit --json` output is one `AuditEntry` object with the fields listed below.

Example entry:

```json
{
  "timestamp": "2026-03-13T19:31:00.090565+00:00",
  "command": "git push -f origin main",
  "action": {
    "type": "deny",
    "detail": {
      "message": "force push is forbidden",
      "fix_suggestion": "git push origin main"
    }
  },
  "sandbox_preset": null,
  "default_action": "ask",
  "metadata": {
    "endpoint_type": "hook",
    "session_id": "abc-123",
    "cwd": "/home/user/project",
    "tool_name": "Bash",
    "hook_event_name": "PreToolUse",
    "tool_use_id": "toolu_01AbCdEfGh"
  },
  "command_evaluations": [
    {
      "command": "git push -f origin main",
      "action": {
        "type": "deny",
        "detail": {
          "message": "force push is forbidden",
          "fix_suggestion": "git push origin main"
        }
      },
      "matched_rules": [
        {
          "action_kind": "deny",
          "pattern": "git push -f|--force *",
          "matched_tokens": ["origin", "main"]
        }
      ],
      "eval_type": "primary",
      "argv": ["git", "push", "-f", "origin", "main"]
    }
  ]
}
```

### `timestamp`

RFC 3339 timestamp in UTC, with sub-second precision and a `+00:00` offset (e.g. `2026-03-13T19:31:00.090565+00:00`), recording when the evaluation was performed. Note that the offset is written as `+00:00`, not `Z` -- `jq` literal-string comparisons (`select(.timestamp >= "...")`) need to use the same form.

**Type:** `str`\
**Always present:** Yes

### `command`

The input command string exactly as runok received it, before any shell parsing or compound-command splitting. For compound input this is the whole expression (`a && b`); for single input this is the same string as `command_evaluations[0].command`.

**Type:** `str`\
**Always present:** Yes

### `action`

Final evaluation result for the input as a whole. For compound input, this is the aggregated decision across all branches (the strictest result wins: any `deny` makes the whole input `deny`, etc.). See [Action Object](#action-object) for the shape.

**Type:** [`Action`](#action-object)\
**Always present:** Yes

### `sandbox_preset`

Name of the sandbox preset that was applied to this evaluation. `null` when no sandbox was applied **or** when multiple presets were merged (compound input where different branches matched different presets -- the merged policy has no single canonical preset name). The preset name, when present, corresponds to a key under [`definitions.sandbox`](/configuration/schema/#definitionssandbox). See [Sandbox merging for compound commands](/sandbox/overview/#sandbox-merging-for-compound-commands).

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `default_action`

The configured `defaults.action` value at the time of evaluation. `null` when no default was configured. See [`defaults.action`](/configuration/schema/#defaultsaction) for the possible values.

**Type:** `"allow" | "ask" | "deny" | null`\
**Always present:** Yes (may be `null`)

### `metadata`

Session and context information about the invocation. See [Metadata Object](#metadata-object).

**Type:** [`Metadata`](#metadata-object)\
**Always present:** Yes

### `command_evaluations`

Per-branch evaluation records, in source order. One entry per shell command extracted from `command`:

- A non-compound input (e.g. `git status`) produces exactly one entry with `eval_type: "primary"`.
- A compound or pipelined input (e.g. `a && b`, `a || b`, `a ; b`, `a | b`) produces one entry per branch, all with `eval_type: "compound"`.
- An input with no runnable command (comment-only, parse error) produces an empty array.

Each entry carries the rule-evaluation result (`action`, `matched_rules`) and the shell-level parse result (`env`, `argv`, `redirects`, `pipe`) side by side, so audit consumers can filter on the actual binary in one `jq` line:

```sh
runok audit --json | jq 'select(.command_evaluations[].argv[0] == "helmfile")'
```

See [CommandEvaluation Object](#commandevaluation-object) for the shape of each entry.

**Type:** [`list[CommandEvaluation]`](#commandevaluation-object)\
**Always present:** Yes (may be empty)

## Action Object

Represents an evaluation result. The `type` field is a discriminator; `detail` is omitted for `allow`, and present (with type-specific keys) for `deny` and `ask`.

```json
// allow
{ "type": "allow" }

// deny
{
  "type": "deny",
  "detail": {
    "message": "force push is forbidden",
    "fix_suggestion": "git push origin main"
  }
}

// ask
{ "type": "ask", "detail": { "message": "are you sure?" } }
```

When no rule matches, the configured [`default_action`](#default_action) is applied directly: `type` is `"allow"`, `"deny"`, or `"ask"` accordingly. There is no separate `"default"` discriminator in the audit-log JSON.

### `type`

The kind of action.

**Type:** `"allow" | "deny" | "ask"`\
**Always present:** Yes

| Value   | Meaning                                 |
| ------- | --------------------------------------- |
| `allow` | The command is permitted.               |
| `deny`  | The command is rejected.                |
| `ask`   | The command requires user confirmation. |

### `detail.message`

Optional message attached to the rule. For `deny` actions this is the rule's `message` (see [Denial Feedback](/configuration/denial-feedback/)); for `ask` actions this is the prompt shown to the user.

**Type:** `str | null`\
**Present when:** `type` is `deny` or `ask`. The value may be `null` when the rule did not set `message`.

### `detail.fix_suggestion`

Optional fix-suggestion attached to a `deny` rule. See [Denial Feedback](/configuration/denial-feedback/).

**Type:** `str | null`\
**Present when:** `type` is `deny`. The value may be `null` when the rule did not set `fix_suggestion`.

## Metadata Object

```json
{
  "endpoint_type": "hook",
  "session_id": "abc-123",
  "cwd": "/home/user/project",
  "tool_name": "Bash",
  "hook_event_name": "PreToolUse",
  "tool_use_id": "toolu_01AbCdEfGh"
}
```

### `endpoint_type`

Which runok subcommand recorded this entry. Audit consumers can use this to distinguish hook invocations from explicit `runok exec` runs.

**Type:** `"exec" | "hook"`\
**Always present:** Yes

| Value  | Source                                                                            |
| ------ | --------------------------------------------------------------------------------- |
| `exec` | The user invoked [`runok exec`](/cli/exec/) directly.                             |
| `hook` | An AI coding agent's tool-use hook (e.g. Claude Code `PreToolUse`) invoked runok. |

[`runok check`](/cli/check/) is a dry-run evaluator and does not write audit log entries, so it never appears here.

### `session_id`

Session identifier supplied by the calling environment, when available. For hook invocations from Claude Code, this is the Claude Code session ID. `null` when no session ID was provided.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `cwd`

Working directory at the time of evaluation. `null` when the working directory could not be determined.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `tool_name`

Hook-specific: name of the tool the agent was about to run (e.g. `Bash`, `Read`). `null` when `endpoint_type` is not `hook`.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `hook_event_name`

Hook-specific: name of the hook event (e.g. `PreToolUse`). `null` when `endpoint_type` is not `hook`.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `tool_use_id`

Hook-specific: ID of the tool call this evaluation belongs to, as supplied by the agent. The agent sends the same `tool_use_id` to the PreToolUse and PostToolUse hooks of one tool call, so this is the correlation key between an `ask` decision entry and its [Ask Resolution Record](#ask-resolution-record). `null` when `endpoint_type` is not `hook`, and in entries written before this field existed.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

## Ask Resolution Record

Written when the user approves an `ask` decision in the agent's permission dialog. Recording these requires the opt-in PostToolUse hook (see [Claude Code Integration](/getting-started/claude-code/#track-ask-approvals-optional)); without it, no `ask_resolution` records appear.

Denials cannot be observed (see [Claude Code Integration](/getting-started/claude-code/#track-ask-approvals-optional) for why), so an `ask` entry without a resolution record means "denied or not yet decided", not "denied".

```json
{
  "kind": "ask_resolution",
  "timestamp": "2026-03-13T19:32:10.512345+00:00",
  "outcome": "approved",
  "tool_use_id": "toolu_01AbCdEfGh",
  "session_id": "abc-123",
  "cwd": "/home/user/project",
  "command": "terraform apply",
  "executed_command": "runok exec --sandbox restricted -- 'terraform apply'"
}
```

### `kind`

Record type discriminator. Always the literal `"ask_resolution"`. Decision entries have no `kind` field.

**Type:** `"ask_resolution"`\
**Always present:** Yes

### `timestamp`

RFC 3339 timestamp in UTC of the approval (when the PostToolUse hook fired), in the same format as the decision-entry [`timestamp`](#timestamp).

**Type:** `str`\
**Always present:** Yes

### `outcome`

How the ask was resolved. Currently always `"approved"`.

**Type:** `"approved"`\
**Always present:** Yes

### `tool_use_id`

Tool use ID of the approved tool call, matching [`metadata.tool_use_id`](#tool_use_id) of the correlated `ask` decision entry. `null` when neither the hook input nor the correlated entry carried a `tool_use_id`; correlation then fell back to session + command matching.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `session_id`

Session ID from the PostToolUse hook input.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `cwd`

Working directory from the PostToolUse hook input.

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

### `command`

The original command, copied from the correlated `ask` decision entry. The record is self-contained: aggregating approvals by command needs no join back to decision entries.

**Type:** `str`\
**Always present:** Yes

### `executed_command`

The command the agent actually executed (`tool_input.command` of the PostToolUse input). Differs from [`command`](#command-1) when the PreToolUse response rewrote the command via `updatedInput` — with runok that happens for [sandbox wrapping](/getting-started/claude-code/#sandbox-execution), producing the `runok exec --sandbox <preset> -- '<command>'` form.

**Type:** `str`\
**Always present:** Yes

## CommandEvaluation Object

One entry per shell command extracted from the input. Higher-level shaping (resolving `binary` vs `subcommand`, normalising `mise` shims, classifying `-n` as boolean vs value-taking) is intentionally not done here because those rules differ per CLI and belong to the audit consumer.

```json
{
  "command": "FOO=x echo hi > /tmp/log",
  "action": { "type": "allow" },
  "eval_type": "compound",
  "env": [{ "name": "FOO", "value": "x" }],
  "argv": ["echo", "hi"],
  "redirects": [
    {
      "redirect_type": "output",
      "operator": ">",
      "target": "/tmp/log",
      "descriptor": null
    }
  ],
  "pipe": { "stdin": false, "stdout": true }
}
```

### `command`

The branch command as runok extracted it, with redirects stripped but the inline env prefix kept. For `eval_type: "primary"` entries this is identical to the top-level [`command`](#command).

**Type:** `str`\
**Always present:** Yes

### `action`

Rule-evaluation result for this branch. See [Action Object](#action-object).

**Type:** [`Action`](#action-object)\
**Always present:** Yes

### `matched_rules`

Rules that matched for this branch, in match order. See [RuleMatch Object](#rulematch-object).

**Type:** [`list[RuleMatch]`](#rulematch-object)\
**Omitted when empty.**

### `eval_type`

How this branch was extracted from the input.

**Type:** `"primary" | "compound"`\
**Always present:** Yes

| Value      | Meaning                                                                                      |
| ---------- | -------------------------------------------------------------------------------------------- |
| `primary`  | Non-compound input. The single entry covers the whole input.                                 |
| `compound` | One branch of a compound or pipelined input (`a && b`, `a \|\| b`, `a ; b`, `a \| b`, etc.). |

### `env`

Inline `KEY=VALUE` env prefix attached to this branch. See [EnvVar Object](#envvar-object).

**Type:** [`list[EnvVar]`](#envvar-object)\
**Omitted when empty.**

### `argv`

Command name plus arguments, with shell quoting resolved. `argv[0]` is the binary as written. Empty (and therefore omitted) when shell parsing could not produce an argv (AST leaf-text fallback path).

**Type:** `list[str]`\
**Omitted when empty.**

### `redirects`

Redirect operators attached to this branch. See [Redirect Object](#redirect-object).

**Type:** [`list[Redirect]`](#redirect-object)\
**Omitted when empty.**

### `pipe`

Pipeline position of this branch. See [Pipe Object](#pipe-object).

**Type:** [`Pipe`](#pipe-object)\
**Omitted when both `stdin` and `stdout` are `false`** (i.e. the branch is not part of a pipeline).

## RuleMatch Object

```json
{
  "action_kind": "deny",
  "pattern": "git push -f|--force *",
  "matched_tokens": ["origin", "main"]
}
```

### `action_kind`

The kind of rule that matched.

**Type:** `"allow" | "ask" | "deny"`\
**Always present:** Yes

### `pattern`

The rule pattern string as written in `runok.yml`. See [Pattern Syntax](/pattern-syntax/overview/).

**Type:** `str`\
**Always present:** Yes

### `matched_tokens`

Tokens the wildcard portion of the pattern captured. For example, the pattern `git push -f|--force *` matched against `git push -f origin main` yields `["origin", "main"]`. Empty for patterns with no wildcards.

**Type:** `list[str]`\
**Always present:** Yes (may be empty)

## EnvVar Object

```json
{ "name": "FOO", "value": "x" }
```

### `name`

Variable name.

**Type:** `str`\
**Always present:** Yes

### `value`

Variable value with shell quotes resolved. `null` for the bare `KEY= cmd` form (which clears the variable in the child process's environment).

**Type:** `str | null`\
**Always present:** Yes (may be `null`)

## Redirect Object

Captures redirect operators (`> file`, `2>&1`, `<<<` here-strings, `<<` here-docs, etc.). The here-doc delimiter and body are not captured — only the operator itself.

```json
{
  "redirect_type": "output",
  "operator": ">",
  "target": "/tmp/log",
  "descriptor": null
}
```

### `redirect_type`

Redirect category.

**Type:** `"input" | "output" | "dup"`\
**Always present:** Yes

| Value    | Examples                                    |
| -------- | ------------------------------------------- |
| `input`  | `<file`, `<<EOF`, `<<-EOF`, `<<<"string"`   |
| `output` | `>file`, `>>file`, `&>file`                 |
| `dup`    | `2>&1`, `>&2` (file-descriptor duplication) |

### `operator`

The redirect operator text.

**Type:** `str`\
**Always present:** Yes

### `target`

Redirect target. A filename for file redirects, an fd reference like `&1` for `dup` redirects, or an empty string for `<<` / `<<-` here-docs (the delimiter is not captured).

**Type:** `str`\
**Always present:** Yes (may be empty)

### `descriptor`

Explicit file descriptor when the redirect specifies one (e.g. `2` in `2>file`). `null` when the redirect uses the default fd (stdin for input, stdout for output).

**Type:** `int | null`\
**Always present:** Yes (may be `null`)

## Pipe Object

```json
{ "stdin": true, "stdout": false }
```

### `stdin`

`true` when this branch's stdin comes from a preceding pipe (i.e. there is a `... | this` upstream).

**Type:** `bool`\
**Always present:** Yes

### `stdout`

`true` when this branch's stdout feeds a following pipe (i.e. there is a `this | ...` downstream).

**Type:** `bool`\
**Always present:** Yes

## Related

- [`runok audit`](/cli/audit/) -- The CLI command that produces this JSON.
- [Configuration Schema -- `audit`](/configuration/schema/#audit) -- How to configure audit logging.
- [Pattern Syntax](/pattern-syntax/overview/) -- Syntax of the `pattern` strings inside [`matched_rules`](#rulematch-object).
