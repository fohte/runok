---
title: runok hook
description: Handle Claude Code and Codex CLI hook events from stdin.
sidebar:
  order: 3
---

`runok hook` is the integration endpoint for coding agents that speak a hook protocol. It reads a hook event as JSON from stdin and dispatches based on the event, writing a response and/or an audit record as a side effect. Unlike [`runok check`](/cli/check/), which only evaluates a command and never writes anything, `runok hook` is expected to have side effects (audit log writes, hook responses) -- register it in your agent's hook configuration, not in scripts that just want a read-only evaluation.

## Usage

```sh
some-json-hook-input | runok hook [options]
```

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags).

### `--agent <agent>` (required)

Which agent's hook protocol to speak: `claude-code` or `codex`. A missing or unrecognized value is rejected with an error through runok's own error-handling path (see [Exit codes](#exit-codes)) rather than a raw CLI usage error, so it never triggers the agent's blocking exit code.

### `--verbose`

Output detailed rule matching information to stderr.

## Event dispatch

`runok hook` reads the `hook_event_name` field of the input JSON and dispatches accordingly:

- **`PreToolUse`** (or absent, for hand-crafted/minimal input): evaluate the command against the rules and print the [`permissionDecision` response](#pretooluse-response) to stdout. When the command resolves to [`defaults.action: pass`](/configuration/schema/#defaultsaction), the exit code is `0` and `permissionDecision` is omitted from stdout -- Claude Code interprets this as "no decision to report" and falls through to its own permission flow, instead of runok forcing an `ask` prompt. If `defaults.sandbox` also applies, `updatedInput` alone is still written so the sandbox wrap still reaches the command Claude Code's own flow ends up running.
- **`PostToolUse`**: no rule evaluation. runok records an `ask_resolution` record in the audit log when the tool call corresponds to an `ask` decision it made at PreToolUse time (i.e. the user approved the permission dialog). Nothing is written to stdout. See [Track ask approvals](/getting-started/claude-code/#track-ask-approvals-optional).
- **Any other event** (including hook events introduced by a future Claude Code release): no-op. Nothing is written to stdout or the audit log, and the exit code is `0`. This lets a `runok hook` registration in `settings.json` keep working as Claude Code adds new hook events, without requiring a runok upgrade first.

### PreToolUse response

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "...",
    "updatedInput": { "command": "..." }
  }
}
```

`permissionDecisionReason` and `updatedInput` are omitted when not applicable. `updatedInput` is present when a `sandbox` preset applies to the matched rule -- it rewrites the command to `RUNOK_HOOK_ORIGIN=<token> runok exec --sandbox <preset> -- <command>` so Claude Code executes it inside the sandbox.

## Codex (`--agent codex`)

Codex CLI speaks two hook events for a Bash tool call: `PreToolUse` and `PermissionRequest`. Both share the same input shape (`PermissionRequest` just omits `tool_use_id`). `runok hook --agent codex` dispatches on `hook_event_name` the same way as `--agent claude-code`, but the two events map differently:

| runok decision                                             | `PreToolUse` response                          | `PermissionRequest` response              |
| ---------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------- |
| `deny`                                                     | `permissionDecision: "deny"` + reason          | `decision: { behavior: "deny", message }` |
| `allow`, sandbox preset applies                            | `permissionDecision: "allow"` + `updatedInput` | `decision: { behavior: "allow" }`         |
| `allow`, no sandbox                                        | nothing written                                | `decision: { behavior: "allow" }`         |
| `ask`                                                      | nothing written                                | nothing written                           |
| `pass` (no rule matched, or `defaults.action: pass`/unset) | nothing written                                | nothing written                           |

Two points where this differs from `--agent claude-code`:

- Codex rejects `updatedInput` unless it is paired with `permissionDecision: "allow"` -- so, unlike Claude Code, a `pass` decision never emits `updatedInput` even when `defaults.sandbox` is configured. The sandbox wrap only reaches Codex through an explicit `allow`.
- `PermissionRequest` has no `updatedInput` support at all, so a resolved sandbox preset is irrelevant there -- `allow` always reports plain `{ behavior: "allow" }` regardless of `defaults.sandbox` or a rule's `sandbox` key.

## Examples

Register both events in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "runok hook --agent claude-code" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "runok hook --agent claude-code" }
        ]
      }
    ]
  }
}
```

Run it directly against a captured hook payload:

```sh
cat hook-input.json | runok hook --agent claude-code
# {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
```

Same, for a Codex CLI `PreToolUse` payload: since the matched rule has no `sandbox`, `--agent codex` writes nothing (see the table above) and exits `0`, deferring to Codex's own approval flow instead of Claude Code's `allow`:

```sh
cat hook-input.json | runok hook --agent codex
# (no output)
```

## Exit codes

The following runok-side failures exit with code `1` instead of `2`:

- Config load errors (YAML syntax errors, etc.)
- Rule pattern parse errors caught during evaluation
- Unknown-flag errors for `runok hook`
- Stdin JSON parse errors
- `HookInput` schema mismatches (e.g. when Claude Code adds a new required field)
- A missing or unknown `--agent` value

Claude Code treats exit `2` from a `PreToolUse` hook as a blocking error, so any of these would otherwise block every Bash tool call until runok or the config catches up. Exit `1` is the documented non-blocking failure mode that lets Claude Code fall back to its normal permission flow. Codex CLI treats any non-`0` exit (or non-JSON stdout) as "no decision" and falls back to its own approval flow the same way, so the same exit `1` policy is also safe under `--agent codex`.

| Code | Meaning                                                                                                                             |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Handled successfully -- PreToolUse decision printed, PostToolUse record written (or skipped), or the event was unknown and ignored. |
| `1`  | A runok-side failure (see above).                                                                                                   |

## Migrating from `runok check --input-format claude-code-hook`

`runok check --input-format claude-code-hook` still works and routes to the same logic described above, but it's deprecated: `check` is documented as a read-only evaluation command, which the PostToolUse audit write contradicts. Running it prints a deprecation warning to stderr (never stdout, so the hook response Claude Code parses stays intact). New setups should register `runok hook --agent claude-code` instead -- [`runok init`](/cli/init/) does this automatically, and rewrites existing `runok check --input-format claude-code-hook` entries to `runok hook --agent claude-code` on re-run. [`runok migrate`](/cli/migrate/#claude-code-legacy-hook-command) does the same rewrite without running the full init wizard.

## Related

- [Claude Code Integration](/getting-started/claude-code/) -- Full hook setup guide.
- [`runok check`](/cli/check/) -- Read-only rule evaluation for humans, CI, and scripts.
- [`runok migrate`](/cli/migrate/) -- Rewrites deprecated config and settings.json entries to the current format.
- [`runok init`](/cli/init/) -- Registers the hook automatically.
