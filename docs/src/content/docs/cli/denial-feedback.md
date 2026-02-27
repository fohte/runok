---
title: Denial feedback
description: Provide helpful messages and fix suggestions when commands are denied.
sidebar:
  order: 4
---

When a rule denies a command, runok can display a human-readable message explaining why, and optionally suggest an alternative command. This is configured with the `message` and `fix_suggestion` fields in rule entries.

## Configuration

```yaml title="runok.yml"
rules:
  - deny: 'rm -rf /'
    message: 'Deleting the root filesystem is not allowed.'
    fix_suggestion: 'rm -rf ./build'

  - deny: 'git push --force'
    message: 'Force-pushing to the remote is prohibited.'
    fix_suggestion: 'git push --force-with-lease'
```

### `message`

A human-readable explanation of why the command was denied. Shown to the user (or the calling tool) whenever the rule matches.

### `fix_suggestion`

A suggested alternative command. This helps users (and AI agents) quickly correct a denied command without having to figure out the right alternative themselves.

## Output by adapter

How denial feedback is presented depends on which adapter processes the command.

### runok exec

Messages are printed to stderr:

```
runok: denied: rm -rf /
  reason: Deleting the root filesystem is not allowed.
  suggestion: rm -rf ./build
```

The `reason` and `suggestion` lines only appear when the corresponding field is set.

### runok check (text output)

Denial information is included in a single line:

```
deny: Deleting the root filesystem is not allowed. (suggestion: rm -rf ./build)
```

### runok check (JSON output)

Both fields appear in the JSON response:

```json
{
  "decision": "deny",
  "reason": "Deleting the root filesystem is not allowed.",
  "fix_suggestion": "rm -rf ./build"
}
```

### Claude Code hook

When runok is used as a Claude Code `PreToolUse` hook, the denial reason is formatted as:

```
denied: rm -rf / (Deleting the root filesystem is not allowed.) [suggestion: rm -rf ./build]
```

This string is returned in the `permissionDecisionReason` field of the hook response, which Claude Code displays to the user.

## Use cases

### Guiding AI agents

When runok is integrated with AI coding agents (e.g., via the Claude Code hook), `fix_suggestion` allows the agent to automatically retry with the suggested command:

```yaml title="runok.yml"
rules:
  - deny: 'npm install'
    message: 'Use pnpm instead of npm.'
    fix_suggestion: 'pnpm install'
```

When the agent tries `npm install`, it receives the deny response with the suggestion and can retry with `pnpm install`.

### Enforcing safer alternatives

Redirect users from dangerous commands to safer equivalents:

```yaml title="runok.yml"
rules:
  - deny: 'git push --force'
    message: 'Use --force-with-lease for safer force pushes.'
    fix_suggestion: 'git push --force-with-lease'

  - deny: 'rm -rf *'
    message: 'Use git clean for cleaning tracked repositories.'
    fix_suggestion: 'git clean -fd'
```
