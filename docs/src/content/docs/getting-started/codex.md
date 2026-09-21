---
title: Codex CLI Integration (Beta)
description: Set up runok as a Codex CLI hook.
sidebar:
  order: 4
---

runok integrates with [Codex CLI](https://github.com/openai/codex) through Codex's hook system. Once configured, runok evaluates each `Bash` command Codex attempts to run against your `runok.yml`.

:::caution[Beta]
Codex support is beta and has not been validated as extensively as the Claude Code integration. Approval routing and wrapper rules have important edge cases; keep the behavior described below in mind when verifying the integration.
:::

## Step 1: Install and configure runok

If you have not installed runok yet, follow the [Installation](/getting-started/installation/) guide. Then run the setup wizard at user scope:

```sh
runok init --scope user
```

The wizard creates `~/.config/runok/runok.yml` when it does not already exist. If it detects `$CODEX_HOME` (or `~/.codex` when `CODEX_HOME` is unset), it also registers the runok hook in `hooks.json` and adds the required exec policy to `rules/runok.rules`. Review the proposed diff and confirm it. The command is safe to run again because it does not duplicate existing entries.

If Codex has not created its configuration directory yet, start Codex once and run `runok init --scope user` again.

Add rules to `~/.config/runok/runok.yml` so you can verify each decision type:

```yaml
rules:
  - allow: 'git status'
  - ask: 'git push *'
  - deny: 'git push -f|--force *'
    message: 'Force push is not allowed.'

defaults:
  action: ask
```

See [Configuration](/configuration/schema/) for the full `runok.yml` reference.

### Preserve ask for the rewritten command

If your configuration has a broad `allow: 'runok exec *'` rule, place the following rule before it. Add the same rule when `defaults.action: allow` is set:

```yaml
rules:
  - ask: 'runok exec --ask *'
```

Codex sends the rewritten `runok exec --ask ...` command to the `PermissionRequest` hook. If that command resolves to `allow`, the hook allows it before Codex handles the approval, so the approval request never appears.

After `runok init` writes the changes, close any existing Codex session and start a new one before verifying the integration. Codex loads its exec policy when a session starts, so an already-running session does not see newly added `runok.rules` entries.

## Manual hook configuration (optional)

`runok init --scope user` registers both Codex events automatically. If you prefer to configure them manually, add these entries to `$CODEX_HOME/hooks.json` (or `~/.codex/hooks.json` when `CODEX_HOME` is unset). Preserve your existing hooks when merging this configuration:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "runok hook --agent codex"
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "runok hook --agent codex"
          }
        ]
      }
    ]
  }
}
```

Also add these lines to `$CODEX_HOME/rules/runok.rules`:

```text
prefix_rule(pattern = ["runok", "exec"], decision = "allow")
prefix_rule(pattern = ["runok", "exec", "--ask"], decision = "prompt")
```

If Codex asks for permission, approve the newly registered hook. When configuring these files manually, also start a new Codex session after saving them.

## Approval routing

Codex chooses the reviewer for approval requests from `$CODEX_HOME/config.toml` (or `~/.codex/config.toml` when `CODEX_HOME` is unset):

- When `approvals_reviewer` is unset, its default is `user`, and runok `ask` decisions reach a human approval dialog.
- When `approvals_reviewer = "auto_review"`, the Guardian LLM sub-agent decides `allow` or `deny`; the request does not reach a human dialog.

Codex does not provide a per-command setting to choose a different reviewer. This setting therefore affects every approval request handled by the session.

## Step 2: Verify the integration

Start Codex in a directory that uses the configuration above:

```sh
codex
```

Ask Codex to run these commands:

1. `git status` should run without an approval prompt.
2. `git push --dry-run origin example-branch` should enter Codex's approval flow. See [Approval routing](#approval-routing) for how Codex selects the reviewer. Cancel the command if a human dialog appears.
3. `git push --force --dry-run origin example-branch` should be blocked by runok before execution.

The hook applies to Codex `Bash` tool calls. File edits and other tools remain under Codex's own controls. See [`runok hook`](/cli/hook/#codex---agent-codex) for the complete event and decision mapping.

## Related

- [Configuration](/configuration/schema/) -- Configure rules and defaults.
- [`runok hook`](/cli/hook/#codex---agent-codex) -- Hook protocol and decision mapping.
- [`runok init`](/cli/init/#what-the-wizard-does) -- Initialization details and supported scopes.
