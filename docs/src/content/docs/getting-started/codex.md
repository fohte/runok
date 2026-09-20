---
title: Codex CLI Integration
description: Set up runok as a Codex CLI hook.
sidebar:
  order: 4
---

runok integrates with [Codex CLI](https://github.com/openai/codex) through Codex's hook system. Once configured, runok evaluates each `Bash` command Codex attempts to run against your `runok.yml`.

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

After `runok init` writes the changes, close any existing Codex session and start a new one before verifying the integration. Codex loads its exec policy when a session starts, so an already-running session does not see newly added `runok.rules` entries.

## Step 2: Configure the Codex hooks

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

## Step 3: Verify the integration

Start Codex in a directory that uses the configuration above:

```sh
codex
```

Ask Codex to run these commands:

1. `git status` should run without an approval prompt.
2. `git push --dry-run origin example-branch` should open Codex's approval prompt. Cancel it instead of approving the command.
3. `git push --force --dry-run origin example-branch` should be blocked by runok before execution.

The hook applies to Codex `Bash` tool calls. File edits and other tools remain under Codex's own controls. See [`runok hook`](/cli/hook/#codex---agent-codex) for the complete event and decision mapping.

## Sandbox execution

To add OS-level restrictions, attach a [sandbox preset](/sandbox/overview/) to an `allow` rule:

```yaml
definitions:
  sandbox:
    restricted:
      fs:
        writable: [./tmp]
      network:
        allow: false

rules:
  - allow: 'python3 *'
    sandbox: restricted
```

See the [Security Model](/sandbox/security-model/#codex-execution-path) for Codex's trust boundary and the [sandbox reference](/configuration/schema/#definitionssandbox) for available options.

## Related

- [Configuration](/configuration/schema/) -- Configure rules, defaults, and sandbox presets.
- [`runok hook`](/cli/hook/#codex---agent-codex) -- Hook protocol and decision mapping.
- [`runok init`](/cli/init/#what-the-wizard-does) -- Initialization details and supported scopes.
