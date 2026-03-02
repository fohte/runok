---
title: Claude Code Integration
description: Set up runok as a Claude Code PreToolUse hook.
sidebar:
  order: 3
---

runok integrates with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) through the **PreToolUse hook** system. When configured, runok evaluates every Bash command that Claude Code attempts to run, enforcing your allow/deny rules before execution.

## How it works

1. Claude Code triggers a **PreToolUse** hook before executing any tool.
2. runok receives the tool invocation as JSON via stdin.
3. For `Bash` tool calls, runok extracts the command string and evaluates it against your `runok.yml` rules.
4. runok returns an `approve`, `deny`, or `ask` decision back to Claude Code.

## Step 1: Set up runok

If you haven't already, follow the [Quick Start](/getting-started/quickstart/) to install runok and create a `runok.yml`.

## Step 2: Configure the PreToolUse hook

Add the runok hook to your Claude Code settings file (`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": ["runok check --input-format claude-code-hook"]
      }
    ]
  }
}
```

### What each field means

- **`"matcher": "Bash"`** -- Only triggers the hook for Bash tool calls. Other tools (file edits, web searches, etc.) are not affected.
- **`"hooks"`** -- The command(s) to run. Claude Code pipes the tool invocation as JSON to stdin. `runok check --input-format claude-code-hook` parses this JSON format and returns the evaluation result.

## Step 3: Verify the integration

Start a Claude Code session in your project directory. Ask Claude to run a command that your rules cover:

1. **Allowed command**: Ask Claude to run `git status`. It should execute without prompting.
2. **Denied command**: Ask Claude to run `git push --force origin main`. It should be blocked with the configured message.
3. **Ask command**: Ask Claude to run `git push origin main`. It should prompt you for confirmation.

## Sandbox execution

runok can enforce OS-level sandboxing (file system and network restrictions) on commands that Claude Code runs. When an `allow` rule has a `sandbox` field, runok automatically rewrites the command so that Claude Code executes it inside a sandbox.

Define a sandbox preset in your `runok.yml`:

```yaml
definitions:
  sandbox:
    restricted:
      fs:
        writable: [./tmp, /tmp]
      network:
        allow: true
```

Then attach it to a rule:

```yaml
rules:
  - allow: 'python3 *'
    sandbox: restricted
```

When Claude Code runs `python3 script.py`, runok's hook response tells Claude Code to execute [`runok exec`](/cli/exec/) `--sandbox restricted -- 'python3 script.py'` instead, transparently applying the sandbox.

You can also set a default sandbox for all allowed commands:

```yaml
defaults:
  action: ask
  sandbox: restricted
```

See [Sandbox](/sandbox/overview/) for the full reference on sandbox presets and platform support (macOS Seatbelt, Linux Landlock/seccomp).

## Settings file locations

The `.claude/settings.json` file can be placed at different scopes:

| Location                               | Scope                                  |
| -------------------------------------- | -------------------------------------- |
| `.claude/settings.json` (project root) | Project-specific, shared with the team |
| `~/.claude/settings.json`              | User-global, applies to all projects   |

For team-wide enforcement, commit `.claude/settings.json` alongside your `runok.yml` in the project repository.

See [`runok check`](/cli/check/) for full command reference.

## Claude Code plugin

The [runok Claude Code plugin](https://github.com/fohte/runok-claude-code-plugin) gives Claude Code knowledge of runok -- its configuration format, pattern syntax, and rule evaluation model. With the plugin installed, Claude Code can answer questions about runok and manage your `runok.yml` through natural language.

### What the plugin provides

- **Configuration reading** -- Discovers and reads global (`~/.config/runok/runok.yml`), project (`./runok.yml`), and override (`./runok.local.yml`) configuration files.
- **Rule management** -- Add, edit, and remove `allow`/`deny`/`ask` rules with full pattern syntax support (wildcards, alternation, negation, optional groups, quoted literals, `when` clauses).
- **Definitions management** -- Manage `paths`, `wrappers`, `sandbox` presets, and `commands` under the `definitions` section.
- **Extends management** -- Add and remove shared presets via local paths, GitHub shorthand (`github:org/repo@ref`), or Git URLs.
- **Initialization** -- Generate a starter `runok.yml` for new projects with sensible defaults.

### Install the plugin

```sh
claude plugin add github:fohte/runok-claude-code-plugin
```

### Usage

The plugin activates automatically when you work with runok configuration or mention "runok" in conversation. You can also invoke the skill directly:

```
/runok
```

For example, you can ask Claude Code to:

- "Add a rule to allow `cargo test`"
- "Deny force pushes with a helpful message"
- "Show me my current runok rules"
- "Initialize runok for this project"
