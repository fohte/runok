---
title: Quick Start
description: Get up and running with runok in minutes.
sidebar:
  order: 2
slug: v0.3/getting-started/quickstart
---

Create a minimal runok configuration and verify it works. By the end, you will have a `runok.yml` that allows safe commands, denies dangerous ones, and asks for confirmation on everything else.

## 1. Install runok

Follow the [Installation](/v0.3/getting-started/installation/) guide to install runok and ensure the `runok` binary is available in your `PATH`.

## 2. Create a configuration file

The easiest way to get started is with the interactive setup wizard:

```sh
runok init
```

This creates a `runok.yml` and, if you have Claude Code configured, offers to migrate your existing Bash permissions to runok rules and register the PreToolUse hook. See [`runok init`](/v0.3/cli/init/) for details.

Alternatively, create `~/.config/runok/runok.yml` manually:

```sh
mkdir -p ~/.config/runok
```

```yaml
# ~/.config/runok/runok.yml

# Start with official presets -- read-only rules for common Unix
# commands, Git, GitHub CLI, and wrapper definitions.
# See https://runok.fohte.net/configuration/official-presets/
extends:
  - 'github:fohte/runok-presets/base@v1'

rules:
  # Add your own rules on top of the presets

  # Ask before pushing
  - ask: 'git push *'

  # Never allow force push
  - deny: 'git push -f|--force *'
    message: 'Force push is not allowed.'
    fix_suggestion: 'git push --force-with-lease'

defaults:
  action: ask
```

### What this does

- **`extends`** pulls in shared rule sets from external sources. The [`base` preset](/v0.3/configuration/official-presets/) covers common read-only commands so you don't have to write them yourself.
- **`allow` rules** permit matching commands to run without prompting.
- **`deny` rules** block matching commands entirely. Deny always takes priority over allow ([Explicit Deny Wins](/v0.3/rule-evaluation/priority-model/)).
- **`ask` rules** prompt for user confirmation before running the command.
- **`defaults.action: ask`** means any command that does not match a rule will require confirmation.

The `*` wildcard matches any additional arguments. The `-f|--force` syntax matches both the short and long flag forms. See [Pattern Syntax](/v0.3/pattern-syntax/overview/) for the full reference.

For the full list of configuration options (file locations, wrapper definitions, sandbox presets, etc.), see [Configuration](/v0.3/configuration/schema/).

## 3. Test with [`runok check`](/v0.3/cli/check/)

Use `runok check` to test how runok evaluates commands without executing them:

```sh
# This should print "allow"
runok check -- git status

# This should print "deny"
runok check -- git push --force origin main

# This should print "ask"
runok check -- git push origin main
```

The decision (`allow`, `deny`, or `ask`) is printed to stdout. Use `--output-format json` for machine-readable output.

:::tip[Real-world configurations]
See how runok is configured in practice:

- [fohte/dotfiles `runok.yml`](https://github.com/fohte/dotfiles/blob/master/config/runok/runok.yml) -- The author's dotfiles configuration extending official presets with project-specific rules.
- [fohte/runok-presets](https://github.com/fohte/runok-presets) -- The official preset collection for common read-only commands. See [Official Presets](/v0.3/configuration/official-presets/) for details.
  :::

## Next steps

- [Official Presets (runok-presets)](/v0.3/configuration/official-presets/) -- Customize the preset selection or learn what each preset includes.
- [Claude Code Integration](/v0.3/getting-started/claude-code/) -- Set up runok as a Claude Code PreToolUse hook, and install the [Claude Code plugin](/v0.3/getting-started/claude-code/#claude-code-plugin) to manage `runok.yml` from inside Claude Code.
- [CLI Reference](/v0.3/cli/overview/) -- Full reference for `runok init`, `runok check`, and `runok exec`.
