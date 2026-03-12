---
title: Quick Start
description: Get up and running with runok in minutes.
sidebar:
  order: 2
---

Create a minimal runok configuration and verify it works. By the end, you will have a `runok.yml` that allows safe commands, denies dangerous ones, and asks for confirmation on everything else.

## 1. Install runok

Follow the [Installation](/getting-started/installation/) guide to install runok and ensure the `runok` binary is available in your `PATH`.

## 2. Create a configuration file

The easiest way to get started is with the interactive setup wizard:

```sh
runok init
```

This creates a `runok.yml` and, if you have Claude Code configured, offers to migrate your existing Bash permissions to runok rules and register the PreToolUse hook. See [`runok init`](/cli/init/) for details.

Alternatively, create `~/.config/runok/runok.yml` manually:

```sh
mkdir -p ~/.config/runok
```

```yaml
# ~/.config/runok/runok.yml
rules:
  # Allow safe read-only git commands
  - allow: 'git status'
  - allow: 'git diff *'
  - allow: 'git log *'

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

- **`allow` rules** permit matching commands to run without prompting.
- **`deny` rules** block matching commands entirely. Deny always takes priority over allow ([Explicit Deny Wins](/rule-evaluation/priority-model/)).
- **`ask` rules** prompt for user confirmation before running the command.
- **`defaults.action: ask`** means any command that does not match a rule will require confirmation.

The `*` wildcard matches any additional arguments. The `-f|--force` syntax matches both the short and long flag forms. See [Pattern Syntax](/pattern-syntax/overview/) for the full reference.

For the full list of configuration options (file locations, wrapper definitions, sandbox presets, etc.), see [Configuration](/configuration/schema/).

## 3. Test with [`runok check`](/cli/check/)

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

## Next steps

- [Official Presets](/configuration/official-presets/) -- Start with ready-made rules for common read-only commands using runok-presets.
- [Claude Code Integration](/getting-started/claude-code/) -- Set up runok as a Claude Code PreToolUse hook.
- [CLI Reference](/cli/overview/) -- Full reference for `runok init`, `runok check`, and `runok exec`.
- [Recipes](/recipes/overview/) -- Common configuration patterns and examples.
