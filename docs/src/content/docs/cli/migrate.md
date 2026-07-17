---
title: runok migrate
description: Migrate config files to the latest format.
sidebar:
  order: 10
---

`runok migrate` automatically updates deprecated config syntax to the latest format while preserving comments and formatting.

## Usage

```sh
runok migrate [options]
```

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags). When omitted, runok discovers config files using the same logic as other commands: global config from `$XDG_CONFIG_HOME/runok/` and project config from the nearest ancestor directory containing `runok.yml`.

## What gets migrated

### Sandbox `fs` legacy format

The legacy `writable`/`deny` fields are rewritten to the new `write.allow`/`write.deny` structure:

```yaml
# Before
fs:
  writable: [., /tmp]
  deny: [.env]

# After
fs:
  write:
    allow: [., /tmp]
    deny: [.env]
```

### Bare `?` in pattern strings

A bare `?` in a pattern string now means "optional value" (see [Matching Behavior -- Optional Flag Values](/pattern-syntax/matching-behavior/#optional-flag-values)). A pattern written before this change that relied on `?` matching the literal character is rewritten to the escaped form `\?`, which keeps matching literal `?`:

```yaml
# Before
rules:
  - allow: 'git branch --abbrev ?'

# After
rules:
  - allow: 'git branch --abbrev \?'
```

This applies to every pattern-syntax field: `rules[].{allow,deny,ask}`, `definitions.wrappers`, `definitions.flag_groups`, `definitions.aliases`, and `definitions.vars` entries with `type: pattern`. `rules[].tests` are left untouched, since inline test commands are not patterns.

### Claude Code legacy hook command

An existing `.claude/settings.json` registration of the deprecated `runok check --input-format claude-code-hook` command is rewritten to `runok hook --agent claude-code` (both `PreToolUse` and `PostToolUse` entries):

```json
// Before
{ "type": "command", "command": "runok check --input-format claude-code-hook" }

// After
{ "type": "command", "command": "runok hook --agent claude-code" }
```

Unlike the config-chain migrations above, this one targets `.claude/settings.json` directly -- at the user scope (`~/.claude/settings.json`) and the project scope (`.claude/settings.json` in the current directory), matching the locations [`runok init`](/cli/init/) sets up. See [`runok hook` -- Migrating from `runok check --input-format claude-code-hook`](/cli/hook/#migrating-from-runok-check---input-format-claude-code-hook) for background.

## Examples

```sh
# Migrate all discovered config files
runok migrate

# Migrate a specific file
runok migrate -c runok.yml
```
