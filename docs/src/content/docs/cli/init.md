---
title: runok init
description: Initialize runok configuration with an interactive setup wizard.
sidebar:
  order: 4
---

`runok init` creates a `runok.yml` configuration file through an interactive setup wizard. It can also detect existing Claude Code Bash permissions and migrate them to runok rules.

## Usage

```sh
runok init [options]
```

## Flags

### `--scope <scope>`

Configuration scope. Available values:

- `user` — Create `~/.config/runok/runok.yml` for global rules that apply to all projects. Also registers the runok PreToolUse hook in `~/.claude/settings.json` if Claude Code is detected.
- `project` — Create `runok.yml` in the current directory for project-specific rules.

When omitted, the wizard prompts you to choose.

### `-y`, `--yes`

Accept all defaults without prompting. Useful for scripted setups.

## What the wizard does

1. **Scope selection** — Choose `user` or `project` scope (skipped if `--scope` is given).
2. **Claude Code detection** — If a `.claude/settings.json` exists with Bash permissions or a missing runok hook, the wizard offers to:
   - **Migrate Bash permissions** — Convert `permissions.allow` and `permissions.deny` entries for `Bash(...)` patterns into runok rules, and remove them from `settings.json`.
   - **Register the hook** — Add the `runok check` PreToolUse hook to `settings.json` (user scope only).
3. **Preview and confirm** — Show a unified diff of all proposed changes and ask for confirmation.
4. **Create `runok.yml`** — Write the configuration file with migrated rules (if any) or a boilerplate template.
5. **Conflicting hook detection** — The wizard checks for other PreToolUse hooks that also match `Bash`. Due to a [known Claude Code issue](https://github.com/anthropics/claude-code/issues/15897), runok's sandbox may not work when multiple PreToolUse hooks match Bash — commands that should be sandboxed could run without any restrictions. If conflicts are found, a warning is displayed advising you to merge all Bash-matching hooks into a single entry.

## Examples

Interactive setup (prompts for scope and options):

```sh
runok init
```

Set up user-global configuration non-interactively:

```sh
runok init --scope user -y
```

Set up project-local configuration:

```sh
runok init --scope project
```

## Related

- [Quick Start](/getting-started/quickstart/) — Getting started with runok.
- [Claude Code Integration](/getting-started/claude-code/) — Manual hook setup and sandbox configuration.
- [Configuration](/configuration/schema/) — Full configuration reference.
