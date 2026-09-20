---
title: runok init
description: Initialize runok configuration with an interactive setup wizard.
sidebar:
  order: 5
---

`runok init` creates a `runok.yml` configuration file through an interactive setup wizard. It can also detect existing Claude Code Bash permissions and migrate them to runok rules.

## Usage

```sh
runok init [options]
```

## Flags

### `--scope <scope>`

Configuration scope. Available values:

- `user` — Create `~/.config/runok/runok.yml` for global rules that apply to all projects. Also registers the runok PreToolUse hook in `~/.claude/settings.json` if Claude Code is detected, and the `runok hook --agent codex` hooks plus the required exec policy in the Codex config directory (`$CODEX_HOME`, or `~/.codex` when that variable is unset) if one is detected.
- `project` — Create `runok.yml` in the current directory for project-specific rules.

When omitted, the wizard prompts you to choose.

### `-y`, `--yes`

Accept all defaults without prompting. Useful for scripted setups.

## What the wizard does

1. **Scope selection** — Choose `user` or `project` scope (skipped if `--scope` is given).
2. **Claude Code detection** — If a `.claude/settings.json` exists with a missing runok hook or a hook entry registered under the pre-[`runok hook`](/cli/hook/) command, the wizard offers to act on it. Bash permissions only trigger this step when `runok.yml` doesn't already exist yet at the selected scope (see below); if `runok.yml` already exists and that's the only thing settings.json has to offer, the wizard prints a note that it's leaving the permissions in place instead. Where triggered, the wizard offers to:
   - **Migrate Bash permissions** — Convert `permissions.allow` and `permissions.deny` entries for `Bash(...)` patterns into runok rules, and remove them from `settings.json`. Only offered when `runok.yml` doesn't already exist yet at the selected scope — init never writes to an existing one, so this step doesn't appear if you already have a `runok.yml` there; migrate the rules into it by hand instead.
   - **Register the hook** — Add the [`runok hook`](/cli/hook/) PreToolUse hook to `settings.json` (user scope only).
   - **Migrate the hook command** — Rewrite an existing `runok check --input-format claude-code-hook` entry (registered before `runok hook` existed) to `runok hook --agent claude-code`, in place.
   - **Track ask approvals** (opt-in) — Also register the same command as a PostToolUse hook so approvals of `ask` decisions are recorded in the audit log (user scope only). See [Track ask approvals](/getting-started/claude-code/#track-ask-approvals-optional).
3. **Codex detection** — If a Codex config directory exists (`$CODEX_HOME`, or `~/.codex` when that variable is unset), the wizard registers the [`runok hook --agent codex`](/cli/hook/#codex---agent-codex) command for both the `PreToolUse` and `PermissionRequest` events in `<codex_home>/hooks.json` and adds the following rules to `<codex_home>/rules/runok.rules` (user scope only):

   ```text
   prefix_rule(pattern = ["runok", "exec"], decision = "allow")
   prefix_rule(pattern = ["runok", "exec", "--ask"], decision = "prompt")
   ```

   These rules make Codex follow runok's `allow` and `ask` decisions after the hook rewrites the command. The step is skipped entirely -- without asking or writing anything -- if the directory doesn't exist, since that means Codex isn't installed or used. Re-running `runok init` is idempotent and won't duplicate the hook or policy entries. You may need to approve the newly-registered hook in Codex before it takes effect.

4. **Preview and confirm** — Show a unified diff of all proposed changes and ask for confirmation.
5. **Create `runok.yml`** — Write a fresh configuration file with migrated rules (if any) or a boilerplate template, but only when `runok.yml` doesn't already exist yet at the selected scope. An existing `runok.yml` — hand-written or otherwise — is never overwritten or modified by init, with or without `-y`.
6. **Conflicting hook detection** — The wizard checks for other PreToolUse hooks that also match `Bash`. Due to a [known Claude Code issue](https://github.com/anthropics/claude-code/issues/15897), runok's sandbox may not work when multiple PreToolUse hooks match Bash — commands that should be sandboxed could run without any restrictions. If conflicts are found, a warning is displayed advising you to merge all Bash-matching hooks into a single entry.

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
