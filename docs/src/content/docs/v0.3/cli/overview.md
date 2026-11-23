---
title: CLI Overview
description: Reference for runok CLI commands.
sidebar:
  order: 1
slug: v0.3/cli/overview
---

runok provides subcommands for initializing configuration, evaluating commands, and executing them against your permission rules.

## Global Flags

### `-c, --config <path>`

Load a specific config file instead of the default config discovery (global + project). When specified, only the given file is loaded — global and project configs are skipped. This flag can appear before or after the subcommand name.

```sh
# These are equivalent:
runok -c custom.yml check -- git push
runok check -c custom.yml -- git push
```

## Commands

### [`runok init`](/v0.3/cli/init/)

Initialize runok configuration with an interactive setup wizard. Detects existing Claude Code Bash permissions and offers to migrate them to runok rules.

### [`runok check`](/v0.3/cli/check/)

Evaluate a command against your rules and report the decision — without executing it. Useful for previewing what runok would do, or for integrating with external tools like [Claude Code hooks](/v0.3/getting-started/claude-code/).

### [`runok exec`](/v0.3/cli/exec/)

Evaluate a command against your rules and, if allowed, execute it — [optionally within a sandbox](/v0.3/sandbox/overview/).

### [`runok audit`](/v0.3/cli/audit/)

View and filter audit log entries. Every `exec` and hook evaluation is logged automatically, and this subcommand lets you query those entries by time range, action, or command.

### [`runok test`](/v0.3/cli/test/)

Run test cases defined in your configuration to verify that rules produce the expected decisions. Supports inline per-rule tests and a top-level `tests` section for cross-rule validation.

### [`runok migrate`](/v0.3/cli/migrate/)

Migrate config files to the latest format. Automatically rewrites deprecated syntax while preserving comments and formatting.

### [`runok update-presets`](/v0.3/cli/update-presets/)

Force-update all remote presets referenced via `extends`, bypassing the TTL-based cache. Shows a diff for each preset that changed.

## Related

- [Denial feedback](/v0.3/configuration/denial-feedback/) -- Configure `message` and `fix_suggestion` for denied commands.
