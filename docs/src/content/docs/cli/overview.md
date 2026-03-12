---
title: CLI Overview
description: Reference for runok CLI commands.
sidebar:
  order: 1
---

runok provides subcommands for initializing configuration, evaluating commands, and executing them against your permission rules.

## Commands

### [`runok init`](/cli/init/)

Initialize runok configuration with an interactive setup wizard. Detects existing Claude Code Bash permissions and offers to migrate them to runok rules.

### [`runok check`](/cli/check/)

Evaluate a command against your rules and report the decision — without executing it. Useful for previewing what runok would do, or for integrating with external tools like [Claude Code hooks](/getting-started/claude-code/).

### [`runok exec`](/cli/exec/)

Evaluate a command against your rules and, if allowed, execute it — [optionally within a sandbox](/sandbox/overview/).

### [`runok audit`](/cli/audit/)

View and filter audit log entries. Every `exec` and hook evaluation is logged automatically, and this subcommand lets you query those entries by time range, action, or command.

## Related

- [Denial feedback](/configuration/denial-feedback/) -- Configure `message` and `fix_suggestion` for denied commands.
