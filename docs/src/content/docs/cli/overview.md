---
title: CLI Overview
description: Reference for runok CLI commands.
sidebar:
  order: 1
---

runok provides two main subcommands for evaluating and executing commands against your permission rules.

## Commands

### [`runok check`](/cli/check/)

Evaluate a command against your rules and report the decision — without executing it. Useful for previewing what runok would do, or for integrating with external tools like Claude Code hooks.

### [`runok exec`](/cli/exec/)

Evaluate a command against your rules and, if allowed, execute it — optionally within a sandbox.

## Related

- [Denial feedback](/configuration/denial-feedback/) — Configure `message` and `fix_suggestion` for denied commands.
