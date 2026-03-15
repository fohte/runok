---
title: Debugging
description: How to diagnose issues using runok check and --verbose flag.
sidebar:
  order: 1
---

## `runok check`: check without executing

The [`runok check`](/cli/check/) command evaluates rules and reports what action would be taken, without executing the command. This is the quickest way to test whether your rules work as expected.

```bash
runok check -- git status
```

Example output:

```
allow
```

Add `--verbose` to see detailed rule matching information:

```bash
runok check --verbose -- git status
```

```
[verbose] Evaluating command: "git status"
[verbose] Rule matched: allow 'git *' (matched tokens: ["status"])
[verbose] Evaluation result: Allow
allow
```

When no rule matches:

```bash
runok check --verbose -- rm -rf /
```

```
[verbose] Evaluating command: "rm -rf /"
[verbose] No rules matched
[verbose] Evaluation result: Deny
deny
```

For [compound commands](/rule-evaluation/compound-commands/) (commands joined with `&&`, `||`, `;`, or `|`), verbose output shows each sub-command individually:

```bash
runok check --verbose -- 'git add . && git commit -m fix'
```

```
[verbose] Compound command detected (2 sub-commands)
[verbose]   sub-command 1: "git add ."
[verbose]   sub-command 2: "git commit -m 'fix'"
[verbose] Compound evaluation result: Allow
allow
```

You can also pipe commands via stdin:

```bash
echo "curl -X POST https://example.com" | runok check
```

## `--verbose` with `runok exec`

The `--verbose` flag also works with `runok exec` for debugging in production-like scenarios:

```bash
runok exec --verbose -- git push --force
```

This prints the rule matching details to stderr while also executing the command.

## Related

- [`runok check` Reference](/cli/check/) -- Full command reference.
- [`runok exec` Reference](/cli/exec/) -- Full command reference.
- [Common Issues](/troubleshooting/common-issues/) -- Solutions for frequently encountered problems.
