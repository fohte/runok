---
title: Compound Commands
description: How runok decomposes and evaluates pipelines, logical operators, and other compound shell constructs.
sidebar:
  order: 3
---

Shell commands often combine multiple operations using pipes (`|`), logical operators (`&&`, `||`), semicolons (`;`), and other constructs. runok splits these **compound commands** into individual sub-commands and evaluates each one separately.

## Decomposition

runok uses [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash) to parse compound commands into an AST. The `extract_commands()` function (`src/rules/command_parser.rs`) recursively walks the AST and extracts individual simple commands from:

- **Pipelines**: `cmd1 | cmd2`
- **Logical AND/OR**: `cmd1 && cmd2`, `cmd1 || cmd2`
- **Command lists**: `cmd1 ; cmd2`
- **Subshells**: `(cmd1 && cmd2)`
- **Redirected statements**: `cmd1 > file`
- **Variable assignments with commands**: `VAR=value cmd1`
- **Negated commands**: `! cmd1`
- **For loops**: `for x in a b; do cmd1; done`
- **Case statements**: `case $x in a) cmd1;; esac`
- **Function definitions**: `f() { cmd1; }`

Each extracted command is evaluated independently as if it were run alone.

### Example

```
git add . && git commit -m "update" | cat
```

This is decomposed into three commands:

1. `git add .`
2. `git commit -m "update"`
3. `cat`

## Strictest wins

After evaluating each sub-command, runok aggregates the results using the same [Explicit Deny Wins](/rule-evaluation/priority-model/) logic:

> The most restrictive action across all sub-commands becomes the final action.

The priority order is: `deny` > `ask` > `allow` > `default`.

### Example

```yaml
rules:
  - allow: 'git add *'
  - allow: 'git commit *'
  - deny: 'rm -rf *'
```

For the command `git add . && rm -rf /tmp`:

1. `git add .` → `allow` (priority 1)
2. `rm -rf /tmp` → `deny` (priority 3)
3. Final result: **deny** (strictest wins)

The entire compound command is blocked because one sub-command is denied.

## Default action resolution

Before merging sub-command results, `Action::Default` (no rule matched) is resolved to the configured [`defaults.action`](/configuration/schema/#defaultsaction). This ensures unmatched sub-commands participate in the aggregation at their effective restriction level.

```yaml
defaults:
  action: ask

rules:
  - allow: 'git status'
```

For the command `git status && unknown-cmd`:

1. `git status` → `allow` (priority 1)
2. `unknown-cmd` → `default` → resolved to `ask` (priority 2)
3. Final result: **ask** (strictest wins)

Without this resolution, the unmatched `unknown-cmd` would silently pass because `default` has the lowest priority.

## Sandbox policy aggregation

When sub-commands have different sandbox presets, the sandbox policies are merged using the **strictest intersection**:

| Policy field    | Merge strategy | Rationale                                               |
| --------------- | -------------- | ------------------------------------------------------- |
| `fs.writable`   | Intersection   | Only paths writable by **all** sub-commands are allowed |
| `fs.deny`       | Union          | Paths denied by **any** sub-command are denied          |
| `network.allow` | AND            | Network is blocked if **any** sub-command denies it     |

### Writable contradiction escalation

If the intersection of `fs.writable` paths is empty — meaning sub-commands require incompatible write access — this is treated as a contradiction. The action is escalated to `ask` (unless it is already `deny`), alerting the user to the conflict.

```yaml
definitions:
  sandbox:
    project-a:
      fs:
        writable: ['/project-a']
    project-b:
      fs:
        writable: ['/project-b']

rules:
  - allow: 'build-a *'
    sandbox: project-a
  - allow: 'build-b *'
    sandbox: project-b
```

For `build-a release && build-b release`:

1. `build-a release` → `allow` with sandbox `project-a` (writable: `/project-a`)
2. `build-b release` → `allow` with sandbox `project-b` (writable: `/project-b`)
3. Writable intersection: empty (contradiction)
4. Final result: **ask** (escalated from `allow`)

## Parse failure fallback

If tree-sitter-bash fails to parse the compound command, the entire input string is treated as a single command and evaluated directly. This ensures that unusual or non-standard shell syntax does not cause an outright error.

## Related

- [Priority Model](/rule-evaluation/priority-model/) -- How action priorities work.
- [Sandbox Overview](/sandbox/overview/) -- How sandbox policies are defined and applied.
