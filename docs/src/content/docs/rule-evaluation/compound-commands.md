---
title: Compound Commands
description: How runok decomposes and evaluates pipelines, logical operators, and other compound shell constructs.
sidebar:
  order: 3
---

Shell commands often combine multiple operations using pipes (`|`), logical operators (`&&`, `||`), semicolons (`;`), and other constructs. runok splits these **compound commands** into individual sub-commands and evaluates each one separately.

## Decomposition

runok uses [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash) to parse compound commands into an AST. The `extract_commands()` function (`src/rules/command_parser/splitter/mod.rs`) recursively walks the AST and extracts individual simple commands from:

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

## Variable resolution

runok tracks shell variable assignments (`X=value`) within a single command string and resolves `$X` / `${X}` references to their statically known value before rule evaluation, if the assignment is unconditional and its value contains no dynamic content.

```yaml
rules:
  - deny: 'git push --force*'
  - allow: 'git push *'
```

For the command `F=--force; git push $F`:

1. `F=--force` is a static, unconditional assignment -- `F` is recorded as `--force`.
2. `git push $F` resolves to `git push --force` before matching.
3. Final result: **deny** -- the flag can no longer evade the rule by being smuggled through a variable.

### What resolves

- A value made only of literal text, a single- or double-quoted string with no interpolation, or a concatenation of those (`X=1`, `X="git status"`, `X='rm -rf'`).
- The resolved value substitutes for `$X` / `${X}` wherever it's referenced, including the command name position (`X=rm; $X -rf /` evaluates as `rm -rf /`).
- An unquoted reference is split on whitespace like bash's default `IFS` (`X="git status"; $X` evaluates as two tokens, `git` and `status`); a quoted reference (`"$X"`) is not split.
- A subshell or command substitution (`(...)`, `$(...)`) forks a child shell, so a reassignment inside it never overwrites the value the parent scope resolves to afterward (`X=--force; (X=--safe); git push $X` still evaluates the outer `git push $X` as `git push --force`).

### What does not resolve

The following are recorded as unresolvable and left as the literal `$X` / `${X}` text:

- A dynamic value: `$(...)`, `` `...` ``, process substitution, or arithmetic expansion (`X=$(cat f)`).
- A reassignment of a name that was previously dynamic in the same command string (`X=1; X=$(date); echo $X` -- the stale `1` is never reused).
- An assignment inside a conditional or loop body (`if`/`elif`/`else`/`case`/`for`/`while`/`until`), since it may run zero, one, or many times: `if true; then X=rm; fi; $X /` leaves `$X` unresolved even though the branch always runs.
- The right-hand side of `&&` / `||`, since it only runs depending on the left side's exit status: `X=--force; false && X=--safe; git push $X` leaves `$X` unresolved.
- A `for` loop's own iteration variable, since its value changes every iteration (`for i in a b; do echo $i; done` never resolves `$i`).
- An array-element assignment (`arr[0]=x`), and a bare `export`/`declare`/`unset` with no value (`X=1; export X; echo $X` leaves `$X` unresolved -- `export X` alone doesn't reassign it, but its current value isn't statically known either).
- An expansion with an operator, such as `${X:-default}` or `${X#pattern}`.
- Anything inside a function body at definition time (`f() { local X=1; }; echo $X` leaves the outer `$X` unresolved) -- the body is only evaluated when the function is called, which runok does not yet resolve.

### Audit log

When variable resolution rewrites a command, the audit log's `command_evaluations` entry records the resolved text in `command` (the value rule evaluation actually used) and the verbatim source in `original_command`, so both the decision and the original input remain inspectable. `original_command` is omitted when nothing was resolved.

```json
{
  "command": "git push --force",
  "original_command": "git push $F",
  "action": {
    "type": "deny",
    "detail": { "message": null, "fix_suggestion": null }
  }
}
```

See [Audit Log JSON Schema](/cli/audit-log-schema/#original_command) for the full field reference.

## Strictest wins

After evaluating each sub-command, runok aggregates the results using the same [Explicit Deny Wins](/rule-evaluation/priority-model/) logic:

> The most restrictive action across all sub-commands becomes the final action.

The priority order is: `deny` > `ask` > `allow`.

### Example

```yaml
rules:
  - allow: 'git add *'
  - allow: 'git commit *'
  - deny: 'rm -rf *'
```

For the command `git add . && rm -rf /tmp`:

1. `git add .` → `allow` (priority 0)
2. `rm -rf /tmp` → `deny` (priority 2)
3. Final result: **deny** (strictest wins)

The entire compound command is blocked because one sub-command is denied.

## Default action resolution

When a sub-command does not match any rule, its action is resolved immediately to the configured [`defaults.action`](/configuration/schema/#defaultsaction) (defaulting to `ask` if unconfigured). This ensures unmatched sub-commands participate in the aggregation at their effective restriction level.

```yaml
defaults:
  action: ask

rules:
  - allow: 'git status'
```

For the command `git status && unknown-cmd`:

1. `git status` → `allow` (priority 0)
2. `unknown-cmd` → no rule matched → resolved to `ask` (priority 1)
3. Final result: **ask** (strictest wins)

Without this resolution, unmatched sub-commands would be silently ignored.

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
