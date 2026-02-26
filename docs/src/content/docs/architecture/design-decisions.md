---
title: Design Decisions
description: Key design principles and the rationale behind runok's architecture.
sidebar:
  order: 3
---

This page documents the key design decisions in runok, their rationale, and the trade-offs involved.

## WYSIWHIP: What You See Is What It Parses

The most fundamental principle in runok's design: **the way you write a rule is exactly how it will be parsed and matched**.

### Motivation

Traditional command allowlisting tools require users to learn a separate schema language to define flag types, value separators, and argument positions. runok eliminates this by inferring parsing behavior directly from the rule pattern itself.

### How it works

When you write:

```yaml
rules:
  - deny: 'curl -X POST *'
```

runok infers from this pattern that:

- `-X` is a flag that takes a value (because `POST` follows it)
- `*` matches remaining positional arguments

When you write:

```yaml
rules:
  - deny: 'rm -rf *'
```

runok infers that:

- `-rf` is a single combined flag token (not `-r` + `-f`)
- It is boolean (no value follows)

There is no hidden schema or definition block that changes how these patterns behave. The pattern is the specification.

### Combined short flags are not split

runok deliberately does **not** split combined short flags like `-am`, `-rf`, or `-la`. The reason:

- Without knowledge of the actual command's flag specification, `-am` could mean `-a -m`, `-a` with value `m`, or a single flag `-am`.
- The FlagSchema is inferred from patterns alone — partial information that cannot safely drive splitting decisions.
- Splitting could cause incorrect matches. For example, if `-m` is in the FlagSchema, `-max` would be incorrectly split into `-m` + `ax`.

This means `deny: "git commit -m 'WIP*'"` does **not** match `git commit -am "WIP fix"`. To cover both, users write separate rules for `-m` and `-am`. This is intentional: the pattern says exactly what it matches.

### Trade-offs

- **Pro**: No surprises. Rules behave exactly as written, without distant definitions altering semantics.
- **Pro**: No learning curve for flag schemas or type annotations.
- **Con**: Users must write explicit patterns for each flag combination they want to cover.
- **Con**: Cannot express "any flag that takes a value" generically.

## Explicit Deny Wins

Rule evaluation follows a strict priority order inspired by AWS IAM Policy evaluation:

```
1. Deny match  → Reject (all other rules ignored)
2. Allow match → Permit
3. Ask match   → Prompt user for confirmation
4. No match    → Fall back to configured default
```

### Motivation

This priority system ensures that security-critical deny rules cannot be overridden by broader allow rules. It enables a common and safe pattern: "allow broadly, deny specifically."

```yaml
rules:
  - allow: 'git *' # Allow all git commands
  - deny: 'git push -f|--force *' # But never allow force push
```

Without Explicit Deny Wins, the order of these rules would matter, and a user could accidentally allow dangerous commands by placing an allow rule after a deny rule. With this system, the deny rule always takes precedence regardless of order.

### Compound command aggregation

For compound commands (e.g., `git add . && git push -f`), each sub-command is evaluated independently, and the strictest action wins:

`Deny` > `Ask` > `Allow` > `Default`

This means a single denied sub-command causes the entire compound command to be rejected.

### Trade-offs

- **Pro**: Secure by default. Deny rules are guaranteed to be enforced.
- **Pro**: Rule order does not matter, reducing configuration errors.
- **Con**: Cannot express "allow this specific case even though a deny rule matches" without restructuring rules.

## Policy-Derived Schema

runok infers the structure of commands (which flags take values, which are boolean) from the rule patterns themselves, rather than requiring explicit schema definitions.

### How inference works

The rule engine scans all patterns to build a `FlagSchema`:

```yaml
# From these rules:
rules:
  - deny: 'curl -X|--request POST *'
  - allow: 'curl -X|--request GET *'
  - deny: 'rm -rf /'
```

runok infers:

- `-X` and `--request` take a value (they are followed by `POST`/`GET` in patterns)
- `-rf` is boolean (no value follows in the pattern)

This schema is then used to structurally parse input commands: `curl -X POST https://example.com` is parsed as `command=curl, flags={-X: POST}, args=[https://example.com]`.

### Fallback behavior

- Unknown flags (not seen in any pattern) are treated as boolean.
- Unrecognized tokens are treated as positional arguments.

This ensures runok can handle any command, even those not covered by rules, without errors.

## Wrapper Command Unwrapping

Commands like `bash -c`, `sudo`, and `xargs` wrap other commands. runok recursively evaluates the inner command rather than treating the wrapper as an opaque string.

### Definition

Wrapper patterns are defined in `definitions.wrappers`:

```yaml
definitions:
  wrappers:
    - 'bash -c <cmd>'
    - 'sudo <cmd>'
    - 'xargs <cmd>'
    - "find <paths>... -exec <cmd> \\;"
```

The `<cmd>` placeholder marks the position where the inner command appears. When a command matches a wrapper pattern, the matcher captures the tokens at `<cmd>` and the rule engine recursively evaluates them.

### Recursion limit

Wrapper evaluation is limited to a depth of 10 to prevent infinite recursion (e.g., `sudo sudo sudo ...`).

### Example

Given `deny: "rm -rf /"` and wrapper `sudo <cmd>`:

1. Input: `sudo rm -rf /`
2. Matches wrapper `sudo <cmd>`, captures `rm -rf /`
3. Recursively evaluates `rm -rf /`
4. Matches deny rule → command is rejected

Without wrapper unwrapping, `sudo rm -rf /` would not match `deny: "rm -rf /"` because the command name is `sudo`, not `rm`.

## Sandbox Merge Strategy: Strictest Wins

When a compound command triggers multiple sandbox policies, runok merges them using the strictest combination:

- **Writable paths**: Intersection (only paths allowed by all sub-commands remain writable)
- **Denied paths**: Union (paths denied by any sub-command are denied)
- **Network access**: AND (denied if any sub-command denies network)

### Rationale

A compound command like `npm install && curl https://example.com` should not gain filesystem access from the `npm install` policy when `curl` has a more restrictive sandbox. The strictest-merge approach ensures that no sub-command in a pipeline can weaken the sandbox of another.

## Three-Tier User Design

runok's configuration system is designed around three tiers of users, inspired by Vim's approach to extensibility:

### Level 1: Casual users

Use presets via `extends` and write simple allow/deny/ask rules using familiar command syntax. No schema definitions needed.

```yaml
extends:
  - 'github:runok/preset-standard@v1'
rules:
  - allow: 'git *'
  - deny: 'rm -rf /'
```

### Level 2: Power users

Define custom wrapper commands, use `when` clauses with CEL expressions, and configure sandbox presets for fine-grained control.

```yaml
rules:
  - ask: 'terraform apply'
    when: "env.TF_WORKSPACE == 'production'"
```

### Level 3: Extension developers

Build custom validators using the JSON-RPC 2.0 extension protocol, and publish presets for the community.

This layered approach ensures that the simple case stays simple, while advanced features are available when needed.
