---
title: Design Decisions
description: Key design principles and the rationale behind runok's architecture.
sidebar:
  order: 3
---

This page documents the key design decisions in runok, their rationale, and the trade-offs involved.

## Pattern-Driven Parsing

The most fundamental principle in runok's design: **the way you write a rule is exactly how it will be parsed and matched**. There is no separate schema language for flag types or argument positions — runok infers parsing behavior directly from the rule pattern itself.

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

### FlagSchema inference

The rule engine scans all patterns to build a `FlagSchema` automatically:

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

Unknown flags (not seen in any pattern) default to boolean, and unrecognized tokens are treated as positional arguments. This ensures runok can handle any command without errors, even those not covered by rules.

### Trade-offs

- **Pro**: No surprises. Rules behave exactly as written, without distant definitions altering semantics.
- **Pro**: No learning curve for flag schemas or type annotations.
- **Con**: Users must write explicit patterns for each flag combination they want to cover.
- **Con**: Cannot express "any flag that takes a value" generically.

## Explicit Deny Wins

When multiple rules match, the most restrictive action always wins: `deny` > `ask` > `allow` > `default`. This is inspired by [AWS IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).

### Why this matters

This priority system ensures that security-critical deny rules cannot be overridden by broader allow rules. It enables a common and safe pattern: "allow broadly, deny specifically." Rule order in the config file does not matter — a `deny` rule always takes precedence regardless of where it appears.

Without this guarantee, a user could accidentally allow dangerous commands by placing an allow rule after a deny rule.

The same priority applies to [compound commands](/rule-evaluation/compound-commands/) — a single denied sub-command causes the entire compound command to be rejected.

### Trade-offs

- **Pro**: Secure by default. Deny rules are guaranteed to be enforced.
- **Pro**: Rule order does not matter, reducing configuration errors.
- **Con**: Cannot express "allow this specific case even though a deny rule matches" without restructuring rules.

For full details, see [Priority Model: Explicit Deny Wins](/rule-evaluation/priority-model/).

## Wrapper Command Unwrapping

Commands like `bash -c`, `sudo`, and `xargs` wrap other commands. Without special handling, `sudo rm -rf /` would not match `deny: "rm -rf /"` because the command name is `sudo`, not `rm`.

runok solves this by recognizing wrapper patterns (defined in [`definitions.wrappers`](/rule-evaluation/wrapper-recursion/#defining-wrapped-command-patterns)) and recursively evaluating the inner command captured by the `<cmd>` placeholder. Recursion is limited to a depth of 10 to prevent infinite loops.

This ensures that rules apply to what actually runs, not just the outer wrapper command.

## Sandbox Merge Strategy: Strictest Wins

When a compound command triggers multiple [sandbox](/sandbox/overview/) policies, runok merges them by taking the strictest combination: intersection for writable paths, union for denied paths, and AND for network access.

The rationale: a compound command like `npm install && curl https://example.com` should not gain filesystem access from the `npm install` policy when `curl` has a more restrictive sandbox. No sub-command in a pipeline can weaken the sandbox of another.

For the full merge table and contradiction handling, see [Compound Commands: Sandbox policy aggregation](/rule-evaluation/compound-commands/#sandbox-policy-aggregation).

## Three-Tier User Design

runok's configuration system is designed around three tiers of users, inspired by Vim's approach to extensibility:

### Level 1: Casual users

Use presets via `extends` and write simple allow/deny/ask rules using familiar command syntax. No schema definitions needed.

```yaml
extends:
  - 'github:example-org/runok-preset-standard@v1'
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
