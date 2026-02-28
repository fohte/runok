---
title: When Clauses
description: Using CEL expressions to add conditional logic to rules.
sidebar:
  order: 5
---

A `when` clause adds a condition to a rule. The rule only takes effect if both the pattern matches **and** the `when` expression evaluates to `true`. This lets you write rules that depend on environment variables, specific flag values, positional arguments, or defined path lists.

```yaml
rules:
  - ask: 'terraform apply *'
    when: "env.TF_WORKSPACE == 'production'"
```

In this example, `terraform apply` only triggers the `ask` prompt when the `TF_WORKSPACE` environment variable is set to `production`. In other workspaces, this rule is skipped.

## Expression language

`when` clauses use [CEL (Common Expression Language)](https://cel.dev/), a lightweight expression language designed for policy evaluation. runok uses the `cel-interpreter` crate to evaluate these expressions.

CEL expressions must evaluate to a **boolean** (`true` or `false`). If the expression returns a non-boolean value, runok reports a type error.

## Context variables

Four context variables are available inside `when` expressions:

### `env` — Environment variables

A map of the current process environment variables.

```yaml
# Only ask when deploying to production
- ask: 'deploy *'
  when: "env.DEPLOY_ENV == 'production'"

# Block curl when a proxy is configured
- deny: 'curl *'
  when: "env.HTTP_PROXY != ''"
```

### `flags` — Parsed command flags

A map of flags extracted from the matched command. Flag names have their **leading dashes stripped** (e.g., `--request` becomes `request`, `-X` becomes `X`).

- Flags with values: `flags.request` → `"POST"` (string)
- Boolean flags (no value): `flags.force` → `null`

```yaml
# Block POST/PUT/PATCH requests to production APIs
- deny: 'curl -X|--request * *'
  when: "flags.request == 'POST' || flags.request == 'PUT'"
```

:::note
The `flags` map only contains flags that **appeared in the actual command**. Accessing a flag that was not present causes an evaluation error. To safely detect boolean flags, use a pattern that explicitly captures them (e.g., `git push -f|--force *`) rather than checking `flags` in a `when` clause.
:::

:::note
Flag names in `flags` correspond to the **flag as it appeared in the command**, minus the dashes. If the user types `curl -X POST`, use `flags.X`. If they type `curl --request POST`, use `flags.request`. To handle both, use the alternation pattern `curl -X|--request * *` — the alternation in the pattern ensures the flag is captured under a consistent name in `flags`.
:::

### `args` — Positional arguments

A list of positional arguments (non-flag tokens after the command name). Access by index with `args[0]`, `args[1]`, etc.

```yaml
# Block terraform destroy on production
- deny: 'terraform destroy *'
  when: "args[0] == 'production'"

# Ask when curl targets a production URL
- ask: 'curl *'
  when: "args[0].startsWith('https://prod.')"
```

### `paths` — Defined path lists

A map of named path lists from the `definitions.paths` section. Useful for checking whether a command operates on sensitive files.

```yaml
definitions:
  paths:
    sensitive:
      - '.env'
      - '.envrc'
      - '~/.ssh/**'

rules:
  # Deny reading sensitive files when there are many defined sensitive paths
  - deny: 'cat <path:sensitive>'
    when: 'size(paths.sensitive) > 0'
```

The `paths` variable is most useful for checking properties of the defined path list itself (e.g., its size), since the `<path:sensitive>` pattern already handles matching individual files against the list.

## Operators

CEL supports standard operators for building conditions:

### Comparison

| Operator   | Description                               |
| ---------- | ----------------------------------------- |
| `==`       | Equal                                     |
| `!=`       | Not equal                                 |
| `<`, `>`   | Less than, greater than                   |
| `<=`, `>=` | Less than or equal, greater than or equal |

### Logical

| Operator | Description |
| -------- | ----------- |
| `&&`     | Logical AND |
| `\|\|`   | Logical OR  |
| `!`      | Logical NOT |

### String methods

| Method                | Description                        |
| --------------------- | ---------------------------------- |
| `.startsWith(prefix)` | Check if string starts with prefix |
| `.endsWith(suffix)`   | Check if string ends with suffix   |
| `.contains(substr)`   | Check if string contains substring |

### Collection

| Expression      | Description                     |
| --------------- | ------------------------------- |
| `value in list` | Check if value exists in a list |
| `size(list)`    | Get the length of a list or map |

## Evaluation order

The `when` clause is evaluated **after** the pattern matches. The evaluation flow is:

1. Check if the rule's pattern matches the input command.
2. If the pattern matches and a `when` clause is present, evaluate the CEL expression.
3. If the expression returns `true`, the rule takes effect.
4. If the expression returns `false`, the rule is **skipped** (as if it never matched).

This means the `when` clause acts as an additional filter, not a replacement for pattern matching. You still need a pattern that matches the command structure.

## Error handling

| Error type  | Cause                                                    | Behavior                    |
| ----------- | -------------------------------------------------------- | --------------------------- |
| Parse error | Invalid CEL syntax (e.g., `@@@ invalid`)                 | Evaluation fails with error |
| Eval error  | Referencing an undeclared variable (e.g., `missing.var`) | Evaluation fails with error |
| Type error  | Expression returns non-boolean (e.g., `env.HOME`)        | Evaluation fails with error |

Errors in `when` clause evaluation cause the entire command evaluation to fail, rather than silently skipping the rule. This is intentional — a misconfigured `when` clause should be surfaced immediately.

## Examples

### Environment-based gating

```yaml
rules:
  # Allow terraform plan everywhere, but ask before apply in production
  - allow: 'terraform plan *'
  - allow: 'terraform apply *'
  - ask: 'terraform apply *'
    when: "env.TF_WORKSPACE == 'production'"
```

### Flag-based restrictions

```yaml
rules:
  # Allow curl GET requests, but ask before POST to specific hosts
  - allow: 'curl -X|--request * *'
  - ask: 'curl -X|--request * *'
    when: "flags.request == 'POST' && args[0].endsWith('.internal')"
```

### Combined conditions

```yaml
rules:
  # Deny destructive HTTP methods to production APIs
  - deny: 'curl -X|--request * *'
    when: "flags.request == 'POST' && args[0].startsWith('https://prod.')"
```
