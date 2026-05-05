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

The following context variables are available inside `when` expressions:

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

### `redirects` — Redirect operators

A list of redirect operators attached to the command. Each element is an object with the following fields:

| Field        | Type            | Description                          | Example                                                                 |
| ------------ | --------------- | ------------------------------------ | ----------------------------------------------------------------------- |
| `type`       | `string`        | `"input"`, `"output"`, or `"dup"`    | `"output"`                                                              |
| `operator`   | `string`        | The redirect operator                | `">"`, `">>"`, `"<"`, `"<<<"`, `">&"`, `"<&"`, `"&>"`, `"&>>"`, `">\|"` |
| `target`     | `string`        | The redirect destination             | `"/tmp/log.txt"`, `"/dev/null"`                                         |
| `descriptor` | `int` or `null` | File descriptor number, if specified | `2` (for `2>`)                                                          |

Type classification:

- `"output"`: `>`, `>>`, `>|`, `&>`, `&>>`
- `"input"`: `<`, `<<<`, `<<`, `<<-`
- `"dup"`: `>&`, `<&`

```yaml
# Require output redirect for renovate-dryrun
- deny: 'renovate-dryrun'
  when: '!redirects.exists(r, r.type == "output")'
  message: 'Please redirect output to a log file'
  fix_suggestion: 'renovate-dryrun > /tmp/renovate-dryrun.log 2>&1'

# Only allow output redirect to /tmp/
- allow: 'renovate-dryrun'
  when: 'redirects.exists(r, r.type == "output" && r.target.startsWith("/tmp/"))'
```

:::note
The `redirects` list is empty when the command has no redirects attached. Both single commands (e.g., `renovate-dryrun > /tmp/log.txt`) and compound commands (e.g., `cmd > file && cmd2`) populate redirect metadata correctly.
:::

### `pipe` — Pipeline position

An object indicating whether the command receives piped input or sends piped output:

| Field    | Type   | Description                                                |
| -------- | ------ | ---------------------------------------------------------- |
| `stdin`  | `bool` | `true` if the command receives input from a preceding pipe |
| `stdout` | `bool` | `true` if the command's output feeds into a following pipe |

Both fields are `false` when the command is not part of a pipeline.

```yaml
# Block piped execution of sh/bash (e.g., curl | sh)
- deny: 'sh'
  when: 'pipe.stdin'
- deny: 'bash'
  when: 'pipe.stdin'
```

### `vars` -- Captured variable values

A map of values captured by `<var:name>` placeholders in the matched pattern. When a pattern contains `<var:name>` and matches a command token, the matched token value is stored in `vars` under the variable name.

```yaml
definitions:
  vars:
    instance-ids:
      values:
        - i-abc123
        - i-prod-001

rules:
  # Deny terminating production instances, allow others
  - deny: 'aws ec2 terminate-instances --instance-ids <var:instance-ids>'
    when: "vars['instance-ids'] == 'i-prod-001'"
  - allow: 'aws ec2 terminate-instances --instance-ids <var:instance-ids>'
```

In this example, when the command matches `<var:instance-ids>`, the actual token value (e.g., `i-prod-001`) is captured into `vars['instance-ids']`. The `when` clause can then inspect this value to make conditional decisions.

```yaml
definitions:
  vars:
    regions:
      type: literal
      values:
        - us-east-1
        - eu-west-1
        - ap-southeast-1

rules:
  # Deny AWS operations in US regions, allow others
  - deny: 'aws --region <var:regions> *'
    when: "has(vars.regions) && vars.regions.startsWith('us-')"
  - allow: 'aws --region <var:regions> *'
```

:::note
The `vars` map only contains entries for `<var:name>` placeholders that were present in the matched pattern. If the pattern doesn't use `<var:name>`, the `vars` map is empty. Use `has(vars.name)` to safely check for a variable before accessing it.
:::

### `flag_groups` -- Captured flag group values

A map of values captured by [`<flag:name>`](/pattern-syntax/placeholders/#flag-groups-flagname) placeholders, keyed by flag group name. **Each value is always a list**, even when only one flag value was captured, so `when` clauses can use list-aware CEL macros (`exists`, `all`, `size`) uniformly.

```yaml
definitions:
  flag_groups:
    field-flag: '-f|-F|--field|--raw-field *'

rules:
  # Allow gh api graphql queries, but ask before mutations.
  - allow: 'gh api graphql <flag:field-flag> *'
    when: '!flag_groups["field-flag"].exists(v, v.startsWith("query=mutation"))'
  - ask: 'gh api graphql <flag:field-flag> *'
```

The captured list contains every occurrence of any aliased flag's value. For example, `gh api graphql -f query=query{...} -f variables={}` produces:

```cel
flag_groups["field-flag"] == ["query=query{...}", "variables={}"]
```

For boolean flag groups (defined without a value pattern, e.g. `"-v|--verbose"`), captured values are empty strings. Use `size(flag_groups["name"]) > 0` to check whether the flag was present.

`flag_groups[name]` is always present for every group declared in `definitions.flag_groups`, even when the matched rule did not use `<flag:name>` for that group — the value is then an empty list `[]`. This means `flag_groups["name"]` never raises an "undeclared reference" error.

```yaml
# Block curl invocations that send a sensitive file as request body
definitions:
  flag_groups:
    data-flag: '-d|--data|--data-raw|--data-binary *'

rules:
  - deny: 'curl <flag:data-flag> *'
    when: 'flag_groups["data-flag"].exists(v, v.startsWith("@/etc/"))'
    message: 'Refused: do not send /etc/* as request body'
```

:::note
Use bracket notation (`flag_groups["name"]`) when the group name contains hyphens. CEL's dot notation (`flag_groups.name`) only supports identifiers without hyphens.
:::

### `os` -- Host operating system

A string identifying the operating system runok is running on. Values match Rust's [`std::env::consts::OS`](https://doc.rust-lang.org/std/env/consts/constant.OS.html), so common values are `"macos"`, `"linux"`, `"windows"`, and `"freebsd"`.

```yaml
rules:
  # macOS ships BSD sed; steer to gsed (GNU sed) instead
  - deny: 'sed *'
    when: "os == 'macos'"
    message: 'Use gsed (GNU sed) on macOS'
  - allow: 'gsed *'

  # On Linux, sed is GNU sed already
  - allow: 'sed *'
    when: "os == 'linux'"
```

`os` is also useful with `in` to whitelist a set of platforms:

```yaml
rules:
  - allow: 'pbcopy'
    when: "os in ['macos']"
```

:::note
Shell built-ins like `OSTYPE`, `HOSTTYPE`, and `MACHTYPE` are **not** exported to child processes, so they don't appear in `env`. Use `os` instead of trying to read those through `env.OSTYPE`.
:::

## Filesystem functions

A `fs` namespace exposes read-only filesystem checks for use inside `when` clauses. These functions let a rule depend on whether a marker file or directory exists on disk -- for example, to gate a rule on the presence of a `.git` directory or a flag file dropped by another tool.

| Function           | Description                                                               |
| ------------------ | ------------------------------------------------------------------------- |
| `fs.exists(path)`  | `true` if `path` exists (after symlink resolution).                       |
| `fs.is_file(path)` | `true` if `path` exists and is a regular file (after symlink resolution). |
| `fs.is_dir(path)`  | `true` if `path` exists and is a directory (after symlink resolution).    |

All three functions take a single `string` argument and return a `bool`.

```yaml
rules:
  # Allow `git commit` only when a marker file exists (e.g., dropped by a
  # skill that ran the required pre-commit checks).
  - allow: 'git commit *'
    when: "fs.exists('/tmp/runok-precommit-ok')"
  - ask: 'git commit *'

  # Only enable a rule when the working tree is a git repository.
  - allow: 'git push *'
    when: "fs.is_dir('.git')"
```

### Behaviour

- **Empty path** (`fs.exists('')`) returns `false`. There is no separate "invalid argument" error.
- **Symlinks are followed.** A symlink that points at a regular file makes `fs.is_file` return `true`; a symlink that points at a directory makes `fs.is_dir` return `true`.
- **Broken symlinks** (the link exists, but its target does not) make all three functions return `false`. To detect a dangling link itself, use a different mechanism -- runok does not expose `lstat`-style checks.
- **`NotFound` is the only "false" condition.** Any other I/O error (most commonly `EACCES` when a parent directory is not stat-able) is surfaced as a `when` evaluation error rather than being folded into `false`. This prevents a permission problem from silently misclassifying a `fs.exists(marker)` gate as "no marker".

:::caution
`fs.*` reads the live filesystem each time the `when` clause is evaluated, so the answer can change between two consecutive `runok check` invocations. Use these functions for state that is genuinely meant to gate the rule (a marker file, a working-tree shape) -- not for state that callers cannot reasonably observe.
:::

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

| Expression           | Description                                      |
| -------------------- | ------------------------------------------------ |
| `value in list`      | Check if value exists in a list                  |
| `size(list)`         | Get the length of a list or map                  |
| `x.exists(e, p)`     | Check if any element satisfies predicate         |
| `x.exists_one(e, p)` | Check if exactly one element satisfies predicate |

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

### Redirect-based gating

```yaml
rules:
  # Require output redirect for commands that produce large output
  - deny: 'renovate-dryrun'
    when: '!redirects.exists(r, r.type == "output")'
    message: 'Please redirect output to a log file'
    fix_suggestion: 'renovate-dryrun > /tmp/renovate-dryrun.log 2>&1'

  # Allow with output redirect to /tmp/
  - allow: 'renovate-dryrun'
    when: 'redirects.exists(r, r.type == "output" && r.target.startsWith("/tmp/"))'
```

### Pipe safety

```yaml
rules:
  # Block curl-pipe-sh attacks
  - deny: 'sh'
    when: 'pipe.stdin'
  - deny: 'bash'
    when: 'pipe.stdin'
```

### OS-specific rules

```yaml
rules:
  # Steer macOS users from BSD sed to GNU sed
  - deny: 'sed *'
    when: "os == 'macos'"
    message: 'Use gsed (GNU sed) on macOS'
  - allow: 'gsed *'
  - allow: 'sed *'
    when: "os == 'linux'"
```

## Related

- [Configuration Schema: `when`](/configuration/schema/#when) -- Configuration reference for the `when` field.
- [Extensions](/extensions/overview/) -- Custom validation beyond CEL expressions.
