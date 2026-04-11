---
title: Wrapped Command Recursion
description: How runok recursively evaluates wrapped commands through sudo, bash -c, xargs, and similar patterns.
sidebar:
  order: 4
---

Commands like `sudo`, `bash -c`, and `xargs` wrap another command inside them. runok recognizes these patterns and recursively evaluates the **wrapped command**, so rules apply to what actually runs, not just the outer command.

## Defining wrapped command patterns

Wrapped command patterns are defined in the `definitions.wrappers` section of your config. The `<cmd>` placeholder marks where the wrapped command appears:

```yaml
definitions:
  wrappers:
    - 'bash -c <cmd>'
    - 'sudo <cmd>'
    - 'xargs <opts> <cmd>'
    - 'env <opts> <vars> <cmd>'
```

The `<cmd>` placeholder captures one or more tokens. For single-token captures (like `bash -c "ls -la"`), the captured string is passed as-is for further parsing. For multi-token captures (like `sudo ls -la`), the tokens are re-quoted using shell quoting rules before evaluation.

For full details on `<cmd>` and other placeholders, see [Placeholders](/pattern-syntax/placeholders/).

## How recursion works

When `evaluate_command()` processes a command, it tries two things in parallel:

1. **Direct rule matching**: Check all rules against the command.
2. **Wrapped command extraction**: Check if the command matches any `definitions.wrappers` pattern and extract the wrapped command via `<cmd>`.

If both produce a result, they are merged using [Explicit Deny Wins](/rule-evaluation/priority-model/).

### Step-by-step example

Config:

```yaml
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'bash -c <cmd>'

rules:
  - allow: 'sudo *'
  - allow: 'ls *'
  - deny: 'rm -rf /'
```

Command: `sudo bash -c "rm -rf /"`

**Step 1: Depth 0 — Evaluate `sudo bash -c "rm -rf /"`**

- Direct rules: `allow: "sudo *"` matches → `allow`
- `sudo <cmd>` matches → wrapped command: `bash -c "rm -rf /"`
- Recurse into wrapped command (depth 1)

**Step 2: Depth 1 — Evaluate `bash -c "rm -rf /"`**

- Direct rules: no match → resolved to `defaults.action`
- `bash -c <cmd>` matches → wrapped command: `rm -rf /`
- Recurse into wrapped command (depth 2)

**Step 3: Depth 2 — Evaluate `rm -rf /`**

- Direct rules: `deny: "rm -rf /"` matches → `deny`
- No `<cmd>` pattern matches
- Result: **deny**

**Unwinding:**

- Depth 1: merge `defaults.action` with `deny` → **deny** wins
- Depth 0: merge `allow` with `deny` → **deny** wins

Final result: **deny**. The dangerous wrapped command is blocked even though `sudo *` is allowed.

## Compound commands inside wrapped commands

When the wrapped command extracted via `<cmd>` is a [compound command](/rule-evaluation/compound-commands/) (containing `|`, `&&`, `||`, or `;`), it is split into individual sub-commands using tree-sitter-bash. Each sub-command is evaluated separately, and results are merged using Explicit Deny Wins.

```yaml
definitions:
  wrappers:
    - 'bash -c <cmd>'

rules:
  - allow: 'ls *'
  - deny: 'rm -rf *'
```

Command: `bash -c "ls /tmp; rm -rf /"`

1. `bash -c <cmd>` extracts wrapped command: `ls /tmp; rm -rf /`
2. Compound command is split into: `ls /tmp` and `rm -rf /`
3. `ls /tmp` → `allow`
4. `rm -rf /` → `deny`
5. Merged result: **deny** (strictest wins)

### Subshell-wrapped compound commands

Wrapper arguments may also be bare subshells (`(...)`), which is a common pattern when you want to time or sandbox an entire pipeline without shell-quoting it:

```yaml
definitions:
  wrappers:
    - 'time <cmd>'

rules:
  - allow: 'lefthook run *'
  - allow: 'tail *'
  - deny: 'rm -rf *'
```

Command: `time (lefthook run pre-commit 2>&1 | tail -40)`

1. `time <cmd>` captures the subshell `(lefthook run pre-commit 2>&1 | tail -40)` as a single `<cmd>` token.
2. The subshell body is split into `lefthook run pre-commit` and `tail -40`.
3. Both sub-commands match their respective `allow` rules.
4. Merged result: **allow**.

The same path handles `time (rm -rf /)` — the inner `rm -rf /` still triggers the deny rule under Explicit Deny Wins.

## Recursion depth limit

To prevent infinite recursion (e.g., `sudo sudo sudo ...`), runok enforces a maximum recursion depth of **10**. If this limit is exceeded, the evaluation returns a `RecursionDepthExceeded` error.

The depth counter increments each time a wrapped command is extracted and evaluated. The limit is defined as `MAX_WRAPPER_DEPTH = 10` in `src/rules/rule_engine.rs`.

## Ambiguous captures

When a wrapper pattern uses placeholders like `<opts>`, the placeholder consumes matching tokens (e.g., flag-like tokens starting with `-`) and the remaining tokens become the wrapped command via `<cmd>`. If a wildcard `*` is used instead of `<opts>`, multiple split points are possible, and runok tries all captures and selects the one with the **highest action priority** (most restrictive).

## Default action resolution

When the wrapped command does not match any rule, its action is resolved immediately to the configured [`defaults.action`](/configuration/schema/#defaultsaction) (defaulting to `ask` if unconfigured). This ensures that unmatched wrapped commands participate in the merge at their effective restriction level, rather than being silently ignored.
