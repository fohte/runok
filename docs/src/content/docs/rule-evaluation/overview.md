---
title: Rule Evaluation Overview
description: How runok evaluates rules and resolves conflicts.
sidebar:
  order: 1
---

runok evaluates commands against your rules to decide whether to **allow**, **deny**, or **ask** for confirmation. This section explains the internal evaluation engine in detail.

## Key concepts

- **[Priority Model: Explicit Deny Wins](/rule-evaluation/priority-model/)** — When multiple rules match, the most restrictive action always wins. A `deny` rule overrides `allow` and `ask`, regardless of rule order.

- **[Compound Commands](/rule-evaluation/compound-commands/)** — Pipelines, logical operators (`&&`, `||`), and semicolons are decomposed into individual sub-commands. Each is evaluated separately, and the strictest result applies to the whole.

- **[Wrapped Command Recursion](/rule-evaluation/wrapper-recursion/)** — Commands like `sudo`, `bash -c`, and `xargs` wrap another command inside them. runok extracts the wrapped command and evaluates it recursively, so rules apply to what actually runs.

- **[When Clauses](/rule-evaluation/when-clause/)** — CEL expressions add conditional logic to rules, letting you gate actions on environment variables, flags, arguments, or path lists.

## Evaluation flow

When runok receives a command:

1. **Parse compound command**: Split into sub-commands using tree-sitter-bash (see [Compound Commands](/rule-evaluation/compound-commands/)).
2. **For each sub-command**:
   a. Match against all rules (pattern + `when` clause filtering).
   b. Try [`definitions.wrappers`](/configuration/schema/#definitionswrappers) pattern matching to extract wrapped commands for recursive evaluation.
   c. Merge direct and wrapped command results using Explicit Deny Wins.
3. **Aggregate**: Merge all sub-command results (strictest wins).
4. **Resolve [sandbox](/sandbox/overview/)**: Merge sandbox policies from matched presets.
5. **Return**: The final action (`allow`, `deny`, or `ask`) and sandbox policy. If no rule matched, the action is resolved to the configured `defaults.action` (defaulting to `ask`).
