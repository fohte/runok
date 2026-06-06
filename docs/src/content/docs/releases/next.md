---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Rule-pattern aliases ([#389](https://github.com/fohte/runok/pull/389))

Add a `definitions.aliases` field that factors out repeated prefixes from rule patterns. Each alias name maps to one or more pattern strings. At rule-load time, every rule whose leading command token equals an alias name is expanded by substituting the alias pattern in for the alias name — so a single rule can cover every variant of a shared flag prefix without rewriting the command itself.

```yaml title="runok.yml"
definitions:
  aliases:
    kubectl:
      - 'kubectl [--namespace|-n *]'
rules:
  - allow: 'kubectl get pods'
```

The rule `kubectl get pods` expands to `kubectl [--namespace|-n *] get pods`, so all of `kubectl get pods`, `kubectl -n prod get pods`, and `kubectl --namespace prod get pods` match it. An alias with N patterns produces N expanded rules. Aliases compose recursively with cycle detection and a depth limit (currently 5).

If an alias pattern ends with a value-taking flag like `--context *` and you want a rule to use that alias with no tail, declare the flag explicitly via `definitions.flag_groups` and reference it as `<flag:name>` in the alias pattern. This tells the command parser that the flag consumes the next token as its value.

The audit log records the alias chain referenced by the matched rule under `command_evaluations[].alias_chain` (in expansion order, outermost-rule reference first). The field is omitted from the JSON when no alias contributed to the match.

See [Configuration schema -> definitions.aliases](/configuration/schema/#definitionsaliases) for details.
