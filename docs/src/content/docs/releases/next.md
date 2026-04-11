---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Flag alias groups with `<flag:name>` placeholder ([#278](https://github.com/fohte/runok/pull/278))

`when` clauses can now inspect every value of a repeated or aliased flag through the new `<flag:name>` placeholder and the corresponding `flag_groups` CEL variable.

Define a group of aliased flags under `definitions.flag_groups`, reference it with `<flag:name>` in a pattern, and then iterate through every captured value in the `when` clause:

```yaml title="runok.yml"
definitions:
  flag_groups:
    field-flag: ['-f', '-F', '--field', '--raw-field']

rules:
  # Allow `gh api graphql` queries, but ask before any mutation.
  - allow: 'gh api graphql <flag:field-flag> *'
    when: '!flag_groups["field-flag"].exists(v, v.startsWith("query=mutation"))'
  - ask: 'gh api graphql <flag:field-flag> *'
```

`flag_groups[name]` is always exposed as a **list**, even for a single occurrence, so you can use CEL list macros (`exists`, `all`, `size`) without juggling string-vs-list types. Every group declared in `definitions.flag_groups` is also present in the CEL variable as an empty list when the matched rule did not capture any value, so `flag_groups["name"]` never fails with an undeclared-reference error.

This unlocks several common security checks that were previously awkward or impossible:

- **`gh api graphql`** -- distinguish queries from mutations across `-f`, `-F`, `--field`, `--raw-field`.
- **`curl --data ...`** -- detect attempts to send sensitive files (`-d @/etc/passwd`) across all `-d`/`--data`/`--data-raw`/`--data-binary` aliases.
- **`docker run -v ...`** -- inspect every `--volume` mount, not just the first one.
- **`git -c key=value ...`** -- check every `-c`/`--config` override at once.

See [`<flag:name>`](/pattern-syntax/placeholders/#flag-groups-flagname) and [When Clauses -- `flag_groups`](/rule-evaluation/when-clause/#flag_groups--captured-flag-group-values) for details.

## Bug Fixes

### Wrapper recognition for subshell-wrapped compound commands ([#297](https://github.com/fohte/runok/pull/297))

Commands of the form `<wrapper> (<compound>)` -- for example `time (lefthook run pre-commit 2>&1 | tail -40)` -- are now recognized by wrapper patterns such as `time <cmd>`. The subshell is captured as a single `<cmd>` argument, then its body is split into sub-commands (`lefthook run pre-commit`, `tail -40`) and each is evaluated individually with Explicit Deny Wins.

Previously the wrapper path flattened the input to whitespace-delimited tokens, so `time (ls | tail -40)` came out as `time`, `(ls`, `|`, `tail`, `-40)` and matched neither the `time <cmd>` wrapper nor the compound-command path, falling through to `defaults.action`. Rule evaluation now uses a tree-sitter-bash walk to tokenize single commands, preserving shell groupings (`(...)`, `$(...)`, `` `...` ``, `<(...)`) as one token each so wrapper placeholder extraction can capture them whole. In the same fix, the compound extractor also recurses into bare subshells attached to a command, which keeps `time (...)` symmetric with the long-standing handling of `echo $(...)`.
