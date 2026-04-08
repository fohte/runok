---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Flag alias groups with `<flag:name>` placeholder

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

See [`<flag:name>`](/pattern-syntax/placeholders/#flag-groups-flagname) and [When Clauses -- `flag_groups`](/rule-evaluation/when-clause/#flag_groups----captured-flag-group-values) for details.
