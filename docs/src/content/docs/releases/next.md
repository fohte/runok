---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### `required_runok_version` field for version guards

Every config and preset file can now declare a `required_runok_version` — a [semver requirement](https://docs.rs/semver/latest/semver/struct.VersionReq.html) expression such as `">=0.3.0"` or `">=0.3, <0.5"`. When runok loads a file whose constraint is not satisfied by the running binary, loading fails with an error that names the exact file and the constraint, rather than silently ignoring newer schema fields.

```yaml title="preset that depends on a newer runok feature"
required_runok_version: '>=0.3.0'
definitions:
  flag_groups:
    field-flag: ['-f', '--field']
```

The check runs per file, so the project `runok.yml`, any file pulled in via `extends`, and every transitively extended preset are all validated independently.

`runok update-presets` now respects this field when choosing upgrade tags. Candidate tags are inspected from newest to oldest, and the newest candidate whose preset tree (including transitive `extends`) satisfies the current runok binary is adopted. This lets preset repositories ship schema-incompatible changes under newer tags without breaking users who are still on older runok.

Nightly builds (`X.Y.Z-nightly+<sha>`) are treated as "latest" for the purpose of version checks, so any `>=X.Y.Z` constraint passes automatically. Upper-bounded ranges still reject nightly intentionally.

See [Configuration Schema — `required_runok_version`](/configuration/schema/#required_runok_version) for details.

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
