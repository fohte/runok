---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Command aliases ([#377](https://github.com/fohte/runok/pull/377))

Add a top-level `aliases` field that rewrites the leading tokens of a command before rule evaluation. Each alias name maps to one or more patterns; when a command matches an alias pattern as a prefix, the matching portion is replaced with the alias name and the rewritten command flows through normal rule evaluation. Rules keyed on the alias name (for example `allow: 'a *'`) then cover commands invoked through development wrappers like `cargo run -- ...`.

```yaml title="runok.yml"
aliases:
  a:
    - 'cargo run [--quiet] [--release] --'
rules:
  - allow: 'a *'
```

With this config, `cargo run --quiet -- doctor` is rewritten to `a doctor` before rule evaluation, so the existing `a *` allow rule applies. Aliases are expanded recursively with cycle detection and a depth limit; the audit log records the applied chain on each command branch.

See [Configuration schema -> aliases](/configuration/schema/) for details.
