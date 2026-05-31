---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Command aliases ([#377](https://github.com/fohte/runok/pull/377), [#380](https://github.com/fohte/runok/pull/380))

Add a top-level `aliases` field that rewrites the leading tokens of a command before rule evaluation. Each alias name maps to one or more patterns; when a command matches an alias pattern as a prefix, the matching portion is replaced with the alias name and the rewritten command flows through normal rule evaluation. Rules keyed on the alias name (for example `allow: 'runok check *'`) then cover commands invoked through development wrappers like `cargo run -- ...`.

```yaml title="runok.yml"
aliases:
  runok:
    - 'cargo run [--quiet] [--release] --'
rules:
  - allow: 'runok check *'
```

With this config, `cargo run --quiet -- check 'git status'` is rewritten to `runok check 'git status'` before rule evaluation, so the existing `runok check *` allow rule applies. Aliases are expanded recursively with cycle detection and a depth limit; the audit log records the applied chain on each command branch.

In an alias prefix pattern, a trailing `*` right after a flag is read as that flag's value (not as a trailing wildcard for the remaining argv). This means `kubectl --context *` consumes both the flag and its value, so `kubectl --context prod get pods` rewrites to `kc get pods`:

```yaml title="runok.yml"
aliases:
  kc:
    - 'kubectl --context *'
rules:
  - allow: 'kc *'
```

See [Configuration schema -> aliases](/configuration/schema/) for details.
