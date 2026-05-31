---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Command aliases ([#377](https://github.com/fohte/runok/pull/377))

Add a top-level `aliases` field that rewrites the leading tokens of a command before rule evaluation. Each alias name maps to one or more patterns; when a command matches an alias pattern as a prefix, the matching portion is replaced with the alias name and the rewritten command flows through normal rule evaluation. Rules keyed on the alias name (for example `allow: 'runok check *'`) then cover commands invoked through development wrappers like `cargo run -- ...`.

```yaml title="runok.yml"
aliases:
  runok:
    - 'cargo run [--quiet] [--release] --'
rules:
  - allow: 'runok check *'
```

With this config, `cargo run --quiet -- check 'git status'` is rewritten to `runok check 'git status'` before rule evaluation, so the existing `runok check *` allow rule applies. Aliases are expanded recursively with cycle detection and a depth limit; the audit log records the applied chain on each command branch.

See [Configuration schema -> aliases](/configuration/schema/) for details.

## Bug Fixes

### Alias prefix consumes flag-with-value values correctly (TODO(pr-link))

Alias patterns with a value-taking flag whose value is `*` (for example `kubectl --context *`) now consume both the flag and its value as part of the alias prefix. Previously the value half (e.g. `foo` in `kubectl --context foo bar baz`) leaked into the rewritten command tail, producing `kc foo bar baz` instead of `kc bar baz`.

```yaml title="runok.yml"
aliases:
  kc:
    - 'kubectl --context *'
rules:
  - allow: 'kc *'
```

With this config, `kubectl --context prod get pods` is now correctly rewritten to `kc get pods` before rule evaluation.
