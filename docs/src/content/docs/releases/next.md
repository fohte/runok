---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Breaking Changes

### Flag group definitions use pattern syntax instead of arrays ([#300](https://github.com/fohte/runok/pull/300))

`definitions.flag_groups` values have changed from arrays of flag names to pattern strings. The new format uses the same syntax as rule patterns, with aliases separated by `|` and an optional value pattern suffix.

**Before:**

```yaml
definitions:
  flag_groups:
    field-flag: ['-f', '-F', '--field', '--raw-field']
```

**After:**

```yaml
definitions:
  flag_groups:
    field-flag: '-f|-F|--field|--raw-field *'
```

The `*` at the end indicates this is a value flag (captures the flag and its value). Omitting it defines a bool flag (captures flag presence only).

## New Features

### Bool flag groups ([#300](https://github.com/fohte/runok/pull/300))

Flag groups can now represent boolean flags (flags without a value). Define a flag group without a value pattern:

```yaml
definitions:
  flag_groups:
    verbose: '-v|--verbose'

rules:
  - ask: 'command <flag:verbose> *'
    when: 'size(flag_groups["verbose"]) > 0'
```

### Value-restricted flag groups ([#300](https://github.com/fohte/runok/pull/300))

Flag group definitions can restrict which values are accepted:

```yaml
definitions:
  flag_groups:
    method: '-X|--method GET|HEAD|OPTIONS'

rules:
  - allow: 'curl <flag:method> *'
```

Only `GET`, `HEAD`, and `OPTIONS` will match. Other values like `POST` will not be captured, causing the rule to be skipped.

### `<flag:name>` no longer requires a trailing value pattern ([#300](https://github.com/fohte/runok/pull/300))

The `<flag:name>` placeholder now stands alone in rule patterns. Whether the flag takes a value is determined by the flag group definition, not by the pattern:

```yaml
# Before: <flag:name> consumed the next token as a value pattern
- allow: 'gh api graphql <flag:field-flag> * *'

# After: value behavior comes from the definition
- allow: 'gh api graphql <flag:field-flag> *'
```

See [Flag Groups](/pattern-syntax/placeholders/#flag-groups-flagname) and [Configuration Schema](/configuration/schema/#definitionsflag_groups) for details.
