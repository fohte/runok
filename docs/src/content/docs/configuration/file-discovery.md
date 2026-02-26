---
title: File Discovery and Merging
description: How runok finds, loads, and merges configuration files.
sidebar:
  order: 2
---

runok loads configuration from up to four layers, merging them in a defined order. This allows you to set organization-wide defaults globally while overriding specific settings per project.

## Configuration File Locations

runok searches for configuration files in two scopes:

| Scope   | Path                              | Purpose                |
| ------- | --------------------------------- | ---------------------- |
| Global  | `~/.config/runok/runok.yml`       | User-wide defaults     |
| Project | `./runok.yml` (working directory) | Project-specific rules |

In each scope, an optional **local override** file is also loaded:

| Scope   | Override Path                           | Purpose                      |
| ------- | --------------------------------------- | ---------------------------- |
| Global  | `~/.config/runok/runok.local.yml`       | Personal tweaks (gitignored) |
| Project | `./runok.local.yml` (working directory) | Personal project overrides   |

:::tip
Use `.local.yml` files for personal preferences that should not be committed to version control.
:::

## File Extension Priority

When both `.yml` and `.yaml` extensions exist, `.yml` takes priority:

1. `runok.yml` (preferred)
2. `runok.yaml` (fallback)

This applies to both the main configuration file and the local override file in each scope.

## Merge Order

Configuration layers are merged bottom-to-top, with later layers taking higher priority:

```
1. Global config         (~/.config/runok/runok.yml)         ← lowest priority
2. Global local override (~/.config/runok/runok.local.yml)
3. Project config        (./runok.yml)
4. Project local override (./runok.local.yml)                ← highest priority
```

After merging all four layers, the resulting configuration is validated.

## Merge Semantics

Different fields use different merge strategies:

| Field                  | Strategy         | Behavior                                             |
| ---------------------- | ---------------- | ---------------------------------------------------- |
| `extends`              | Append           | Lists are concatenated.                              |
| `rules`                | Append           | Rules from all layers are concatenated in order.     |
| `defaults.action`      | Override         | Higher-priority layer wins.                          |
| `defaults.sandbox`     | Override         | Higher-priority layer wins.                          |
| `definitions.paths`    | Per-key append   | Values for each key are concatenated (deduplicated). |
| `definitions.sandbox`  | Per-key override | Higher-priority layer replaces the entire preset.    |
| `definitions.wrappers` | Append           | Lists are concatenated.                              |
| `definitions.commands` | Append           | Lists are concatenated.                              |

### Example

Given a global config:

```yaml
# ~/.config/runok/runok.yml
defaults:
  action: ask

rules:
  - allow: 'git *'

definitions:
  paths:
    secrets:
      - ~/.ssh
```

And a project config:

```yaml
# ./runok.yml
defaults:
  action: allow

rules:
  - deny: 'rm -rf /'

definitions:
  paths:
    secrets:
      - ~/.aws/credentials
```

The merged result is:

```yaml
defaults:
  action: allow # project overrides global

rules:
  # global rules come first, then project rules
  - allow: 'git *'
  - deny: 'rm -rf /'

definitions:
  paths:
    secrets: # values are merged per-key
      - ~/.ssh
      - ~/.aws/credentials
```

## Validation

After merging, runok validates the final configuration:

- Each rule must have exactly one of `deny`, `allow`, or `ask`.
- `deny` rules must not have a `sandbox` attribute.
- `sandbox` values must reference names defined in `definitions.sandbox`.
- `<path:name>` references in `fs.deny` must resolve to entries in `definitions.paths`.
- `<path:name>` references are not allowed inside `definitions.paths` values.

All validation errors are collected and reported together so you can fix every issue in a single pass.
