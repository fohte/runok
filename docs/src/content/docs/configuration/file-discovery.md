---
title: File Discovery and Merging
description: How runok finds, loads, and merges configuration files.
sidebar:
  order: 2
---

runok loads configuration from up to four layers, merging them in a defined order. This allows you to set organization-wide defaults globally while overriding specific settings per project. For sharing configuration across repositories, see [Extends (Presets)](/configuration/extends/).

## Configuration File Locations

runok searches for configuration files in two scopes:

| Scope   | Path                               | Purpose                |
| ------- | ---------------------------------- | ---------------------- |
| Global  | `$XDG_CONFIG_HOME/runok/runok.yml` | User-wide defaults     |
| Project | `<project>/runok.yml`              | Project-specific rules |

When `XDG_CONFIG_HOME` is not set, the global config directory defaults to `~/.config/runok/`. See [Environment Variables](/configuration/environment-variables/) for details.

In each scope, an optional **local override** file is also loaded:

| Scope   | Override Path                            | Purpose                    |
| ------- | ---------------------------------------- | -------------------------- |
| Global  | `$XDG_CONFIG_HOME/runok/runok.local.yml` | Personal tweaks            |
| Project | `<project>/runok.local.yml`              | Personal project overrides |

### Project Directory Discovery

runok does **not** require you to run commands from the directory containing `runok.yml`. It automatically walks up from the current working directory, checking each ancestor for a configuration file (`runok.yml`, `runok.yaml`, `runok.local.yml`, or `runok.local.yaml`). The first directory that contains any of these files is used as the project configuration directory.

The traversal stops at the user's home directory (`$HOME`). Configuration files placed directly in `$HOME` (e.g. `~/runok.yml`) are **not** loaded as project configuration — use the [global configuration](#configuration-file-locations) instead.

For example, given this directory structure:

```
~/projects/myapp/
├── runok.yml          ← project config found here
├── runok.local.yml
└── src/
    └── lib/           ← you run `runok check` here
```

Running `runok check` from `~/projects/myapp/src/lib/` loads `~/projects/myapp/runok.yml` and `~/projects/myapp/runok.local.yml`.

If multiple ancestor directories contain configuration files, the **nearest** ancestor (closest to the current working directory) wins.

:::tip
Use `.local.yml` files for personal preferences. Add `runok.local.yml` to your global gitignore (`~/.config/git/ignore`) to keep them out of version control across all repositories.
:::

## File Extension Priority

When both `.yml` and `.yaml` extensions exist, `.yml` takes priority:

1. `runok.yml` (preferred)
2. `runok.yaml` (fallback)

This applies to both the main configuration file and the local override file in each scope.

## Merge Order

Configuration layers are merged bottom-to-top, with later layers taking higher priority:

| Priority | Layer                  | Path                                     |
| -------- | ---------------------- | ---------------------------------------- |
| 1 (low)  | Global config          | `$XDG_CONFIG_HOME/runok/runok.yml`       |
| 2        | Global local override  | `$XDG_CONFIG_HOME/runok/runok.local.yml` |
| 3        | Project config         | `./runok.yml`                            |
| 4 (high) | Project local override | `./runok.local.yml`                      |

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

```yaml title="~/.config/runok/runok.yml"
rules:
  - allow: 'git *'

definitions:
  paths:
    secrets:
      - ~/.ssh
```

And a project config:

```yaml title="./runok.yml"
rules:
  - allow: 'cargo build *'
  - deny: 'rm -rf /'

definitions:
  paths:
    secrets:
      - ~/.aws/credentials
```

The merged result is:

```yaml title="Merged result"
rules:
  # global rules come first, then project rules
  - allow: 'git *'
  - allow: 'cargo build *'
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

## Related

- [Configuration Schema](/configuration/schema/) -- Full reference for `runok.yml` fields.
- [Extends (Presets)](/configuration/extends/) -- Inherit configuration from other files or repositories.
