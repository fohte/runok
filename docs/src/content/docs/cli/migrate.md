---
title: runok migrate
description: Migrate config files to the latest format.
sidebar:
  order: 8
---

`runok migrate` automatically updates deprecated config syntax to the latest format while preserving comments and formatting.

## Usage

```sh
runok migrate [options]
```

## Flags

### `--config`, `-c` `<path>`

Path to a specific config file to migrate. When omitted, runok discovers config files using the same logic as other commands: global config from `$XDG_CONFIG_HOME/runok/` and project config from the nearest ancestor directory containing `runok.yml`.

## What gets migrated

### Sandbox `fs` legacy format

The legacy `writable`/`deny` fields are rewritten to the new `write.allow`/`write.deny` structure:

```yaml
# Before
fs:
  writable: [., /tmp]
  deny: [.env]

# After
fs:
  write:
    allow: [., /tmp]
    deny: [.env]
```

## Examples

```sh
# Migrate all discovered config files
runok migrate

# Migrate a specific file
runok migrate -c runok.yml
```
