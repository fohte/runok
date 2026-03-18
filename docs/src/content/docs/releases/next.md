---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Highlights

### Breaking: sandbox `fs` config format changed to `read`/`write` sub-sections

The sandbox `fs` section now uses explicit `read` and `write` sub-sections instead of the flat `writable`/`deny` fields. This enables a new capability: **denying read access** to specific paths.

**What should I do?**

Update your `definitions.sandbox` entries to use the new format:

```yaml title="runok.yml"
# Before (v0.2.x)
definitions:
  sandbox:
    restricted:
      fs:
        writable: ['.']
        deny: ['.git']

# After: use read/write sub-sections
definitions:
  sandbox:
    restricted:
      fs:
        write:
          allow: ['.']
          deny: ['.git']
```

The previous `writable`/`deny` format is still accepted for backward compatibility, but the new format is recommended.

## New Features

### Read access control in sandbox presets

Sandbox presets now support denying **read access** to specific paths via `fs.read.deny`. Previously, sandboxing could only restrict write access and network access. With this change, sensitive files like `~/.ssh` and `~/.gnupg` can be made completely inaccessible to sandboxed commands.

```yaml title="runok.yml"
definitions:
  sandbox:
    restricted:
      fs:
        read:
          deny: [~/.ssh, ~/.gnupg]
        write:
          allow: [., /tmp]
          deny: [.env, .envrc]
```

See [Sandbox Overview](/sandbox/overview/) for details.

## Bug fixes

### `runok test` no longer evaluates inline tests from remote presets

Inline tests defined in remote presets (e.g., `github:org/repo`) are now stripped on load. Previously, these tests were collected and evaluated against the full merged config, causing them to fail when local rules overrode the same patterns with stricter actions. Remote preset inline tests are meant to be validated by the preset itself, not by downstream consumers.
