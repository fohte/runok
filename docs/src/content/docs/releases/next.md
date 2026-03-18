---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Read access control in sandbox presets

Sandbox presets now support denying **read access** to specific paths via `fs.read.deny`. Previously, sandboxing could only restrict write access and network access. With this change, sensitive files like `~/.ssh` and `~/.gnupg` can be made completely inaccessible to sandboxed commands.

The `fs` section now uses explicit `read`/`write` sub-sections:

```yaml
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

The previous `writable`/`deny` format is still supported for backward compatibility.

See [Sandbox Overview](/sandbox/overview/) for details.

## Bug fixes

### `runok test` no longer evaluates inline tests from remote presets

Inline tests defined in remote presets (e.g., `github:org/repo`) are now stripped on load. Previously, these tests were collected and evaluated against the full merged config, causing them to fail when local rules overrode the same patterns with stricter actions. Remote preset inline tests are meant to be validated by the preset itself, not by downstream consumers.
