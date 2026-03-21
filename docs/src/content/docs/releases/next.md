---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Highlights

### Deprecated: sandbox `fs.writable`/`fs.deny` replaced by `fs.read`/`fs.write` sub-sections ([#236](https://github.com/fohte/runok/pull/236))

The sandbox `fs` section now uses explicit `read` and `write` sub-sections instead of the flat `writable`/`deny` fields. The old format still works but emits a deprecation warning and will be removed in a future release.

```yaml title="runok.yml"
# Deprecated (emits warning)
fs:
  writable: ['.']
  deny: ['.git']

# New format
fs:
  write:
    allow: ['.']
    deny: ['.git']
```

### `runok migrate` command for automatic config migration ([#252](https://github.com/fohte/runok/pull/252))

Run `runok migrate` to automatically update deprecated config syntax to the latest format. Currently migrates legacy sandbox `fs.writable`/`fs.deny` fields to the new `fs.write.allow`/`fs.write.deny` structure. The deprecation warning now includes a hint to run this command.

```sh
# Migrate all config files discovered for the current directory
runok migrate

# Migrate a specific config file
runok migrate -c path/to/runok.yml
```

See [`runok migrate`](/cli/migrate/) for details.

## New Features

### Read access control in sandbox presets ([#236](https://github.com/fohte/runok/pull/236))

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

## Bug Fixes

### Deprecation warnings now identify their source ([#242](https://github.com/fohte/runok/pull/242))

Deprecation warnings are now prefixed with `runok warning:` and include the config file path, making them distinguishable from warnings emitted by other tools in stderr.

```
runok warning: sandbox fs 'writable'/'deny' fields are deprecated, use 'write: { allow: [...], deny: [...] }' instead
  --> /path/to/runok.yml
```

### Remove unused `definitions.commands` field ([#235](https://github.com/fohte/runok/pull/235))

The `definitions.commands` configuration field has been removed. This field was parsed and merged but never referenced by the rule engine or command parser, so it had no effect at runtime. If your configuration includes `definitions.commands`, simply remove it — no other changes are needed.

### `runok test` no longer evaluates inline tests from remote presets

Inline tests defined in remote presets (e.g., `github:org/repo`) are now stripped on load. Previously, these tests were collected and evaluated against the full merged config, causing them to fail when local rules overrode the same patterns with stricter actions. Remote preset inline tests are meant to be validated by the preset itself, not by downstream consumers.
