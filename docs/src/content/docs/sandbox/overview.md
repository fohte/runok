---
title: Sandbox Overview
description: Run allowed commands in a restricted sandbox environment.
sidebar:
  order: 1
---

runok can execute allowed commands inside a **sandbox** that restricts file system writes and network access. Sandboxing is applied at the OS level using platform-native mechanisms ([macOS Seatbelt](/architecture/sandbox/macos/) or [Linux Landlock + seccomp](/architecture/sandbox/linux/)), so sandboxed processes cannot bypass the restrictions.

See [Security Model](/sandbox/security-model/) for trust boundaries and design rationale.

## Defining sandbox presets

Sandbox policies are defined as named presets under `definitions.sandbox` in your `runok.yml`:

```yaml
definitions:
  sandbox:
    restricted:
      fs:
        read:
          deny:
            - '~/.ssh'
            - '~/.gnupg'
        write:
          allow:
            - '.'
          deny:
            - '.git'
            - '.runok'
      network:
        allow: false
```

Each preset contains two sections:

### `fs` — File system policy

The `fs` section controls both read and write access through `read` and `write` sub-sections:

#### `fs.write` — Write access control

| Field   | Type       | Description                                                                                                                                                            |
| ------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allow` | `string[]` | Directories the sandboxed process can write to. Paths support `~` expansion.                                                                                           |
| `deny`  | `string[]` | Paths the sandboxed process cannot write to, even within writable directories. Supports glob patterns (`*`, `**`, `?`, `[...]`, `{a,b}`) and `<path:name>` references. |

The `deny` list always takes priority over `allow`. For example, if `allow` includes `"."` (the current directory) and `deny` includes `".git"`, the process can write anywhere in the project except the `.git` directory.

#### `fs.read` — Read access control

| Field  | Type       | Description                                                                                   |
| ------ | ---------- | --------------------------------------------------------------------------------------------- |
| `deny` | `string[]` | Paths the sandboxed process cannot read. Supports glob patterns and `<path:name>` references. |

When `fs.read.deny` is specified, the listed paths are completely inaccessible (both read and write are blocked).

:::caution[Deprecated legacy format]
The previous `writable`/`deny` format is still accepted but deprecated. It emits a warning at parse time and will be removed in a future release. Migrate to the new `read`/`write` format.

```yaml
# Deprecated
fs:
  writable: ['.']
  deny: ['.git']

# Equivalent new format
fs:
  write:
    allow: ['.']
    deny: ['.git']
```

:::

### `network` — Network policy

| Field   | Type   | Description                                                                                |
| ------- | ------ | ------------------------------------------------------------------------------------------ |
| `allow` | `bool` | Whether the sandboxed process can make network connections. Defaults to `true` if omitted. |

When `network.allow` is `false`, TCP/UDP sockets are blocked. Unix domain sockets (used for local IPC) are always permitted regardless of this setting.

## Using `<path:name>` references

You can define reusable path lists under `definitions.paths` and reference them in sandbox deny lists:

```yaml
definitions:
  paths:
    sensitive:
      - '.env*'
      - 'credentials.*'
    secrets:
      - '~/.ssh/**'
      - '~/.gnupg/**'
  sandbox:
    restricted:
      fs:
        read:
          deny:
            - '<path:secrets>'
        write:
          deny:
            - '<path:sensitive>'
```

The `<path:secrets>` reference expands to all paths listed under `definitions.paths.secrets`. References can be used in both `read.deny` and `write.deny`. See [Path References](/pattern-syntax/placeholders/#path-references-pathname) and [`definitions.paths`](/configuration/schema/#definitionspaths) for details.

## Applying sandbox to rules

Attach a sandbox preset to any `allow` or `ask` rule with the `sandbox` field:

```yaml
rules:
  - allow: 'python3 *'
    sandbox: restricted
  - allow: 'npm test'
    sandbox: restricted
```

:::caution
`deny` rules cannot have a `sandbox` field. Denied commands are never executed, so sandboxing does not apply.
:::

## Default sandbox

Use `defaults.sandbox` to apply a sandbox preset to all rules that do not specify one explicitly:

```yaml
defaults:
  sandbox: restricted

rules:
  - allow: 'git status' # uses "restricted" sandbox
  - allow: 'cargo build *'
    sandbox: build-env # overrides with "build-env"
```

## Sandbox merging for compound commands

When a compound command like `sh -c "cmd1 && cmd2"` is evaluated, each sub-command may match a different sandbox preset. runok merges all matched policies using the **Strictest Wins** rule:

| Field           | Merge strategy | Effect                                                       |
| --------------- | -------------- | ------------------------------------------------------------ |
| `write.allow`   | Intersection   | Only directories allowed by **all** policies remain writable |
| `write.deny`    | Union          | Write-denied paths from **any** policy are protected         |
| `read.deny`     | Union          | Read-denied paths from **any** policy are protected          |
| `network.allow` | AND            | Network is blocked if **any** policy denies it               |

This ensures that a less-restricted command in a pipeline cannot weaken the restrictions of a more-restricted command.

If the intersection of `writable` roots becomes empty (a contradiction), runok escalates the action to `ask` so the user can decide whether to proceed.

## Example: complete configuration

```yaml
definitions:
  paths:
    sensitive:
      - '.env*'
      - 'credentials.*'
    secrets:
      - '~/.ssh/**'
      - '~/.gnupg/**'
  sandbox:
    workspace-write:
      fs:
        read:
          deny:
            - '<path:secrets>'
        write:
          allow:
            - '.'
          deny:
            - '.git'
            - '.runok'
            - '<path:sensitive>'
      network:
        allow: true
    no-network:
      fs:
        write:
          allow:
            - '.'
          deny:
            - '.git'
            - '.runok'
      network:
        allow: false

defaults:
  sandbox: workspace-write

rules:
  - allow: 'git *'
  - allow: 'python3 *'
    sandbox: no-network
  - allow: 'npm test'
    sandbox: no-network
  - deny: 'rm -rf /'
```

## Related

- [Security Model](/sandbox/security-model/) -- What the sandbox protects and design rationale.
- [macOS Sandbox (Seatbelt)](/architecture/sandbox/macos/) -- macOS implementation details.
- [Linux Sandbox (Landlock + seccomp)](/architecture/sandbox/linux/) -- Linux implementation details.
- [Configuration Schema: `definitions.sandbox`](/configuration/schema/#definitionssandbox) -- Sandbox preset configuration reference.
