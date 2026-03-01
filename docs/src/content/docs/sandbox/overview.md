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
        writable:
          - '.'
        deny:
          - '.git'
          - '.runok'
      network:
        allow: false
```

Each preset contains two sections:

### `fs` — File system policy

| Field      | Type       | Description                                                                                                                                                            |
| ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `writable` | `string[]` | Directories the sandboxed process can write to. Paths support `~` expansion.                                                                                           |
| `deny`     | `string[]` | Paths the sandboxed process cannot write to, even within writable directories. Supports glob patterns (`*`, `**`, `?`, `[...]`, `{a,b}`) and `<path:name>` references. |

The `deny` list always takes priority over `writable`. For example, if `writable` includes `"."` (the current directory) and `deny` includes `".git"`, the process can write anywhere in the project except the `.git` directory.

:::note
Read access is never restricted. The sandbox only controls **write** access and **network** access.
:::

### `network` — Network policy

| Field   | Type   | Description                                                                                |
| ------- | ------ | ------------------------------------------------------------------------------------------ |
| `allow` | `bool` | Whether the sandboxed process can make network connections. Defaults to `true` if omitted. |

When `network.allow` is `false`, TCP/UDP sockets are blocked. Unix domain sockets (used for local IPC) are always permitted regardless of this setting.

## Using `<path:name>` references

You can define reusable path lists under `definitions.paths` and reference them in sandbox `deny` lists:

```yaml
definitions:
  paths:
    sensitive:
      - '.env*'
      - '~/.ssh/**'
  sandbox:
    restricted:
      fs:
        deny:
          - '<path:sensitive>'
```

The `<path:sensitive>` reference expands to all paths listed under `definitions.paths.sensitive`. See [Path References](/pattern-syntax/placeholders/#path-references-pathname) and [`definitions.paths`](/configuration/schema/#definitionspaths) for details.

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
| `writable`      | Intersection   | Only directories allowed by **all** policies remain writable |
| `deny`          | Union          | Denied paths from **any** policy are protected               |
| `network.allow` | AND            | Network is blocked if **any** policy denies it               |

This ensures that a less-restricted command in a pipeline cannot weaken the restrictions of a more-restricted command.

If the intersection of `writable` roots becomes empty (a contradiction), runok escalates the action to `ask` so the user can decide whether to proceed.

## Example: complete configuration

```yaml
definitions:
  paths:
    sensitive:
      - '.env*'
      - '~/.ssh/**'
      - 'credentials.*'
  sandbox:
    workspace-write:
      fs:
        writable:
          - '.'
        deny:
          - '.git'
          - '.runok'
          - '<path:sensitive>'
      network:
        allow: true
    no-network:
      fs:
        writable:
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
