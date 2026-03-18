---
title: macOS Sandbox (Seatbelt)
description: How runok uses macOS Seatbelt to sandbox commands.
sidebar:
  order: 10
---

On macOS, runok uses the **Seatbelt** framework (`sandbox-exec`) to enforce [sandbox policies](/sandbox/overview/). Seatbelt is a kernel-level mandatory access control system built into macOS.

## How it works

When [`runok exec`](/cli/exec/) runs a command with a sandbox policy, it:

1. Generates a **Sandbox Profile Language (SBPL)** policy from the sandbox configuration
2. Launches the command via `/usr/bin/sandbox-exec -p <profile> -- <command>`
3. The kernel enforces the policy for the entire lifetime of the process and all its children

The sandboxed process cannot bypass these restrictions — they are enforced by the macOS kernel, not by runok itself.

## Generated policy structure

runok generates an SBPL profile with the following structure:

```scheme
(version 1)
(allow default)                ; Allow all operations by default
(deny file-write*)             ; Then deny all file writes globally

;; Selectively allow writes to configured writable roots
(allow file-write* (subpath "/path/to/writable"))

;; Re-deny writes to protected subpaths (deny wins over allow)
(deny file-write* (subpath "/path/to/writable/.git"))

;; Block read+write to read-denied paths (e.g., ~/.ssh)
(deny file-read* (subpath "/Users/me/.ssh"))
(deny file-write* (subpath "/Users/me/.ssh"))

;; Always allow /dev/null writes (many tools depend on it)
(allow file-write* (literal "/dev/null"))

;; Block network if configured
(deny network*)
(allow network* (local unix-socket))  ; Keep local IPC working
```

Key design decisions:

- **`(allow default)`** is used as the base, then `(deny file-write*)` blocks all writes. Read access is permitted by default, but can be selectively denied via `fs.read.deny` using `(deny file-read*)` rules. Seatbelt technically supports `deny file-read*` — runok uses it when `fs.read.deny` paths are configured.
- **Deny rules take priority** over allow rules in Seatbelt, so `deny` entries in the sandbox config are enforced even within writable directories.
- **Unix domain sockets** are always allowed because many development tools require local inter-process communication.

## Path handling

### Canonicalization

All `writable` paths are **canonicalized** (symlinks resolved, `.` and `..` removed) before being included in the profile. This prevents bypass via symlinks — for example, `/var` and `/private/var` on macOS refer to the same location.

### Glob patterns in deny paths

The `deny` list supports glob patterns. runok converts these to SBPL regex rules:

| Glob    | SBPL regex | Matches                      |
| ------- | ---------- | ---------------------------- |
| `*`     | `[^/]*`    | Any characters except `/`    |
| `**`    | `.*`       | Any characters including `/` |
| `?`     | `[^/]`     | Single character except `/`  |
| `{a,b}` | `(a\|b)`   | Alternation                  |

For example, `.env*` becomes a regex that matches `.env`, `.env.local`, `.env.production`, etc.

### Relative deny paths

Relative paths in the `deny` list (like `.git`) are resolved against each writable root. If the writable root is `/Users/me/project`, then `.git` becomes `/Users/me/project/.git`.

## Availability

runok checks for the presence of `/usr/bin/sandbox-exec` at runtime. If it is not available, sandbox execution is not supported and runok will report an error.

:::note
Apple has marked `sandbox-exec` as deprecated, but no replacement has been provided. Apple's own applications and system services continue to use Seatbelt internally, so it is expected to remain functional for the foreseeable future.
:::

## Related

- [Sandbox Overview](/sandbox/overview/) -- How sandbox presets are defined and applied.
- [Security Model](/sandbox/security-model/) -- What the sandbox protects.
- [Linux Sandbox (Landlock + seccomp)](/architecture/sandbox/linux/) -- Linux implementation.
