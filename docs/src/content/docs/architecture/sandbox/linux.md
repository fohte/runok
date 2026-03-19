---
title: Linux Sandbox (Landlock + seccomp)
description: How runok uses Landlock, seccomp-bpf, and bubblewrap to sandbox commands on Linux.
sidebar:
  order: 11
---

On Linux, runok uses a combination of three kernel mechanisms to enforce [sandbox policies](/sandbox/overview/):

| Mechanism        | Controls                                       |
| ---------------- | ---------------------------------------------- |
| **bubblewrap**   | Mount namespace isolation (file system layout) |
| **Landlock LSM** | File system access permissions                 |
| **seccomp-bpf**  | Network system call filtering                  |

## Two-stage execution

Linux sandboxing requires a **two-stage execution** model because the different mechanisms must be applied at different points in the process lifecycle.

### Stage 1: Namespace isolation (bubblewrap)

`runok` launches itself inside **bubblewrap** (`bwrap`) using a hidden `__sandbox-exec` subcommand, which creates an isolated mount namespace:

- `/` is mounted **read-only** (the entire root file system)
- Writable directories are re-mounted with write access
- Write-denied subpaths are mounted read-only on top (mount ordering ensures deny takes priority)
- Read-denied paths are hidden via tmpfs (directories) or `/dev/null` bind-mounts (files)
- `/proc` and `/dev` are set up for the sandboxed process
- `/tmp` gets a private tmpfs (unless it overlaps with a writable root)
- All namespaces are unshared (`--unshare-all`), with network selectively shared back if allowed

### Stage 2: Process-level restrictions (Landlock + seccomp)

Inside the bubblewrap namespace, the re-invoked `runok` process applies:

1. **Landlock** rules for file system access control
2. **seccomp-bpf** filters for network system call blocking
3. Then replaces itself with the target command via `execvp`

This two-stage model is necessary because bubblewrap sets up the namespace before `exec`, while Landlock and seccomp must be applied within the namespace. By re-invoking itself via `runok __sandbox-exec`, runok achieves this without requiring a separate helper binary.

## Landlock (file system access)

[Landlock](https://docs.kernel.org/userspace-api/landlock.html) is a Linux Security Module (available since Linux 5.13) that provides unprivileged file system access control.

runok uses Landlock to define which paths are readable and writable:

- `/` is granted **read-only** access
- `/dev/null` is granted **read-write** access (required by many tools)
- `/dev/zero`, `/dev/urandom`, `/dev/random` are granted **read-only** access
- `/tmp` is granted **read-write** access (unless overlapping with a writable root)
- Each configured `writable` directory is granted **read-write** access

:::note
Landlock rules within a single ruleset are **additive** (union of permissions). This means Landlock alone cannot make a subdirectory read-only when its parent is writable. That enforcement is handled by bubblewrap's mount ordering.
:::

### Compatibility

runok uses Landlock ABI V5 with **best-effort compatibility**. On older kernels with limited Landlock support, unsupported permissions are automatically dropped. The sandbox still provides as much protection as the kernel supports.

## seccomp-bpf (network control)

When `network.allow` is `false`, runok installs a [seccomp-bpf](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) filter that blocks network socket creation:

- The `socket(2)` system call is intercepted
- If the socket domain is **not** `AF_UNIX`, the call returns `EPERM`
- `AF_UNIX` (Unix domain sockets) is always allowed for local IPC

This effectively blocks TCP (`AF_INET`) and IPv6 (`AF_INET6`) connections while keeping local inter-process communication working.

All other system calls are unaffected — seccomp is only used for network control, not for general system call filtering.

## Write-deny path handling

The `write.deny` list is enforced through bubblewrap's mount ordering:

- **Literal paths** (e.g., `.git`, `/etc/shadow`) are mounted read-only via `--ro-bind`
- **Glob patterns** (e.g., `.env*`, `~/.ssh/**`) are expanded against the filesystem at startup, and each matched real path is mounted read-only

:::caution
Glob expansion happens before the sandbox starts. Files created after the sandbox is running that match a glob pattern will **not** be protected. For guaranteed protection, use literal paths.
:::

## Read-deny path handling

The `read.deny` list is enforced by hiding paths entirely via bubblewrap mounts:

- **Directories** are replaced with an empty `--tmpfs` mount, making the original contents invisible
- **Files** are replaced by bind-mounting `/dev/null` over them, so reads return empty content and the original data is inaccessible
- **Glob patterns** are expanded at startup and each match is hidden using the appropriate method above

Since Landlock rules are additive and cannot revoke the baseline read-only access granted to `/`, read-deny enforcement relies entirely on bubblewrap's mount operations.

:::caution
The same glob expansion caveat applies: files created after the sandbox starts that match a glob pattern will not be hidden.
:::

## Related

- [Sandbox Overview](/sandbox/overview/) -- How sandbox presets are defined and applied.
- [Security Model](/sandbox/security-model/) -- What the sandbox protects.
- [macOS Sandbox (Seatbelt)](/architecture/sandbox/macos/) -- macOS implementation.
