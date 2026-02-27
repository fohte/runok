---
title: Linux Sandbox (Landlock + seccomp)
description: How runok uses Landlock, seccomp-bpf, and bubblewrap to sandbox commands on Linux.
sidebar:
  order: 3
---

On Linux, runok uses a combination of three kernel mechanisms to enforce sandbox policies:

| Mechanism        | Controls                                       |
| ---------------- | ---------------------------------------------- |
| **bubblewrap**   | Mount namespace isolation (file system layout) |
| **Landlock LSM** | File system access permissions                 |
| **seccomp-bpf**  | Network system call filtering                  |

## Two-stage execution

Linux sandboxing requires a **two-stage execution** model because the different mechanisms must be applied at different points in the process lifecycle.

### Stage 1: Namespace isolation (bubblewrap)

The main `runok` binary launches `runok-linux-sandbox` (a helper binary) via **bubblewrap** (`bwrap`), which creates an isolated mount namespace:

- `/` is mounted **read-only** (the entire root file system)
- Writable directories are re-mounted with write access
- Protected subpaths are mounted read-only on top (mount ordering ensures deny takes priority)
- `/proc` and `/dev` are set up for the sandboxed process
- `/tmp` gets a private tmpfs (unless it overlaps with a writable root)
- All namespaces are unshared (`--unshare-all`), with network selectively shared back if allowed

### Stage 2: Process-level restrictions (Landlock + seccomp)

Inside the bubblewrap namespace, the helper binary applies:

1. **Landlock** rules for file system access control
2. **seccomp-bpf** filters for network system call blocking
3. Then replaces itself with the target command via `execvp`

This two-stage model is necessary because bubblewrap sets up the namespace before `exec`, while Landlock and seccomp must be applied within the namespace.

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

## Deny path handling

The `deny` list in the sandbox configuration is enforced through bubblewrap's mount ordering:

- **Literal paths** (e.g., `.git`, `/etc/shadow`) are mounted read-only via `--ro-bind`
- **Glob patterns** (e.g., `.env*`, `~/.ssh/**`) are **skipped by bubblewrap** because it can only operate on real paths, not patterns

:::caution
On Linux, glob patterns in `deny` are not enforced by bubblewrap mounts. They are still enforced by other layers when possible, but for maximum protection, use literal paths in the `deny` list.
:::

## Required binaries

Linux sandboxing requires two binaries:

| Binary                | Purpose                                                            |
| --------------------- | ------------------------------------------------------------------ |
| `runok`               | Main binary — generates the sandbox policy and launches the helper |
| `runok-linux-sandbox` | Helper binary — applies Landlock + seccomp and execs the command   |

The helper binary is searched in the following order:

1. The same directory as the `runok` binary
2. The system `PATH`
