---
title: Security Model
description: What the sandbox protects against and how the security model works.
sidebar:
  order: 2
---

This page explains what runok's sandbox is designed to protect against, the trust boundaries it enforces, and the rationale behind its design decisions.

## What the sandbox protects

The sandbox restricts three capabilities of executed commands:

1. **File system writes** — Prevents commands from modifying files outside of explicitly allowed directories
2. **File system reads** — Optionally prevents commands from reading specific sensitive paths (e.g., `~/.ssh`, `~/.gnupg`)
3. **Network access** — Prevents commands from making TCP/UDP connections when configured

### File system protection

Without a sandbox, an allowed command like `python3 script.py` has full write access to the entire file system (within the user's permissions). A malicious or buggy script could:

- Modify `.git/hooks/` to inject code that runs on every commit
- Overwrite `.env` files or credentials
- Tamper with the `runok.yml` configuration itself
- Write to `~/.ssh/` or other sensitive locations

With a sandbox, write access is restricted to explicitly listed directories. Common protected paths include `.git`, `.runok`, and credential files.

### Network protection

When `network.allow` is `false`, the sandbox prevents the command from:

- Exfiltrating data to external servers
- Downloading and executing remote payloads
- Making unintended API calls

## Trust model

### Commands are untrusted

The sandbox treats every executed command as potentially untrusted. Even commands from `allow` rules may behave unexpectedly — a dependency could have a supply-chain vulnerability, a script could contain bugs, or an AI agent could construct a command that does more than intended.

The sandbox provides a **second layer of defense** beyond the [rule-based allow/deny system](/rule-evaluation/overview/). A command is first checked against rules (is it allowed to run?), then executed inside a sandbox (what can it do?).

### Read access is permitted by default

The sandbox permits read access by default. Most development commands need to read source files, configuration, and dependencies, so blanket read restriction would break most workflows.

However, specific paths can be denied for reading via `fs.read.deny`. This is useful for protecting highly sensitive files like private keys (`~/.ssh`) or credential stores (`~/.gnupg`) that sandboxed commands should never access. Paths listed in `fs.read.deny` become completely inaccessible (both read and write are blocked).

### Unix domain sockets are always permitted

Unix domain sockets (`AF_UNIX`) are never blocked, even when `network.allow` is `false`. Many development tools (package managers, build tools, language servers) use Unix sockets for local inter-process communication. Blocking them would break basic tool functionality without meaningful security benefit, since Unix sockets cannot be used for network exfiltration.

## Deny takes priority over allow

Within the sandbox itself, deny paths always override writable directories. If you configure:

```yaml
fs:
  write:
    allow:
      - '.'
    deny:
      - '.git'
```

Then `.git` is protected even though `.` (its parent) is writable. This matches how both [macOS Seatbelt](/architecture/sandbox/macos/) and [Linux bubblewrap](/architecture/sandbox/linux/) work:

- On macOS, Seatbelt's `(deny file-write*)` rules take priority over `(allow file-write*)` rules
- On Linux, bubblewrap applies `--ro-bind` **after** `--bind`, so read-only mounts overlay writable mounts

## Strictest Wins for compound commands

When multiple sandbox policies apply, runok uses a **Strictest Wins** strategy. See [Sandbox Overview](/sandbox/overview/#sandbox-merging-for-compound-commands) for the merge rules.

This prevents a less-restricted command from weakening the sandbox of a more-restricted command in the same pipeline.

## OS-level enforcement

The sandbox is enforced by the operating system kernel, not by runok's own process. A sandboxed command cannot:

- Disable or modify the sandbox policy at runtime
- Escape the restrictions via child processes (children inherit the sandbox)
- Use `exec()` to replace itself with an unrestricted process

On macOS, this is provided by the Seatbelt kernel extension. On Linux, it is provided by mount namespaces (bubblewrap), Landlock LSM, and seccomp-bpf filters. See the platform-specific pages for details:

- [macOS Sandbox (Seatbelt)](/architecture/sandbox/macos/)
- [Linux Sandbox (Landlock + seccomp)](/architecture/sandbox/linux/)

## Limitations

- **Read restriction is opt-in and path-based** — by default all files are readable; only paths explicitly listed in `fs.read.deny` are blocked
- **Network granularity is binary** — network access is either fully allowed or fully blocked; per-host or per-port filtering is not supported
- **macOS Seatbelt is deprecated** — Apple has deprecated `sandbox-exec` but provides no replacement. It continues to work and is used by Apple's own tools
- **Linux glob deny patterns are expanded at startup** — on Linux, glob patterns in `deny` are expanded against the filesystem before the sandbox starts. Files created after startup that match a glob pattern will not be protected
- **Landlock kernel version** — Landlock requires Linux 5.13 or later. On older kernels, file system restrictions may be partially enforced
