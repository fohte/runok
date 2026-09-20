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

### Codex execution path

When a Codex integration routes a Bash command through [`runok exec`](/cli/exec/), Codex's exec policy treats `runok exec` as trusted and `runok exec --ask` as a prompt. `runok init` installs these policy rules so the final command can be evaluated by runok before it runs.

Codex's `allow` exec policy is a trusted execution path and can bypass Codex's normal workspace sandbox. Commands routed through this integration therefore rely on the sandbox preset selected by runok. If no runok sandbox preset applies, the command has no OS-level sandbox from either layer.

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

## Isolated sandboxes for compound commands

In a compound command (`|`, `&&`, `||`, `;`, loops), runok replaces each sub-command that needs a sandbox with `runok exec --hook-origin <token> --sandbox <preset> -- '<sub-command>'`, where `<sub-command>` is that sub-command's own text -- including its `KEY=VALUE` env prefix and its own redirects -- shell-quoted as a single argument. Only the operators joining sub-commands (`|`, `&&`, `||`, `;`) stay in the outer, unsandboxed shell -- one sub-command's sandbox never weakens or gets weakened by another's, because they run as separate processes. Only the Claude Code hook's `updatedInput` rewrite performs this per-sub-command replacement; `runok exec` and `runok check` each hand the whole input to a single process, so they always apply one policy to the entire compound command -- the merged policy described below, or, when every sub-command resolves to the same preset, that preset directly.

For example, with a rule that sandboxes `wc *` under a `readonly` preset and leaves `cat *` unsandboxed:

```
cat notes.txt > out.json | wc -l
```

becomes

```
cat notes.txt > out.json | runok exec --hook-origin <token> --sandbox readonly -- 'wc -l'
```

`cat notes.txt > out.json` is untouched and keeps running outside any sandbox, exactly as the rule matching `cat *` specified. Because the replacement covers the sandboxed sub-command's own text in full, a redirect belonging to that sub-command is carried inside its sandbox: with `cat *` sandboxed under `readonly` and `secret.txt` listed in that preset's `fs.read.deny`, `cat < secret.txt | wc -l` becomes `runok exec --hook-origin <token> --sandbox readonly -- 'cat < secret.txt' | wc -l` -- `secret.txt` is opened inside the sandbox, so the deny rule still applies.

runok falls back to one merged sandbox for the whole compound command -- including inside the hook -- when a sub-command that needs a sandbox meets any of these conditions:

- It has no byte range of its own in the input to replace (the case after a parse failure, where the whole input is treated as one sub-command).
- Its range sits inside another sub-command's range (`$(...)`, `<(...)`). A plain subshell `( ... )` does not trigger this: the subshell itself is not extracted as a sub-command, so the commands inside it are not nested in another sub-command's range.
- It is a shell builtin that changes shell state (`cd`, `export`, `source`, `.`, `eval`, `exec`, `set`, `shift`, `unset`, `readonly`, `local`, `declare`, `typeset`, `alias`, `unalias`, `trap`, `read`, `umask`, `ulimit`, `shopt`, `pushd`, `popd`). Replacing one would run it in a child process spawned by `runok exec`, so the state change would never reach the shell running the rest of the compound command -- `cd build && make` would run `make` in the original directory, not `build`.
- It calls a shell function defined in the same input. The function exists only in the shell that read the definition, so the child process `runok exec` spawns would not find it.

When any of these apply, the whole compound command falls back to one sandbox built from all matched presets with a **Strictest Wins** merge. See [Compound Commands: Sandbox policy aggregation](/rule-evaluation/compound-commands/#sandbox-policy-aggregation) for the merge rules and worked examples.

## OS-level enforcement

The sandbox is enforced by the operating system kernel, not by runok's own process. A sandboxed command cannot:

- Disable or modify the sandbox policy at runtime
- Escape the restrictions via child processes (children inherit the sandbox)
- Use `exec()` to replace itself with an unrestricted process

On macOS, this is provided by the Seatbelt kernel extension. On Linux, it is provided by mount namespaces (bubblewrap), Landlock LSM, and seccomp-bpf filters. See the platform-specific pages for details:

- [macOS Sandbox (Seatbelt)](/architecture/sandbox/macos/)
- [Linux Sandbox (Landlock + seccomp)](/architecture/sandbox/linux/)

## Limitations

- **Codex `write_stdin` input is outside runok's hook path** -- `write_stdin` sends input to a shell session that `exec_command` already started, so no runok hook runs for that input and no new runok decision or approval is made. The session keeps the sandbox established when it started. Interactive shells therefore remain governed by Codex's sandbox, while commands that runok wrapped with a sandbox preset remain governed by that preset.
- **Read restriction is opt-in and path-based** — by default all files are readable; only paths explicitly listed in `fs.read.deny` are blocked
- **Network granularity is binary** — network access is either fully allowed or fully blocked; per-host or per-port filtering is not supported
- **macOS Seatbelt is deprecated** — Apple has deprecated `sandbox-exec` but provides no replacement. It continues to work and is used by Apple's own tools
- **Linux glob deny patterns are expanded at startup** — on Linux, glob patterns in `deny` are expanded against the filesystem before the sandbox starts. Files created after startup that match a glob pattern will not be protected
- **Landlock kernel version** — Landlock requires Linux 5.13 or later. On older kernels, file system restrictions may be partially enforced
