---
title: 'General Commands'
description: Allow common shell commands, block dangerous operations, and sandbox interpreters.
sidebar:
  order: 2
---

This recipe shows how to build a general-purpose runok configuration that covers shell builtins, file operations, development tools, and interpreters. It works well as a global config at `~/.config/runok/runok.yml`.

## Complete Example

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

defaults:
  action: ask
  sandbox: default

rules:
  # === deny rules ===

  - deny: 'rm -rf *'
    message: 'Recursive forced deletion is irreversible.'
    fix_suggestion: 'rm -r'

  # === allow rules ===

  # Any command with --help or --version
  - allow: '* --help'
  - allow: '* --version'

  # Shell builtins and basic utilities
  - allow: 'basename *'
  - allow: 'cd *'
  - allow: 'command *'
  - allow: 'cp *'
  - allow: 'dirname *'
  - allow: 'echo *'
  - allow: 'false'
  - allow: 'id'
  - allow: 'mv *'
  - allow: 'printf *'
  - allow: 'pwd'
  - allow: 'readlink *'
  - allow: 'realpath *'
  - allow: 'sleep *'
  - allow: 'test *'
  - allow: 'true'
  - allow: 'type *'
  - allow: 'uname *'
  - allow: 'which *'
  - allow: 'whoami'

  # File viewing and text processing
  - allow: 'cat *'
  - allow: 'cut *'
  - allow: 'diff *'
  - allow: 'du *'
  - allow: 'head *'
  - allow: 'less *'
  - allow: 'ls *'
  - allow: 'sort *'
  - allow: 'stat *'
  - allow: 'tail *'
  - allow: 'tr *'
  - allow: 'tree *'
  - allow: 'uniq *'
  - allow: 'wc *'

  # Search
  - allow: 'find *'
  - allow: 'grep *'
  - allow: 'rg *'

  # File modification
  - allow: 'chmod +x *'
  - allow: 'mkdir *'
  - allow: 'touch *'
  - allow: 'sed *'

  # Data processing
  - allow: 'jq *'
  - allow: 'yq *'
  - allow: 'base64 *'
  - allow: 'date *'

  # Network (read-only)
  - allow: 'curl [-s] [-X GET] *'
  - allow: 'dig *'

  # Process inspection
  - allow: 'ps *'
  - allow: 'lsof *'
  - allow: 'pgrep *'

  # Linters and formatters
  - allow: 'shellcheck *'
  - allow: 'shfmt *'
  - allow: 'prettier *'

  # Interpreters (sandboxed: read-only filesystem, no network)
  - allow: 'node *'
    sandbox: readonly
  - allow: 'python3 *'
    sandbox: readonly
  - allow: 'ruby *'
    sandbox: readonly

definitions:
  paths:
    sensitive:
      - '.env'
      - '.env.*'
      - '.envrc'
      - '~/.ssh/**'
      - '~/.gnupg/**'
      - '~/.aws/credentials'
      - '~/.config/gh/hosts.yml'

  sandbox:
    default:
      fs:
        writable: [., /tmp]
        deny:
          - '<path:sensitive>'
      network:
        allow: true
    readonly:
      fs:
        writable: []
        deny:
          - '<path:sensitive>'
      network:
        allow: false

  wrappers:
    - 'sudo <cmd>'
    - 'bash -c <cmd>'
    - 'sh -c <cmd>'
    - 'xargs <cmd>'
```

## How It Works

### Default sandbox

Every command runs in the `default` sandbox unless overridden. This sandbox:

- Allows writing to the current directory (`.`) and `/tmp`
- Blocks access to sensitive files (`.env`, SSH keys, AWS credentials, etc.)
- Allows network access

Commands not matched by any rule fall through to `defaults.action: ask`.

### `* --help` and `* --version`

The `*` in command position matches any command name. This lets you allow `--help` and `--version` for every command with just two rules.

### curl — read-only by default

```yaml
- allow: 'curl [-s] [-X GET] *'
```

This allows `curl` with optional `-s` (silent) and optional `-X GET`. Other HTTP methods (POST, PUT, DELETE) fall through to `ask` since they are not matched.

### Interpreters with readonly sandbox

```yaml
- allow: 'node *'
  sandbox: readonly
```

Interpreters like `node`, `python3`, and `ruby` are allowed but restricted to a `readonly` sandbox:

- **No filesystem writes** — `writable: []` means no directory is writable
- **No network access** — `network.allow: false`
- **Sensitive files blocked** — same `<path:sensitive>` deny list

This lets you safely run scripts for data processing or calculation without risk of file modification or network exfiltration.

### Sensitive file protection

The `definitions.paths.sensitive` list defines files that should never be accessible from sandboxed commands. The `<path:sensitive>` reference in sandbox `deny` lists expands to this list. Glob patterns like `~/.ssh/**` match all files under a directory.

### Wrapper unwrapping

```yaml
wrappers:
  - 'sudo <cmd>'
  - 'bash -c <cmd>'
  - 'sh -c <cmd>'
  - 'xargs <cmd>'
```

When a command is wrapped (e.g., `sudo rm -rf /`), runok unwraps it and evaluates the inner command (`rm -rf /`) against your rules. The `<cmd>` placeholder captures the inner command.

## Variations

### Add project-specific tools

Extend this base config in a project's `runok.yml`:

```yaml
rules:
  # npm scripts
  - allow: 'npm run build *'
  - allow: 'npm run test *'
  - allow: 'npm run lint *'

  # cargo
  - allow: 'cargo build *'
  - allow: 'cargo test *'
  - allow: 'cargo clippy *'
  - allow: 'cargo fmt *'
```

These project rules merge with the global config. The global deny rules and sandbox policies still apply.

### Allow awk with readonly sandbox

`awk` can execute arbitrary code, so you may want to restrict it:

```yaml
rules:
  - allow: 'awk *'
    sandbox: readonly
```

### Block dangerous commands

Add more deny rules for commands that are irreversible or have high blast radius:

```yaml
rules:
  - deny: 'mkfs *'
    message: 'Formatting disks is not allowed.'

  - deny: 'dd *'
    message: 'dd can overwrite disks. Use with extreme caution.'

  - deny: 'chmod -R 777 *'
    message: 'Recursive 777 permissions are a security risk.'
```
