# runok

[![CI](https://github.com/fohte/runok/actions/workflows/test.yml/badge.svg)](https://github.com/fohte/runok/actions/workflows/test.yml)
[![GitHub Release](https://img.shields.io/github/v/release/fohte/runok)](https://github.com/fohte/runok/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Command execution permission framework for LLM agents, primarily designed for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

runok replaces Claude Code's built-in Bash tool permission system with a more powerful alternative. Define intuitive rules using the commands you already know, and runok handles allow/deny/ask decisions with structural matching that goes beyond simple prefix matching. While built with Claude Code as the primary target, runok also works with other LLM agents via its generic check interface.

## Why runok?

Claude Code's built-in permission system has limitations:

- **Prefix-only matching** -- `git push -f` can be bypassed with `git push branch -f`
- **No pipe awareness** -- permissions don't apply inside piped commands
- **Wrapper command blind spots** -- `sudo`, `bash -c`, `xargs` bypass permission rules
- **Shell parsing bugs** -- comments, `for` loops, and special characters cause misbehavior

runok solves these by providing structural (order-independent) argument matching, wrapper command unwrapping, and OS-level sandboxing -- all integrated via Claude Code's PreToolUse hook.

## Features

- **Intuitive rule syntax** -- write rules as commands you already know (`deny: "git push -f|--force *"`)
- **Structural matching** -- argument-order-independent matching with alias support (`-X|--request`)
- **Three actions** -- `allow`, `deny`, `ask` with Explicit Deny Wins priority (like AWS IAM)
- **Wrapper command unwrapping** -- recursively evaluate commands inside `bash -c`, `sudo`, `xargs`, etc.
- **OS-level sandboxing** -- restrict file and network access via macOS Seatbelt or Linux Landlock/seccomp
- **Claude Code hook integration** -- use `runok check` as a PreToolUse hook
- **Generic check interface** -- `runok check --command` works with any agent
- **Preset sharing** -- share configs via `extends` with local paths or remote Git repositories
- **Conditional rules** -- `when` clause with CEL expressions for environment-aware decisions
- **Denial feedback** -- custom messages and fix suggestions when commands are denied

## Installation

### From source (cargo)

```sh
cargo install --git https://github.com/fohte/runok.git
```

### From GitHub Releases

Download the pre-built binary from [GitHub Releases](https://github.com/fohte/runok/releases) and place it in your `PATH`.

## Usage

### Configuration file

Create a `runok.yml` in your project root or `~/.config/runok/runok.yml` for global settings:

```yaml
rules:
  # Allow safe read-only commands
  - allow: 'git status'
  - allow: 'git diff *'
  - allow: 'git log *'

  # Allow curl GET requests
  - allow: 'curl [-X|--request GET] *'

  # Ask before push
  - ask: 'git push *'

  # Never allow force push
  - deny: 'git push -f|--force *'
    message: 'Force push is not allowed'
    fix_suggestion: 'git push --force-with-lease'

  # Block production AWS operations
  - deny: 'aws *'
    when: "env.AWS_PROFILE == 'prod'"
    message: 'Production AWS operations are not allowed'

definitions:
  # Define wrapper commands for recursive evaluation
  wrappers:
    - 'sudo <cmd>'
    - 'bash -c <cmd>'
    - 'sh -c <cmd>'
    - 'xargs <cmd>'

  # Named path lists for sandbox deny rules
  paths:
    sensitive:
      - '.env*'
      - '~/.ssh/**'
      - '/etc/**'

  # Sandbox presets
  sandbox:
    restricted:
      fs:
        writable: [./tmp, /tmp]
        deny:
          - '<path:sensitive>'
      network:
        allow: true

defaults:
  action: ask
```

### Rule priority

Rules are evaluated with **Explicit Deny Wins** priority:

1. `deny` match -- command is rejected (overrides everything)
2. `allow` match -- command is permitted
3. `ask` match -- prompt for user confirmation
4. No match -- falls back to `defaults.action` (default: `ask`)

### Subcommands

#### `runok check` -- Check command permissions

Check whether a command would be allowed without executing it:

```sh
# Check a command directly
runok check --command "git push origin main"

# Read from stdin (plaintext)
echo "git push -f origin main" | runok check

# Claude Code PreToolUse hook format
echo '{"toolName":"Bash","toolInput":{"command":"git status"},...}' | runok check --format claude-code-hook
```

#### `runok exec` -- Execute with permission checks

Execute a command after checking permissions, with optional sandbox enforcement:

```sh
# Execute with permission check
runok exec -- git status

# Execute with sandbox
runok exec --sandbox restricted -- python3 script.py
```

### Claude Code integration

Add runok as a PreToolUse hook in your Claude Code settings (`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": ["runok check --format claude-code-hook"]
      }
    ]
  }
}
```

### Pattern syntax

| Syntax          | Meaning                             | Example                     |
| --------------- | ----------------------------------- | --------------------------- |
| `*`             | Match any arguments                 | `git push *`                |
| `-X\|--request` | Alias/alternation (space-free `\|`) | `curl -X\|--request GET *`  |
| `!`             | Negation                            | `curl -X\|--request !GET *` |
| `[...]`         | Optional group                      | `git [-C *] status`         |
| `<cmd>`         | Wrapper placeholder                 | `sudo <cmd>`                |
| `<path:name>`   | Path list reference                 | `<path:sensitive>`          |

## Configuration

### File locations

| Location                    | Scope                            |
| --------------------------- | -------------------------------- |
| `~/.config/runok/runok.yml` | Global (all projects)            |
| `./runok.yml`               | Project-local (overrides global) |

Both `runok.yml` and `runok.yaml` are recognized (`.yml` takes precedence).

### Presets (`extends`)

Share configurations across projects:

```yaml
extends:
  - './local-rules.yml'
  - 'github:runok/preset-standard@v1'
```

Remote presets are cached in `~/.cache/runok/` via shallow clone.

## License

MIT
