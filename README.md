<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/src/assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/src/assets/logo-light.svg">
    <img alt="runok" src="docs/src/assets/logo-light.svg" width="300">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/fohte/runok/actions/workflows/test.yml"><img src="https://github.com/fohte/runok/actions/workflows/test.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/fohte/runok/releases/latest"><img src="https://img.shields.io/github/v/release/fohte/runok" alt="GitHub Release"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

<p align="center">
  <a href="https://runok.fohte.net">Documentation</a> &middot;
  <a href="https://runok.fohte.net/getting-started/quickstart/">Quick Start</a> &middot;
  <a href="https://runok.fohte.net/configuration/schema/">Configuration</a> &middot;
  <a href="https://runok.fohte.net/recipes/overview/">Recipes</a>
</p>

runok is a command permission tool for LLM coding agents.

## Why runok?

Even with allow rules configured, Claude Code asks for confirmation in cases like these:

```sh
# Claude adds a comment before the command -- no longer matches your allow rule
⏺ Bash(# check logs
      git log --oneline -5)
  ⎿  Running…

Command contains newlines that could separate multiple commands

Do you want to proceed?
❯ 1. Yes
  2. No
```

```sh
# Claude chains commands with && -- same problem
⏺ Bash(git log --oneline -5 && echo "---" && git status)
  ⎿  Running…

Command contains quoted characters in flag names

Do you want to proceed?
❯ 1. Yes
  2. No
```

runok parses commands with `tree-sitter-bash`, so comments, compound commands (`&&`, `|`, `;`), and wrapper commands (`sudo`, `bash -c`, `xargs`) are all handled correctly. Each sub-command is evaluated independently against your rules.

## Features

**Flexible command parsing**

- `tree-sitter-bash` AST parsing -- comments, pipes, `&&`, `;` are understood, not treated as opaque strings
- `sudo`, `bash -c`, `xargs` are recursively unwrapped so rules apply to the inner command

**Flexible rule configuration**

- Wildcards, flag alternation (`-f|--force`), optional groups, argument-order-independent matching
- Conditional `when` clauses with CEL expressions for environment-aware decisions
- OS-level sandboxing (macOS Seatbelt / Linux Landlock) for file and network restrictions

**And more** -- [preset sharing](https://runok.fohte.net/configuration/extends/), [denial feedback](https://runok.fohte.net/configuration/denial-feedback/), [extension protocol](https://runok.fohte.net/extensions/overview/)

## Quick start

### Install

```sh
cargo install --git https://github.com/fohte/runok.git
```

Pre-built binaries are also available on [GitHub Releases](https://github.com/fohte/runok/releases). See [Installation](https://runok.fohte.net/getting-started/installation/) for details.

### Configure

Create `~/.config/runok/runok.yml`:

```yaml
rules:
  - allow: 'git status'
  - allow: 'git diff *'
  - allow: 'git log *'
  - ask: 'git push *'
  - deny: 'git push -f|--force *'
    message: 'Force push is not allowed'

defaults:
  action: ask
```

### Integrate with Claude Code

Add runok as a PreToolUse hook in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": ["runok check --input-format claude-code-hook"]
      }
    ]
  }
}
```

See [Claude Code Integration](https://runok.fohte.net/getting-started/claude-code/) for sandbox setup and advanced configuration.

### Verify

```sh
runok check -- git status        # => allow
runok check -- git push -f main  # => deny
runok check -- git push main     # => ask
```

## Full Documentation

See **[runok.fohte.net](https://runok.fohte.net)**

## Feedback

Feature requests and bug reports are welcome on [GitHub Issues](https://github.com/fohte/runok/issues).
