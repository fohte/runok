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

<p align="center"><b>runok</b> is a command permission tool for LLM coding agents.</p>

<p align="center">
  <a href="https://runok.fohte.net">📖 Documentation</a> &middot;
  <a href="https://runok.fohte.net/getting-started/quickstart/">🚀 Quick Start</a> &middot;
  <a href="https://runok.fohte.net/configuration/schema/">🔧 Configuration</a>
</p>

---

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
# Text-based parsing flags safe commands as suspicious
⏺ Bash(git log --oneline -5 && echo "---" && git status)
  ⎿  Running…

Command contains quoted characters in flag names

Do you want to proceed?
❯ 1. Yes
  2. No
```

runok parses commands with `tree-sitter-bash`, so comments, compound commands (`&&`, `|`, `;`), and wrapper commands (`sudo`, `bash -c`, `xargs`) are all handled correctly. Each sub-command is evaluated independently against your rules.

And that's just the start. Claude Code's built-in permissions have other limitations too:

**Denied commands give no explanation.** The agent has no idea why a command was blocked. With runok, deny rules include a message and a suggested fix -- the agent reads it and self-corrects:

```yaml
# runok.yml
- deny: 'git push -f|--force *'
  message: 'Force push is not allowed.'
  fix_suggestion: 'git push --force-with-lease'
```

**Global flags break matching.** Claude sometimes adds flags like `-C` before the subcommand. `git -C /path commit` does not match `Bash(git commit *)`. runok handles this with optional groups and order-independent matching:

```yaml
# runok.yml
- allow: 'git [-C *] commit *'
# matches: git commit -m "fix"
# matches: git -C /path/to/repo commit -m "fix"
```

**No recursive parsing of wrappers.** Claude Code does not inspect `sudo`, `bash -c`, or `$()`. runok recursively unwraps them to evaluate the inner command:

```yaml
# runok.yml
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'bash -c <cmd>'

rules:
  - deny: 'rm -rf /'
# "sudo bash -c 'rm -rf /'" -> unwrap sudo -> unwrap bash -c -> deny
```

**JSON only, no comments.** `settings.json` cannot be annotated. runok uses YAML:

```yaml
# runok.yml
rules:
  # read-only git commands are always safe
  - allow: 'git status'
  - allow: 'git diff *'

  # allow push, but not force push -- rewrites shared history
  - deny: 'git push -f|--force *'
    message: 'Use --force-with-lease instead.'
  - ask: 'git push *'
```

See [Why runok?](https://runok.fohte.net/getting-started/why-runok/) for a full comparison table.

## Features

**Flexible command parsing**

- `tree-sitter-bash` AST parsing -- comments, pipes, `&&`, `;` are understood, not treated as opaque strings
- `sudo`, `bash -c`, `xargs` are recursively unwrapped so rules apply to the inner command

**Flexible rule configuration**

- Wildcards, flag alternation (`-f|--force`), optional groups, argument-order-independent matching
- Conditional `when` clauses with CEL expressions for environment-aware decisions
- OS-level sandboxing (macOS Seatbelt / Linux Landlock) for file and network restrictions

**Official presets** -- get started instantly with curated rule sets

- [`base`](https://runok.fohte.net/configuration/official-presets/) -- bundles all presets below plus `--help`/`--version` rules (recommended starting point)
- `readonly-unix` -- common read-only Unix commands (`cat`, `grep`, `find`, `ls`, ...)
- `readonly-git` -- read-only Git subcommands (`status`, `diff`, `log`, ...)
- `readonly-gh` -- read-only GitHub CLI commands (`pr list`, `issue view`, ...)
- `definitions` -- wrapper definitions for `bash -c`, `sudo`, `xargs`, `find -exec`, ...

```yaml
extends:
  - 'github:fohte/runok-presets/base@v1'
```

**[Claude Code plugin](https://runok.fohte.net/getting-started/claude-code/#claude-code-plugin)** -- configure runok rules in natural language directly from Claude Code

```
/plugin install runok@runok-claude-code-plugin
```

**And more** -- [rule testing](https://runok.fohte.net/cli/test/), [audit logging](https://runok.fohte.net/cli/audit/), [preset sharing](https://runok.fohte.net/configuration/extends/), [denial feedback](https://runok.fohte.net/configuration/denial-feedback/), [extension protocol](https://runok.fohte.net/extensions/overview/)

## Quick start

### Install

**Homebrew**

```sh
brew install fohte/tap/runok
```

**From source with Cargo**

```sh
cargo install --git https://github.com/fohte/runok.git
```

Pre-built binaries are also available on [GitHub Releases](https://github.com/fohte/runok/releases). See [Installation](https://runok.fohte.net/getting-started/installation/) for all options.

### Configure

The fastest way to get started is with the interactive setup wizard:

```sh
runok init
```

This creates a `runok.yml`, and if you have Claude Code configured, migrates your Bash permissions to runok rules and registers the PreToolUse hook automatically.

You can also configure manually. Create `~/.config/runok/runok.yml`:

```yaml
# Start with official presets -- covers common read-only commands,
# Git, GitHub CLI, and wrapper definitions out of the box
extends:
  - 'github:fohte/runok-presets/base@v1'

rules:
  # Add your own rules on top of the presets
  - ask: 'git push *'
  - deny: 'git push -f|--force *'
    message: 'Force push is not allowed'

defaults:
  action: ask
```

And add runok as a PreToolUse hook in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "runok check --input-format claude-code-hook"
          }
        ]
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
