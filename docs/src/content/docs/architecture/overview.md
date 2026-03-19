---
title: Architecture Overview
description: High-level overview of runok's internal processing pipeline.
sidebar:
  order: 1
---

This page describes the internal architecture of runok for contributors and advanced users who want to understand how commands are evaluated and executed.

## Processing Pipeline

When runok receives a command, it flows through the following stages:

| Step | Stage              | Description                               |
| ---- | ------------------ | ----------------------------------------- |
| 1    | Config Loading     | 4-layer merge + preset resolution         |
| 2    | Command Parsing    | Tokenization + compound command splitting |
| 3    | Rule Evaluation    | Pattern matching + when-clause evaluation |
| 4    | Action Decision    | Allow / Deny / Ask / Default              |
| 5    | Sandbox Resolution | Preset lookup + strictest-merge           |
| 6    | Command Execution  | Sandboxed or direct execution             |

### 1. Config Loading

runok merges configuration from [four layers](/configuration/file-discovery/#merge-order) in ascending priority (global config, global local override, project config, project local override).

The [`extends`](/configuration/extends/) field triggers recursive preset resolution (DFS with cycle detection, max depth 10). Presets can be loaded from local paths or remote GitHub repositories.

Source: [`src/config/loader.rs`](https://github.com/fohte/runok/blob/main/src/config/loader.rs), [`src/config/preset.rs`](https://github.com/fohte/runok/blob/main/src/config/preset.rs)

### 2. Command Parsing

The command parser ([`src/rules/command_parser.rs`](https://github.com/fohte/runok/blob/main/src/rules/command_parser.rs)) handles two tasks:

- **Tokenization**: Shell-aware splitting that respects single/double quotes and backslash escapes.
- **Compound command splitting**: Uses `tree-sitter-bash` to decompose pipelines (`|`), logical operators (`&&`, `||`), semicolons (`;`), subshells, loops, conditionals, and command substitutions into individual commands.

Each individual command is then structurally parsed using a `FlagSchema` inferred from rule patterns (see [Pattern Matching](/architecture/pattern-matching/)).

### 3. Rule Evaluation

The rule engine ([`src/rules/rule_engine.rs`](https://github.com/fohte/runok/blob/main/src/rules/rule_engine.rs)) evaluates each command against the configured rules:

- **Single commands**: Each rule's pattern is tested against the command via the [pattern matching pipeline](/architecture/pattern-matching/), then any [`when` clauses](/rule-evaluation/when-clause/) are evaluated using a CEL expression evaluator.
- **Compound commands**: Each sub-command is evaluated individually, then results are aggregated using the [Explicit Deny Wins](/architecture/design-decisions/#explicit-deny-wins) principle.
- **Wrapper commands**: If a command matches a wrapper definition (e.g., `bash -c <cmd>`, `sudo <cmd>`), the inner command captured by the `<cmd>` placeholder is recursively evaluated (max depth 10).

### 4. Action Decision

The rule engine returns one of four actions:

| Action    | Meaning                                                    |
| --------- | ---------------------------------------------------------- |
| `Allow`   | Command is permitted to execute                            |
| `Deny`    | Command is rejected (with optional reason and suggestion)  |
| `Ask`     | User confirmation is required                              |
| `Default` | No rule matched; falls back to configured default behavior |

For compound commands, actions are aggregated by priority: `Deny` > `Ask` > `Allow` > `Default`.

### 5. Sandbox Resolution

If a matching rule specifies a `sandbox` preset name, the adapter resolves it to a concrete policy:

1. Look up the preset in `definitions.sandbox`
2. Resolve CWD-relative paths to absolute paths
3. For compound commands, merge all sub-command policies using a strictest-wins strategy:
   - `write.allow` paths: intersection (more restrictive)
   - `write.deny` paths: union (all denied paths combined)
   - `read.deny` paths: union (all denied paths combined)
   - `network`: AND (denied if either denies)

If no rule-level sandbox is specified, the global `defaults.sandbox` is applied as a fallback.

### 6. Command Execution

The executor layer ([`src/exec/`](https://github.com/fohte/runok/blob/main/src/exec/)) runs the command in one of three modes:

| Mode               | Description                                         |
| ------------------ | --------------------------------------------------- |
| `TransparentProxy` | Replaces the current process via `exec` syscall     |
| `SpawnAndWait`     | Spawns a child process and waits for it to complete |
| `ShellExec`        | Runs through `sh -c` for shell features             |

When a sandbox policy is active, a platform-specific sandbox wraps the execution:

- **macOS**: Generates an SBPL (Seatbelt Profile Language) profile and runs the command through `sandbox-exec`.
- **Linux**: Uses bubblewrap for mount namespace isolation, Landlock LSM for filesystem access control, and seccomp-bpf for network syscall filtering.

## Module Overview

The source code ([`src/`](https://github.com/fohte/runok/tree/main/src)) is organized into four top-level modules:

| Module                                                           | Responsibility                                                                                            |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| [`cli/`](https://github.com/fohte/runok/tree/main/src/cli)       | CLI argument definitions and subcommand routing                                                           |
| [`config/`](https://github.com/fohte/runok/tree/main/src/config) | Config data model, 4-layer loading/merging, and preset resolution                                         |
| [`rules/`](https://github.com/fohte/runok/tree/main/src/rules)   | Pattern matching pipeline (lexer, parser, matcher), rule engine, command parser, CEL expression evaluator |
| [`exec/`](https://github.com/fohte/runok/tree/main/src/exec)     | Command execution, platform-specific sandbox implementations, extension runner                            |

## Adapter Layer

runok supports three adapter types that share the same evaluation pipeline but differ in how they handle the result:

- **Exec** (`runok exec`): Executes allowed commands directly (or via sandbox). Exits with code 3 for denied/ask actions.
- **Check** (`runok check`): Performs dry-run evaluation and outputs the result as JSON or text. Always exits with code 0.
- **Hook**: Integrates with LLM agent hook systems (e.g., [Claude Code's `PreToolUse` hook](/getting-started/claude-code/)). Evaluates only `Bash` tool invocations and wraps allowed commands with `runok exec --sandbox`.
