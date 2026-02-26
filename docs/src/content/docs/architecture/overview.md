---
title: Architecture Overview
description: High-level overview of runok's internal processing pipeline.
sidebar:
  order: 1
---

This page describes the internal architecture of runok for contributors and advanced users who want to understand how commands are evaluated and executed.

## Processing Pipeline

When runok receives a command, it flows through the following stages:

```
Input (shell command string)
  │
  ▼
Config Loading ─── 4-layer merge + preset resolution
  │
  ▼
Command Parsing ─── tokenization + compound command splitting
  │
  ▼
Rule Evaluation ─── pattern matching + when-clause evaluation
  │
  ▼
Action Decision ─── Allow / Deny / Ask / Default
  │
  ▼
Sandbox Resolution ─── preset lookup + strictest-merge
  │
  ▼
Command Execution ─── sandboxed or direct execution
```

### 1. Config Loading

`DefaultConfigLoader` merges configuration from four layers (in ascending priority):

1. Global config (`~/.config/runok/runok.yml`)
2. Global local override (`~/.config/runok/runok.local.yml`)
3. Project config (`runok.yml`)
4. Project local override (`runok.local.yml`)

The `extends` field triggers recursive preset resolution (DFS with cycle detection, max depth 10). Presets can be loaded from local paths or remote GitHub repositories.

Source: `src/config/loader.rs`, `src/config/preset.rs`

### 2. Command Parsing

The command parser (`src/rules/command_parser.rs`) handles two tasks:

- **Tokenization**: Shell-aware splitting that respects single/double quotes and backslash escapes.
- **Compound command splitting**: Uses `tree-sitter-bash` to decompose pipelines (`|`), logical operators (`&&`, `||`), semicolons (`;`), subshells, loops, conditionals, and command substitutions into individual commands.

Each individual command is then structurally parsed using a `FlagSchema` inferred from rule patterns (see [Pattern Matching](../pattern-matching/)).

### 3. Rule Evaluation

The rule engine (`src/rules/rule_engine.rs`) evaluates each command against the configured rules:

- **Single commands**: `evaluate_command()` runs the [pattern matching pipeline](../pattern-matching/) against each rule, then evaluates any `when` clauses using a CEL expression evaluator.
- **Compound commands**: `evaluate_compound()` evaluates each sub-command individually, then aggregates results using the [Explicit Deny Wins](../design-decisions/#explicit-deny-wins) principle.
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

If a matching rule specifies a `sandbox` preset name, the adapter resolves it to a concrete `SandboxPolicy`:

1. Look up the preset in `definitions.sandbox`
2. Convert to `MergedSandboxPolicy` (resolving CWD-relative paths)
3. For compound commands, merge all sub-command policies using `merge_strictest()`:
   - `writable` paths: intersection (more restrictive)
   - `deny` paths: union (all denied paths combined)
   - `network`: AND (denied if either denies)

If no rule-level sandbox is specified, the global `defaults.sandbox` is applied as a fallback.

### 6. Command Execution

The executor layer (`src/exec/`) runs the command in one of three modes:

| Mode               | Description                                         |
| ------------------ | --------------------------------------------------- |
| `TransparentProxy` | Replaces the current process via `exec` syscall     |
| `SpawnAndWait`     | Spawns a child process and waits for it to complete |
| `ShellExec`        | Runs through `sh -c` for shell features             |

When a sandbox policy is active, a platform-specific `SandboxExecutor` wraps the execution:

- **macOS**: `MacOsSandboxExecutor` generates an SBPL (Seatbelt Profile Language) profile and runs the command through `sandbox-exec`.
- **Linux**: `LinuxSandboxExecutor` uses Landlock LSM for filesystem access control.

## Module Structure

```
src/
├── main.rs                  # Entry point, platform detection, CLI dispatch
├── lib.rs                   # Public module exports
├── cli/
│   ├── mod.rs               # CLI argument definitions (clap)
│   └── route.rs             # Check subcommand routing
├── adapter/
│   ├── mod.rs               # Endpoint trait, run_with_options() orchestration
│   ├── exec_adapter.rs      # ExecAdapter: execute commands
│   ├── check_adapter.rs     # CheckAdapter: dry-run checks
│   └── hook_adapter.rs      # ClaudeCodeHookAdapter: LLM agent hook integration
├── rules/
│   ├── pattern_lexer.rs     # Pattern string → LexToken list
│   ├── pattern_parser.rs    # LexToken list → Pattern AST
│   ├── pattern_matcher.rs   # Pattern vs ParsedCommand matching
│   ├── command_parser.rs    # Shell command tokenization and structural parsing
│   ├── rule_engine.rs       # Rule evaluation orchestration
│   ├── expr_evaluator.rs    # CEL expression evaluation (when clauses)
│   └── error.rs             # Rule-related error types
├── config/
│   ├── model.rs             # Config data model (Config, RuleEntry, SandboxPreset, etc.)
│   ├── loader.rs            # 4-layer config loading and merging
│   └── preset.rs            # Preset resolution (extends)
└── exec/
    ├── command_executor.rs  # CommandExecutor/SandboxExecutor traits, ExecMode
    ├── macos_sandbox/
    │   ├── mod.rs           # MacOsSandboxExecutor, SBPL generation
    │   └── glob_pattern.rs  # Glob-to-SBPL regex conversion
    ├── extension_runner.rs  # JSON-RPC 2.0 extension protocol
    └── error.rs             # Execution-related error types
```

## Adapter Layer

runok supports three adapter types that share the same evaluation pipeline but differ in how they handle the result:

- **ExecAdapter** (`runok exec`): Executes allowed commands directly (or via sandbox). Exits with code 3 for denied/ask actions.
- **CheckAdapter** (`runok check`): Performs dry-run evaluation and outputs the result as JSON or text. Always exits with code 0.
- **HookAdapter**: Integrates with LLM agent hook systems (e.g., Claude Code's `PreToolUse` hook). Evaluates only `Bash` tool invocations and wraps allowed commands with `runok exec --sandbox`.
