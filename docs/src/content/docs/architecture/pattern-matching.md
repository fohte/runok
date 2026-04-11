---
title: Pattern Matching Pipeline
description: How runok's 3-layer pattern matching works internally.
sidebar:
  order: 2
---

runok uses a 3-layer pipeline to match rule patterns against shell commands: **Lexer** → **Parser** → **Matcher**. This page describes each layer in detail.

## Overview

The pipeline has two independent input paths that converge at the Matcher:

**Rule pattern path:**

1. **Lexer** — splits the pattern string into a list of tokens (literals, wildcards, alternations, etc.)
2. **Parser** — transforms the token list into a structured pattern with command name, flags, and arguments

**Command path:**

1. **Command Parser** — tokenizes and structurally parses the shell command string into a command name, flags, and positional arguments

**Convergence:**

- The **Matcher** receives the structured pattern and the parsed command, compares them, and returns a match result (with optional captures for wrapper placeholder extraction).

## Layer 1: Lexer

**Source**: [`src/rules/pattern_lexer.rs`](https://github.com/fohte/runok/blob/main/src/rules/pattern_lexer.rs)

The lexer converts a pattern string into a flat list of `LexToken` values. It handles:

| Token type                     | Example                    | Description                                         |
| ------------------------------ | -------------------------- | --------------------------------------------------- |
| `Literal`                      | `git`, `'hello world'`     | Plain string token (quotes act as grouping only)    |
| `Alternation`                  | `-X\|--request`            | Pipe-separated alternatives (no spaces around `\|`) |
| `Wildcard`                     | `*`                        | Matches any number of arguments                     |
| `Negation`                     | `!prod`                    | Must not match the value                            |
| `NegationAlternation`          | `!POST\|PUT`               | Must not match any of the alternatives              |
| `OpenBracket` / `CloseBracket` | `[--verbose]`              | Optional group markers                              |
| `Placeholder`                  | `<cmd>`                    | Wrapper command placeholder                         |
| `MultiWordAlternation`         | `"npx prettier"\|prettier` | Multi-word alternatives                             |

The lexer splits on whitespace, then classifies each token by examining prefix characters (`!`, `<`, `[`, `]`), pipe separators, and quote boundaries.

### Example

Pattern: `curl -X|--request POST|PUT *`

Lexer output:

```
[Literal("curl"), Alternation(["-X", "--request"]), Alternation(["POST", "PUT"]), Wildcard]
```

## Layer 2: Parser

**Source**: [`src/rules/pattern_parser.rs`](https://github.com/fohte/runok/blob/main/src/rules/pattern_parser.rs)

The parser transforms `Vec<LexToken>` into a structured `Pattern`:

```rust
struct Pattern {
    command: CommandPattern,  // Command name (Literal, Alternation, or Wildcard)
    tokens: Vec<PatternToken>, // Argument patterns
}
```

### Key transformations

**Flag-value association**: When a flag alternation is followed by a non-flag token, the parser combines them into a `FlagWithValue`:

```
Alternation(["-X", "--request"]) + Alternation(["POST", "PUT"])
  → FlagWithValue { aliases: ["-X", "--request"], value: Alternation(["POST", "PUT"]) }
```

This is how `deny: "curl -X POST"` teaches runok that `-X`/`--request` is a flag that takes a value, not a boolean flag.

**Multi-word expansion**: `parse_multi()` expands `MultiWordAlternation` tokens into multiple independent `Pattern` instances. For example, `"npx prettier"|prettier` produces two patterns: one for `npx prettier` and one for `prettier`.

**Optional groups**: `[--verbose]` is parsed as an `Optional` token, meaning the pattern matches with or without that flag.

### FlagSchema inference

The parser's output drives **FlagSchema** construction in the rule engine. By examining which patterns have `FlagWithValue` tokens, runok infers which flags take values and which are boolean — without needing an explicit flag definition file. This is core to the [Pattern-Driven Parsing](/architecture/design-decisions/#pattern-driven-parsing) design principle.

## Layer 3: Matcher

**Source**: [`src/rules/pattern_matcher.rs`](https://github.com/fohte/runok/blob/main/src/rules/pattern_matcher.rs)

The matcher compares a `Pattern` against a `ParsedCommand` and returns whether they match (optionally with captures for placeholder extraction).

### Matching algorithm

The core algorithm in `match_tokens_core()` uses recursive matching with backtracking:

1. Walk through pattern tokens and command tokens in parallel.
2. For each pattern token, attempt to match against the current command position.
3. On failure, backtrack to the last wildcard and try consuming one more command token.

A step counter (`MAX_MATCH_STEPS = 10,000`) prevents exponential blowup on pathological patterns.

### Matching rules by token type

| Pattern token   | Matching behavior                                                                                                                                                                                                                                                                                                                              |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Literal`       | Skips leading flag tokens to find the first positional argument and matches against it. Unescaped `*` acts as a glob; `\*` matches a literal `*`. **Order-independent** relative to flags; positional order among non-flag tokens is preserved. After `--`, matches at the current position with no skipping                                   |
| `Wildcard`      | Matches zero or more remaining tokens (greedy with backtracking)                                                                                                                                                                                                                                                                               |
| `Alternation`   | Alternations containing any flag alternative (starting with `-`) scan the entire token list (**order-independent**). Purely non-flag alternations skip leading flags like `Literal`. After `--`, matches at the current position                                                                                                               |
| `FlagWithValue` | Scans the entire token list for the flag, then checks the next token matches the value. Also matches `=`-joined forms (e.g. `--flag=value`) and fused short flag forms (e.g. `-n3`). **Order-independent**: the flag can appear anywhere in the command                                                                                        |
| `Negation`      | **Positional negation**: skips leading flags to find the first positional token and checks it does **not** equal the value. **Flag-only negation** (all alternatives start with `-`): scans the entire token list for the forbidden flag without consuming a positional token. Passes when the flag is absent, including when no tokens remain |
| `Optional`      | Tries matching with the optional tokens included, falls back to without                                                                                                                                                                                                                                                                        |
| `Placeholder`   | Captures remaining tokens for wrapper command re-evaluation                                                                                                                                                                                                                                                                                    |
| `PathRef`       | Expands `definitions.paths` entries and matches against them                                                                                                                                                                                                                                                                                   |

### Order-independent matching

Several token types use order-independent matching so that flag placement does not affect rule evaluation:

- **`FlagWithValue`**: Scans the entire token list for the flag regardless of position. `curl -X POST *` matches both `curl -X POST url` and `curl url -X POST`.
- **`Literal`** and purely non-flag **`Alternation`**: Skip over leading flag tokens (and their values for known value-flags) to find the first positional argument. `gh api -X GET *` matches `gh -X GET api /repos` because `api` is found after skipping `-X GET`. Positional order among non-flag tokens is still preserved.
- **Flag-containing `Alternation`** and **flag-only `Negation`**: Scan all tokens for a matching flag, independent of position. Mixed alternations like `-v|verbose` also scan all tokens so that both the flag and non-flag variants can match.

The bare `--` separator disables flag-skipping for subsequent `Literal` and `Alternation` matches, preserving the POSIX end-of-options semantics.

### `=`-joined flag splitting

`FlagWithValue` also matches `=`-joined command tokens (e.g. `--sort=value` for a pattern `--sort value`). The splitting only recognizes standard flag forms:

- **Short flags**: `-X=val` (single dash + one character)
- **Long flags**: `--flag=val` (double dash)

Non-standard forms like `-Denv=prod` (Java) or `-DFOO=bar` (GCC) are not split. These are treated as single tokens because the portion before `=` (`-Denv`, `-DFOO`) is not a standard flag name — it is a fused flag-key combination specific to the command.

### Fused short flag splitting

`FlagWithValue` also matches fused short flag tokens where the value is directly attached to the flag character (e.g. `-n3` for a pattern `-n *`). The splitting extracts the first two bytes as the flag part (`-n`) and the remainder as the value (`3`). This is only attempted when:

- The token starts with `-` (not `--`) and is longer than 2 bytes
- The second byte is an ASCII character (non-ASCII characters are rejected to avoid slicing inside multi-byte UTF-8 characters)
- The extracted flag matches one of the `FlagWithValue` aliases

This design avoids false splits on combined boolean flags like `-rf`, since splitting only occurs when the pattern explicitly declares the flag takes a value.

### Wrapper command matching

When a pattern contains a `<cmd>` placeholder (defined in `definitions.wrappers`), the matcher captures all tokens at that position. The captured tokens are then reassembled into a command string and recursively evaluated by the rule engine.

Example: With wrapper `sudo <cmd>`, the command `sudo rm -rf /` matches, and `rm -rf /` is captured for recursive evaluation.

## Command Parser

**Source**: [`src/rules/command_parser.rs`](https://github.com/fohte/runok/blob/main/src/rules/command_parser.rs)

The command parser operates on the input command (not the pattern). It provides:

### Tokenization

`tokenize()` splits a shell command string into tokens, respecting:

- Single and double quotes
- Backslash escapes
- Empty quoted strings (preserved as empty tokens)
- Balanced shell groupings kept as single tokens (subshells `(...)`, command substitutions `$(...)` / `` `...` ``, parameter expansions `${...}`). This lets wrapper patterns such as `time <cmd>` capture a whole subshell (`time (ls | tail -40)`) as one `<cmd>` placeholder before recursing into it.

### Structural parsing

`parse_command()` uses the `FlagSchema` (inferred from rule patterns) to classify tokens:

```rust
struct ParsedCommand {
    command: String,           // Command name
    flags: HashMap<String, Option<String>>, // Recognized flags and their values
    args: Vec<String>,         // Positional arguments
    raw_tokens: Vec<String>,   // Original token list
}
```

Unrecognized flags default to boolean (no value consumed). This is a deliberate fallback — runok does not need a complete flag specification because the FlagSchema is derived from what rules actually reference.

### Compound command splitting

`extract_commands()` uses `tree-sitter-bash` to parse compound shell expressions and extract individual commands from:

- Pipelines (`cmd1 | cmd2`)
- Logical operators (`cmd1 && cmd2`, `cmd1 || cmd2`)
- Semicolons (`cmd1; cmd2`)
- Subshells (`(cmd)`, `$(cmd)`)
- Loops and conditionals (`for`, `while`, `if`, `case`)
- Redirections (stripped, command extracted)
- Variable assignments with commands
