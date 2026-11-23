---
title: Pattern Syntax Overview
description: Learn the pattern syntax for matching commands in runok.
sidebar:
  order: 1
slug: v0.3/pattern-syntax/overview
---

runok uses a pattern syntax to define which commands are allowed or denied. The basic form looks like the commands you normally type in the terminal, with additional syntax elements like wildcards (`*`), alternation (`|`), and optional groups (`[]`) for flexible matching.

Patterns are parsed exactly as written, with no hidden rewriting or implicit transformation. See [Matching Behavior](/v0.3/pattern-syntax/matching-behavior/) for details.

## Syntax Elements

| Syntax                                                                             | Example                                      | Description                                                  |
| ---------------------------------------------------------------------------------- | -------------------------------------------- | ------------------------------------------------------------ |
| Literal                                                                            | `git status`                                 | Exact token match                                            |
| [Wildcard](/v0.3/pattern-syntax/wildcards/)                                        | `git *`                                      | Zero or more tokens                                          |
| [Glob](/v0.3/pattern-syntax/wildcards/#glob-patterns)                              | `list-*`, `*.txt`                            | `*` inside a literal matches zero or more characters         |
| [Alternation](/v0.3/pattern-syntax/alternation/)                                   | `-X\|--request`, `main\|master`              | Pipe-separated alternatives                                  |
| [Negation](/v0.3/pattern-syntax/alternation/#negation)                             | `!GET`, `!describe\|get`                     | Matches anything except the specified value(s)               |
| [Optional group](/v0.3/pattern-syntax/optional-groups/)                            | `[-f]`, `[-X POST]`                          | Matches with or without the group                            |
| [Flag with value](/v0.3/pattern-syntax/matching-behavior/#flag-schema-inference)   | `-X\|--request POST`                         | A flag-value pair matched in any order                       |
| [Placeholder](/v0.3/pattern-syntax/placeholders/)                                  | `<cmd>`, `<opts>`, `<path:...>`, `<var:...>` | Special tokens in `<...>` with various behaviors (see below) |
| Backslash escape                                                                   | `\;`, `\*`                                   | Literal match after removing the backslash                   |
| Quoted literal                                                                     | `"hello world"`, `'hello'`                   | Grouping only; `*` is still a glob, use `\*` for literal `*` |
| [Multi-word alternation](/v0.3/pattern-syntax/alternation/#multi-word-alternation) | `"npx prettier"\|prettier`                   | Alternatives that include multi-word commands                |

### Placeholders

Tokens wrapped in `<...>` are **placeholders** — special tokens that match dynamically rather than by exact string comparison. Each placeholder type has different matching behavior:

| Placeholder   | Example                | Description                                                                | Details                                                                               |
| ------------- | ---------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `<cmd>`       | `sudo <cmd>`           | Captures the wrapped command for further rule evaluation                   | [Command](/v0.3/pattern-syntax/placeholders/#command-cmd)                             |
| `<opts>`      | `env <opts> <cmd>`     | Absorbs zero or more flag-like tokens (starting with `-`)                  | [Options](/v0.3/pattern-syntax/placeholders/#options-opts)                            |
| `<vars>`      | `env <vars> <cmd>`     | Absorbs zero or more `KEY=VALUE` tokens                                    | [Variables](/v0.3/pattern-syntax/placeholders/#variables-vars)                        |
| `<path:name>` | `cat <path:sensitive>` | Matches against a named list of paths from `definitions`                   | [Path References](/v0.3/pattern-syntax/placeholders/#path-references-pathname)        |
| `<var:name>`  | `cmd <var:ids>`        | Matches against a typed variable definition (argument or command position) | [Variable References](/v0.3/pattern-syntax/placeholders/#variable-references-varname) |

## Pattern Structure

A pattern consists of a **command name** followed by **argument tokens**:

```
<command> [argument tokens...]
```

The first token is always the command name. The remaining tokens define the argument pattern.

```yaml
# Command: "git", argument tokens: ["push", "--force"]
- deny: 'git push --force'

# Command: "curl", argument tokens: ["-X|--request", "POST", "*"]
- allow: 'curl -X|--request POST *'
```

## Pages in This Section

- [Wildcards](/v0.3/pattern-syntax/wildcards/) — Token and glob wildcards
- [Alternation](/v0.3/pattern-syntax/alternation/) — Pipe-separated alternatives and negation
- [Optional Groups](/v0.3/pattern-syntax/optional-groups/) — Tokens that may or may not be present
- [Placeholders](/v0.3/pattern-syntax/placeholders/) — `<cmd>`, `<opts>`, `<vars>`, `<path:...>` placeholders
- [Matching Behavior](/v0.3/pattern-syntax/matching-behavior/) — Flag inference, order-independent matching, and combined short flags

:::note
Pattern syntax and [`when` expressions](/v0.3/rule-evaluation/when-clause/) work on string tokens. If you need to parse structured arguments (e.g., GraphQL queries, URLs), see [Extensions](/v0.3/extensions/overview/).
:::
