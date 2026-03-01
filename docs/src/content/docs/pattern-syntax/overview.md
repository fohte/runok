---
title: Pattern Syntax Overview
description: Learn the pattern syntax for matching commands in runok.
sidebar:
  order: 1
---

runok uses a pattern syntax to define which commands are allowed or denied. The basic form looks like the commands you normally type in the terminal, with additional syntax elements like wildcards (`*`), alternation (`|`), and optional groups (`[]`) for flexible matching.

Patterns are parsed exactly as written, with no hidden rewriting or implicit transformation. See [Matching Behavior](/pattern-syntax/matching-behavior/) for details.

## Syntax Elements

| Syntax                                                                        | Example                         | Description                                                  |
| ----------------------------------------------------------------------------- | ------------------------------- | ------------------------------------------------------------ |
| Literal                                                                       | `git status`                    | Exact token match                                            |
| [Wildcard](/pattern-syntax/wildcards/)                                        | `git *`                         | Zero or more tokens                                          |
| [Glob](/pattern-syntax/wildcards/#glob-patterns)                              | `list-*`, `*.txt`               | `*` inside a literal matches zero or more characters         |
| [Alternation](/pattern-syntax/alternation/)                                   | `-X\|--request`, `main\|master` | Pipe-separated alternatives                                  |
| [Negation](/pattern-syntax/alternation/#negation)                             | `!GET`, `!describe\|get`        | Matches anything except the specified value(s)               |
| [Optional group](/pattern-syntax/optional-groups/)                            | `[-f]`, `[-X POST]`             | Matches with or without the group                            |
| [Flag with value](/pattern-syntax/matching-behavior/#flag-schema-inference)   | `-X\|--request POST`            | A flag-value pair matched in any order                       |
| [Placeholder](/pattern-syntax/placeholders/)                                  | `<cmd>`, `<opts>`, `<path:...>` | Special tokens in `<...>` with various behaviors (see below) |
| Quoted literal                                                                | `"WIP*"`, `'hello'`             | Exact match without glob expansion                           |
| [Multi-word alternation](/pattern-syntax/alternation/#multi-word-alternation) | `"npx prettier"\|prettier`      | Alternatives that include multi-word commands                |

### Placeholders

Tokens wrapped in `<...>` are **placeholders** — special tokens that match dynamically rather than by exact string comparison. Each placeholder type has different matching behavior:

| Placeholder   | Example                | Description                                               | Details                                                                   |
| ------------- | ---------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------- |
| `<cmd>`       | `sudo <cmd>`           | Captures the wrapped command for further rule evaluation  | [Command](/pattern-syntax/placeholders/#command-cmd)                      |
| `<opts>`      | `env <opts> <cmd>`     | Absorbs zero or more flag-like tokens (starting with `-`) | [Options](/pattern-syntax/placeholders/#options-opts)                     |
| `<vars>`      | `env <vars> <cmd>`     | Absorbs zero or more `KEY=VALUE` tokens                   | [Variables](/pattern-syntax/placeholders/#variables-vars)                 |
| `<path:name>` | `cat <path:sensitive>` | Matches against a named list of paths from `definitions`  | [Path References](/pattern-syntax/placeholders/#path-references-pathname) |

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

- [Wildcards](/pattern-syntax/wildcards/) — Token and glob wildcards
- [Alternation](/pattern-syntax/alternation/) — Pipe-separated alternatives and negation
- [Optional Groups](/pattern-syntax/optional-groups/) — Tokens that may or may not be present
- [Placeholders](/pattern-syntax/placeholders/) — `<cmd>`, `<opts>`, `<vars>`, `<path:...>` placeholders
- [Matching Behavior](/pattern-syntax/matching-behavior/) — Flag inference, order-independent matching, and combined short flags

:::note
Pattern syntax and [`when` expressions](/rule-evaluation/when-clause/) work on string tokens. If you need to parse structured arguments (e.g., GraphQL queries, URLs), see [Extensions](/extensions/overview/).
:::
