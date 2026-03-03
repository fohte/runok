---
title: Wildcards
description: Match any number of tokens or characters with wildcard patterns.
sidebar:
  order: 2
---

runok supports two kinds of wildcards: **token wildcards** and **glob patterns**.

## Token Wildcard (`*`)

A standalone `*` matches **zero or more tokens** in the command.

```yaml
# Matches: git status, git push origin main, git log --oneline -n 5
- allow: 'git *'

# Matches: docker run hello-world, docker run -it ubuntu bash
- allow: 'docker run *'
```

The token wildcard tries all possible token counts to find a valid match.

### Wildcard as Command Name

When `*` is in the command position, it matches **any command**:

```yaml
# Matches: git --help, docker --help, curl --help
# Also matches: docker compose --help (multi-token command name)
- allow: '* --help'

# Matches any single command with no arguments
- allow: '*'
```

A wildcard command pattern tries all possible splits — the command name can span one or more tokens. For example, `* --help` matches both `git --help` and `docker compose --help`.

### Trailing Wildcard with Flags

When `*` appears at the **end** of a pattern after a flag, it remains an independent wildcard rather than being consumed as the flag's value:

```yaml
# -f|--force is a boolean flag, * matches remaining tokens
- allow: 'git push -f|--force *'
```

However, when `*` appears **between** a flag and another token, it is consumed as the flag's value:

```yaml
# First * is the value of -X|--request, second * matches remaining tokens
- allow: 'curl -X|--request * *'
# Matches: curl -X GET /api/endpoint
```

## Glob Patterns

When `*` appears **inside a literal token** (not as a standalone token), it acts as a glob and matches zero or more **characters**:

```yaml
# Matches: list-buckets, list-objects, list-users
- allow: 'aws s3api list-*'

# Matches: file.txt, readme.txt, notes.txt
- deny: 'rm *.txt'

# Matches: pre-middle-suf, pre-suf, pre123suf
- allow: 'echo pre*suf'
```

:::note
Only `*` is supported for glob matching. Other glob characters like `?` or `[...]` are treated as literal characters.
:::

### Escaping `*` with Backslash

To match a literal `*` character (without glob expansion), escape it with a backslash (`\*`). This works both inside and outside quotes:

```yaml
# Only matches the exact string "WIP*" (including the asterisk character)
- deny: 'git commit -m "WIP\*"'

# Also works outside quotes
- allow: 'cmd WIP\*'
```

### Quotes and Glob

Quotes (`"..."` or `'...'`) act as **grouping only** — they allow spaces inside a single token but do **not** disable glob expansion. A `*` inside quotes is still treated as a glob:

```yaml
# Matches: renovate-config-validator foo.json, renovate-config-validator bar.json
- allow: "npx -c 'renovate-config-validator *'"

# WIP* is a glob — matches WIPfoo, WIPbar, etc.
- deny: 'git commit -m "WIP*"'

# Use \* to match the literal asterisk
- deny: 'git commit -m "WIP\*"'
```

## Related

- [Matching Behavior](/pattern-syntax/matching-behavior/) -- How commands are parsed and matched against patterns.
- [Alternation](/pattern-syntax/alternation/) -- Pipe-separated alternatives.
