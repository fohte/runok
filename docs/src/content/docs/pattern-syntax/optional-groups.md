---
title: Optional Groups
description: Define tokens that may or may not be present in a command.
sidebar:
  order: 4
---

Optional groups, wrapped in `[` and `]`, match commands **with or without** the enclosed tokens.

## Basic Usage

```yaml
# Matches: git push, git push --force
- allow: 'git push [--force]'

# Matches: rm file.txt, rm -f file.txt
- allow: 'rm [-f] *'
```

Optional groups can contain multiple tokens including flags with values:

```yaml
# Matches: curl https://example.com
# Matches: curl -X POST https://example.com
- allow: 'curl [-X|--request POST] *'
```

## Matching Rules

Optional groups follow a **try-then-skip** strategy:

1. First, try matching **with** the optional tokens included
2. If that fails, verify the optional group's flags are **absent** from the command, then try matching **without** them

### Flag Absence Check

When an optional group is skipped, runok verifies that any flags in the group are not present in the command. This prevents incorrect matches where a flag is used with an unexpected value:

```yaml
- allow: 'curl [-X|--request POST] *'
```

| Command                              | Result         | Reason                               |
| ------------------------------------ | -------------- | ------------------------------------ |
| `curl https://example.com`           | Matches        | Optional group is absent             |
| `curl -X POST https://example.com`   | Matches        | Optional group matches               |
| `curl -X DELETE https://example.com` | Does not match | `-X` is present but with wrong value |
| `curl -X=POST https://example.com`   | Matches        | `=`-joined form is also supported    |
| `curl -X=DELETE https://example.com` | Does not match | `-X` is present but with wrong value |

## Literal `[` and `]`

To match the POSIX `[` test command, `[` followed by a space (or at end of input) is treated as a literal:

```yaml
# Matches the POSIX test command: [ -f file ]
- allow: '[ -f * ]'
```

A `]` outside of an optional group is also treated as a literal.

## Restrictions

- Optional groups **cannot be nested**: `[[-f]]` is a syntax error
- Optional groups must be closed: `[-f` without `]` is a syntax error

## Related

- [Alternation](/pattern-syntax/alternation/) -- Pipe-separated alternatives.
- [Matching Behavior](/pattern-syntax/matching-behavior/) -- How commands are parsed and matched against patterns.
