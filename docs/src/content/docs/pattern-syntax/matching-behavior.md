---
title: Matching Behavior
description: How runok parses and matches commands against patterns.
sidebar:
  order: 7
---

This page explains how runok parses commands and matches them against patterns.

## Patterns are Parsed as Written

runok does not rewrite or preprocess patterns. The way you write a rule is exactly how it is parsed and matched:

- **No implicit splitting or joining.** Tokens are separated by spaces, and `=`-joined values stay as a single token.
- **Rules are self-contained.** You can understand a rule's behavior by reading it alone — `definitions` do not change how a pattern is parsed.

```yaml
# "-Denv=prod" is a single token — matched as-is
- deny: 'java -Denv=prod *'
# Matches: java -Denv=prod -jar app.jar
# Does NOT match: java -Denv staging -jar app.jar

# "-X" and "POST" are separate tokens — matched as flag and value
- deny: 'curl -X POST *'
# Matches: curl -X POST https://example.com
```

## Flag Schema Inference

When a pattern contains a flag followed by a value, runok **infers** that the flag takes a value argument. This inference is used when parsing the actual command to correctly associate values with their flags.

```yaml
# Pattern: curl -X|--request POST *
# Inferred flag schema: -X and --request take a value
- deny: 'curl -X|--request POST *'
```

With this inferred schema, the command `curl -X POST https://example.com` is parsed as:

- `-X` — flag
- `POST` — value of `-X`
- `https://example.com` — positional argument

Without this inference, `POST` would be treated as a positional argument rather than a flag value.

### Flags in Optional Groups

Flags inside optional groups are also included in the inferred schema:

```yaml
# Both -o/--output and -X/--request are inferred as value flags
- allow: 'curl [-o|--output *] -X|--request GET *'
```

## Order-independent Flag Matching

Flags (tokens starting with `-`) in patterns are matched **regardless of their position** in the command:

```yaml
- allow: 'git push -f|--force *'
```

| Command                        | Result  |
| ------------------------------ | ------- |
| `git push --force origin main` | Matches |
| `git push origin --force main` | Matches |
| `git push origin main --force` | Matches |

This applies to standalone flags ([alternation](/pattern-syntax/alternation/)), [flag-value pairs](/pattern-syntax/matching-behavior/#flag-schema-inference), and flag-only [negations](/pattern-syntax/alternation/#negation). The matcher scans the entire command token list to find a matching flag, removes it, and continues matching the remaining tokens.

### Flag-only Negation

Negation patterns where all alternatives start with `-` also use order-independent matching. The matcher scans the entire command for any token matching the negated pattern and rejects the match if found. Unlike positional negation, flag-only negation does **not** consume a positional token — it only asserts that the forbidden flag is absent. This means it also passes when there are no command tokens (the flag is trivially absent):

```yaml
- allow: 'find !-delete|-fprint|-fls *'
```

| Command                    | Result         |
| -------------------------- | -------------- |
| `find . -name foo -type f` | Matches        |
| `find`                     | Matches        |
| `find . -delete`           | Does not match |
| `find -fprint output .`    | Does not match |

This also works with `=`-joined flags. For example, `!--pre` rejects both `--pre value` (space-separated) and `--pre=value` (`=`-joined):

```yaml
- allow: 'rg !--pre *'
```

| Command                  | Result         |
| ------------------------ | -------------- |
| `rg pattern file.txt`    | Matches        |
| `rg --pre pdftotext pat` | Does not match |
| `rg --pre=pdftotext pat` | Does not match |

### Non-flag Tokens are Position-dependent

Tokens that do not start with `-` are matched **in order**:

```yaml
- allow: 'git push origin main'
```

| Command                | Result         |
| ---------------------- | -------------- |
| `git push origin main` | Matches        |
| `git push main origin` | Does not match |

## Backslash Escapes

A backslash (`\`) in a pattern escapes the following character. During matching, the backslash is stripped and the remaining character is compared literally. This is useful for characters that have special meaning in shells, such as `;`:

```yaml
# \; in the pattern matches ; in the command
- "find * -exec <cmd> \\;|+"
```

The shell resolves `\;` to `;` before runok sees the command, so the pattern's `\;` (after unescape) matches the command's `;`.

## Combined Short Flags

Combined short flags like `-am` are **not** split into individual flags — they are matched as a single token, exactly as written:

```yaml
- deny: 'git commit -m *'
```

| Command                    | Result         | Reason                               |
| -------------------------- | -------------- | ------------------------------------ |
| `git commit -m "fix bug"`  | Matches        | `-m` matches directly                |
| `git commit -am "fix bug"` | Does not match | `-am` is a different token than `-m` |

If you want to match `-am`, write it explicitly:

```yaml
- deny: 'git commit -am *'
```

## Recursion Limit

To prevent pathological patterns (such as many consecutive wildcards) from causing excessive computation, matching is limited to **10,000 steps**. Patterns that exceed this limit fail to match.

## Related

- [Pattern Syntax Overview](/pattern-syntax/overview/) -- All syntax elements at a glance.
- [Architecture: Pattern Matching](/architecture/pattern-matching/) -- Internal implementation details.
