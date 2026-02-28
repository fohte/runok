---
title: Alternation
description: Match one of several alternatives using pipe-separated patterns.
sidebar:
  order: 3
---

Alternation lets you match any one of several alternatives using the pipe (`|`) separator, **without spaces** around the pipe.

## Basic Alternation

```yaml
# Matches: git checkout main, git checkout master
- allow: 'git checkout main|master'

# Matches: curl -X POST ..., curl --request POST ...
- allow: 'curl -X|--request POST *'
```

Each alternative is matched using the same rules as a literal token, including [glob patterns](/pattern-syntax/wildcards/#glob-patterns):

```yaml
# Matches: kubectl describe pods, kubectl get pods, kubectl list-pods
- allow: 'kubectl describe|get|list-* pods'
```

### Flag Alternation

When all alternatives start with `-`, the alternation is treated as a **flag alternation** and is matched [order-independently](/pattern-syntax/matching-behavior/#order-independent-flag-matching):

```yaml
# Matches both: git push --force origin, git push origin --force
- allow: 'git push -f|--force *'
```

### Command Alternation

Alternation in the command position matches multiple command names:

```yaml
# Matches: ast-grep --pattern ..., sg --pattern ...
- allow: 'ast-grep|sg *'
```

## Multi-word Alternation

When one or more alternatives contain multiple words, wrap them in quotes:

```yaml
# Matches: npx prettier --write ., prettier --write .
- allow: '"npx prettier"|prettier *'
```

Multi-word alternation is only supported in the **command position** (the first token). Each alternative is expanded into a separate pattern internally:

- `"npx prettier"|prettier *` becomes two patterns:
  - `npx prettier *`
  - `prettier *`

## Negation

Prefix a token with `!` to match anything **except** the specified value:

```yaml
# Matches: curl -X POST, curl -X PUT, curl -X PATCH
# Does NOT match: curl -X GET
- deny: 'curl -X|--request !GET *'
```

### Negation with Alternation

Combine negation with alternation to exclude multiple values. The `!` prefix applies to the **entire alternation**, not just the first alternative:

```yaml
# !describe|get|list-* means "anything except describe, get, or list-*"
# Matches: kubectl delete my-pod, kubectl apply -f file.yaml
# Does NOT match: kubectl describe pods, kubectl get pods, kubectl list-buckets
- deny: 'kubectl !describe|get|list-* *'
```

### Negation with Glob

Negated alternatives support glob patterns:

```yaml
# Matches any verb that does NOT start with "list-"
- deny: 'kubectl !list-* *'
```
