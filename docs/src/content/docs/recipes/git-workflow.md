---
title: 'Git Workflow'
description: Control which Git operations are allowed, require confirmation for pushes, and block dangerous commands.
sidebar:
  order: 2
---

This recipe shows how to configure runok to enforce safe Git practices. It covers read-only operations, protected pushes, and blocked destructive commands.

## Complete Example

```yaml
# yaml-language-server: $schema=https://runok.fohte.net/schema/runok.schema.json

defaults:
  action: ask

rules:
  # Read-only operations — always allowed
  - allow: 'git status'
  - allow: 'git diff *'
  - allow: 'git log *'
  - allow: 'git show *'
  - allow: 'git branch *'
  - allow: 'git stash list'

  # Safe write operations — allowed
  - allow: 'git add *'
  - allow: 'git commit *'
  - allow: 'git stash *'
  - allow: 'git checkout *'
  - allow: 'git switch *'
  - allow: 'git merge *'
  - allow: 'git rebase *'
  - allow: 'git fetch *'
  - allow: 'git pull *'

  # Push — require confirmation
  - ask: 'git push *'

  # Dangerous operations — blocked
  - deny: 'git push -f|--force *'
    message: 'Force push can overwrite remote history.'
    fix_suggestion: 'git push --force-with-lease'

  - deny: 'git reset --hard *'
    message: 'Hard reset discards uncommitted changes permanently.'
    fix_suggestion: 'git stash'

  - deny: 'git clean -f *'
    message: 'git clean -f permanently deletes untracked files.'
    fix_suggestion: 'git clean -n'
```

## How It Works

### Read-only operations

Commands like `git status`, `git diff`, and `git log` are safe to run at any time. The `*` wildcard matches any additional arguments, so `git diff --cached` and `git log --oneline -10` are both covered.

### Safe write operations

Local write operations (`git add`, `git commit`, `git checkout`, etc.) modify only the local repository. These are allowed without confirmation.

### Push with confirmation

`git push` sends commits to a remote, which is a shared resource. The `ask` action prompts the user to confirm before executing.

### Blocked destructive commands

- **`git push --force`** — Rewrites remote history. The `fix_suggestion` recommends `--force-with-lease`, which fails if someone else has pushed.
- **`git reset --hard`** — Discards all uncommitted work. The suggestion is to `git stash` first.
- **`git clean -f`** — Permanently removes untracked files. The suggestion is `git clean -n` (dry run).

## Variations

### Allow force push to feature branches only

Use a `when` condition with the CEL expression language to allow force pushes to branches that start with `feature/`:

```yaml
rules:
  - allow: 'git push -f|--force *'
    when: "args.exists(a, a.startsWith('feature/'))"

  - deny: 'git push -f|--force *'
    message: 'Force push is only allowed on feature/ branches.'
```

Since deny rules take priority, the deny rule catches everything that the allow rule doesn't match.

### Block pushes to main branch

```yaml
rules:
  - deny: 'git push * main'
    message: 'Direct push to main is not allowed. Use a pull request.'
  - deny: 'git push * master'
    message: 'Direct push to master is not allowed. Use a pull request.'
```
