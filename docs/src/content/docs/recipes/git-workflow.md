---
title: 'Git Workflow'
description: Control which Git operations are allowed, require confirmation for pushes, and block dangerous commands.
sidebar:
  order: 3
---

This recipe shows how to configure runok to enforce safe Git practices. It covers read-only operations, safe writes, and blocked destructive commands.

## Complete Example

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json

defaults:
  action: ask

rules:
  # === deny rules ===

  - deny: 'git [-C *] commit --amend *'
    message: 'Amending rewrites the previous commit, which may destroy work.'
    fix_suggestion: 'git commit -m "fix: ..."'

  - deny: 'git [-C *] commit -n|--no-verify *'
    message: 'Skipping pre-commit hooks is not allowed.'
    fix_suggestion: 'git commit -m "..."'

  - deny: 'git [-C *] push -f|--force|--force-with-lease *'
    message: 'Force push can overwrite remote history.'
    fix_suggestion: 'git push'

  # === allow rules ===

  # Read-only operations
  - allow: 'git [-C *] status *'
  - allow: 'git [-C *] diff *'
  - allow: 'git [-C *] log *'
  - allow: 'git [-C *] show *'
  - allow: 'git [-C *] branch'
  - allow: 'git [-C *] branch [-a|--all] [-r|--remotes] [-v|--verbose] [--sort *] [-l|--list *]'
  - allow: 'git [-C *] branch --show-current'
  - allow: 'git [-C *] branch --contains|--merged|--no-merged *'
  - allow: 'git [-C *] rev-parse *'
  - allow: 'git [-C *] ls-files *'
  - allow: 'git [-C *] ls-tree *'
  - allow: 'git [-C *] grep *'
  - allow: 'git [-C *] remote get-url *'

  # Local write operations
  - allow: 'git [-C *] add *'
  - allow: 'git [-C *] commit *'
  - allow: 'git [-C *] mv *'
  - allow: 'git [-C *] fetch *'

  # Push and pull
  - allow: 'git [-C *] push *'
  - allow: 'git [-C *] pull *'
```

## How It Works

### `[-C *]` optional pattern

The [`[-C *]` optional group](/pattern-syntax/optional-groups/) pattern matches an optional `-C <path>` argument. This lets rules apply whether the user runs `git status` or `git -C /path/to/repo status`.

### Deny rules win

When both an allow and a deny rule match the same command, the [deny rule always takes priority](/rule-evaluation/priority-model/) regardless of rule order. This means you can broadly allow `git push *` while still blocking `git push --force *`.

### Read-only operations

Commands like `git status`, `git diff`, `git log`, and `git show` only read repository state. These are always safe to allow.

### Local write operations

`git add`, `git commit`, `git fetch`, and `git mv` modify only the local repository. They are allowed without confirmation.

Note that `git commit` is allowed, but `git commit --amend` and `git commit --no-verify` are denied by the deny rules above.

### Push and pull

Both `git push` and `git pull` are allowed. However, force push variants (`--force`, `-f`, `--force-with-lease`) are all denied.

### Unmatched commands fall through to `ask`

Commands not covered by any rule (e.g., `git merge`, `git rebase`, `git checkout`, `git reset`) fall through to the [`defaults.action: ask`](/configuration/schema/#defaultsaction) setting, prompting the user for confirmation.

## Variations

### Strict mode — require confirmation for pushes

If you prefer to confirm before pushing to a remote:

```yaml
rules:
  # Change push from allow to ask
  - ask: 'git push *'
```

Since `defaults.action` is `ask`, you can also simply omit the push allow rule — any unmatched command falls through to the default action.

### Block pushes to main branch

```yaml
rules:
  - deny: 'git [-C *] push * main|master'
    message: 'Direct push to main is not allowed. Use a pull request.'
```

### Allow only interactive rebase

If you want to allow interactive rebase while prompting for other rebase commands, simply add an allow rule. Other rebase invocations fall through to the default `ask` action:

```yaml
rules:
  - allow: 'git [-C *] rebase -i|--interactive *'
```
