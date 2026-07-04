---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### `fs.home` and `fs.cwd` in `when` clauses (TODO(pr-link))

The `fs` namespace now exposes `fs.home` and `fs.cwd` as string values, alongside the existing `fs.exists()` / `fs.is_file()` / `fs.is_dir()` functions. These let a rule scope itself to a directory tree without relying on the shell exporting `PWD` or `HOME` into `env`.

```yaml
rules:
  # Allow `make` only under this user's own repos.
  - allow: 'make *'
    when: "fs.cwd.startsWith(fs.home + '/ghq/github.com/fohte/')"
```

See [When Clauses -> Filesystem](/rule-evaluation/when-clause/#filesystem) for details.
