---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### `fs.home` and `fs.cwd` in `when` clauses ([#451](https://github.com/fohte/runok/pull/451))

The `fs` namespace now exposes `fs.home` and `fs.cwd` as values, alongside the existing `fs.exists()` / `fs.is_file()` / `fs.is_dir()` functions. `fs.cwd` is read directly from the OS, so unlike `env.PWD` it cannot go stale or be left unset by a shell that does not export `PWD`. `fs.home` is `null` when the home directory cannot be determined, rather than folding that into an empty-string prefix that would silently match everything.

```yaml
rules:
  # Allow `make` only under a chosen directory tree in the user's home.
  - allow: 'make *'
    when: "fs.cwd.startsWith(fs.home + '/projects/')"
```

See [When Clauses -> Filesystem](/rule-evaluation/when-clause/#filesystem) for details.

### `glob_matches()` and `definitions` in `when` clauses ([#467](https://github.com/fohte/runok/pull/467))

`when` clauses can now call `glob_matches(pattern, value)` and read the raw contents of `definitions.paths` / `definitions.vars` through the new `definitions` context variable. Combined, these let a `deny`/`when` guard and an `allow`/`<var:name>` pattern share a single declared list of `type: pattern` glob values, instead of duplicating the list:

```yaml
definitions:
  vars:
    safe-rm-paths:
      type: pattern
      values:
        - '**/node_modules'
        - 'node_modules'
        - '**/dist'
        - 'dist'
        - '/tmp/*'

rules:
  - deny: 'rm -rf *'
    when: '!args.all(a, definitions.vars["safe-rm-paths"].exists(p, glob_matches(p, a)))'
  - allow: 'rm -rf <var:safe-rm-paths>'
```

`definitions.paths` exposes the same data as the existing `paths` context variable; `definitions.vars` is new and lists every declared value for each `definitions.vars` entry, unlike `vars`, which only holds the single value a matched `<var:name>` placeholder captured. See [When Clauses -> `definitions`](/rule-evaluation/when-clause/#definitions--raw-definitions-data) and [When Clauses -> Glob matching](/rule-evaluation/when-clause/#glob-matching) for details.
