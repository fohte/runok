---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### `runok pending-asks` command (TODO(pr-link))

`runok pending-asks` scans the audit log for `ask` decisions, re-evaluates each one against the current config, and reports commands that still fall back to `defaults.action` -- i.e. no `allow`/`deny`/`ask` rule covers them yet. Matching entries are grouped by exact command string with an ask count, approval count, first/last seen timestamps, and the distinct working directories they were asked from:

```sh
runok pending-asks --since 7d --json
```

```json
{
  "command": "terraform apply",
  "ask_count": 5,
  "approved_count": 4,
  "first_seen": "2026-06-20T09:00:00Z",
  "last_seen": "2026-07-08T10:30:00Z",
  "cwds": ["/home/user/projects/infra"]
}
```

Commands already covered by an explicit rule -- including an explicit `ask:` rule written on purpose to keep confirming a command -- are excluded, so the output only surfaces genuine candidates for a new rule. See [`runok pending-asks`](/cli/pending-asks/) for details.

### Track ask approvals in the audit log ([#468](https://github.com/fohte/runok/pull/468))

The audit log used to record only that runok answered `ask` for a command -- not whether the user then approved it in Claude Code's permission dialog. Registering runok as an opt-in **PostToolUse** hook (offered by `runok init --scope user`, or added manually to `settings.json`) closes that gap: approving an ask now appends a self-contained `ask_resolution` record correlated with the original `ask` entry via `tool_use_id`.

`runok audit` marks approved asks as `ask ✓`, and `runok audit --json` emits the `ask_resolution` records alongside decision entries. Denials cannot be recorded -- Claude Code fires no hook after a denied dialog -- so an unmarked `ask` means "denied or not yet decided".

```json
{
  "kind": "ask_resolution",
  "outcome": "approved",
  "tool_use_id": "toolu_01AbCdEfGh",
  "command": "terraform apply",
  "executed_command": "runok exec --sandbox restricted -- 'terraform apply'"
}
```

See [Claude Code Integration -> Track ask approvals](/getting-started/claude-code/#track-ask-approvals-optional) and [Audit Log JSON Schema -> Ask Resolution Record](/cli/audit-log-schema/#ask-resolution-record) for details.

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

## Bug Fixes

### `runok init` no longer replaces an existing `runok.yml` with boilerplate ([#468](https://github.com/fohte/runok/pull/468))

Applying Claude Code integration changes in `runok init` used to rewrite an existing `runok.yml` with the boilerplate template when no permission migration happened. The wizard now only rewrites an existing config when a migration was accepted; re-running init just to register hooks leaves the file untouched.
