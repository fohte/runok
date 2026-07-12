---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Highlights

### Breaking: `?` in a flag's value position now means "optional value" ([#471](https://github.com/fohte/runok/pull/471))

Some flags accept a value but also work without one (e.g. git's `--abbrev[=<n>]`, `-n[<n>]`). Writing `?` in the value position now matches **zero or one** token, unlike `*` which requires exactly one:

```yaml
- allow: 'git branch --abbrev ?'
```

`--abbrev` and `--abbrev=8` both match. Like real optional-argument flags (GNU `getopt_long` convention), a space-separated following token is never consumed as the value -- `git branch --abbrev 8` actually creates a branch named `8` in real git, so runok does not treat `8` as `--abbrev`'s value either. `?` is also supported as the value pattern in `<flag:name>` group definitions.

**What changes for existing rules?**

A pattern that wrote a bare `?` directly after a flag used to match the literal string `?` as that flag's value. It now means "optional value" instead.

**What should I do?**

If you have a rule that intentionally relied on `?` being a literal flag value, escape it: replace `?` with `\?` (this works the same as `\*` for a literal `*`).

See [Matching Behavior -- Optional Flag Values](/pattern-syntax/matching-behavior/#optional-flag-values) for details.

## New Features

### `runok audit --recheck` re-evaluates entries against the current config (TODO(pr-link))

An audit entry's recorded `action` and `matched_rules` are a snapshot from when the entry was decided -- if rules changed since then, the log alone can't tell you how a command would evaluate today. `--recheck` re-evaluates each displayed entry's `command` against the config currently in effect (loaded from the entry's own `metadata.cwd`) and annotates the output with the result. It's an annotation, not a filter: it never changes which entries are shown, and composes with `--action`, `--since`, `--dir`, and the other filters.

```sh
runok audit --action ask --recheck --json \
  | jq 'select(.recheck.action.type == "ask")'
```

Text mode gains a NOW column next to ACTION; JSON mode gains a `recheck` object per entry, distinguishing an `ask` resolved by an explicit rule from one resolved purely via `defaults.action` fallback. Every `ask` decision entry in `--json` output also now carries an `approved` boolean -- the same `ask_resolution` join used for the `ask ✓` marker in text mode.

See [`runok audit` -- `--recheck`](/cli/audit/#--recheck) and [Audit Log JSON Schema -- Recheck Object](/cli/audit-log-schema/#recheck-object) for details.

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
