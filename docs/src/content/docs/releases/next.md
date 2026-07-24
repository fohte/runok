---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Highlights

### Static variable resolution closes a deny-bypass gap ([#473](https://github.com/fohte/runok/pull/473))

runok previously matched shell variables (`$X`, `${X}`) as literal, unresolved tokens. This meant a `deny` rule written against a flag's literal text could be bypassed by smuggling the flag through a variable:

```yaml
rules:
  - deny: 'git push --force*'
```

`F=--force; git push $F` used to slip past this rule (`git push $F` never contains the literal text `--force`). runok now tracks static, single-value variable assignments within a command string and resolves `$X` / `${X}` to their value before rule evaluation, so `F=--force; git push $F` is now correctly denied. The same resolution also lets an allow rule match a command hidden behind a variable, e.g. `X="git status"; $X` now evaluates as `git status` instead of falling through to an unknown-command default.

Only assignments that are unconditional and statically known are resolved -- a dynamic value (`$(...)`, backticks, process/arithmetic substitution), a reassignment inside a conditional or loop body, an array-element assignment, or anything referenced inside a function body at definition time falls back to the pre-existing verbatim-token behavior. See [Rule Evaluation -- Variable resolution](/rule-evaluation/compound-commands/#variable-resolution) for the full list and examples.

When a command is rewritten this way, the audit log records both the resolved text (`command`) and the verbatim source (`original_command`). See [Audit Log JSON Schema -- `original_command`](/cli/audit-log-schema/#original_command) for details.

**What changes for existing rules?** A rule that matches literal `$X` text (e.g. `allow: 'echo $X'`, intending to match the variable reference itself rather than its value) now sees the resolved value instead, when that value is statically known. This is unlikely in practice -- patterns are normally written against a command's real arguments, not its unexpanded source -- but if a rule specifically depended on `$X` staying unresolved, it should be rewritten against the values the variable can actually take, since those are now what reaches rule evaluation.

### Function call resolution closes a deny-bypass gap for shell functions ([#475](https://github.com/fohte/runok/pull/475))

A shell function's **body** was always evaluated unconditionally at definition time, as a safety backstop, but a **call** to that function (`f() { git push; }; f`) was matched as an ordinary, unknown command -- resolving to `defaults.action` (usually `ask`) on every call, and never seeing the arguments the call itself passed in:

```yaml
rules:
  - allow: 'git push'
  - deny: 'git push --force*'
```

`f() { git push $1; }; f --force` used to slip past the deny rule: definition-time evaluation only ever sees the literal, unexpanded `git push $1`. runok now detects a call to a function defined earlier in the same command string, and evaluates the call by substituting the call's own arguments for `$1`..`$N` / `$@` / `$*` / `$#` in the body, then evaluating the body itself -- so `f --force` above is now correctly denied. A call to a fully allow-able function (`f() { git push; }; f`) now resolves to `allow` too, instead of `ask` on every call.

The function's body is still evaluated unconditionally at definition time regardless of whether it is ever called -- this remains the safety backstop for cases where the function was defined in a previous tool invocation that runok cannot see. See [Rule Evaluation -- Function call resolution](/rule-evaluation/compound-commands/#function-call-resolution) for the full list of what resolves and what does not.

**What changes for existing rules?** A call to a function whose body always evaluates to `allow` now resolves to `allow` on every call, instead of falling through to `defaults.action` (commonly `ask`) as it did before. If a rule (or the absence of one) relied on every function call landing on `ask` for a human to review regardless of what the function's body does, that call now goes straight to `allow` instead. This only affects functions defined earlier in the same command string -- a function defined in a previous, separate tool invocation is unaffected, since only its unconditional definition-time evaluation (unchanged) can see it.

### Breaking: `?` in a flag's value position now means "optional value" ([#471](https://github.com/fohte/runok/pull/471))

Some flags accept a value but also work without one (e.g. git's `--abbrev[=<n>]`, `-n[<n>]`). Writing `?` in the value position now matches **zero or one** token, unlike `*` which requires exactly one:

```yaml
- allow: 'git branch --abbrev ?'
```

`--abbrev` and `--abbrev=8` both match. Like real optional-argument flags (GNU `getopt_long` convention), a space-separated following token is never consumed as the value -- `git branch --abbrev 8` actually creates a branch named `8` in real git, so runok does not treat `8` as `--abbrev`'s value either. `?` is also supported as the value pattern in `<flag:name>` group definitions.

**What changes for existing rules?**

A pattern that wrote a bare `?` directly after a flag used to match the literal string `?` as that flag's value. It now means "optional value" instead.

**What should I do?**

If you have a rule that intentionally relied on `?` being a literal flag value, escape it: replace `?` with `\?` (this works the same as `\*` for a literal `*`). [`runok migrate`](/cli/migrate/#bare--in-pattern-strings) does this automatically across every pattern-syntax field.

See [Matching Behavior -- Optional Flag Values](/pattern-syntax/matching-behavior/#optional-flag-values) for details.

## New Features

### `runok check --verbose` / `runok exec --verbose` / `runok hook --verbose` now render a tree instead of `[verbose]`-prefixed log lines ([#486](https://github.com/fohte/runok/pull/486))

Verbose output is a colorized, indented tree: each sub-command of a compound command gets its own numbered block listing every matched rule alongside the resolved action, and a footer states the overall result and which sub-command decided it.

```
▶ Evaluating: git add . && curl -s https://install.example.com | sh
  Compound command (3 sub-commands)

  [1] git add .
      ├─ allow  'git *'  (tokens: add, .)
      └─ result: allow

  [2] curl -s https://install.example.com
      └─ result: ask  (no rules matched)

  [3] sh
      └─ result: ask  (no rules matched)

  ────────────────────────────────────────────
  Result: ASK  (blocked by [2] curl -s https://install.example.com)
ask
```

Colors (green/yellow/red for allow/ask/deny) are applied automatically on a TTY and omitted otherwise (piped output, log files). See [Debugging](/troubleshooting/debugging/) for more examples.

### `runok migrate` rewrites the legacy Claude Code hook command, which now prints a deprecation warning ([#480](https://github.com/fohte/runok/pull/480))

Following up on `runok hook` ([#476](https://github.com/fohte/runok/pull/476)), `runok migrate` now rewrites an existing `.claude/settings.json` registration of the deprecated `runok check --input-format claude-code-hook` command to `runok hook --agent claude-code`, for both the `PreToolUse` and `PostToolUse` events:

```json
// Before
{ "type": "command", "command": "runok check --input-format claude-code-hook" }

// After
{ "type": "command", "command": "runok hook --agent claude-code" }
```

Unlike the config-chain migrations above, this one targets `.claude/settings.json` directly at the user scope (`~/.claude/settings.json`) and the project scope (`.claude/settings.json` in the current directory), matching the locations `runok init` sets up. Running `runok check --input-format claude-code-hook` now also prints a deprecation warning to stderr on every invocation, pointing at `runok hook` and `runok migrate`; stdout is untouched, since it carries the hook response Claude Code parses. See [`runok migrate` -- Claude Code legacy hook command](/cli/migrate/#claude-code-legacy-hook-command) for details.

### `runok migrate` escapes bare `?` left over from the optional-value marker change ([#479](https://github.com/fohte/runok/pull/479))

Following up on the breaking change above, `runok migrate` now rewrites a bare `?` in every pattern-syntax field (`rules[].{allow,deny,ask}`, `definitions.wrappers`, `definitions.flag_groups`, `definitions.aliases`, and `definitions.vars` entries with `type: pattern`) to the escaped form `\?`, so a config written before v0.4.0 keeps matching the literal `?` it relied on:

```yaml
# Before
rules:
  - allow: 'git branch --abbrev ?'

# After
rules:
  - allow: 'git branch --abbrev \?'
```

Comments, formatting, and quoting style outside the rewritten fields are preserved. `rules[].tests` are left untouched, since inline test commands are not patterns. See [`runok migrate` -- Bare `?` in pattern strings](/cli/migrate/#bare--in-pattern-strings) for details.

### `runok hook`: a dedicated command for agent hook integrations ([#476](https://github.com/fohte/runok/pull/476))

Claude Code integration used to register `runok check --input-format claude-code-hook` for both the `PreToolUse` and `PostToolUse` events. This was misleading: `check` is documented as a read-only evaluation command, but in `PostToolUse` mode it does no evaluation at all -- it only writes an `ask_resolution` record to the audit log.

`runok hook` replaces it as the dedicated agent-integration endpoint. It takes a required `--agent` flag identifying which agent's hook protocol to speak (currently only `claude-code`) rather than defaulting silently to Claude Code, since the flag determines the response shape as well as the input parsing, and `hook` is meant to grow additional agent integrations over time:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "runok hook --agent claude-code" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "runok hook --agent claude-code" }
        ]
      }
    ]
  }
}
```

It dispatches on the input's `hook_event_name` the same way the old hook mode did (`PreToolUse` evaluates and responds, `PostToolUse` records ask approvals), plus one addition: any other event -- including hook events a future Claude Code release might add -- is silently ignored (exit `0`, no output), so `runok hook --agent claude-code` keeps working without requiring a runok upgrade first.

[`runok init`](/cli/init/) now registers `runok hook --agent claude-code` for new setups, and rewrites an existing `runok check --input-format claude-code-hook` entry to `runok hook --agent claude-code` in place when re-run. `runok check --input-format claude-code-hook` still works for backward compatibility but is deprecated -- see [`runok hook`](/cli/hook/) for the full reference.

### `runok audit --recheck` re-evaluates entries against the current config ([#474](https://github.com/fohte/runok/pull/474))

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
