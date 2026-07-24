---
title: Experimental Features
description: Opt-in features under experimental, and what to expect from them.
sidebar:
  order: 6
---

`experimental` holds opt-in features that are still evolving. Each one is disabled by default and has no effect until you explicitly turn it on.

:::caution
Fields under `experimental` may change shape, change default behavior, or be removed in a minor release without following the usual semver compatibility guarantees. Review the release notes before upgrading if you rely on any of them.
:::

## `require_command_in_path`

Denies (or asks, per `action`) a command whose `argv[0]` cannot be resolved via `PATH`. This catches the case an AI coding agent hits most often: a typo'd or hallucinated command name (`tarraform` for `terraform`) that would otherwise fail only after runok allows it through and the shell actually tries to run it.

```yaml title="runok.yml"
experimental:
  require_command_in_path:
    enabled: true
    action: deny
    ignore:
      - my-shell-function
```

### Fields

#### `enabled`

Whether this check is active.

**Type:** `bool`\
**Default:** `false`

#### `action`

Action to take when a command's `argv[0]` cannot be resolved via `PATH`.

**Type:** `"ask" | "deny"`\
**Default:** `"deny"`

`allow` is rejected at config validation time -- setting it would defeat the purpose of the check.

#### `ignore`

Command names exempt from this check, matched as a literal exact string against `argv[0]`.

**Type:** `list[str]`\
**Default:** `[]`

See [When you need `ignore`](#when-you-need-ignore) below -- most shell functions and sourced scripts never need to be listed here.

### When this check does not fire

This check only applies where no `rules` entry matches and no [wrapper](/configuration/schema/#definitionswrappers) unwraps the command -- the same point where [`defaults.action`](/configuration/schema/#defaultsaction) would otherwise decide. An explicit `allow` rule is therefore always a working escape hatch: writing one for a command skips this check entirely, the same way it skips `defaults.action`.

Beyond that, the check skips itself outright in several situations where flagging the command would likely be a false positive:

- **`argv[0]` is an unresolved shell expansion.** `$TF version` or `` `$(pick-tool)` version `` -- runok already resolves statically known variables before matching (see [Rule Evaluation -- Variable resolution](/rule-evaluation/compound-commands/#variable-resolution)), so a surviving expansion means the value genuinely cannot be determined without running the shell.
- **`argv[0]` is a function defined earlier in the same command string.** `f() { ...; }; f` -- runok already resolves this call to the function's body (see [Rule Evaluation -- Function call resolution](/rule-evaluation/compound-commands/#function-call-resolution)); by the time this check would run, the name is known to be a real function, not a missing command.
- **The input contains `source`, `.`, or `eval` anywhere.** A sourced script can define shell functions runok cannot see statically, and `eval` can run arbitrary constructed text. When either appears anywhere in the command string, the check is skipped for the entire input, not just the commands after it.
- **`argv[0]` contains a `/`.** A relative or absolute path (`./script.sh`, `/usr/local/bin/tool`) is skipped, since resolving it correctly would require the working directory of the process that will actually run the command, which can differ from the working directory of whichever runok command (`check`, `exec`, or `hook`) is evaluating it.
- **`argv[0]` matches an entry in `ignore`.**

Together, these conditions mean the check almost never needs to see a real command name it doesn't recognize -- it only fires once a name has survived every avenue runok has for resolving it another way.

### When you need `ignore`

`ignore` exists for one specific gap the skip conditions above don't cover: a shell function or alias defined in your shell profile (`~/.zshrc`, `~/.bashrc`, etc.) rather than inline in the command string being evaluated. runok only sees the single command string a tool invocation passes it -- it has no visibility into what your interactive shell's startup files define, so a call to a profile-defined function looks like an unresolvable command name.

You do not need to list:

- Functions defined earlier in the _same_ command string -- already skipped (see above).
- Anything reachable through `source`/`.`/`eval` in the same command string -- already skipped (see above).

`ignore` is deliberately narrower than writing an `allow` rule for the same name. An `allow` rule changes what's permitted -- it also disables `defaults.action`, `when` clauses, and every other rule that might otherwise apply to that command. `ignore` only exempts the command from _this_ check; every other rule and default still applies exactly as if the check didn't exist. Reach for `ignore` when you want to keep your existing permission model unchanged and only silence a false positive from this check.

```yaml title="runok.yml"
experimental:
  require_command_in_path:
    enabled: true
    ignore:
      # A function defined in ~/.zshrc, invisible to runok.
      - my-deploy-helper
```
