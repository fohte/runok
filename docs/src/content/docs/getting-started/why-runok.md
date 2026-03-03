---
title: Why runok?
description: Concrete problems that runok solves beyond Claude Code's built-in command permissions.
sidebar:
  order: 0
---

Claude Code provides built-in command permissions through `settings.json`. For simple allowlists, these work fine. But as your workflow grows, you encounter limitations that cause unexpected confirmation prompts, silent failures, and security gaps.

This page describes specific problems and shows how runok addresses each one.

## Comments break your allowlist

Claude frequently adds a comment before a command:

```
# check recent commits
git log --oneline -5
```

Even though `Bash(git log *)` is in your allow list, the comment introduces a newline. Claude Code treats the entire string as a single command that no longer matches the glob pattern. You see a confirmation prompt with a message like "Command contains newlines that could separate multiple commands" -- but the reason is not obvious.

**How runok handles this:**

runok uses [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash) to parse the command into an AST. Comments are stripped during parsing. The actual command `git log --oneline -5` is extracted and evaluated against your rules.

```yaml title="runok.yml"
rules:
  - allow: 'git log *'
```

This rule matches regardless of leading comments.

## Command arguments are misinterpreted as flags

Claude Code parses commands to check for suspicious patterns, but this parsing sometimes produces false positives. For example:

```
⏺ Bash(git log --oneline -5 && echo "---" && git status)

Command contains quoted characters in flag names
```

Here, `"---"` is just an argument to `echo`, but Claude Code interprets the `--` inside it as a flag-like pattern and triggers a confirmation prompt. This happens even though every sub-command is individually allowed.

Similarly, `$()` subshell expressions are not expanded, so commands like `echo $(date)` may be treated differently than expected.

**How runok handles this:**

runok uses [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash) to build a full AST. It distinguishes arguments from flags, decomposes compound commands (`&&`, `||`, `;`, `|`) into individual sub-commands, and evaluates each one independently. The strictest result wins. See [Compound Commands](/rule-evaluation/compound-commands/) for details.

```yaml title="runok.yml"
rules:
  - allow: 'git log *'
  - allow: 'echo *'
  - allow: 'git status'
# "git log --oneline -5 && echo '---' && git status"
# -> each sub-command is allowed -> final result: allow
```

## Denied commands provide no feedback

In Claude Code's `settings.json`, the deny list is an array of patterns:

```json title="settings.json"
{
  "permissions": {
    "deny": ["Bash(git push --force*)"]
  }
}
```

When Claude tries `git push --force`, the command is blocked -- but neither the user nor the agent knows _why_. The agent cannot learn from the denial or suggest an alternative.

**How runok handles this:**

runok supports `message` and `fix_suggestion` fields on deny rules:

```yaml title="runok.yml"
rules:
  - deny: 'git push -f|--force *'
    message: 'Force push rewrites history and is not allowed on this project.'
    fix_suggestion: 'git push --force-with-lease'
```

The message is returned to the AI agent, which reads it and retries with the suggested command. See [Denial Feedback](/configuration/denial-feedback/) for details.

## Global flags defeat simple glob matching

Claude sometimes uses global flags before the subcommand:

```sh
git -C /path/to/repo commit -m "fix"
```

Claude Code's glob matching for `Bash(git commit *)` does not match this because `-C /path/to/repo` appears between `git` and `commit`. While `*` can appear at any position in a Claude Code pattern (e.g., `Bash(git * main)`), there is no way to express "match an optional flag with its argument in any position."

**How runok handles this:**

runok's pattern syntax supports [optional groups](/pattern-syntax/optional-groups/) that match zero or one occurrence of a flag in any position:

```yaml title="runok.yml"
rules:
  - allow: 'git [-C *] commit *'
```

All flags are [matched order-independently](/pattern-syntax/matching-behavior/) by default, so flag position within the command does not matter.

## No recursive parsing of subshells and wrappers

Claude may generate commands like:

```sh
sudo bash -c "rm -rf /tmp/build"
```

Claude Code evaluates the entire string as one command. It cannot look inside `sudo`, `bash -c`, `$()` subshells, or backticks to see what actually runs.

**How runok handles this:**

runok defines wrapper patterns in `definitions.wrappers` and recursively extracts and evaluates the inner command:

```yaml title="runok.yml"
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'bash -c <cmd>'

rules:
  - allow: 'rm -rf /tmp/build'
  - deny: 'rm -rf /'
```

For `sudo bash -c "rm -rf /"`, runok unwraps through `sudo`, then `bash -c`, reaches `rm -rf /`, and denies it. See [Wrapper Command Recursion](/rule-evaluation/wrapper-recursion/) for details.

## Per-command sandboxing

Claude Code's OS-level sandbox applies the same restrictions to all commands. There is no way to say "run Python in a restricted environment but let git access the network freely."

**How runok handles this:**

runok attaches sandbox presets to individual rules:

```yaml title="runok.yml"
definitions:
  sandbox:
    restricted:
      fs:
        writable: ['.']
        deny: ['.git', '.env*']
      network:
        allow: false

rules:
  - allow: 'python3 *'
    sandbox: restricted
  - allow: 'git *'
    # no sandbox -- full access
```

Python runs with filesystem and network restrictions. Git runs unrestricted. See [Sandbox](/sandbox/overview/) for details.

## JSON-only configuration, no comments

Claude Code uses `settings.json` for configuration. JSON does not support comments. As your permission rules grow, you cannot annotate why a rule exists, who requested it, or when it was added.

**How runok handles this:**

runok uses YAML, which supports comments natively:

```yaml title="runok.yml"
rules:
  # read-only git commands are always safe
  - allow: 'git status'
  - allow: 'git diff *'
  - allow: 'git log *'

  # allow push, but not force push -- rewrites shared history
  - deny: 'git push -f|--force *'
    message: 'Use --force-with-lease instead.'
  - ask: 'git push *'
```

## Pattern matching expressiveness

Claude Code's `Bash(pattern*)` glob syntax supports `*` wildcards at any position, but it cannot express:

- Flag alternation: "match `-f` or `--force`"
- Optional arguments: "match with or without `--verbose`"
- Negation: "match any verb except `delete`"
- Argument-order-independent matching

**How runok handles this:**

runok's [pattern syntax](/pattern-syntax/overview/) covers all of these:

```yaml title="runok.yml"
rules:
  # Flag alternation
  - deny: 'git push -f|--force *'

  # Optional group
  - allow: 'curl [-o|--output *] -X|--request GET *'

  # Deny kubectl verbs except describe and get
  - deny: 'kubectl !describe|get *'

  # All flags are matched order-independently by default
  - allow: 'git push --force-with-lease *'
  # Matches: git push --force-with-lease origin main
  # Matches: git push origin --force-with-lease main
```

## Unexplained confirmation prompts

Many Claude Code users experience unexpected confirmation prompts even after carefully configuring their allowlists. The prompt messages ("Command contains newlines...", "Command contains quoted characters...") do not clearly explain which rule failed or why. Users cannot tell whether this is a bug, an edge case, or a misconfiguration.

**How runok handles this:**

runok makes evaluation transparent. `runok check` shows exactly what decision was made, and `--output-format json` returns structured output with the matched rule, action, and reason:

```sh
$ runok check --output-format json -- 'git push --force origin main'
```

```json
{
  "decision": "deny",
  "reason": "Force push rewrites history and is not allowed on this project.",
  "fix_suggestion": "git push --force-with-lease"
}
```

The tree-sitter-bash parser handles edge cases (comments, compound commands, wrappers) that cause false positives in glob-based matching, eliminating the category of "unexplained prompts" entirely.

## Summary

| Capability                          | Claude Code settings.json                | runok                                             |
| ----------------------------------- | ---------------------------------------- | ------------------------------------------------- |
| Configuration format                | JSON (no comments)                       | YAML (comments supported)                         |
| Pattern matching                    | Simple glob (`*` wildcards)              | Wildcards, alternation, optional groups, negation |
| Flag order                          | Position-dependent                       | Order-independent                                 |
| Comments in commands                | Break matching                           | Stripped by tree-sitter-bash                      |
| Compound commands (`&&`, `\|`, `;`) | Arguments can be misinterpreted as flags | Decomposed and evaluated individually via AST     |
| Deny feedback                       | Pattern only, no message                 | `message` + `fix_suggestion` fields               |
| Subshell/wrapper parsing            | Not inspected                            | Recursive unwrapping (`sudo`, `bash -c`, `$()`)   |
| Per-command sandboxing              | Same restrictions for all                | Per-rule sandbox presets                          |
| Debugging                           | Limited                                  | `runok check` with JSON output                    |

## Next steps

- [Installation](/getting-started/installation/) -- Install runok.
- [Quick Start](/getting-started/quickstart/) -- Set up your first configuration.
- [Claude Code Integration](/getting-started/claude-code/) -- Configure runok as a Claude Code hook.
