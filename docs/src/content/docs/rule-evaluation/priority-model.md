---
title: 'Priority Model: Explicit Deny Wins'
description: How runok resolves conflicts when multiple rules match a command.
sidebar:
  order: 2
---

When multiple rules match a single command, runok must decide which action to take. runok uses the **Explicit Deny Wins** model, inspired by [AWS IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html): a `deny` rule always overrides `allow` and `ask`, regardless of rule order.

## Priority order

Each action has a fixed restriction level. When multiple rules match, the **most restrictive** action wins:

| Priority    | Action    | Meaning                                |
| ----------- | --------- | -------------------------------------- |
| 3 (highest) | `deny`    | Block the command                      |
| 2           | `ask`     | Prompt the user for confirmation       |
| 1           | `allow`   | Permit the command                     |
| 0           | (default) | No rule matched; use `defaults.action` |

This priority is defined in `action_priority()` in the rule engine (`src/rules/rule_engine.rs`).

## How it works

1. runok iterates over **all** rules and collects every rule whose pattern matches the input command (and whose `when` clause, if any, evaluates to `true`).
2. Among all matching rules, the one with the **highest restriction level** determines the final action.
3. Rule order in the config file does **not** affect priority. A `deny` rule always wins, even if an `allow` rule appears later.

```yaml
rules:
  - allow: 'git *' # priority 1
  - deny: 'git push -f|--force *' # priority 3 — always wins
```

In this example, `git push --force main` matches both rules. The `deny` (priority 3) overrides the `allow` (priority 1), so the command is blocked.

## Comparison with AWS IAM

| Aspect             | AWS IAM               | runok                              |
| ------------------ | --------------------- | ---------------------------------- |
| Explicit deny      | Always wins           | Always wins                        |
| Allow              | Permits unless denied | Permits unless denied or asked     |
| Default            | Implicit deny (block) | Configurable via `defaults.action` |
| Ask (confirmation) | Not applicable        | Middle tier between allow and deny |

The key difference is that runok adds an `ask` tier between `allow` and `deny`, and the default action is configurable rather than fixed to deny.

## The default action

When no rule matches a command, the result is `Default`. You can configure what happens in this case:

```yaml
defaults:
  action: ask # "allow", "deny", or "ask"
```

If `defaults.action` is not set, the adapter layer (e.g., Claude Code integration) determines the behavior.

During [compound command evaluation](/rule-evaluation/compound-commands/), `Default` is resolved to the configured `defaults.action` **before** merging with other sub-command results. This ensures that unmatched sub-commands participate in the Explicit Deny Wins comparison at their effective restriction level, rather than being silently ignored.

## Wrapped command interactions

When a command matches a `definitions.wrappers` pattern (e.g., `sudo <cmd>`), the [wrapped command is extracted and evaluated recursively](/rule-evaluation/wrapper-recursion/). The result from the wrapped command evaluation is then merged with any direct rule matches using the same Explicit Deny Wins logic.

For example:

```yaml
definitions:
  wrappers:
    - pattern: 'sudo <cmd>'

rules:
  - allow: 'sudo *'
  - deny: 'rm -rf /'
```

When evaluating `sudo rm -rf /`:

1. `allow: "sudo *"` matches directly (priority 1).
2. `sudo <cmd>` extracts the wrapped command `rm -rf /` and evaluates it recursively.
3. `deny: "rm -rf /"` matches the wrapped command (priority 3).
4. The results are merged: `deny` (priority 3) wins over `allow` (priority 1).

The command is denied.

## Sandbox preset selection

For a single command, the sandbox preset is taken from whichever rule wins the Explicit Deny Wins comparison. The sandbox preset does not affect the priority comparison itself — it is carried along with the winning action.

```yaml
rules:
  - allow: 'npm install *'
    sandbox: restricted-network
```

For compound commands, sandbox presets from all sub-commands are merged using a [strictest intersection strategy](/rule-evaluation/compound-commands/#sandbox-policy-aggregation).
