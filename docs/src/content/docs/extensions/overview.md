---
title: Extensions Overview
description: Call external JSON value providers from CEL rule conditions.
sidebar:
  order: 1
---

Extensions let a rule read information that runok cannot derive from the command, environment, or filesystem. Each extension is a process that receives a JSON object and returns a JSON value over JSON-RPC 2.0 on stdin and stdout.

Extensions return data, not permission decisions. A rule calls an extension from `when` and decides whether to allow, ask, or deny:

```yaml title="runok.yml"
definitions:
  extensions:
    repo_state:
      executor: ./checks/repo_state
      timeout: 5s
      env: [GIT_AUTH_TOKEN]

rules:
  - deny: 'git push *'
    when: "ext.repo_state({'remote': args[1]}).protected_branch"
```

The extension receives `{"remote": args[1]}` as its JSON-RPC `params` object. Its result can be any JSON value, which CEL exposes as a map, list, string, boolean, number, or `null`. See the [Protocol Reference](/extensions/protocol/) for the request and response format.

## Evaluation behavior

- runok calls an extension only when its rule pattern matches and CEL evaluates that call.
- A repeated call with the same extension name and argument map runs once within a single `when` evaluation. Results are not shared between rules.
- A failed extension call, or a `when` evaluation error after an extension call, makes that rule ask for confirmation. Evaluation continues and matching results combine as `deny > ask > allow`.
- A `when` error that occurs without calling an extension still stops evaluation as before.

Each call starts a new process. The process inherits runok's current working directory and receives `PATH`, `HOME`, and only the extra environment variable names listed in the extension definition. The default timeout is five seconds per extension call. There is no timeout for the whole `runok check` evaluation.

## Configuration trust

Default config discovery accepts extension definitions and calls only from the global configuration. Extension definitions found in project configuration are ignored with a warning. Project rules that call `ext.*` fail as `ask`. An explicitly selected `--config` file and its `extends` chain may define and call extensions.

## Next steps

- [Protocol Reference](/extensions/protocol/) -- JSON-RPC request, result, and process settings.
- [Tutorial](/extensions/tutorial/) -- Build an extension that returns data to a rule.
