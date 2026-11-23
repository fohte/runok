---
title: Protocol Reference
description: JSON-RPC 2.0 protocol and process settings for runok extensions.
sidebar:
  order: 2
---

Extensions communicate with runok using JSON-RPC 2.0 over standard input and output. runok starts one process for each extension call, writes one request, and reads one response.

## Transport

| Property  | Value                              |
| --------- | ---------------------------------- |
| Protocol  | JSON-RPC 2.0                       |
| Transport | stdin and stdout                   |
| Encoding  | UTF-8                              |
| Lifecycle | One request per process invocation |

The process inherits runok's current working directory. Its environment contains `PATH`, `HOME`, and the variables listed in the extension's `env` setting. Other environment variables are cleared. Extension stderr is discarded.

## Request

runok sends the `call` method. The `params` value is the map passed to `ext.<name>(map)` in the `when` expression. If the call has no argument, runok sends an empty object.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "call",
  "params": {
    "remote": "origin",
    "branch": "topic"
  }
}
```

runok does not add command details to `params`. A rule can choose the command data it needs from CEL variables such as `flags` and `args` and pass them explicitly:

```yaml
when: "ext.repo_state({'remote': args[1], 'branch': args[2]}).protected_branch"
```

## Response

Return one JSON-RPC response with the matching request ID. The `result` may be any JSON value; runok converts it to a CEL value and does not validate its shape.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protected_branch": true,
    "labels": ["release", "restricted"],
    "metadata": null
  }
}
```

Use JSON-RPC's `error` response for protocol-level failures. A JSON-RPC error, malformed response, nonzero process exit, spawn failure, timeout, or argument that cannot be converted to JSON makes the calling rule ask for confirmation. A CEL error after an extension was called has the same result. Other matching rules are still evaluated, and their results combine as `deny > ask > allow`.

If the returned value has a missing field or an incompatible type, CEL reports an evaluation error. Because the `when` expression already called an extension, that rule becomes `ask`. A `when` error that occurs before any extension call remains a normal rule evaluation error.

## Extension definitions

Define the executor under `definitions.extensions.<name>`:

```yaml
definitions:
  extensions:
    repo_state:
      executor: 'python3 ./checks/repo_state.py'
      timeout: 8s
      env: [GIT_AUTH_TOKEN]
```

The executor is split with shell-style quoting. A leading `~` in its executable path expands to `HOME`; relative paths resolve from runok's current working directory.

| Field      | Type            | Default  | Description                                                            |
| ---------- | --------------- | -------- | ---------------------------------------------------------------------- |
| `executor` | `string`        | Required | Program and arguments to start.                                        |
| `timeout`  | duration string | `5s`     | Maximum time from process start until runok reads the response.        |
| `env`      | `string[]`      | `[]`     | Additional environment variable names copied from runok's environment. |

Timeout values use `ms`, `s`, `m`, or `h`, for example `250ms` or `8s`. Each call has its own timeout; runok does not impose a total timeout across all matching rules.

Extension names must be CEL identifiers and cannot conflict with a CEL or runok built-in function. Call them as `ext.<name>(map)`; the argument is one map and may be omitted to send `{}`.

## Call reuse

Within one `when` evaluation, repeated calls with the same extension name and equal map arguments reuse the first result. Each rule's `when` expression has its own cache. Results are not reused across rules or separate checks.

## Configuration trust

Default config discovery permits extension definitions and calls only in the global configuration and its `extends`. Project-discovered extension definitions are ignored with a warning. A project rule that evaluates an `ext.*` call becomes `ask`. A file selected with `--config`, and its `extends` chain, may define extensions and call them.

## Compatibility

The JSON-RPC method is `call`. The earlier `validateCommand` method and rule fields `extension` / `match` are not supported. Extensions now return data, and rules choose the decision in CEL. See [Extensions Overview](/extensions/overview/) for an example.

## Related

- [Extensions Overview](/extensions/overview/) -- How extension values are used in rules.
- [Tutorial](/extensions/tutorial/) -- Build a JSON-RPC extension.
