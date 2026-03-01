---
title: Protocol Reference
description: JSON-RPC 2.0 request and response specification for runok extensions.
sidebar:
  order: 2
---

Extensions communicate with runok using **JSON-RPC 2.0** over standard I/O. runok spawns the extension as a child process, writes a single request to its stdin, then reads a single response from its stdout.

## Transport

| Property  | Value                                                               |
| --------- | ------------------------------------------------------------------- |
| Protocol  | JSON-RPC 2.0                                                        |
| Transport | stdio (stdin/stdout)                                                |
| Encoding  | UTF-8                                                               |
| Direction | runok writes to extension's stdin, reads from extension's stdout    |
| Lifecycle | One request per process invocation (spawn, request, response, exit) |

Extension stderr is discarded by runok (redirected to `/dev/null`). Use stderr for debug logging in your extension without affecting the protocol.

## Request

runok sends a single JSON-RPC 2.0 request with method `validateCommand`.

### Envelope

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "validateCommand",
  "params": {
    "command": "curl",
    "flags": {
      "X": "POST"
    },
    "args": ["https://api.example.com"],
    "raw_command_line": "curl -X POST https://api.example.com",
    "env": {
      "AWS_PROFILE": "prod"
    },
    "cwd": "/home/user/project"
  }
}
```

### `params` fields

| Field              | Type       | Description                                                              |
| ------------------ | ---------- | ------------------------------------------------------------------------ |
| `command`          | `string`   | The base command name (e.g., `"curl"`, `"git"`)                          |
| `flags`            | `object`   | Parsed flags as key-value pairs. Boolean flags have empty string values. |
| `args`             | `string[]` | Positional arguments (non-flag tokens)                                   |
| `raw_command_line` | `string`   | The original command line as entered by the user                         |
| `env`              | `object`   | Relevant environment variables (key-value pairs)                         |
| `cwd`              | `string`   | Current working directory where the command would be executed            |

### Notes on `flags`

Flags are extracted from the parsed command. For example, `curl -X POST --silent` produces:

```json
{
  "flags": {
    "X": "POST",
    "silent": ""
  }
}
```

Flags are parsed into key-value pairs. The flag name (without leading dashes) becomes the key.

- For flags with a value (e.g., `-X POST` or `--request POST`), the value is stored as a string.
- For boolean flags without a value (e.g., `--silent`), the value is an empty string (`""`).

## Response

The extension must write a single JSON-RPC 2.0 response to stdout.

### Success response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "status": "deny",
    "message": "POST requests are not allowed in production",
    "fix_suggestion": "curl -X GET https://api.example.com"
  }
}
```

### `result` fields

| Field            | Type     | Required | Description                                    |
| ---------------- | -------- | -------- | ---------------------------------------------- |
| `status`         | `string` | **Yes**  | One of `"allow"`, `"deny"`, or `"ask"`         |
| `message`        | `string` | No       | Human-readable message explaining the decision |
| `fix_suggestion` | `string` | No       | A suggested alternative command                |

### Status values

| Status    | Action                                                                        |
| --------- | ----------------------------------------------------------------------------- |
| `"allow"` | The command is permitted to run                                               |
| `"deny"`  | The command is blocked. `message` and `fix_suggestion` are shown to the user. |
| `"ask"`   | The user is prompted for confirmation before the command runs                 |

Any unrecognized status value is treated as `"ask"`.

### Error response

Extensions can return a JSON-RPC 2.0 error object to indicate a protocol-level failure:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "Invalid request: missing required field 'command'"
  }
}
```

runok treats any JSON-RPC error response as an `InvalidResponse` error, which triggers the ask fallback.

## Error handling

runok defines three error categories for extension communication:

| Error             | Cause                                                      | Behavior            |
| ----------------- | ---------------------------------------------------------- | ------------------- |
| `Timeout`         | Extension did not respond within the configured timeout    | Falls back to `ask` |
| `Spawn`           | Extension process failed to start (e.g., binary not found) | Falls back to `ask` |
| `InvalidResponse` | Extension returned unparseable output or a JSON-RPC error  | Falls back to `ask` |

In all error cases, runok falls back to `ask` mode, prompting the user for confirmation. This ensures that a broken or unreachable extension never silently allows a dangerous command.

When verbose mode is enabled, error details are printed to stderr:

```
[verbose] Extension error: timeout after 5s
[verbose] Extension error: spawn error: plugin not found
[verbose] Extension error: invalid response: JSON parse error: ...
```

## Security

Extension output is sanitized before display. ASCII control characters (except `\n`, `\r`, `\t`) are stripped to prevent terminal injection attacks from malicious extension output.

## Executor command

The extension process is specified via the `executor` field in the [configuration](/configuration/schema/). runok uses shell-style tokenization (`shlex`) to parse the command:

```yaml
types:
  InternalUrl:
    executor: 'deno run --allow-net ./checks/url_check.ts'
```

The executor string is split into a program and arguments. In this example, runok spawns `deno` with arguments `["run", "--allow-net", "./checks/url_check.ts"]`. Quoted strings and backslash escapes in the executor command are handled correctly.

## Related

- [Extensions Overview](/extensions/overview/) -- Why and when to use extensions.
- [Tutorial](/extensions/tutorial/) -- Build your first extension.
