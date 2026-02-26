---
title: Tutorial
description: Build your first runok extension with timeout handling and error behavior.
sidebar:
  order: 3
---

This tutorial walks you through building a runok extension that validates commands using the JSON-RPC 2.0 protocol. You'll learn how extensions are invoked, how to handle the request/response cycle, and how runok behaves when things go wrong.

## What you'll build

A simple extension that denies `curl` commands using `POST` method in production environments, while allowing everything else.

## Step 1: Create the extension script

Create a file called `checks/env_guard.sh`:

```bash
#!/bin/sh

# Read the JSON-RPC request from stdin
request=$(cat)

# Extract fields using jq
method=$(echo "$request" | jq -r '.params.flags.X // empty')
env_profile=$(echo "$request" | jq -r '.params.env.AWS_PROFILE // empty')

# Decision logic
if [ "$method" = "POST" ] && [ "$env_profile" = "prod" ]; then
  printf '{"jsonrpc":"2.0","id":1,"result":{"status":"deny","message":"POST requests are blocked in production","fix_suggestion":"Use a staging environment instead"}}'
else
  printf '{"jsonrpc":"2.0","id":1,"result":{"status":"allow"}}'
fi
```

Make it executable:

```bash
chmod +x checks/env_guard.sh
```

## Step 2: Configure runok

Add the extension to your `runok.yml`:

```yaml
types:
  ProdGuard:
    executor: './checks/env_guard.sh'
```

## Step 3: Test the extension manually

You can test the extension by piping a JSON-RPC request directly:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"validateCommand","params":{"command":"curl","flags":{"X":"POST"},"args":["https://api.example.com"],"raw_command_line":"curl -X POST https://api.example.com","env":{"AWS_PROFILE":"prod"},"cwd":"/home/user"}}' | ./checks/env_guard.sh
```

Expected output:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "status": "deny",
    "message": "POST requests are blocked in production",
    "fix_suggestion": "Use a staging environment instead"
  }
}
```

## Writing extensions in other languages

Since extensions are standalone processes communicating over stdio, you can use any language. Here are examples in Python and Deno.

### Python

```python
#!/usr/bin/env python3
import json
import sys

request = json.loads(sys.stdin.read())
params = request["params"]

flags = params.get("flags", {})
env = params.get("env", {})

if flags.get("X") == "POST" and env.get("AWS_PROFILE") == "prod":
    result = {
        "status": "deny",
        "message": "POST requests are blocked in production",
        "fix_suggestion": "Use a staging environment instead",
    }
else:
    result = {"status": "allow"}

response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
print(json.dumps(response))
```

### Deno (TypeScript)

```typescript
const request = JSON.parse(await new Response(Deno.stdin.readable).text())
const { flags, env } = request.params

const result =
  flags?.X === 'POST' && env?.AWS_PROFILE === 'prod'
    ? {
        status: 'deny',
        message: 'POST requests are blocked in production',
        fix_suggestion: 'Use a staging environment instead',
      }
    : { status: 'allow' }

console.log(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }))
```

Configure the executor accordingly:

```yaml
types:
  ProdGuard:
    executor: 'python3 ./checks/env_guard.py'
  # or
  ProdGuard:
    executor: 'deno run --allow-read ./checks/env_guard.ts'
```

## Timeout and fallback behavior

runok enforces a timeout on extension execution. Understanding the fallback behavior is critical for writing reliable extensions.

### What happens on timeout

1. runok spawns the extension process and sends the JSON-RPC request.
2. If the extension does not respond within the configured timeout, runok kills the process.
3. runok falls back to **ask** mode -- the user is prompted for confirmation.

The user sees a message like:

```
Extension timed out, asking user for confirmation
```

### What happens on other errors

| Scenario                                              | Error type         | Fallback |
| ----------------------------------------------------- | ------------------ | -------- |
| Extension binary not found                            | `Spawn`            | ask      |
| Extension crashes or exits without output             | `InvalidResponse`  | ask      |
| Extension returns malformed JSON                      | `InvalidResponse`  | ask      |
| Extension returns a JSON-RPC error object             | `InvalidResponse`  | ask      |
| Extension returns unknown status (not allow/deny/ask) | N/A (success path) | ask      |
| Extension times out                                   | `Timeout`          | ask      |

In every failure case, runok falls back to `ask`. This design ensures that a broken extension never silently allows a command to run -- the user is always involved in the decision.

### Why "ask" is the safe default

The ask fallback is a deliberate security design choice:

- **Never auto-allow on failure**: a crashing extension must not grant permission.
- **Never auto-deny on failure**: a temporary issue (e.g., slow network in an extension that checks URLs) should not permanently block the user.
- **User stays in control**: the human always gets the final say when the automated system is uncertain.

### Tips for reliable extensions

- **Read stdin completely before processing.** runok closes the stdin pipe after writing the request. If your extension doesn't drain stdin, it may receive `SIGPIPE`.
- **Keep extensions fast.** Extensions run synchronously in runok's execution path. Avoid network calls or heavy computation where possible.
- **Write debug output to stderr.** runok discards extension stderr, so you can safely use it for logging without affecting the protocol.
- **Return valid JSON-RPC even on internal errors.** Rather than crashing, return an `"ask"` status with a descriptive message:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "status": "ask",
    "message": "Extension internal error: could not connect to policy server"
  }
}
```

## Process lifecycle

Each extension invocation follows this lifecycle:

1. **Spawn**: runok starts the extension process from the `executor` command. The command is parsed using shell-style tokenization (supporting quoted arguments and escapes).
2. **Request**: runok writes the JSON-RPC request to the process's stdin and closes the pipe.
3. **Wait**: runok polls the process, checking for completion or timeout.
4. **Response**: once the process exits, runok reads stdout and parses the JSON-RPC response.
5. **Cleanup**: on timeout, runok kills the process and waits for it to exit.

Extensions are spawned fresh for each validation. There is no persistent connection or process reuse.
