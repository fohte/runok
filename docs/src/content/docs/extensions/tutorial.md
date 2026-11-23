---
title: Tutorial
description: Build a runok extension that returns JSON data to CEL rules.
sidebar:
  order: 3
---

This tutorial creates an extension that reports whether a branch is protected. The rule reads that value and decides whether to deny a push.

## Create the extension

Save this script as `checks/repo_state.py`:

```python
#!/usr/bin/env python3
import json
import sys

request = json.loads(sys.stdin.read())
params = request["params"]

result = {
    "protected_branch": params.get("branch") == "release",
    "remote": params.get("remote"),
}
print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}))
```

Make the script executable:

```sh
chmod +x checks/repo_state.py
```

The `result` is data, not an `allow`, `deny`, `ask`, or `pass` decision. This example returns an object, but extensions can return any JSON value, including a list, string, number, boolean, or `null`.

## Call it from a rule

Define the executor and pass it the command arguments needed by the extension:

```yaml title="runok.yml"
definitions:
  extensions:
    repo_state:
      executor: ./checks/repo_state.py

rules:
  - deny: 'git push * *'
    when: "ext.repo_state({'remote': args[1], 'branch': args[2]}).protected_branch"
```

When `git push origin release` matches, runok sends `{"remote":"origin","branch":"release"}` as the JSON-RPC `params` object. In this command, `args[1]` is `origin` and `args[2]` is `release`. CEL reads the returned `protected_branch` field. The `deny` rule applies when it is `true`.

You can invoke the script directly to inspect its protocol:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"call","params":{"remote":"origin","branch":"release"}}' \
  | ./checks/repo_state.py
```

Expected output:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": { "protected_branch": true, "remote": "origin" }
}
```

## Test a rule with return-value overrides

Inline tests can provide a result per extension name. The override is returned regardless of the call arguments, and the process is not started for that extension in that test:

```yaml
rules:
  - deny: 'git push * *'
    when: "ext.repo_state({'remote': args[1], 'branch': args[2]}).protected_branch"
    tests:
      - deny: 'git push origin release'
        extensions:
          repo_state: { protected_branch: true }
      - pass: 'git push origin topic'
        extensions:
          repo_state: { protected_branch: false }
```

Run the cases with `runok test`. A test without an override uses the configured extension process. See [`runok test`](/cli/test/) for details.

## Process settings and failures

Each extension call starts a fresh process. It inherits runok's current working directory and receives `PATH`, `HOME`, and only the additional variable names listed in `env`. Set `timeout` per extension; it defaults to `5s` and measures from process start until runok reads the response.

```yaml
definitions:
  extensions:
    repo_state:
      executor: ./checks/repo_state.py
      timeout: 8s
      env: [REPO_API_TOKEN]
```

A timeout, spawn error, nonzero exit, invalid JSON-RPC response, argument that cannot be converted to JSON, or CEL error after a call makes that rule ask for confirmation. Evaluation continues so another matching `deny` rule can still deny the command. See the [Protocol Reference](/extensions/protocol/) for all process and error details.
