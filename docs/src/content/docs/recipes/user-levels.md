---
title: 'User Levels'
description: A progressive guide from preset user to custom rule author to extension developer.
sidebar:
  order: 5
---

This guide walks through three levels of runok usage. Start with shared presets and progress to custom rules and extensions as your needs grow.

## Level 1: Light User — Use Shared Presets

If you want sensible defaults without writing rules yourself, use the `extends` field to inherit from a shared configuration.

### Setup

Create a `runok.yml` in your project root:

```yaml
# yaml-language-server: $schema=https://runok.fohte.net/schema/runok.schema.json

extends:
  - 'github:your-org/runok-presets@main'
```

This pulls in rules from a remote Git repository. The configuration is cached locally in `~/.cache/runok/` and refreshed periodically.

### Personal overrides

If you need to adjust the shared rules for your local environment, create `runok.local.yml` (automatically git-ignored):

```yaml
rules:
  # Allow a tool that the shared config blocks
  - allow: 'terraform apply *'
```

Rules from `runok.local.yml` are merged after the project config. Since deny rules always win, you cannot override a shared deny rule with a local allow — this is by design for security.

### Configuration layering

runok loads configuration in this order (later files take priority for non-deny rules):

1. `~/.config/runok/runok.yml` — Global defaults
2. `./runok.yml` — Project rules (including `extends`)
3. `./runok.local.yml` — Personal overrides

### What you get

- Protection from common dangerous commands out of the box
- No need to learn the pattern syntax
- Easy to adopt across a team — everyone extends the same preset

## Level 2: Heavy User — Write Custom Rules

When shared presets don't cover your workflow, write your own rules with patterns, `when` conditions, and sandbox policies.

### Custom rules with patterns

```yaml
rules:
  # Allow read-only operations
  - allow: 'kubectl get *'
  - allow: 'kubectl describe *'
  - allow: 'kubectl logs *'

  # Require confirmation for applies
  - ask: 'kubectl apply *'

  # Block destructive operations
  - deny: 'kubectl delete namespace *'
    message: 'Deleting namespaces is not allowed via CLI.'
```

Patterns use structured matching — `*` matches zero or more arguments, and flags like `-f|--force` match either form. See the [Pattern Syntax](/pattern-syntax/overview/) reference for the full syntax.

### Conditional rules with `when`

Use CEL (Common Expression Language) expressions to apply rules only under specific conditions:

```yaml
rules:
  # Block production database access
  - deny: 'psql *'
    when: "env.DATABASE_URL.contains('production')"
    message: 'Direct production database access is not allowed.'

  # Allow dry-run in any environment
  - allow: 'terraform plan *'

  # Block apply in production
  - deny: 'terraform apply *'
    when: "env.TF_WORKSPACE == 'production'"
    message: 'Production applies must go through CI/CD.'
```

Available context variables in `when` expressions:

| Variable | Description           | Example                              |
| -------- | --------------------- | ------------------------------------ |
| `env`    | Environment variables | `env.NODE_ENV == 'production'`       |
| `flags`  | Parsed command flags  | `flags.method == 'POST'`             |
| `args`   | Positional arguments  | `args[0].startsWith('https://prod')` |
| `paths`  | Defined path lists    | `'.env' in paths.sensitive`          |

### Sandbox policies

Restrict what a command can access on the filesystem and network:

```yaml
definitions:
  paths:
    sensitive:
      - '.env*'
      - '~/.ssh/**'
      - '/etc/**'

  sandbox:
    dev-sandbox:
      fs:
        writable: [./src, ./dist, /tmp]
        deny:
          - '<path:sensitive>'
      network:
        allow: true

rules:
  - allow: 'node *'
    sandbox: dev-sandbox

  - allow: 'python3 *'
    sandbox: dev-sandbox
```

The `<path:sensitive>` reference expands to the paths defined in `definitions.paths.sensitive`. Sandbox enforcement uses OS-level mechanisms (Seatbelt on macOS, Landlock + seccomp on Linux).

### Wrapper commands

Define wrapper commands so runok can look through them and evaluate the inner command:

```yaml
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'bash -c <cmd>'
    - 'sh -c <cmd>'
    - 'env <opts> <vars> <cmd>'
    - 'xargs <opts> <cmd>'
```

With this configuration, `sudo rm -rf /` is unwrapped and `rm -rf /` is evaluated against your rules. Wrappers are evaluated recursively up to 10 levels deep.

### What you get

- Fine-grained control over every command
- Environment-aware rules that adapt to context
- OS-level sandboxing for untrusted commands
- Transparent wrapper handling

## Level 3: Extension Developer — Build Plugins

For workflows that require dynamic logic beyond static rules, build extensions using the JSON over Stdio protocol.

### How extensions work

Extensions are external processes that communicate with runok through JSON messages over stdin/stdout. This design is language-agnostic — you can write extensions in any language.

The protocol follows an LSP-inspired request/response pattern:

1. runok sends a JSON request to the extension's stdin
2. The extension processes the request
3. The extension writes a JSON response to stdout

### Example: Custom audit logger

A simple extension that logs every command evaluation to a file:

```python
#!/usr/bin/env python3
"""runok extension that logs command evaluations."""
import json
import sys
from datetime import datetime, timezone

def handle_request(request):
    method = request.get("method")

    if method == "evaluate":
        command = request["params"]["command"]
        timestamp = datetime.now(timezone.utc).isoformat()

        with open("/var/log/runok-audit.log", "a") as f:
            f.write(f"{timestamp} | {command}\n")

        # Return no opinion — let other rules decide
        return {"result": None}

    return {"error": {"code": -1, "message": f"Unknown method: {method}"}}

if __name__ == "__main__":
    for line in sys.stdin:
        request = json.loads(line)
        response = handle_request(request)
        print(json.dumps(response), flush=True)
```

### When to build an extension

| Scenario                        | Approach                       |
| ------------------------------- | ------------------------------ |
| Static allow/deny rules         | Use `rules` in `runok.yml`     |
| Environment-dependent logic     | Use `when` conditions with CEL |
| Dynamic logic, external lookups | Build an extension             |
| Organization-wide audit trail   | Build an extension             |
| Custom approval workflows       | Build an extension             |

### What you get

- Unlimited flexibility with any programming language
- Access to external systems (databases, APIs, approval tools)
- Custom audit and compliance workflows
- Composable with static rules — extensions and rules work together
