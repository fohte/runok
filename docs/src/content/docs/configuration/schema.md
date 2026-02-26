---
title: Configuration Schema
description: Full reference for runok.yml configuration options.
sidebar:
  order: 1
---

This page documents every field available in `runok.yml`. Each option is described using a consistent format: name, description, type, default value, and example.

## Top-Level Fields

### `extends`

List of configuration files to inherit from. Supports local paths and remote Git repositories.

**Type:** `list[str]`\
**Default:** `[]`\
**Required:** No

```yaml
extends:
  - ./base.yml
  - github:fohte/runok-presets@v1.0.0
```

See [Extends (Presets)](/configuration/extends/) for full details on local paths, GitHub shorthand, and Git URLs.

### `defaults`

Default settings applied when no rule matches a command.

**Type:** `object`\
**Default:** `{ action: "ask" }`\
**Required:** No

```yaml
defaults:
  action: allow
  sandbox: strict
```

#### `defaults.action`

Action to take when no rule matches.

**Type:** `"allow" | "ask" | "deny"`\
**Default:** `"ask"`

| Value   | Behavior                              |
| ------- | ------------------------------------- |
| `allow` | Permit the command without prompting. |
| `ask`   | Prompt the user for confirmation.     |
| `deny`  | Reject the command.                   |

#### `defaults.sandbox`

Name of a sandbox preset (defined in `definitions.sandbox`) to apply by default.

**Type:** `str`\
**Default:** None

```yaml
defaults:
  sandbox: standard
```

### `rules`

Ordered list of permission rules evaluated top-to-bottom against each command. The first matching rule wins.

**Type:** `list[RuleEntry]`\
**Default:** `[]`\
**Required:** No

```yaml
rules:
  - allow: 'git *'
  - deny: 'rm -rf /'
    message: Dangerous operation
  - ask: 'docker *'
    sandbox: container-safe
```

#### Rule Entry

Each rule entry must have exactly one of `deny`, `allow`, or `ask` set.

##### `deny` / `allow` / `ask`

Command pattern that triggers this rule. Only one of the three may be specified per rule.

**Type:** `str`\
**Required:** Exactly one

```yaml
# deny rule
- deny: 'rm -rf /'

# allow rule
- allow: 'git status'

# ask rule
- ask: 'docker run *'
```

##### `when`

CEL (Common Expression Language) expression that must evaluate to `true` for this rule to apply. If omitted, the rule always applies when the pattern matches.

**Type:** `str`\
**Default:** None

```yaml
- allow: 'npm publish'
  when: "env.CI == 'true'"
```

##### `message`

Message shown to the user when the rule matches. Primarily useful for `deny` rules to explain why a command is blocked.

**Type:** `str`\
**Default:** None

```yaml
- deny: 'rm -rf /'
  message: This operation is too dangerous to allow.
```

##### `fix_suggestion`

Suggested alternative command shown when a `deny` rule matches. Helps users find a safer alternative.

**Type:** `str`\
**Default:** None

```yaml
- deny: 'rm -rf *'
  message: Use trash instead of rm for safety.
  fix_suggestion: 'trash *'
```

##### `sandbox`

Name of a sandbox preset (defined in `definitions.sandbox`) to apply when this rule matches. Not allowed on `deny` rules.

**Type:** `str`\
**Default:** None

```yaml
- allow: 'node *'
  sandbox: strict
```

### `definitions`

Reusable definitions for paths, sandbox presets, wrappers, and commands.

**Type:** `object`\
**Default:** `{}`\
**Required:** No

#### `definitions.paths`

Named path lists that can be referenced by `<path:name>` in sandbox `fs.deny` rules.

**Type:** `map[str, list[str]]`\
**Default:** `{}`

```yaml
definitions:
  paths:
    secrets:
      - ~/.ssh
      - ~/.gnupg
      - ~/.aws/credentials
```

The name is referenced via `<path:name>` syntax:

```yaml
definitions:
  sandbox:
    secure:
      fs:
        deny:
          - <path:secrets>
```

:::note
Path definitions must contain concrete paths. `<path:name>` references inside `definitions.paths` values are not allowed.
:::

#### `definitions.sandbox`

Named sandbox presets that define filesystem and network restrictions.

**Type:** `map[str, SandboxPreset]`\
**Default:** `{}`

```yaml
definitions:
  sandbox:
    strict:
      fs:
        writable:
          - ./src
          - ./tests
        deny:
          - <path:secrets>
      network:
        allow: false
```

##### Sandbox Preset Fields

###### `fs`

Filesystem access policy.

**Type:** `object`\
**Default:** None

###### `fs.writable`

Directories the sandboxed process is allowed to write to.

**Type:** `list[str]`\
**Default:** `[]`

###### `fs.deny`

Paths the sandboxed process is denied access to. Supports `<path:name>` references to entries in `definitions.paths`.

**Type:** `list[str]`\
**Default:** `[]`

###### `network`

Network access policy.

**Type:** `object`\
**Default:** None

###### `network.allow`

Whether network access is allowed.

**Type:** `bool`\
**Default:** `true`

##### Sandbox Merge Strategy (Strictest Wins)

When multiple sandbox presets apply to a command, they are merged using a "Strictest Wins" policy:

| Field           | Merge strategy | Effect                                      |
| --------------- | -------------- | ------------------------------------------- |
| `fs.writable`   | Intersection   | Only paths in all presets remain writable.  |
| `fs.deny`       | Union          | Denied paths from all presets are combined. |
| `network.allow` | AND            | If any preset denies network, it is denied. |

#### `definitions.wrappers`

Wrapper command patterns for recursive rule evaluation. When a command matches a wrapper pattern, the inner `<cmd>` is extracted and evaluated against the rules independently.

**Type:** `list[str]`\
**Default:** `[]`

```yaml
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'env * <cmd>'
```

#### `definitions.commands`

Additional command patterns to recognize during parsing.

**Type:** `list[str]`\
**Default:** `[]`

```yaml
definitions:
  commands:
    - mycustomtool
```

## Complete Example

```yaml
extends:
  - github:fohte/runok-presets@v1.0.0

defaults:
  action: ask
  sandbox: standard

definitions:
  paths:
    secrets:
      - ~/.ssh
      - ~/.gnupg
  sandbox:
    standard:
      fs:
        writable:
          - .
        deny:
          - <path:secrets>
      network:
        allow: true
    strict:
      fs:
        writable:
          - ./src
        deny:
          - <path:secrets>
      network:
        allow: false
  wrappers:
    - 'sudo <cmd>'
  commands:
    - mycustomtool

rules:
  - allow: 'git *'
  - allow: 'cargo test *'
    sandbox: strict
  - deny: 'rm -rf /'
    message: This operation is too dangerous.
    fix_suggestion: 'trash /'
  - ask: 'docker *'
    sandbox: standard
```
