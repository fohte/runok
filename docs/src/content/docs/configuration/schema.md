---
title: Configuration Schema
description: Full reference for runok.yml configuration options.
sidebar:
  order: 1
---

This page documents every field available in `runok.yml`. Each option is described using a consistent format: name, description, type, default value, and example.

## File Format

runok configuration is written in YAML. The configuration file is named `runok.yml` (or `runok.yaml`) and placed at the project root or in the global config directory. See [File Discovery and Merging](/configuration/file-discovery/) for details on where runok looks for configuration files.

A minimal configuration file looks like this:

```yaml title="runok.yml"
rules:
  - allow: 'git *'
  - ask: 'npm *'
```

The top-level keys are `required_runok_version`, `extends`, `defaults`, `rules`, `definitions`, `audit`, and `tests`. All are optional.

### JSON Schema

runok provides a JSON Schema for configuration file validation and editor autocompletion. The schema file is available at [`schema/runok.schema.json`](https://github.com/fohte/runok/blob/main/schema/runok.schema.json) in the repository.

To enable autocompletion in your editor, add a `# yaml-language-server` directive at the top of your configuration file:

```yaml title="runok.yml"
# yaml-language-server: $schema=https://raw.githubusercontent.com/fohte/runok/main/schema/runok.schema.json
rules:
  - allow: 'git *'
```

## Top-Level Fields

### `required_runok_version`

Minimum runok version required to load this file, expressed as a [semver requirement](https://docs.rs/semver/latest/semver/struct.VersionReq.html) (e.g. `">=0.3.0"`, `"^0.3"`, `">=0.3, <0.5"`). If the current runok binary does not satisfy the requirement, loading fails with an error that names the file and the constraint. The check runs per file, so every file in an `extends` chain is validated independently.

See [Extends -- Version Guards](/configuration/extends/#version-guards-required_runok_version) for preset authoring guidance and how `update-presets` and automatic refresh interact with this field.

**Type:** `str`\
**Default:** None\
**Required:** No

```yaml title="runok.yml"
required_runok_version: '>=0.3.0'
rules:
  - allow: 'echo *'
```

### `extends`

List of configuration files to inherit from. Supports local paths and remote Git repositories.

**Type:** `list[str]`\
**Default:** `[]`\
**Required:** No

```yaml title="runok.yml"
extends:
  - ./base.yml
  - github:example-org/example-presets@v1.0.0
  - github:example-org/runok-presets/readonly-unix@v1
```

See [Extends (Presets)](/configuration/extends/) for full details on local paths, GitHub shorthand, and Git URLs. For the official preset collection, see [Official Presets (runok-presets)](/configuration/official-presets/).

### `defaults`

Default settings applied when no rule matches a command.

**Type:** `object`\
**Default:** `{ action: "ask" }`\
**Required:** No

```yaml title="runok.yml"
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

Name of a sandbox preset (defined in `definitions.sandbox`) to apply by default. See [Sandbox](/sandbox/overview/) for how sandboxing works.

**Type:** `str`\
**Default:** None

```yaml title="runok.yml"
defaults:
  sandbox: standard
```

### `rules`

Ordered list of permission rules evaluated top-to-bottom against each command. The first matching rule wins. See [Rule Evaluation](/rule-evaluation/overview/) for how rules are matched and prioritized.

**Type:** `list[RuleEntry]`\
**Default:** `[]`\
**Required:** No

```yaml title="runok.yml"
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

Command pattern that triggers this rule. Only one of the three may be specified per rule. See [Pattern Syntax](/pattern-syntax/overview/) for the pattern matching language.

**Type:** `str`\
**Required:** Exactly one

```yaml title="runok.yml"
# deny rule
- deny: 'rm -rf /'

# allow rule
- allow: 'git status'

# ask rule
- ask: 'docker run *'
```

##### `when`

CEL (Common Expression Language) expression that must evaluate to `true` for this rule to apply. If omitted, the rule always applies when the pattern matches. See [Rule Evaluation](/rule-evaluation/overview/) for details on condition evaluation.

**Type:** `str`\
**Default:** None

```yaml title="runok.yml"
- allow: 'npm publish'
  when: "env.CI == 'true'"
```

:::tip
`when` expressions work on parsed tokens (flags, args, environment variables). For validation that requires deeper argument parsing -- such as inspecting a GraphQL query string or parsing a URL -- use an [extension](/extensions/overview/) instead.
:::

##### `message`

Message shown to the user when the rule matches. Primarily useful for `deny` rules to explain why a command is blocked. See [Denial Feedback](/configuration/denial-feedback/) for usage examples.

**Type:** `str`\
**Default:** None

```yaml title="runok.yml"
- deny: 'rm -rf /'
  message: This operation is too dangerous to allow.
```

##### `fix_suggestion`

Suggested alternative command shown when a `deny` rule matches. Helps users find a safer alternative. See [Denial Feedback](/configuration/denial-feedback/) for usage examples.

**Type:** `str`\
**Default:** None

```yaml title="runok.yml"
- deny: 'rm -rf *'
  message: Use trash instead of rm for safety.
  fix_suggestion: 'trash *'
```

##### `sandbox`

Name of a sandbox preset (defined in `definitions.sandbox`) to apply when this rule matches. Not allowed on `deny` rules. See [Sandbox](/sandbox/overview/) for how sandboxing works.

**Type:** `str`\
**Default:** None

```yaml title="runok.yml"
- allow: 'node *'
  sandbox: strict
```

##### `tests`

Inline test cases for this rule. Each entry specifies the expected decision and the command to evaluate. Used by [`runok test`](/cli/test/) to verify the rule behaves as expected.

**Type:** `list[TestEntry]`\
**Default:** `[]`

```yaml title="runok.yml"
- allow: 'git status'
  tests:
    - allow: 'git status'
    - ask: 'git status --short'
```

### `definitions`

Reusable definitions for paths, variables, sandbox presets, and wrappers.

**Type:** `object`\
**Default:** `{}`\
**Required:** No

#### `definitions.paths`

Named path lists that can be referenced by `<path:name>` in sandbox `fs.deny` rules.

**Type:** `map[str, list[str]]`\
**Default:** `{}`

```yaml title="runok.yml"
definitions:
  paths:
    secrets:
      - ~/.ssh
      - ~/.gnupg
      - ~/.aws/credentials
```

The name is referenced via `<path:name>` syntax:

```yaml title="runok.yml"
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

Named sandbox presets that define filesystem and network restrictions. See [Sandbox](/sandbox/overview/) for details on how sandbox policies are enforced.

**Type:** `map[str, SandboxPreset]`\
**Default:** `{}`

```yaml title="runok.yml"
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

Filesystem access policy with `read` and `write` sub-sections.

**Type:** `object`\
**Default:** None

###### `fs.read.deny`

Paths the sandboxed process cannot read. These paths become completely inaccessible (both read and write are blocked). Supports glob patterns and `<path:name>` references.

**Type:** `list[str]`\
**Default:** `[]`

###### `fs.write.allow`

Directories the sandboxed process is allowed to write to.

**Type:** `list[str]`\
**Default:** `[]`

###### `fs.write.deny`

Paths the sandboxed process cannot write to, even within writable directories. Supports glob patterns (`*`, `**`, `?`, `[...]`, `{a,b}`) and `<path:name>` references.

**Type:** `list[str]`\
**Default:** `[]`

:::note[Legacy format]
The previous flat format (`fs.writable` / `fs.deny`) is still accepted but deprecated. See [Sandbox Overview](/sandbox/overview/) for migration guidance.
:::

###### `network`

Network access policy.

**Type:** `object`\
**Default:** None

###### `network.allow`

Whether network access is allowed.

**Type:** `bool`\
**Default:** `true`

##### Sandbox Merge Strategy (Strictest Wins)

When multiple sandbox presets apply to a command, they are merged using a **Strictest Wins** strategy. See [Sandbox Overview](/sandbox/overview/#sandbox-merging-for-compound-commands) for the merge rules and examples.

#### `definitions.wrappers`

Wrapper command patterns for recursive rule evaluation. When a command matches a wrapper pattern, the inner `<cmd>` is extracted and evaluated against the rules independently. See [Rule Evaluation](/rule-evaluation/overview/) for details on wrapper processing.

**Type:** `list[str]`\
**Default:** `[]`

```yaml title="runok.yml"
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'env * <cmd>'
```

#### `definitions.vars`

Typed variable definitions referenced by `<var:name>` in rule patterns. Each variable has a `type` (controlling how values are matched) and a list of `values`.

**Type:** `map[str, VarDefinition]`\
**Default:** `{}`

```yaml title="runok.yml"
definitions:
  vars:
    instance-ids:
      values:
        - i-abc123
        - i-def456
    test-script:
      type: path
      values:
        - ./tests/run
    runok:
      values:
        - runok
        - 'cargo run --'
        - type: path
          value: target/debug/runok
```

##### Variable Definition Fields

###### `type`

Controls how the variable's values are matched against command arguments. This is the definition-level default; individual values can override it with per-value type.

**Type:** `"literal" | "path"`\
**Default:** `"literal"`

| Type      | Matching behavior                                                         |
| --------- | ------------------------------------------------------------------------- |
| `literal` | Exact string match                                                        |
| `path`    | Canonicalize both sides before comparison, fallback to path normalization |

###### `values`

List of allowed values for this variable. Each element can be either a plain string (inherits the definition-level `type`) or an object with explicit `type` and `value` fields.

**Type:** `list[str | { type: "literal" | "path", value: str }]`\
**Required:** Yes

```yaml
values:
  - runok # plain string, inherits definition-level type
  - 'cargo run --' # multi-word value
  - type: path # per-value type override
    value: target/debug/runok
```

:::note
Variable definitions must contain concrete values. `<var:name>` or `<path:name>` references inside `definitions.vars` values are not allowed.
:::

#### `definitions.flag_groups`

Named flag alias groups referenced by `<flag:name>` in rule patterns. Each group lists every flag spelling that shares semantic meaning (e.g. `-f`, `-F`, `--field`, `--raw-field` for `gh api`'s field flag). When a `<flag:name>` placeholder matches a command, every occurrence of any aliased flag is captured into the `flag_groups[name]` list available in `when` clauses.

**Type:** `map[str, list[str]]`\
**Default:** `{}`

```yaml title="runok.yml"
definitions:
  flag_groups:
    field-flag: ['-f', '-F', '--field', '--raw-field']
    header-flag: ['-H', '--header']
```

##### Validation rules

- Each entry must contain at least one flag.
- Every flag name must start with `-` (long flags use `--`). The bare `--` separator is rejected because it is positional.
- Rules referencing `<flag:name>` must reference a group defined here; undefined references are rejected at config load time.

See [`<flag:name>`](/pattern-syntax/placeholders/#flag-groups-flagname) and [When Clauses -- `flag_groups`](/rule-evaluation/when-clause/#flag_groups--captured-flag-group-values) for details on how the captured values are exposed to `when` expressions.

### `audit`

Audit log settings. Controls whether command evaluations are recorded and where log files are stored. Audit settings can only be configured in the **global** `runok.yml` — audit sections in project or local override configs are silently ignored.

**Type:** `object`\
**Default:** `{ enabled: true }`\
**Required:** No

```yaml title="~/.config/runok/runok.yml"
audit:
  enabled: true
  path: ~/.local/share/runok/
  rotation:
    retention_days: 30
```

#### `audit.enabled`

Whether audit logging is enabled.

**Type:** `bool`\
**Default:** `true`

#### `audit.path`

Directory path for audit log files.

**Type:** `str`\
**Default:** `~/.local/share/runok/` (or `$XDG_DATA_HOME/runok/`)

#### `audit.rotation`

Log rotation settings.

**Type:** `object`\
**Default:** `{}`

#### `audit.rotation.retention_days`

Number of days to retain log files. Files older than this are automatically deleted during log writes.

**Type:** `int`\
**Default:** `7`

### `tests`

Top-level test section for cross-rule test cases and test-only configuration. Used by [`runok test`](/cli/test/).

**Type:** `object`\
**Default:** `{}`\
**Required:** No

```yaml title="runok.yml"
tests:
  extends:
    - ./test-fixtures/extra-rules.yml
  cases:
    - allow: 'git push origin main'
    - deny: 'git push --force origin main'
```

#### `tests.extends`

Additional configuration files to merge only during test execution. These files are not loaded during normal `runok check` or `runok exec`.

**Type:** `list[str]`\
**Default:** `[]`

#### `tests.cases`

Test cases to evaluate. Each entry specifies the expected decision (`allow`, `ask`, or `deny`) and the command to evaluate.

**Type:** `list[TestEntry]`\
**Default:** `[]`

## Complete Example

```yaml title="runok.yml"
extends:
  - github:example-org/example-presets@v1.0.0

defaults:
  action: ask
  sandbox: standard

definitions:
  paths:
    secrets:
      - ~/.ssh
      - ~/.gnupg
  vars:
    safe-scripts:
      type: path
      values:
        - ./tests/run
        - ./scripts/lint.sh
  sandbox:
    standard:
      fs:
        read:
          deny:
            - <path:secrets>
        write:
          allow:
            - .
          deny:
            - <path:secrets>
      network:
        allow: true
    strict:
      fs:
        read:
          deny:
            - <path:secrets>
        write:
          allow:
            - ./src
          deny:
            - <path:secrets>
      network:
        allow: false
  wrappers:
    - 'sudo <cmd>'

audit:
  enabled: true
  rotation:
    retention_days: 30

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
