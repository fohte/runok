---
title: Placeholders
description: Special tokens in <...> for wrappers, option absorption, and path matching.
sidebar:
  order: 5
---

Tokens wrapped in `<...>` are **placeholders** — special tokens that match dynamically rather than by exact string comparison.

| Placeholder                                  | Description                                              |
| -------------------------------------------- | -------------------------------------------------------- |
| [`<cmd>`](#command-cmd)                      | Captures the wrapped command for further rule evaluation |
| [`<opts>`](#options-opts)                    | Absorbs zero or more flag-like tokens                    |
| [`<vars>`](#variables-vars)                  | Absorbs zero or more `KEY=VALUE` tokens                  |
| [`<path:name>`](#path-references-pathname)   | Matches against a named list of paths                    |
| [`<var:name>`](#variable-references-varname) | Matches against a typed variable definition              |

## Command (`<cmd>`)

The `<cmd>` placeholder captures the **remaining tokens** as the wrapped command. The wrapped command is then evaluated against the other rules in the configuration. See [Wrapped Command Recursion](/rule-evaluation/wrapper-recursion/) for details.

`<cmd>` only matches token sequences whose **first token is not a flag** (does not start with `-`). This prevents wrapper patterns from accidentally consuming flag arguments as commands. For example, `command <cmd>` does not match `command -v a` because `-v` is a flag, not a command name.

```yaml
# sudo echo hello -> wrapped command is "echo hello"
- allow: 'sudo <cmd>'
```

### Defining Wrappers

Wrapper patterns are defined in the [`definitions.wrappers`](/configuration/schema/#definitionswrappers) block and referenced by rules:

```yaml
definitions:
  wrappers:
    - 'sudo <cmd>'
    - 'xargs <opts> <cmd>'

rules:
  - allow: 'echo *'
  # With the wrapper definition, this also allows:
  #   sudo echo hello
  #   xargs -I{} echo hello
```

## Options (`<opts>`)

The `<opts>` placeholder absorbs **zero or more flag-like tokens** (tokens starting with `-`):

```yaml
# Matches: env FOO=bar command
# Matches: env -i FOO=bar command
# Matches: env -u HOME -i FOO=bar command
- allow: 'env <opts> <vars> <cmd>'
```

`<opts>` stops consuming tokens when it encounters:

- A token that does not start with `-`
- The `--` end-of-options marker

For short flags consisting of exactly `-` plus one ASCII letter (e.g., `-n`, `-S`), if the next token does not start with `-`, it is consumed as the flag's argument:

```yaml
# env -S "FOO=bar" command -> <opts> consumes "-S" and "FOO=bar"
- allow: 'env <opts> <cmd>'
```

:::note
Self-contained flags like `-0` (digit flags) and `-I{}` (flag with attached argument) do not consume the next token.
:::

## Variables (`<vars>`)

The `<vars>` placeholder absorbs **zero or more `KEY=VALUE` tokens** — tokens that contain `=`:

```yaml
# Matches: env command
# Matches: env FOO=bar command
# Matches: env FOO=bar BAZ=qux command
- allow: 'env <vars> <cmd>'
```

`<vars>` stops consuming tokens when it encounters a token without `=`.

## Path References (`<path:name>`)

The `<path:name>` placeholder matches a command argument against a **named list of paths** defined in the [`definitions.paths`](/configuration/schema/#definitionspaths) block.

### Defining Paths

```yaml
definitions:
  paths:
    sensitive:
      - /etc/passwd
      - /etc/shadow
      - /etc/sudoers
    config:
      - /etc/nginx/nginx.conf
      - /etc/hosts
```

### Using Path References

Reference a path list with `<path:name>`:

```yaml
rules:
  - deny: 'cat <path:sensitive>'
  - deny: 'rm <path:sensitive>'
  - allow: 'cat <path:config>'
```

| Command           | Rule                           | Result  |
| ----------------- | ------------------------------ | ------- |
| `cat /etc/passwd` | `deny: "cat <path:sensitive>"` | Denied  |
| `cat /etc/hosts`  | `allow: "cat <path:config>"`   | Allowed |
| `rm /etc/shadow`  | `deny: "rm <path:sensitive>"`  | Denied  |

### Path Normalization

Paths are **normalized** before comparison. The following path components are resolved:

- `.` (current directory) is removed
- `..` (parent directory) is resolved

```yaml
definitions:
  paths:
    sensitive:
      - /etc/passwd
```

| Command                  | Matches `<path:sensitive>` |
| ------------------------ | -------------------------- |
| `cat /etc/passwd`        | Yes                        |
| `cat /etc/./passwd`      | Yes (`.` removed)          |
| `cat /tmp/../etc/passwd` | Yes (`..` resolved)        |

This prevents bypassing path rules through path manipulation.

### Undefined Path Names

If a pattern references a path name that is not defined in `definitions.paths`, the pattern **never matches**:

```yaml
# If "sensitive" is not defined, this rule has no effect
- deny: 'cat <path:sensitive>'
```

## Variable References (`<var:name>`)

The `<var:name>` placeholder matches a command token against a **typed variable definition** in the [`definitions.vars`](/configuration/schema/#definitionsvars) block. It can be used in both **argument position** and **command position**.

### Defining Variables

Each variable has an optional `type` (default: `literal`) and a list of `values`. Values can be plain strings (inheriting the definition-level type) or objects with an explicit per-value `type` override:

```yaml
definitions:
  vars:
    instance-ids:
      values:
        - i-abc123
        - i-def456
        - i-ghi789
    test-script:
      type: path
      values:
        - ./tests/run
    runok:
      values:
        - runok # literal (default): exact match
        - 'cargo run --' # literal: multi-word, consumes multiple tokens
        - type: path
          value: target/debug/runok # path: canonicalize before comparison
```

### Variable Types

| Type      | Matching behavior                                                         |
| --------- | ------------------------------------------------------------------------- |
| `literal` | Exact string match (default)                                              |
| `path`    | Canonicalize both sides before comparison, fallback to path normalization |

Each value inherits the definition-level `type` unless it specifies its own `type` via the `{ type, value }` form.

### Using Variable References

#### In argument position

```yaml
rules:
  - allow: aws ec2 terminate-instances --instance-ids <var:instance-ids>
  - allow: bash <var:test-script>
```

| Command                                                | Rule                                             | Result                       |
| ------------------------------------------------------ | ------------------------------------------------ | ---------------------------- |
| `aws ec2 terminate-instances --instance-ids i-abc123`  | `allow: "... --instance-ids <var:instance-ids>"` | Allowed                      |
| `aws ec2 terminate-instances --instance-ids i-UNKNOWN` | `allow: "... --instance-ids <var:instance-ids>"` | No match                     |
| `bash ./tests/run`                                     | `allow: "bash <var:test-script>"`                | Allowed                      |
| `bash tests/run`                                       | `allow: "bash <var:test-script>"`                | Allowed (path normalization) |

#### In command position

`<var:name>` can also be used as the command name in a pattern. This is useful when the same tool can be invoked in multiple ways:

```yaml
definitions:
  vars:
    runok:
      values:
        - runok
        - 'cargo run --'
        - type: path
          value: target/debug/runok
rules:
  - allow: '<var:runok> check'
```

| Command                      | Result                       |
| ---------------------------- | ---------------------------- |
| `runok check`                | Allowed                      |
| `cargo run -- check`         | Allowed (multi-word value)   |
| `./target/debug/runok check` | Allowed (path normalization) |
| `node check`                 | No match                     |

Multi-word values (e.g. `"cargo run --"`) consume multiple leading tokens from the input command.

### Path Type Normalization

When `type: path` is set, both the command argument and the defined values are **canonicalized** (resolved to absolute paths via the filesystem). If the path does not exist on disk, logical normalization is used as a fallback (`.` removal and `..` resolution).

This handles cases where the same file is referenced with different path forms:

```yaml
definitions:
  vars:
    test-script:
      type: path
      values:
        - ./tests/run
```

| Command                     | Matches `<var:test-script>` |
| --------------------------- | --------------------------- |
| `bash tests/run`            | Yes                         |
| `bash ./tests/run`          | Yes                         |
| `bash ./tests/../tests/run` | Yes                         |
| `bash ./scripts/deploy`     | No                          |

### Undefined Variable Names

If a pattern references a variable name that is not defined in `definitions.vars`, the pattern **never matches**.

## Combining Placeholders

Placeholders can be combined to handle complex wrapper patterns:

```yaml
definitions:
  wrappers:
    # Handles: env [-i] [-u NAME] [KEY=VALUE...] command [args...]
    - 'env <opts> <vars> <cmd>'

    # Handles: sudo [-u user] command [args...]
    - 'sudo <opts> <cmd>'

    # Handles: xargs [flags...] command [args...]
    - 'xargs <opts> <cmd>'

    # Handles: find [args...] -exec|-execdir|-ok|-okdir command [args...] \;|+
    - "find * -exec|-execdir|-ok|-okdir <cmd> \\;|+"
```

:::note
In the `find` wrapper example, `\\;` is a backslash-escaped semicolon in YAML. The pattern parser preserves the backslash (`\;`), and the matcher strips it during comparison so that it matches the shell-unescaped `;` in the actual command.
:::

## Restrictions

- `<cmd>` captures one or more tokens whose first token is not a flag (does not start with `-`); it tries all possible split points to find a valid wrapped command
- Optional groups, path references, and variable references are not supported inside wrapper patterns

## Related

- [Wrapped Command Recursion](/rule-evaluation/wrapper-recursion/) -- How wrapper commands are recursively evaluated.
- [Configuration Schema](/configuration/schema/#definitionswrappers) -- Wrapper and path definition reference.
