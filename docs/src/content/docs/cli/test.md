---
title: runok test
description: Run tests defined in runok.yml to verify that rules behave as expected.
sidebar:
  order: 7
---

`runok test` runs test cases defined in your `runok.yml` and reports whether each command produces the expected decision (allow, ask, or deny). Use it to verify that your rules work as intended before deploying configuration changes.

## Usage

```sh
runok test [options]
```

## Flags

### `-c, --config <path>`

See [Global Flags](/cli/overview/#global-flags). When omitted, runok looks for `runok.yml` (or `runok.yaml`) in the current directory.

```sh
runok test -c ./path/to/runok.yml
```

## Defining test cases

Test cases can be defined in two places:

### Inline tests (per-rule)

Add a `tests` list to any rule entry. Each entry specifies the expected decision (`allow`, `ask`, or `deny`) and the command to evaluate:

```yaml title="runok.yml"
rules:
  - allow: 'git status'
    tests:
      - allow: 'git status'
      - ask: 'git status --short'

  - deny: 'git push -f|--force *'
    tests:
      - deny: 'git push --force origin main'
      - deny: 'git push -f origin main'
```

### Top-level tests

For cross-rule tests or tests that need additional configuration, use the top-level `tests` section:

```yaml title="runok.yml"
rules:
  - allow: 'git *'
  - deny: 'git push -f|--force *'

tests:
  cases:
    - allow: 'git push origin main'
    - deny: 'git push --force origin main'
```

#### `tests.extends`

Load additional configuration files only during test execution. This is useful for testing rules that depend on shared presets without affecting production configuration:

```yaml title="runok.yml"
tests:
  extends:
    - ./test-fixtures/readonly-unix.yml
  cases:
    - allow: 'cat /etc/hosts'
    - deny: 'rm -rf /'
```

## Test environment

`runok test` runs in an isolated environment:

- **Global configuration is excluded.** The global `~/.config/runok/runok.yml` is not loaded. Only the target configuration file and its `extends` are used.
- **Remote preset inline tests are excluded.** Inline tests from remote presets (e.g., `github:org/repo`) are stripped on load and not evaluated. Remote preset tests are meant to be validated by the preset itself.
- **All test cases run.** The runner does not stop on the first failure — it executes every test case and reports all results.

## Output

Each test case produces a `PASS` or `FAIL` line:

```
PASS: git status => allow
PASS: git push --force origin main => deny
FAIL: git push origin main => expected allow, got ask
```

After all tests, a summary is printed:

```
2 passed, 1 failed, 3 total
```

## Exit codes

| Code | Meaning                                                                  |
| ---- | ------------------------------------------------------------------------ |
| `0`  | All tests passed.                                                        |
| `1`  | One or more tests failed.                                                |
| `2`  | An error occurred before tests could run (config error, no tests, etc.). |

## Examples

Run tests in the current directory:

```sh
runok test
```

Run tests for a specific config file:

```sh
runok test -c ./presets/my-preset.yml
```
