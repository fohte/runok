# CLAUDE.md

## Test code rules

### Parameterize similar test cases with rstest

Do not write multiple test functions that differ only in input/expected values. Use `#[rstest]` with `#[case]`.

```rust
// bad: separate functions per case
#[test]
fn test_parse_empty() { assert_eq!(parse(""), None); }
#[test]
fn test_parse_valid() { assert_eq!(parse("hello"), Some("hello")); }

// good: parameterized
#[rstest]
#[case::empty("", None)]
#[case::valid("hello", Some("hello"))]
fn test_parse(#[case] input: &str, #[case] expected: Option<&str>) {
    assert_eq!(parse(input), expected);
}
```

### Always name `#[case]` variants

Use `#[case::descriptive_name(...)]`, not bare `#[case(...)]`. Named cases identify failures without inspecting values.

### Use `#[fixture]` for shared test setup

Do not repeat the same setup code across tests. Extract into `#[fixture]`.

```rust
// bad: duplicated setup
#[rstest]
fn test_a() { let repo = make_repo(); /* ... */ }
#[rstest]
fn test_b() { let repo = make_repo(); /* ... */ }

// good: fixture injection
#[fixture]
fn repo() -> Repo { make_repo() }
#[rstest]
fn test_a(repo: Repo) { /* ... */ }
```

### Use `indoc!` for multiline string literals in tests

Do not embed `\n` in string literals. Use `indoc!` for readability.

### Extract repeated assertions into helper functions

If the same assertion chain appears in 3+ tests, extract it into a helper.

### Do not write tests that only verify test helpers

Tests must verify production code. Tests that only assert on test helpers, fixtures, or mocks are unnecessary. Remove them.

### Integration tests for rule evaluation logic

Write integration tests in `tests/integration/`. Integration tests verify the end-to-end path: YAML config -> `parse_config` -> `evaluate_command`/`evaluate_compound`. Unit tests focus on internal algorithm correctness (pattern matching, command parsing, expression evaluation). Both may exercise the same code paths from different perspectives (ripgrep-style test separation).

## Documentation rules

### Keep docs and README up to date

When adding, changing, or removing user-facing features, CLI options, configuration fields, or behavior, update the relevant documentation:

- **README.md** -- Update if the change affects the project overview, feature list, or getting-started instructions.
- **docs/ (Starlight site)** -- Update the corresponding page(s) under `docs/src/content/docs/`. Common areas:
  - CLI changes: `cli/`
  - Configuration changes: `configuration/`
  - Pattern syntax changes: `pattern-syntax/`
  - Rule evaluation changes: `rule-evaluation/`
  - Sandbox changes: `sandbox/`

Do not create new doc pages unless the change introduces an entirely new concept. Prefer updating existing pages first.

## Code rules

### Use the `shlex` crate for shell quoting and splitting

Use `shlex::try_join`, `shlex::try_quote`, and `shlex::split` for shell quoting and command splitting. Do not implement custom shell quoting or whitespace-based command splitting.
