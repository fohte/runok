# Gemini Code Assist Style Guide

## DO NOT suggest

- Changing versions or editions specified in config files

Assume version choices are intentional. Your training data may be outdated.

## Code comment rules

Comments must explain non-obvious WHY, not WHAT. Well-named identifiers already describe what the code does.

### Write only stock information

A comment must carry information that stays true for the lifetime of the code: a non-obvious WHY, an invariant, an external constraint (spec, protocol, hardware quirk), or a workaround tied to a specific upstream bug. If a future reader could delete the comment without losing context, it should not exist.

### Do not write flow information in code comments

Flow information — change history, alternatives that were considered and rejected, review feedback, "previously we did X / now we do Y", or links kept purely as a record of past decisions — belongs in commit messages and PR descriptions, not in source files. Code comments are read out of chronological context and rot as the code evolves.

A link to a PR or issue is fine when it documents an _active_ external constraint the reader needs right now: an upstream bug being worked around, a tracking issue for a TODO, an RFC the code conforms to. The test is whether the link still helps explain the current code; if it only records "this is how we got here", it is flow information and belongs in the commit log.

```bash
# bad: history and rationale that belongs in the PR / commit log
# Background:
#   When we put the terraform plugin cache on actions/cache, old providers
#   accumulate every time the lock file is updated. GitHub's 7-day LRU is
#   per primary key so daily touches keep stale entries alive forever.
#   We considered relying on Terraform's built-in cleanup but it does not
#   exist, so we delete unpinned providers ourselves before save.
prune_unpinned_providers

# good: only the non-obvious WHY that the reader needs at this line
# Terraform has no built-in cache cleanup, so prune providers absent from
# the current lock files before actions/cache save to bound cache size.
prune_unpinned_providers
```

### Do not copy task / issue / PR background into code comments

Do not paste the "background" or "context" section of a task instruction, GitHub issue, or PR description into a source file as a header comment. That text exists in the PR description and commit message already; duplicating it in code creates two copies that drift and forces future readers to re-read context that is not needed to understand the code itself. A `Usage:` block or a one-line WHY at the relevant call site is enough.

## Test code review rules

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
