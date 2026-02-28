---
title: Extends (Presets)
description: Inherit and share configuration using the extends field.
sidebar:
  order: 3
---

The `extends` field lets you inherit configuration from other files or remote repositories. This enables sharing common rulesets across projects and teams.

## Reference Formats

runok supports three ways to specify an extends source:

### Local Path

Reference a configuration file on the local filesystem.

```yaml title="runok.yml"
extends:
  - ./shared/base.yml
  - ~/company/runok-base.yml
```

Path resolution rules:

- `~/...` expands to `$HOME`
- `./...` and relative paths resolve from the directory containing the current config file
- Absolute paths are used as-is
- Path traversal beyond the filesystem root is rejected

### GitHub Shorthand

Reference a configuration file in a GitHub repository using the `github:` prefix.

```yaml title="runok.yml"
extends:
  - github:example-org/example-presets@v1.0.0
  - github:example-org/security-rules@main
  - github:example-org/security-rules # uses default branch
```

Format: `github:<owner>/<repo>@<ref>`

The `@<ref>` part is optional and can be:

- A tag (e.g., `v1.0.0`)
- A branch name (e.g., `main`)
- A full commit SHA (40-character hex string)
- Omitted to use the repository's default branch

The referenced repository must contain a `runok.yml` (or `runok.yaml`) at the root.

### Git URL

Reference any Git repository by URL.

```yaml title="runok.yml"
extends:
  - https://github.com/example-org/runok-config.git
  - https://github.com/example-org/runok-config.git@v2.0.0
  - git@github.com:example-org/runok-config.git@main
```

Supports `https://`, `http://`, and `git@` URLs. An optional `@<ref>` suffix specifies the version.

## Mutable vs Immutable References

runok distinguishes between mutable and immutable references for caching:

| Reference Type      | Example                       | Caching Behavior   |
| ------------------- | ----------------------------- | ------------------ |
| Commit SHA (40 hex) | `github:org/repo@a1b2c3d4...` | Cached permanently |
| Tag or branch       | `github:org/repo@v1.0.0`      | Cached with TTL    |
| Default branch      | `github:org/repo`             | Cached with TTL    |

Mutable references (tags, branches) are cached for 24 hours by default. Immutable references (commit SHAs) are cached permanently. See [Environment Variables](/configuration/environment-variables/) for how to configure the cache TTL.

:::caution
runok warns when you use mutable references (tags, branches, or default branch) because they can change over time. For reproducible builds, prefer pinning to a specific commit SHA.
:::

## Resolution Order

When a config file specifies `extends`, runok resolves presets using depth-first traversal:

1. For each entry in `extends` (in order), recursively load and resolve its own `extends`.
2. Merge all resolved presets in order.
3. Merge the current config on top.

This means the current file always takes the highest priority, and earlier `extends` entries serve as the base.

### Diamond Inheritance

Diamond-shaped extends (where two presets share a common ancestor) are allowed. The shared ancestor is loaded once for each path, and both copies are merged.

```yaml title="a.yml"
# a.yml
extends:
  - ./b.yml
  - ./c.yml

# b.yml extends: [./shared.yml]
# c.yml extends: [./shared.yml]
# This is valid — shared.yml is merged from both paths.
```

### Circular Reference Detection

Circular references are detected and rejected. runok normalizes file paths before checking, so `./runok.yml` and `runok.yml` pointing to the same file are correctly identified as circular.

The maximum extends depth is **10** levels. Exceeding this limit produces an error.

## Caching

Remote presets are cached locally to avoid repeated network fetches.

### Cache Location

The cache directory is determined by:

1. `$XDG_CACHE_HOME/runok/presets` (if `XDG_CACHE_HOME` is set)
2. `$HOME/.cache/runok/presets` (fallback)

Each cached preset is stored in a directory named by the SHA-256 hash of the reference string.

### Cache Behavior

| Scenario          | Action                                                     |
| ----------------- | ---------------------------------------------------------- |
| Cache hit (fresh) | Use cached data directly.                                  |
| Cache stale       | Attempt to fetch updates. If fetch fails, use stale cache. |
| Cache miss        | Clone the repository. Fail if clone fails.                 |

Stale cache provides resilience against temporary network failures — if a fetch fails, the previously cached version is used with a warning.

### Cache Metadata

Each cached entry includes a `metadata.json` file tracking:

- `fetched_at` — Unix timestamp of when the preset was fetched
- `is_immutable` — Whether the reference is a commit SHA
- `reference` — The original reference string
- `resolved_sha` — The resolved commit SHA (if available)

## Related

- [File Discovery and Merging](/configuration/file-discovery/) -- How configuration files are loaded and merged.
- [Configuration Schema](/configuration/schema/) -- Full reference for `runok.yml`.
