---
title: runok update-presets
description: Update all remote presets referenced via extends.
sidebar:
  order: 5
---

`runok update-presets` updates all remote presets referenced in your configuration's `extends` field. For branch references, it forces a re-fetch bypassing the TTL cache. For version-tagged references, it finds the latest compatible version and updates your config file.

## Usage

```sh
runok update-presets
```

## Behavior

1. **Collect references** -- Scans all configuration layers (global, global local override, project, project local override) for remote `extends` references (GitHub shorthand and git URLs). Local file references are ignored.
2. **Skip immutable references** -- Presets pinned to a commit SHA (40-character hex) are permanently cached and skipped.
3. **Version tag upgrade** -- For references with a version tag, queries the remote repository for all available tags and finds the latest compatible version. The upgrade scope depends on the tag precision (see [Version upgrade rules](#version-upgrade-rules) below). If a newer compatible version exists, fetches it and updates the `extends` entry in your config file.
4. **Branch/Latest re-fetch** -- For non-version references (e.g., `@main`, no version), forces a re-fetch regardless of cache TTL.
5. **Show diff** -- Displays a colored unified diff for any preset whose content changed.
6. **Summary** -- Prints a summary of how many presets were updated, upgraded, already up to date, skipped, or errored.

## Examples

Update all remote presets:

```sh
runok update-presets
```

Example output when a semver tag is upgraded:

```
Upgraded: github:org/shared-rules@v1.0.0 → github:org/shared-rules@v1.2.0
--- a/github:org/shared-rules@v1.0.0
+++ b/github:org/shared-rules@v1.2.0
@@ -1,3 +1,4 @@
 rules:
   - allow: 'git status'
+  - allow: 'git log'
   - deny: 'rm -rf /'

  Updated runok.yml: github:org/shared-rules@v1.0.0 → github:org/shared-rules@v1.2.0

Summary: 0 updated, 1 upgraded, 0 already up to date, 0 skipped, 0 errors
```

Example output when a branch reference has new content:

```
Updated: github:org/shared-rules@main
--- a/github:org/shared-rules@main
+++ b/github:org/shared-rules@main
@@ -1,3 +1,4 @@
 rules:
   - allow: 'git status'
+  - allow: 'git push'
   - deny: 'rm -rf /'

Summary: 1 updated, 0 upgraded, 0 already up to date, 0 skipped, 0 errors
```

## Version upgrade rules

- **Major-only tags** (`v1`, `2`): Upgraded to the latest major version (e.g., `@v1` → `@v2`). Crosses major version boundaries.
- **Major.minor tags** (`v1.0`, `1.2`): Upgraded to the latest minor version within the same major (e.g., `@v1.0` → `@v1.3`). Does not cross major version boundaries.
- **Full semver tags** (`v1.0.0`, `1.2.3`): Upgraded to the latest stable version within the same major version (e.g., `@v1.0.0` → `@v1.2.0`). Does not cross major version boundaries.
- **Non-version tags** (`main`, `stable`): Treated as branch references and force-re-fetched.
- **Commit SHA** (40-character hex): Skipped entirely (immutable).
- **Pre-release exclusion**: Pre-release versions (e.g., `v2.0.0-beta.1`) are never selected as upgrade candidates.
- **v-prefix matching**: If your current tag uses a `v` prefix (e.g., `v1`), only tags with a `v` prefix are considered as upgrade candidates, and vice versa.

## Exit codes

| Code | Meaning                                                             |
| ---- | ------------------------------------------------------------------- |
| 0    | All presets updated successfully (or already up to date / skipped). |
| 1    | One or more presets failed to update.                               |

## Related

- [Extending configuration](/configuration/schema/#extends) -- How to use `extends` to share presets.
- [CLI Overview](/cli/overview/) -- All available commands.
