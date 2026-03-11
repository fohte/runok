---
title: runok update-presets
description: Force-update all remote presets referenced via extends.
sidebar:
  order: 5
---

`runok update-presets` forces a re-fetch of all remote presets referenced in your configuration's `extends` field, bypassing the TTL-based cache. After updating, it shows a unified diff for each preset that changed.

## Usage

```sh
runok update-presets
```

## Behavior

1. **Collect references** -- Scans all configuration layers (global, global local override, project, project local override) for remote `extends` references (GitHub shorthand and git URLs). Local file references are ignored.
2. **Skip immutable references** -- Presets pinned to a commit SHA (40-character hex) are permanently cached and skipped with a message.
3. **Force re-fetch** -- For each mutable remote preset, fetches the latest version regardless of cache TTL. If no cache exists yet, performs a fresh clone.
4. **Show diff** -- Compares the previous cached content with the newly fetched content. If the preset changed, displays a colored unified diff. If unchanged, reports "already up to date".
5. **Summary** -- Prints a summary of how many presets were updated, already up to date, skipped, or errored.

## Examples

Update all remote presets:

```sh
runok update-presets
```

Example output when a preset has changed:

```
Updated: github:org/shared-rules@main
--- a/github:org/shared-rules@main
+++ b/github:org/shared-rules@main
@@ -1,3 +1,4 @@
 rules:
   - allow: 'git status'
+  - allow: 'git push'
   - deny: 'rm -rf /'

Summary: 1 updated, 0 already up to date, 0 skipped, 0 errors
```

## Exit codes

| Code | Meaning                                                             |
| ---- | ------------------------------------------------------------------- |
| 0    | All presets updated successfully (or already up to date / skipped). |
| 1    | One or more presets failed to update.                               |

## Related

- [Extending configuration](/configuration/schema/#extends) -- How to use `extends` to share presets.
- [CLI Overview](/cli/overview/) -- All available commands.
