---
title: Troubleshooting
description: Common issues and debugging tips for runok.
---

This page covers common issues you may encounter when using runok, along with solutions and debugging techniques.

## Debugging tools

runok provides two flags to help diagnose issues: `--verbose` and `--dry-run`.

### `--verbose`: inspect rule matching

The `--verbose` flag prints detailed rule matching information to stderr, prefixed with `[verbose]`.

```bash
runok exec --verbose -- git status
```

Example output:

```
[verbose] Evaluating command: "git status"
[verbose] Rule matched: allow 'git *' (matched tokens: ["status"])
[verbose] Evaluation result: Allow
```

When no rule matches:

```
[verbose] Evaluating command: "rm -rf /"
[verbose] No rules matched
[verbose] No matching rule, using default behavior
```

For compound commands (commands joined with `&&`, `||`, `;`, or `|`), verbose output shows each sub-command individually:

```
[verbose] Compound command detected (2 sub-commands)
[verbose]   sub-command 1: "git add ."
[verbose]   sub-command 2: "git commit -m 'fix'"
[verbose] Compound evaluation result: Allow
```

### `--dry-run`: check without executing

The `--dry-run` flag evaluates rules and reports what action would be taken, without actually executing the command.

```bash
runok exec --dry-run -- curl -X POST https://example.com
```

Example output:

```
runok: dry-run: command would be allowed
```

Possible dry-run messages:

| Message                                         | Meaning                            |
| ----------------------------------------------- | ---------------------------------- |
| `command would be allowed`                      | A rule matched with `allow` action |
| `command would be denied: <reason>`             | A rule matched with `deny` action  |
| `command would require confirmation: <message>` | A rule matched with `ask` action   |
| `no matching rule (default behavior)`           | No rule matched the command        |

Dry-run always exits with code 0, regardless of the action result.

Combine both flags for maximum insight:

```bash
runok exec --verbose --dry-run -- git push --force
```

## Common issues

### Rules not matching

**Symptom:** A command is not matched by any rule, even though you expect it to be.

**Diagnosis:** Run with `--verbose` to see exactly how runok evaluates the command:

```bash
runok exec --verbose --dry-run -- <your-command>
```

Look for the `[verbose] No rules matched` message to confirm, then check the following causes.

**Common causes:**

1. **Combined short flags are not split.** runok treats combined flags like `-am` as a single token. A rule matching `-m` will not match `-am`.

   ```yaml
   # This rule will NOT match `git commit -am "msg"`
   rules:
     - allow: "git commit -m *"

   # Use a separate pattern for the combined flag
   rules:
     - allow: "git commit -am *"
   ```

2. **Redirects are stripped before matching.** runok uses tree-sitter to parse commands and removes redirects before rule evaluation. A rule that includes redirects will never match.

   ```yaml
   # This rule will NOT match, because the redirect is stripped
   rules:
     - allow: "echo hello > file.txt"

   # Match the command without the redirect
   rules:
     - allow: "echo hello"
   ```

3. **Pattern syntax errors.** If a pattern has unmatched brackets or invalid syntax, it may silently fail to match. Check for these errors:
   - Unclosed `{` in alternation patterns (e.g., `{a,b` without closing `}`)
   - Unclosed `[` in character class patterns
   - Empty alternation branches (e.g., `{a,,b}`)

4. **Wrapper commands not configured.** Commands like `sudo <cmd>` or `env VAR=val <cmd>` need corresponding wrapper definitions. Without them, runok matches the entire command (including the wrapper) against rules.

   ```yaml
   definitions:
     wrappers:
       - 'sudo <cmd>'
       - 'env * <cmd>'
   ```

### Stale preset cache

**Symptom:** Configuration changes from a remote preset are not reflected after updating the preset repository.

**Background:** runok caches remote preset repositories locally for performance. The default cache TTL is 24 hours. The cache is stored at `$XDG_CACHE_HOME/runok/presets` (or `$HOME/.cache/runok/presets`).

**Solutions:**

1. **Wait for the cache to expire.** The cache refreshes automatically after 24 hours.

2. **Set a shorter TTL.** Use the `RUNOK_CACHE_TTL` environment variable (in seconds):

   ```bash
   # Set to 1 hour
   export RUNOK_CACHE_TTL=3600
   ```

3. **Clear the cache manually:**

   ```bash
   rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/runok/presets"
   ```

4. **Pin to a commit SHA.** Commit SHA references are treated as immutable and never expire. This also improves reproducibility:

   ```yaml
   extends:
     - 'github:org/repo@abc1234'
   ```

**Note:** If a cache refresh fails (e.g., due to network issues), runok falls back to the stale cached version and prints a warning:

```
warning: Failed to update preset 'github:org/repo', using cached version
```

### Mutable preset reference warnings

**Symptom:** Warning message about mutable preset references appears on every run.

```
warning: Mutable preset reference 'github:org/repo@main'
  Consider pinning to a commit SHA for reproducibility
```

**Cause:** The `extends` field uses a branch name, tag, or version without pinning to a specific commit. This is risky because the upstream content can change unexpectedly.

**Solution:** Pin to a commit SHA:

```yaml
# Before
extends:
  - "github:org/repo@main"

# After
extends:
  - "github:org/repo@a1b2c3d4e5f6"
```

### Sandbox errors

**Symptom:** Commands fail with sandbox-related error messages.

#### Sandbox not supported on this platform

```
sandbox not supported on this platform
```

runok uses platform-specific sandboxing: `sandbox-exec` on macOS. If the sandbox mechanism is not available, this error occurs.

**Solution:** Remove or disable the sandbox preset for the affected rule, or run on a supported platform.

#### Sandbox setup failed: cannot canonicalize path

```
sandbox setup failed: cannot canonicalize path '/some/path': No such file or directory
```

A `writable_roots` path in the sandbox definition does not exist on disk.

**Solution:** Create the missing directory, or fix the path in the sandbox definition:

```yaml
definitions:
  sandbox:
    my-preset:
      writable_roots:
        - '/path/that/exists'
```

#### Conflicting sandbox policies

```
conflicting sandbox policies: no common writable roots
```

This occurs with compound commands where sub-commands have different sandbox presets, and the intersection of their `writable_roots` is empty.

**Solution:** Either use the same sandbox preset for both commands, or expand the writable roots to include a common directory:

```yaml
definitions:
  sandbox:
    shared-preset:
      writable_roots:
        - '/common/path'
```

For compound commands with irreconcilable sandbox policies, runok escalates the action to `ask` with the message:

```
sandbox policy conflict: writable roots are contradictory
```

#### Sandbox preset not defined

```
sandbox preset 'my-preset' is not defined in definitions.sandbox
```

A rule references a sandbox preset name that does not exist in the `definitions.sandbox` section.

**Solution:** Add the missing preset definition or correct the preset name:

```yaml
definitions:
  sandbox:
    my-preset:
      writable_roots:
        - '.'
```

### Preset loading errors

#### Circular reference detected

Remote presets that `extends` each other in a cycle cause an error. Check the `extends` chain across all referenced presets.

#### Maximum extends depth exceeded

Preset chains deeper than the maximum allowed depth cause an error. Flatten the chain or reduce the nesting level.

#### Git clone failed

```
git clone failed for 'github:org/repo': <message>
```

This occurs on the first fetch of a remote preset when there is no cached version available. Common causes:

- Network connectivity issues
- Invalid repository URL
- Repository is private and no authentication is configured

**Solution:** Verify the repository URL, check network connectivity, and ensure `git` has access to the repository.
