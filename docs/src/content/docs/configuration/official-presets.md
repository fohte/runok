---
title: Official Presets (runok-presets)
description: Ready-made rule presets for common read-only commands, wrapper definitions, and more.
sidebar:
  order: 4
---

[runok-presets](https://github.com/fohte/runok-presets) is the official preset collection for runok. It provides curated allow rules for common read-only commands and wrapper definitions so you can get started quickly without writing every rule from scratch.

## Quick start

Add the `base` preset to your `runok.yml`:

```yaml title="runok.yml"
extends:
  - 'github:fohte/runok-presets/base@v1'

rules:
  # Add your project-specific rules here
  - allow: 'npm test'
```

The `base` preset bundles all individual presets and adds universal `--help` / `--version` rules. This single line gives you a solid read-only baseline.

## Available presets

| Preset          | Description                                                                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `base`          | Bundles all presets below via `extends` and adds `* --help` / `* --version` rules. Recommended starting point.                                        |
| `definitions`   | Wrapper command definitions (`bash -c`, `sudo`, `xargs`, `find -exec`, etc.) for [recursive command evaluation](/rule-evaluation/wrapper-recursion/). |
| `readonly-unix` | Allow rules for common read-only Unix commands (`cat`, `grep`, `find`, `ls`, `sed` without `-i`, etc.).                                               |
| `readonly-git`  | Allow rules for read-only Git subcommands (`status`, `diff`, `log`, `branch --list`, etc.).                                                           |
| `readonly-gh`   | Allow rules for read-only GitHub CLI subcommands (`pr list`, `issue view`, `api`, `search`, etc.).                                                    |

### What is included

The presets cover tools that virtually every developer uses regardless of stack -- common Unix utilities, popular modern alternatives (e.g. `fd`, `rg`, `bat`), Git, and GitHub CLI (`gh`).

### What is not included

Tools whose usage varies by project or team are intentionally excluded:

- Infrastructure tools (`docker`, `kubectl`)
- Cloud CLIs (`aws`, `gcloud`, `az`)
- Language runtimes (`node`, `python`)
- Package managers (`npm`, `cargo`)

Define rules for those in your own `runok.yml`. See [Real-World Examples](/getting-started/real-world-examples/) for reference configurations.

## Referencing presets

Presets are referenced using the [GitHub shorthand](/configuration/extends/#github-shorthand) syntax with a path component:

```
github:fohte/runok-presets/<preset-name>@<ref>
```

The `/<preset-name>` part specifies which preset file to load (without the `.yml` extension).

### Using the base preset

```yaml title="runok.yml"
extends:
  - 'github:fohte/runok-presets/base@v1'
```

### Picking individual presets

If you only need specific presets, reference them individually:

```yaml title="runok.yml"
extends:
  - 'github:fohte/runok-presets/definitions@v1'
  - 'github:fohte/runok-presets/readonly-unix@v1'
  - 'github:fohte/runok-presets/readonly-git@v1'
```

This is useful when you want fine-grained control -- for example, including Unix read-only rules without Git rules.

## Version pinning

Always specify a version reference with `@<ref>` to avoid unexpected changes. The recommended approach is to pin to a **major version tag**:

```yaml title="runok.yml"
extends:
  - 'github:fohte/runok-presets/base@v1'
```

The `@v1` tag tracks the latest `v1.x.x` release. It receives backward-compatible updates (new commands, bug fixes) but not breaking changes. When a new major version is released, you can upgrade at your own pace by changing `@v1` to `@v2`.

For stricter pinning, use a specific release tag:

```yaml title="runok.yml"
extends:
  - 'github:fohte/runok-presets/base@v1.0.0'
```

See [Extends (Presets)](/configuration/extends/#mutable-vs-immutable-references) for details on caching behavior for different reference types.

## Security considerations

These presets are building blocks for command permissions, not a complete security policy. While they are designed to allow only read-only operations, the level of protection depends on which presets you choose and how you combine them with your own rules.

Review the [preset source files](https://github.com/fohte/runok-presets) to confirm they match your security requirements.

## Related

- [Extends (Presets)](/configuration/extends/) -- Full reference for the `extends` field, including resolution order and caching.
- [Real-World Examples](/getting-started/real-world-examples/) -- See how runok is used in real projects.
- [Configuration Schema](/configuration/schema/) -- Complete reference for `runok.yml`.
