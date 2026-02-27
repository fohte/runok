---
title: Environment Variables
description: Environment variables that affect runok behavior.
sidebar:
  order: 5
---

runok reads several environment variables to configure cache behavior and file paths.

## Reference

### `XDG_CONFIG_HOME`

Base directory for the global configuration. Follows the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/).

**Default:** `$HOME/.config`\
**Used for:** `$XDG_CONFIG_HOME/runok/runok.yml`

```bash
export XDG_CONFIG_HOME=~/.local/config
# Config location becomes: ~/.local/config/runok/runok.yml
```

### `XDG_CACHE_HOME`

Base directory for the preset cache. Follows the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/).

**Default:** `$HOME/.cache`\
**Used for:** `$XDG_CACHE_HOME/runok/presets`

```bash
export XDG_CACHE_HOME=~/.local/cache
# Cache location becomes: ~/.local/cache/runok/presets
```

### `RUNOK_CACHE_TTL`

Time-to-live (in seconds) for cached remote presets with mutable references (tags, branches). Immutable references (commit SHAs) are cached permanently regardless of this setting.

**Default:** `86400` (24 hours)\
**Type:** Integer (seconds)

```bash
# Cache for 1 hour
export RUNOK_CACHE_TTL=3600

# Cache for 7 days
export RUNOK_CACHE_TTL=604800

# Disable caching (always fetch)
export RUNOK_CACHE_TTL=0
```

## Summary

| Variable          | Purpose                        | Default            |
| ----------------- | ------------------------------ | ------------------ |
| `XDG_CONFIG_HOME` | Config base directory          | `$HOME/.config`    |
| `XDG_CACHE_HOME`  | Cache base directory           | `$HOME/.cache`     |
| `RUNOK_CACHE_TTL` | Mutable preset cache TTL (sec) | `86400` (24 hours) |
