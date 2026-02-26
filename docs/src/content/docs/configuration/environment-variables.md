---
title: Environment Variables
description: Environment variables that affect runok behavior.
sidebar:
  order: 4
---

runok reads several environment variables to configure cache behavior and file paths.

## Reference

### `HOME`

Used to resolve the global configuration directory and the default cache directory.

**Default:** Set by the operating system.\
**Used for:**

- Global config path: `$HOME/.config/runok/runok.yml`
- Default cache path: `$HOME/.cache/runok/presets` (when `XDG_CACHE_HOME` is not set)

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
| `HOME`            | Global config and cache base   | OS-provided        |
| `XDG_CACHE_HOME`  | Cache base directory           | `$HOME/.cache`     |
| `RUNOK_CACHE_TTL` | Mutable preset cache TTL (sec) | `86400` (24 hours) |
