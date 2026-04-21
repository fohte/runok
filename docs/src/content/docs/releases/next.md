---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## New Features

### Global `--config` / `-c` flag ([#315](https://github.com/fohte/runok/pull/315))

All subcommands now accept a `-c` / `--config` flag to load a specific config file instead of the default config discovery (global + project). The flag can appear before or after the subcommand name.

```sh
runok check -c readonly-gh.yml -- gh api graphql
runok -c custom.yml exec -- npm test
runok test -c my-rules.yml
```

This replaces the previous per-subcommand `--config` flags on `runok test` and `runok migrate`. The flag now works identically on all subcommands including `check` and `exec`.

See [Global Flags](/cli/overview/#global-flags) for details.
