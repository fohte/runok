---
title: Next (unreleased)
sidebar:
  order: 1
---

This page tracks changes that will be included in the next release. It is updated as pull requests are merged.

## Breaking Changes

### Remove `definitions.commands` field

The `definitions.commands` configuration field has been removed. This field was parsed and merged but never referenced by the rule engine or command parser, so it had no effect at runtime. If your configuration includes `definitions.commands`, simply remove it — no other changes are needed.

## Bug fixes

### `runok test` no longer evaluates inline tests from remote presets

Inline tests defined in remote presets (e.g., `github:org/repo`) are now stripped on load. Previously, these tests were collected and evaluated against the full merged config, causing them to fail when local rules overrode the same patterns with stricter actions. Remote preset inline tests are meant to be validated by the preset itself, not by downstream consumers.
