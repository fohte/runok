---
title: Recipes Overview
description: Practical configuration examples for common use cases.
sidebar:
  order: 1
---

This section provides ready-to-use configuration examples for common scenarios. Each recipe includes a complete `runok.yml` snippet that you can copy and adapt to your project.

## Available Recipes

- [Git Workflow](/recipes/git-workflow/) — Control which Git operations are allowed, require confirmation for pushes, and block dangerous force-pushes.
- [AWS CLI](/recipes/aws-cli/) — Restrict destructive AWS operations, protect production environments, and enforce safe defaults.
- [Docker](/recipes/docker/) — Enforce container security policies, restrict privileged operations, and control image sources.

## User Levels Guide

Not sure where to start? The [User Levels](/recipes/user-levels/) guide walks you through runok configuration from beginner to advanced, covering:

1. **Light users** — Use shared presets with minimal setup.
2. **Heavy users** — Write custom rules with `when` conditions and sandbox policies.
3. **Extension developers** — Build plugins using the JSON over Stdio protocol.
