---
title: Extensions Overview
description: Extend runok with custom plugins via JSON-RPC.
sidebar:
  order: 1
---

runok's extension system lets you implement custom command validators as external processes. Extensions communicate with runok over **JSON-RPC 2.0 via stdio** (the same transport mechanism used by LSP), so you can write them in any language: Python, Ruby, Deno, Go, or anything that can read stdin and write to stdout.

## Why extensions?

runok's YAML rules with [pattern matching](/pattern-syntax/overview/) and [`when` expressions](/configuration/schema/#when) cover most use cases, but they work purely on string tokens. When the command arguments carry structured data that needs parsing to make a safe decision, static rules aren't enough. Extensions let you write custom validation logic that understands what the arguments actually mean:

- **GraphQL query parsing**: `gh api graphql -f query='...'` can express reads or mutations. An extension can parse the GraphQL query string, extract the operation type, and deny mutations while allowing queries -- something pattern matching on the raw string cannot reliably do.
- **URL-aware network control**: `curl -X POST https://api.example.com/v2/deploy` carries a URL whose domain and path determine the risk level. An extension can parse the URL properly and apply per-domain policies (e.g., allow internal APIs but require confirmation for external endpoints).
- **Structured argument validation**: commands like `jq`, `kubectl apply -f`, or `aws s3 cp` take arguments with their own grammar. An extension can parse these domain-specific arguments and make fine-grained decisions that flat pattern matching cannot express.

## How it works

1. **runok** spawns the extension process specified by the `executor` field.
2. **runok** sends a `validateCommand` JSON-RPC request to **the extension process**'s stdin.
3. **The extension process** reads the request, performs its validation logic, and writes a JSON-RPC response to stdout.
4. **runok** parses the response and maps the `status` field (`allow`, `deny`, or `ask`) to the corresponding action.

Each extension is spawned as a fresh process per validation. There is no persistent connection or process reuse.

## Key design principles

- **Language-agnostic**: runok does not embed any language runtime. Extensions are standalone executables.
- **Single-binary**: runok remains a single Rust binary. The extension system adds no runtime dependencies.
- **Fail-safe**: if an extension times out, crashes, or returns invalid output, runok falls back to `ask` mode so the user is always prompted for confirmation.

## Next steps

- [Protocol Reference](/extensions/protocol/) -- JSON-RPC 2.0 request/response specification
- [Tutorial](/extensions/tutorial/) -- build your first extension with error handling and timeout behavior
