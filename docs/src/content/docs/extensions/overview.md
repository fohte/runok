---
title: Extensions Overview
description: Extend runok with custom plugins via JSON-RPC.
sidebar:
  order: 1
---

runok's extension system lets you implement custom command validators as external processes. Extensions communicate with runok over **JSON-RPC 2.0 via stdio** (the same transport mechanism used by LSP), so you can write them in any language: Python, Ruby, Deno, Go, or anything that can read stdin and write to stdout.

## How it works

1. When runok evaluates a command, it spawns the extension process specified by the `executor` field.
2. runok sends a `validateCommand` JSON-RPC request to the process's stdin.
3. The extension reads the request, performs its validation logic, and writes a JSON-RPC response to stdout.
4. runok parses the response and maps the `status` field (`allow`, `deny`, or `ask`) to the corresponding action.

```
runok                          Extension Process
  │                                  │
  │──── spawn process ──────────────▶│
  │                                  │
  │──── JSON-RPC request (stdin) ───▶│
  │                                  │
  │◀─── JSON-RPC response (stdout) ──│
  │                                  │
  │──── process exits ───────────────│
```

## Key design principles

- **Language-agnostic**: runok does not embed any language runtime. Extensions are standalone executables.
- **Single-binary**: runok remains a single Rust binary. The extension system adds no runtime dependencies.
- **Fail-safe**: if an extension times out, crashes, or returns invalid output, runok falls back to `ask` mode so the user is always prompted for confirmation.

## Next steps

- [Protocol Reference](/extensions/protocol/) -- JSON-RPC 2.0 request/response specification
- [Tutorial](/extensions/tutorial/) -- build your first extension with error handling and timeout behavior
