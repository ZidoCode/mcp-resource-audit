# mcp-resource-audit

**Offline audit of a recorded MCP session's resource, template, prompt, and
capability surface.** Zero dependencies. Deterministic. Exit codes for CI.

Half of MCP never touches `tools/call` — resources, resource templates, and
prompts — and that half fails in ways a tool-focused audit never sees:

- A URI template leaks into `resources/list`, so a client tries to read
  `user://{userId}` literally and fails forever
  ([modelcontextprotocol/java-sdk #319](https://github.com/modelcontextprotocol/java-sdk/issues/319))
- A handler logs the request and never answers — the client hangs until
  timeout
  ([openai/codex #20194](https://github.com/openai/codex/issues/20194))
- The `prompts` capability is parsed at initialize and then thrown away, so
  a prompt-gallery server shows up empty
  ([1jehuang/jcode #698](https://github.com/1jehuang/jcode/issues/698),
  [warpdotdev/warp #9456](https://github.com/warpdotdev/warp/issues/9456))
- A declared mimeType is ignored and a base64 PNG arrives labeled
  `text/plain`
  ([modelcontextprotocol/python-sdk #152](https://github.com/modelcontextprotocol/python-sdk/issues/152))
- The server advertises a capability at initialize, then answers -32601 to
  its own list call
  ([modelcontextprotocol/python-sdk #2689](https://github.com/modelcontextprotocol/python-sdk/issues/2689),
  reverse direction)

All of these are visible in a recorded transcript — if something actually
looks. This tool looks.

## Usage

```
$ python mcp_resource_audit.py session.jsonl

mcp-resource-audit — session.jsonl
critical: 2  warning: 1  info: 0
[CRITICAL] template-in-resources-list: line 4: resources/list returned
templated URI 'user://{userId}' — templates belong in
resources/templates/list; clients cannot read this
(ref: modelcontextprotocol/java-sdk #319)
...
```

Input is JSONL, one recorded JSON-RPC message per line:

```
{"direction":"request","id":1,"method":"resources/list","params":{}}
{"direction":"response","id":1,"result":{"resources":[...]}}
```

Direction defaults to `response` for lines with a result/error and no
method. Bare JSON-RPC batches and junk lines are tolerated, never fatal.

## Checks

| finding | severity | what it means |
|---|---|---|
| `template-in-resources-list` | CRITICAL | `{param}` URI returned by resources/list (java-sdk #319) |
| `request-never-answered` | CRITICAL | resources/prompts request with no response — client hang (codex #20194) |
| `method-not-found-on-advertised` | CRITICAL | -32601 on a capability the server advertised (python-sdk #2689) |
| `unadvertised-call` | CRITICAL | list call issued for a capability never advertised (python-sdk #2689) |
| `mime-mismatch` | WARNING | binary `blob` content labeled text/plain (python-sdk #152) |
| `duplicate-resource-uri` | WARNING | same URI twice in one resources/list |
| `duplicate-prompt-name` | WARNING | same prompt name twice in one prompts/list |
| `capability-lost` | WARNING | capability advertised but never queried in the session (jcode #698, warp #9456) |

Every finding carries the upstream issue it mirrors, so the report reads as
evidence, not guesswork. When no initialize response is recorded, capability
comparisons would be guesses — the tool says so (INFO) and runs pairing and
shape checks only.

## Exit codes

- `0` — clean (or INFO-only)
- `1` — warnings
- `2` — any CRITICAL finding, or the file could not be read

## Part of ZidoCode

One of the audit tools at [github.com/ZidoCode](https://github.com/ZidoCode) —
the audit layer for AI agents. Siblings: `a2a-doctor` (A2A protocol),
`mcp-session-audit`, `mcp-schema-audit`, `mcp-doctor` (MCP umbrella,
`pip install mcpmedic`).

Zero dependencies · deterministic · offline replay · exit codes for CI ·
stress-tested (50 randomized fuzz sessions, zero crashes) · fresh-clone
verified before every push.
