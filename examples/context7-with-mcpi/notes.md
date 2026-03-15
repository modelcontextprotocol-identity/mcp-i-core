# MCP-I Integration Audit: Context7 MCP Server

**Date:** 2026-03-14
**Subject:** `@upstash/context7-mcp` v2.1.4
**Goal:** Determine if MCP-I can be added to a real, popular MCP server by a server author — without changing mcp-i-core code.

## Verdict: Yes, it works. ~40 lines added, zero mcp-i-core changes.

---

## What Was Easy

### Handshake registration
Registering `_mcpi_handshake` as a regular tool via `McpServer.registerTool()` works exactly as expected. The zod schema maps naturally to the handshake input. ~10 lines.

### `wrapWithProof` composability
The handler signature `(args: Record<string, unknown>) => Promise<{ content: [...] }>` is compatible with what `McpServer.registerTool` callbacks return. Wrapping each tool handler is ~5 lines per tool. The proof appears in `_meta.proof` on the response, which MCP Inspector renders and LLMs ignore.

### No mcp-i-core changes required
The middleware API was flexible enough to integrate without any modifications to the core library. All integration happened in userland code.

### `autoSession` for dev ergonomics
Setting `autoSession: true` means the server works immediately with MCP Inspector and other non-MCP-I-aware clients. No manual handshake required for testing.

---

## Friction Points

### 1. API Level Mismatch (High Friction)

**Problem:** Context7 (and most real-world MCP servers) uses the **high-level `McpServer` API** with `server.registerTool()` and zod schemas. The mcp-i-core examples and documentation exclusively use the **low-level `Server` API** with `server.setRequestHandler(CallToolRequestSchema, ...)`.

**Impact:** A server author looking at the examples would not immediately know how to apply MCP-I to their `McpServer`-based server. The pattern is different — instead of a single `CallToolRequest` handler with a switch/if block, `McpServer` registers individual tool handlers.

**Workaround:** Define the proof-wrapped handler separately, then pass it through from the `registerTool` callback:
```typescript
const handler = mcpi.wrapWithProof('my-tool', async (args) => { ... });
server.registerTool('my-tool', { ... }, async (args) =>
  handler(args as Record<string, unknown>));
```

### 2. Type Casting Between Zod and Record<string, unknown> (Medium Friction)

**Problem:** `McpServer.registerTool` provides typed args from zod parsing (e.g., `{ query: string; libraryName: string }`). `wrapWithProof` expects `Record<string, unknown>`. This requires `as` casts in both directions:
- Cast zod-typed args to `Record<string, unknown>` when calling the wrapped handler
- Cast `Record<string, unknown>` back to the typed shape inside the handler

**Impact:** Slightly ugly code, loss of type safety at the boundary. Not a showstopper but makes the integration feel bolted-on rather than native.

**Ideal:** `wrapWithProof` should accept a generic type parameter or work with typed args natively.

### 3. Identity Boilerplate (~15 lines) (Low Friction)

**Problem:** Generating a DID identity requires:
```typescript
const crypto = new NodeCryptoProvider();
const keyPair = await crypto.generateKeyPair();
const did = generateDidKeyFromBase64(keyPair.publicKey);
const kid = `${did}#keys-1`;
```
Plus the middleware creation with the config object. Total ~15 lines of boilerplate.

**Impact:** Minor — this is a one-time setup. But it could be a one-liner.

### 4. Each Handler Individually Wrapped (Low Friction)

**Problem:** Each tool handler must be individually wrapped with `wrapWithProof`. For Context7 with 2 tools, this is fine. For a server with 20 tools, this is tedious and error-prone (easy to forget one).

**Impact:** Scales linearly with tool count. No automatic/bulk wrapping option.

### 5. Tool Registration Order Change (Low Friction)

**Problem:** Tool registration had to be moved from module-level into `main()` because MCP-I setup requires async key generation. The original Context7 code registers tools at module scope, before `main()` runs.

**Impact:** Minor structural change. The diff is larger than it needs to be because tool registration moves inside `main()`.

---

## Suggested Improvements

### 1. `McpServer` Adapter (High Value)

Provide a first-class adapter for the high-level `McpServer` API:
```typescript
// Dream API
const mcpi = await createMCPIForMcpServer(server, {
  autoSession: true,
  proofAllTools: true,
});
// Automatically: registers _mcpi_handshake, wraps all tool handlers
```

### 2. One-Liner Identity Setup (Medium Value)

```typescript
const mcpi = await createMCPIMiddleware.withGeneratedIdentity({
  autoSession: true,
  sessionTtlMinutes: 60,
});
```

### 3. Generic Type Support for `wrapWithProof` (Medium Value)

```typescript
const handler = mcpi.wrapWithProof<{ query: string; libraryName: string }>(
  'resolve-library-id',
  async (args) => {
    // args is typed as { query: string; libraryName: string }
  },
);
```

### 4. `McpServer` Example in Documentation (High Value)

Most real-world MCP servers use `McpServer`, not `Server`. The primary example should show the `McpServer` pattern.

### 5. Bulk Wrapping (Low Value)

```typescript
mcpi.wrapAllToolsWithProof(server);
// or
mcpi.proofAllTools: true  // in config
```

---

## Diff Summary

| Area | Lines Added | Lines Modified | Lines Removed |
|------|-------------|----------------|---------------|
| MCP-I imports | 3 | 0 | 0 |
| Identity setup | 15 | 0 | 0 |
| Handshake tool | 12 | 0 | 0 |
| resolve-library-id wrap | 5 | 0 | 0 |
| query-docs wrap | 5 | 0 | 0 |
| Structural (move into main) | 0 | ~20 | 0 |
| **Total** | **~40** | **~20** | **0** |

---

## Grade: B+

**What works well:** The integration is possible, the proof generation is solid, the handshake tool registers cleanly, and no core changes were needed.

**What holds it back from A:** The API level mismatch means most real server authors will need to figure out the `McpServer` pattern themselves. The type casting friction makes the integration feel like a workaround rather than a first-class feature.

**Path to A:** Ship a `McpServer` adapter with auto-wrapping, add an example using the high-level API, and support generic typed args.
