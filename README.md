# @mcp-i/core

**Identity, delegation, and proof for the Model Context Protocol.**

MCP-I answers three questions for every AI agent tool call: *who* is calling (DID), *are they allowed* (delegation VC), and *what happened* (signed proof). It uses W3C Verifiable Credentials, Ed25519 signatures, and Decentralized Identifiers — no central authority required.

> [DIF TAAWG](https://identity.foundation/working-groups/agent-and-authorization.html) protocol reference implementation. Spec: [modelcontextprotocol-identity.io](https://modelcontextprotocol-identity.io)

---

## Try It

See the consent flow in action — an agent calls a protected tool, a human approves, and the agent retries with a signed credential:

```bash
git clone https://github.com/modelcontextprotocol-identity/mcp-i-core.git
cd mcp-i-core
pnpm install
npx tsx examples/consent-basic/src/server.ts
```

Then connect with [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npx @modelcontextprotocol/inspector
# → Connect to http://localhost:3002/sse
```

Call `checkout` — you'll get a consent link. Open it, approve, then retry the tool. [Full walkthrough →](./examples/consent-basic/README.md)

---

## Add to Your Server

One line to add identity, sessions, and proofs to any MCP server:

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { withMCPI, NodeCryptoProvider } from '@mcp-i/core';

const server = new McpServer({ name: 'my-server', version: '1.0.0' });
await withMCPI(server, { crypto: new NodeCryptoProvider() });

// Register tools normally — proofs are attached automatically
```

Default behavior is compatibility-first:
- `withMCPI` auto-registers `_mcpi`, so it appears in MCP Inspector and tool lists.
- Handshake is not tied to MCP `initialize`; a client/runtime must call it (or use `autoSession`).

If your runtime has a native connection/auth handshake hook, disable tool exposure and call middleware directly:

```typescript
const mcpi = await withMCPI(server, {
  crypto: new NodeCryptoProvider(),
  handshakeExposure: 'none',
  autoSession: false,
});

// In your runtime's connection handshake hook:
await mcpi.handleMCPI({
  action: 'handshake',
  nonce: 'client-generated-nonce',
  audience: mcpi.identity.did,
  timestamp: Math.floor(Date.now() / 1000),
  agentDid: 'did:key:...optional...',
});
```

Every tool response now includes a cryptographic proof. For protected tools that require human consent, add `wrapWithDelegation`:

```typescript
import { createMCPIMiddleware, generateIdentity, NodeCryptoProvider } from '@mcp-i/core';

const crypto = new NodeCryptoProvider();
const identity = await generateIdentity(crypto);
const mcpi = createMCPIMiddleware({ identity, session: { sessionTtlMinutes: 60 } }, crypto);

// Public tool — proof attached automatically
const search = mcpi.wrapWithProof('search', async (args) => ({
  content: [{ type: 'text', text: `Results for: ${args['query']}` }],
}));

// Protected tool — requires delegation with scope 'orders:write'
const placeOrder = mcpi.wrapWithDelegation(
  'place_order',
  { scopeId: 'orders:write', consentUrl: 'https://example.com/consent' },
  mcpi.wrapWithProof('place_order', async (args) => ({
    content: [{ type: 'text', text: `Order placed: ${args['item']}` }],
  })),
);
```

---

## Install

```bash
npm install @mcp-i/core
```

Requires Node.js 20+. Peer dependency on `@modelcontextprotocol/sdk` (optional — only needed for `withMCPI`).

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Agent      │────▶│  MCP Server  │────▶│  Downstream  │
│  (did:key)   │     │  + MCP-I     │     │  Services    │
└─────────────┘     └──────────────┘     └─────────────┘
       │                    │                     │
       │ handshake          │ verify delegation   │ outbound headers
       │ (nonce+DID)        │ attach proof        │ (X-Agent-DID,
       │                    │ check scopes        │  X-Delegation-Chain)
       ▼                    ▼                     ▼
   Session established   Tool executes        Context forwarded
   with replay           with signed           to downstream
   prevention            receipt               with delegation
```

---

## Modules

| Module | What it does |
|--------|-------------|
| **middleware** | `withMCPI(server)` — one-call integration. `createMCPIMiddleware` for low-level control. |
| **delegation** | Issue and verify W3C VCs. DID:key and DID:web resolution. StatusList2021 revocation. Cascading revocation. |
| **proof** | Generate and verify detached JWS proofs with canonical hashing (JCS + SHA-256). |
| **session** | Nonce-based handshake. Replay prevention. Session TTL management. |
| **providers** | Abstract `CryptoProvider`, `IdentityProvider`, `StorageProvider`. Plug in your own KMS, HSM, or vault. |
| **types** | Pure TypeScript interfaces. Zero runtime dependencies. |

All modules available as subpath exports: `@mcp-i/core/delegation`, `@mcp-i/core/proof`, etc.

---

## Examples

| Example | What it shows |
|---------|--------------|
| [**consent-basic**](./examples/consent-basic/) | Human-in-the-loop consent flow: `needs_authorization` → consent page → delegation VC → tool execution. SSE + Streamable HTTP transports. |
| [**consent-full**](./examples/consent-full/) | Same consent flow as consent-basic, powered by [`@kya-os/consent`](https://www.npmjs.com/package/@kya-os/consent) — multi-mode auth, configurable branding, and production-grade consent UI. |
| [**node-server**](./examples/node-server/) | Low-level Server API with handshake, proof, and restricted tools. |
| [**brave-search-mcp-server**](./examples/brave-search-mcp-server/) | Real-world MCP server wrapping Brave Search with MCP-I identity and proofs. |
| [**outbound-delegation**](./examples/outbound-delegation/) | Forwarding delegation context to downstream services (§7 gateway pattern). |
| [**verify-proof**](./examples/verify-proof/) | Standalone proof verification with DID:key resolution. |
| [**context7-with-mcpi**](./examples/context7-with-mcpi/) | Adding MCP-I to an existing MCP server with `withMCPI`. |

---

## Extension Points

MCP-I is a protocol, not a platform. All cryptographic operations, storage, and identity management are abstracted behind interfaces you implement:

```typescript
// Use AWS KMS instead of local keys
class KMSCryptoProvider extends CryptoProvider {
  async sign(data: Uint8Array, keyArn: string) {
    return kmsClient.sign({ KeyId: keyArn, Message: data });
  }
}

// Use Redis instead of in-memory nonce cache
class RedisNonceCacheProvider extends NonceCacheProvider {
  async hasNonce(nonce: string) { return redis.exists(`nonce:${nonce}`); }
  async addNonce(nonce: string, ttl: number) { redis.setex(`nonce:${nonce}`, ttl, '1'); }
}
```

Supported DID methods: `did:key` (built-in, self-resolving), `did:web` (built-in, HTTP resolution), or any custom method via `DIDResolver`.

---

## Conformance

Three levels defined in [CONFORMANCE.md](./CONFORMANCE.md):

| Level | Requirements |
|-------|-------------|
| **Level 1** — Core Crypto | Ed25519 signatures, DID:key resolution, JCS canonicalization |
| **Level 2** — Full Session | Nonce-based handshake, session management, replay prevention |
| **Level 3** — Full Delegation | W3C VC issuance/verification, scope attenuation, StatusList2021, cascading revocation |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). DCO sign-off required. All PRs must pass CI (type check, lint, test across Node 20/22 on Linux/macOS/Windows).

## Governance

See [GOVERNANCE.md](./GOVERNANCE.md). Lazy consensus for non-breaking changes. Explicit vote for breaking changes.

## Security

See [SECURITY.md](./SECURITY.md). 48-hour acknowledgement. 90-day coordinated disclosure.

## License

MIT — see [LICENSE](./LICENSE)
