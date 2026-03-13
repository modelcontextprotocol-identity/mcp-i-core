# @mcpi/core

**MCP-I protocol reference implementation** — delegation, proof, and session for the Model Context Protocol Identity (MCP-I) standard.

> This package is a [DIF TAAWG](https://identity.foundation/working-groups/agent-and-authorization.html) protocol reference implementation donated to the Decentralized Identity Foundation.

---

## What is MCP-I?

MCP-I (Model Context Protocol Identity) is a protocol extension for the Model Context Protocol (MCP) that adds cryptographic identity, delegation chains, and non-repudiation proofs to AI agent interactions. It enables MCP servers to verify *who* is calling (agent DID), *on whose behalf* (user delegation), and *what* was done (signed proof). Delegations are issued as W3C Verifiable Credentials with Ed25519 signatures, revocation is tracked via StatusList2021, and every tool call produces a detached JWS proof for audit trails.

Spec: [modelcontextprotocol-identity.io](https://modelcontextprotocol-identity.io)

---

## What this package provides

| Module | Description |
|--------|-------------|
| **delegation** | W3C VC delegation issuance (`DelegationCredentialIssuer`), verification (`DelegationCredentialVerifier`), graph management, StatusList2021 revocation, cascading revocation, outbound delegation propagation (`buildOutboundDelegationHeaders`), DID:key resolution (`createDidKeyResolver`), and DID:web resolution (`createDidWebResolver`) |
| **proof** | Platform-agnostic proof generation (`ProofGenerator`) and server-side verification (`ProofVerifier`) — JCS canonicalization, SHA-256 hashing, Ed25519 JWS signing/verification |
| **session** | Handshake validation and session management (`SessionManager`) with nonce replay prevention |
| **auth** | Authorization handshake orchestration (`verifyOrHints`) — checks delegation and returns authorization hints |
| **middleware** | MCP SDK integration (`createMCPIMiddleware`) — adds identity, sessions, and proof generation to a standard `@modelcontextprotocol/sdk` Server |
| **providers** | Abstract base classes (`CryptoProvider`, `StorageProvider`, etc.) and in-memory implementations for testing |
| **types** | Pure TypeScript interfaces for all protocol types — zero runtime dependencies |

---

## Quick Start

The fastest way to see MCP-I in action is the example server:

```bash
git clone https://github.com/modelcontextprotocol-identity/mcp-i-core.git
cd mcp-i-core
pnpm install
npx tsx examples/node-server/server.ts
```

This starts an MCP server on stdio with identity handshake and proof generation. See [`examples/node-server/README.md`](./examples/node-server/README.md) for details.

For outbound delegation propagation (forwarding delegation context to downstream services), see [`examples/outbound-delegation/README.md`](./examples/outbound-delegation/README.md).

---

## Installation

```bash
npm install @mcpi/core
```

---

## Examples

> Requires Node.js 20+. Save each block as `example.ts` and run with `npx tsx example.ts`.

---

## Example 1 — Issue a Delegation VC

```typescript
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
} from 'node:crypto';
import {
  CryptoProvider,
  MemoryIdentityProvider,
  DelegationCredentialIssuer,
  type DelegationIdentityProvider,
  type VCSigningFunction,
} from '@mcpi/core';

// Minimal Node.js CryptoProvider backed by node:crypto
class NodeCryptoProvider extends CryptoProvider {
  async generateKeyPair() {
    const { privateKey: pk, publicKey: pub } = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding: { type: 'spki', format: 'der' },
    });
    // Ed25519 PKCS8 DER: 16-byte header + 32-byte seed
    // Ed25519 SPKI DER:  12-byte header + 32-byte public key
    return {
      privateKey: (pk as Buffer).subarray(16).toString('base64'),
      publicKey: (pub as Buffer).subarray(12).toString('base64'),
    };
  }
  async hash(data: Uint8Array) {
    return 'sha256:' + createHash('sha256').update(data).digest('hex');
  }
  async randomBytes(n: number) { return new Uint8Array(randomBytes(n)); }
  async sign(data: Uint8Array, privateKeyBase64: string) {
    const seed = Buffer.from(privateKeyBase64, 'base64').subarray(0, 32);
    const hdr = Buffer.from([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
      0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    const key = createPrivateKey({ key: Buffer.concat([hdr, seed]), format: 'der', type: 'pkcs8' });
    return new Uint8Array(nodeSign(null, data, key));
  }
  async verify(): Promise<boolean> { throw new Error('unused'); }
}

const cryptoProvider = new NodeCryptoProvider();

// MemoryIdentityProvider generates a real Ed25519 DID + key pair
const identityProvider = new MemoryIdentityProvider(cryptoProvider);
const agent = await identityProvider.getIdentity();

// Adapt AgentIdentity to the DelegationIdentityProvider interface
const identity: DelegationIdentityProvider = {
  getDid: () => agent.did,
  getKeyId: () => agent.kid,
  getPrivateKey: () => agent.privateKey,
};

// Real Ed25519 signing function — delegates to NodeCryptoProvider
const signingFunction: VCSigningFunction = async (canonicalVC, issuerDid) => {
  const sig = await cryptoProvider.sign(
    new TextEncoder().encode(canonicalVC),
    agent.privateKey
  );
  return {
    type: 'Ed25519Signature2020',
    created: new Date().toISOString(),
    verificationMethod: `${issuerDid}#key-1`,
    proofPurpose: 'assertionMethod',
    proofValue: Buffer.from(sig).toString('base64url'),
  };
};

const issuer = new DelegationCredentialIssuer(identity, signingFunction);

const vc = await issuer.createAndIssueDelegation({
  id: 'delegation-001',
  issuerDid: agent.did,
  subjectDid: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8sisDArDJF74t',
  constraints: {
    scopes: ['tool:execute', 'resource:read'],
    notAfter: Math.floor(Date.now() / 1000) + 3600,
  },
});

console.log('VC type:', vc.type);
// ['VerifiableCredential', 'DelegationCredential']
console.log('Scopes:', vc.credentialSubject.delegation.constraints.scopes);
// ['tool:execute', 'resource:read']
console.log('Proof type:', vc.proof?.type);
// 'Ed25519Signature2020'
```

---

## Example 2 — Session Handshake

```typescript
import { randomBytes } from 'node:crypto';
import {
  CryptoProvider,
  SessionManager,
  MemoryNonceCacheProvider,
  createHandshakeRequest,
} from '@mcpi/core';

// SessionManager only needs randomBytes() for session ID generation
class NodeCryptoProvider extends CryptoProvider {
  async randomBytes(n: number) { return new Uint8Array(randomBytes(n)); }
  async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> { throw new Error('unused'); }
  async hash(_: Uint8Array): Promise<string> { throw new Error('unused'); }
  async sign(_: Uint8Array, __: string): Promise<Uint8Array> { throw new Error('unused'); }
  async verify(_: Uint8Array, __: Uint8Array, ___: string): Promise<boolean> { throw new Error('unused'); }
}

const cryptoProvider = new NodeCryptoProvider();
const nonceCache = new MemoryNonceCacheProvider();

const sessionManager = new SessionManager(cryptoProvider, {
  nonceCache,
  sessionTtlMinutes: 30,
  timestampSkewSeconds: 120,
  serverDid: 'did:web:my-mcp-server.example.com',
});

// Client: build handshake request (uses globalThis.crypto, built into Node 20+)
const request = createHandshakeRequest('did:web:my-mcp-server.example.com');
request.agentDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

// Server: validate it
const result = await sessionManager.validateHandshake(request);

if (result.success && result.session) {
  console.log('Session ID:', result.session.sessionId);
  // e.g. 'mcpi_4f3e2a1b-c7d2-4e5f-b6a3-...'
  console.log('Audience:', result.session.audience);
  // 'did:web:my-mcp-server.example.com'
  console.log('Agent DID:', result.session.agentDid);
  // 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
}
console.log('Stats:', sessionManager.getStats());
// { activeSessions: 1, config: { sessionTtlMinutes: 30, ... } }
```

---

## Example 3 — Generate a Tool Call Proof

```typescript
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
} from 'node:crypto';
import {
  CryptoProvider,
  MemoryIdentityProvider,
  ProofGenerator,
  SessionManager,
} from '@mcpi/core';

class NodeCryptoProvider extends CryptoProvider {
  async generateKeyPair() {
    const { privateKey: pk, publicKey: pub } = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding: { type: 'spki', format: 'der' },
    });
    return {
      privateKey: (pk as Buffer).subarray(16).toString('base64'),
      publicKey: (pub as Buffer).subarray(12).toString('base64'),
    };
  }
  async hash(data: Uint8Array) {
    return 'sha256:' + createHash('sha256').update(data).digest('hex');
  }
  async randomBytes(n: number) { return new Uint8Array(randomBytes(n)); }
  async sign(data: Uint8Array, privateKeyBase64: string) {
    const seed = Buffer.from(privateKeyBase64, 'base64').subarray(0, 32);
    const hdr = Buffer.from([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
      0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    const key = createPrivateKey({ key: Buffer.concat([hdr, seed]), format: 'der', type: 'pkcs8' });
    return new Uint8Array(nodeSign(null, data, key));
  }
  async verify(): Promise<boolean> { throw new Error('unused'); }
}

const cryptoProvider = new NodeCryptoProvider();

// MemoryIdentityProvider generates a fresh DID + Ed25519 key pair
const identityProvider = new MemoryIdentityProvider(cryptoProvider);
const agent = await identityProvider.getIdentity();

// ProofGenerator signs tool call request+response pairs with the agent's key
const generator = new ProofGenerator(agent, cryptoProvider);

const request = {
  method: 'tools/call',
  params: { name: 'read_file', arguments: { path: '/etc/hosts' } },
};
const response = { data: { content: '127.0.0.1 localhost' } };

// SessionContext — in production this comes from SessionManager.validateHandshake()
const session = {
  sessionId: 'mcpi_demo-session',
  audience: 'did:web:my-mcp-server.example.com',
  nonce: SessionManager.generateNonce(),
  timestamp: Math.floor(Date.now() / 1000),
  createdAt: Math.floor(Date.now() / 1000),
  lastActivity: Math.floor(Date.now() / 1000),
  ttlMinutes: 30,
  identityState: 'anonymous' as const,
};

const proof = await generator.generateProof(request, response, session);

console.log('JWS (first 40 chars):', proof.jws.slice(0, 40) + '...');
// 'eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk...'
console.log('Request hash:', proof.meta.requestHash);
// 'sha256:e3b0...'
console.log('Agent DID:', proof.meta.did);
// 'did:key:z...'
```

---

## Example 4 — MCP Server with Middleware

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createMCPIMiddleware, CryptoProvider } from '@mcpi/core';

// ... (NodeCryptoProvider as above)

const crypto = new NodeCryptoProvider();
const keys = await crypto.generateKeyPair();

const mcpi = createMCPIMiddleware({
  identity: { did: 'did:key:z...', kid: 'did:key:z...#key-1', ...keys },
  session: { sessionTtlMinutes: 60 },
}, crypto);

const echo = mcpi.wrapWithProof('echo', async (args) => ({
  content: [{ type: 'text', text: `Echo: ${args['message']}` }],
}));

const server = new Server({ name: 'my-server', version: '1.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [mcpi.handshakeTool, { name: 'echo', inputSchema: { type: 'object' } }],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === '_mcpi_handshake') return mcpi.handleHandshake(req.params.arguments ?? {});
  if (req.params.name === 'echo') return echo(req.params.arguments ?? {}, req.params.arguments?.['sessionId']);
  return { content: [{ type: 'text', text: 'Unknown tool' }], isError: true };
});

await server.connect(new StdioServerTransport());
```

---

## Example 5 — Verify a Proof with DID:key Resolution

```typescript
import { ProofVerifier, createDidKeyResolver, CryptoProvider } from '@mcpi/core';

// ... (NodeCryptoProvider with verify + hash)

const crypto = new NodeCryptoProvider();
const didResolver = createDidKeyResolver();

const verifier = new ProofVerifier({
  cryptoProvider: crypto,
  fetchPublicKeyFromDID: async (did) => {
    const result = didResolver(did);
    return result?.publicKeyJwk ?? null;
  },
  timestampSkewSeconds: 120,
});

const result = await verifier.verifyProofDetached(proof);
console.log('Valid:', result.valid);
```

---

## License

MIT — see [LICENSE](./LICENSE)

---

*This package is a DIF TAAWG protocol reference implementation.*
*Spec: [modelcontextprotocol-identity.io](https://modelcontextprotocol-identity.io)*
