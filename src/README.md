# @mcp-i/core — Module Reference

This document covers the internal modules of `@mcp-i/core`. Each module is available as a subpath export:

```typescript
import { withMCPI } from "@mcp-i/core";                    // top-level
import { verifyProof } from "@mcp-i/core/proof";            // subpath
import { issueDelegation } from "@mcp-i/core/delegation";   // subpath
```

---

## middleware

**One-call integration for MCP servers.**

| Export | Purpose |
|--------|---------|
| `withMCPI(server, opts)` | Wraps an existing `McpServer` with full MCP-I support (identity, handshake, proofs, delegation). Two-line integration. |
| `createMCPIMiddleware(config, crypto)` | Low-level middleware factory for custom setups. Returns `wrapWithProof()` and `wrapWithDelegation()` helpers. |
| `MCPITransport` | Transport wrapper that intercepts MCP messages to inject proof and delegation logic. |

```typescript
// High-level (most users)
await withMCPI(server, { crypto: new NodeCryptoProvider() });

// Low-level (custom control)
const mcpi = createMCPIMiddleware({ identity, session: { sessionTtlMinutes: 60 } }, crypto);
const handler = mcpi.wrapWithProof("search", searchHandler);
```

---

## delegation

**W3C Verifiable Credential issuance, verification, and revocation.**

| Export | Purpose |
|--------|---------|
| `issueDelegation()` | Issue a scoped, time-limited VC from a human approver to an agent |
| `verifyDelegation()` | Verify a delegation VC: signature, expiry, scope, revocation status |
| `resolveDIDKey()` | Resolve `did:key` identifiers to public keys |
| `resolveDIDWeb()` | Resolve `did:web` identifiers via HTTP |
| `DelegationGraph` | Track parent/child delegation chains for cascading revocation |
| `StatusList2021` | Bitstring-based credential revocation ([W3C StatusList2021](https://www.w3.org/TR/2023/WD-vc-status-list-20230427/)) |
| `outboundHeaders()` | Serialize delegation context into HTTP headers for downstream forwarding (§7) |

DID resolution is pluggable. Built-in resolvers cover `did:key` (self-resolving, no network) and `did:web` (HTTP-based). Custom methods implement the `DIDResolver` interface.

---

## proof

**Detached JWS proof generation and verification.**

Every tool response gets a signed proof: the canonical response (JCS + SHA-256) is signed with Ed25519, producing a detached JWS attached to `_meta.proof`.

| Export | Purpose |
|--------|---------|
| `generateProof()` | Sign a canonical response → detached JWS |
| `verifyProof()` | Verify a detached JWS against the response + signer's DID |

The proof is independently verifiable by any party with the signer's public DID — no shared secrets, no API keys.

---

## session

**Nonce-based handshake and session lifecycle.**

| Export | Purpose |
|--------|---------|
| `SessionManager` | Manages session creation, validation, and TTL expiry |
| `handshake()` | Exchange DIDs + nonces between agent and server |

Sessions prevent replay attacks. Each session has a unique nonce, a TTL, and is bound to a specific agent-server DID pair.

---

## auth

**Authorization orchestration.**

| Export | Purpose |
|--------|---------|
| `verifyOrHints()` | Check delegation → if missing, return `needs_authorization` + consent URL |
| `SensitiveScope` | Detect which tool scopes require delegation |
| `ResumeTokenStore` | Store resume tokens for interrupted authorization flows |

This module ties delegation and session together: when an agent calls a protected tool without a VC, `verifyOrHints` returns the consent URL and a resume token so the flow can continue after human approval.

---

## providers

**Abstract interfaces for crypto, storage, identity, and nonce caching.**

| Export | Purpose |
|--------|---------|
| `CryptoProvider` | Abstract: sign, verify, generate keys. Implement for KMS, HSM, or vault. |
| `StorageProvider` | Abstract: persist sessions, delegations, revocation lists |
| `NonceCacheProvider` | Abstract: track used nonces for replay prevention |
| `IdentityProvider` | Abstract: resolve and manage DID documents |
| `NodeCryptoProvider` | Built-in: uses Node.js `crypto` for Ed25519 operations |
| `MemoryStorageProvider` | Built-in: in-memory storage (development/testing) |

```typescript
// Plug in your own KMS
class KMSCryptoProvider extends CryptoProvider {
  async sign(data: Uint8Array, keyId: string) {
    return kmsClient.sign({ KeyId: keyId, Message: data });
  }
}

// Plug in Redis for nonce cache
class RedisNonceCacheProvider extends NonceCacheProvider {
  async hasNonce(nonce: string) { return redis.exists(`nonce:${nonce}`); }
  async addNonce(nonce: string, ttl: number) { redis.setex(`nonce:${nonce}`, ttl, "1"); }
}
```

---

## logging

**Structured logging for MCP-I operations.**

| Export | Purpose |
|--------|---------|
| `MCPILogger` | Configurable logger with level filtering and structured output |

---

## types

**Pure TypeScript interfaces. Zero runtime dependencies.**

All protocol types (`DelegationCredential`, `DetachedProof`, `HandshakeRequest`, `SessionRecord`, etc.) live here. Import from `@mcp-i/core/types` for type-only usage.

---

## utils

**Internal helpers.** Not part of the public API — may change between minor versions.

| Util | Purpose |
|------|---------|
| `base58` / `base64` | Encoding helpers for DID and key serialization |
| `crypto-service` | Shared crypto abstraction used by proof and delegation |
| `did-helpers` | DID parsing and formatting |
| `ed25519-constants` | Multicodec prefixes and key length constants |
