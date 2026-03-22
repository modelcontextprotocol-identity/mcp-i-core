/**
 * MCP-I Client Helper
 *
 * Wraps an MCP Client with MCP-I identity capabilities:
 * - Automatic handshake with _mcpi tool on connection
 * - Proof verification on tool responses
 * - Session management (sessionId tracking)
 *
 * Usage:
 *   import { MCPIClientHelper } from '@mcp-i/core';
 *   import { Client } from '@modelcontextprotocol/sdk/client/index.js';
 *
 *   const client = new Client({ name: 'my-agent', version: '1.0' });
 *   const mcpi = new MCPIClientHelper(client, {
 *     crypto: new NodeCryptoProvider(),
 *     agentDid: 'did:key:z6Mk...',     // optional: client's DID
 *     verifyProofs: true,                // default: true
 *   });
 *
 *   await client.connect(transport);
 *   await mcpi.handshake();              // call _mcpi tool
 *
 *   // All subsequent callTool responses will have proofs verified
 *   const result = await mcpi.callTool('resolve-library-id', { libraryName: 'react' });
 *   // result.proof is the verified proof, result.content is the original response
 */

import type { CryptoProvider, FetchProvider as FetchProviderType } from '../providers/base.js';
import { ProofVerifier, type ProofVerifierConfig, type ProofVerificationResult } from '../proof/verifier.js';
import { MemoryNonceCacheProvider } from '../providers/memory.js';
import { logger } from '../logging/index.js';
import type { DIDDocument } from '../delegation/vc-verifier.js';
import type { StatusList2021Credential, DelegationRecord } from '../types/protocol.js';

/**
 * Minimal clock provider for client-side proof verification.
 * Implements only what ProofVerifier actually calls.
 */
const clientClock = {
  now: () => Math.floor(Date.now() / 1000),
  isWithinSkew: (timestamp: number, skewSeconds: number) =>
    Math.abs(Math.floor(Date.now() / 1000) - timestamp) <= skewSeconds,
  hasExpired: (expiresAt: number) => Math.floor(Date.now() / 1000) > expiresAt,
  calculateExpiry: (ttlSeconds: number) => Math.floor(Date.now() / 1000) + ttlSeconds,
  format: (timestamp: number) => new Date(timestamp * 1000).toISOString(),
};

/**
 * Create a minimal fetch provider for client-side DID resolution.
 * Supports did:key (inline) and did:web (fetch).
 */
function createClientFetchProvider(): FetchProviderType {
  return {
    async resolveDID(did: string): Promise<DIDDocument | null> {
      if (did.startsWith('did:key:')) {
        try {
          const { createDidKeyResolver } = await import('../delegation/did-key-resolver.js');
          const resolver = createDidKeyResolver();
          return resolver.resolve(did);
        } catch {
          return null;
        }
      }
      if (did.startsWith('did:web:')) {
        try {
          const { createDidWebResolver } = await import('../delegation/did-web-resolver.js');
          // Pass `this` as the fetch provider for did:web resolution
          const resolver = createDidWebResolver(this as any);
          return resolver.resolve(did);
        } catch {
          return null;
        }
      }
      return null;
    },
    async fetchStatusList(_url: string): Promise<StatusList2021Credential | null> {
      return null; // Client doesn't need status list checking
    },
    async fetchDelegationChain(_id: string): Promise<DelegationRecord[]> {
      return []; // Client doesn't need delegation chain resolution
    },
    async fetch(url: string, options?: unknown): Promise<Response> {
      return globalThis.fetch(url, options as RequestInit);
    },
  } as FetchProviderType;
}

/**
 * Minimal MCP Client interface — we only need callTool.
 * This avoids a hard dependency on @modelcontextprotocol/sdk.
 */
export interface MCPClientLike {
  callTool(params: {
    name: string;
    arguments?: Record<string, unknown>;
  }): Promise<{
    content: Array<{ type: string; text?: string; [key: string]: unknown }>;
    isError?: boolean;
    _meta?: Record<string, unknown>;
  }>;
}

export interface MCPIClientConfig {
  /** Crypto provider for verification */
  crypto: CryptoProvider;
  /** Optional fetch provider for DID resolution (defaults to node fetch) */
  fetch?: FetchProviderType;
  /** Client's DID (sent during handshake) */
  agentDid?: string;
  /** Client info for handshake */
  clientInfo?: {
    name?: string;
    version?: string;
    operator?: string;
  };
  /** Whether to verify proofs on responses (default: true) */
  verifyProofs?: boolean;
  /** Timestamp skew tolerance in seconds (default: 300) */
  timestampSkewSeconds?: number;
  /** Server DID — if known, validates proof.meta.did matches */
  expectedServerDid?: string;
}

export interface MCPIHandshakeResult {
  success: boolean;
  sessionId?: string;
  serverDid?: string;
  serverName?: string;
  error?: string;
}

export interface MCPIToolResult {
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  isError?: boolean;
  /** The verified proof if present and valid */
  proof?: {
    valid: boolean;
    meta?: Record<string, unknown>;
    verification?: ProofVerificationResult;
  };
}

export class MCPIClientHelper {
  private client: MCPClientLike;
  private config: MCPIClientConfig;
  private verifier: ProofVerifier;
  private sessionId?: string;
  private serverDid?: string;

  constructor(client: MCPClientLike, config: MCPIClientConfig) {
    this.client = client;
    this.config = config;

    // Set up proof verifier with lightweight client-side providers
    const verifierConfig: ProofVerifierConfig = {
      cryptoProvider: config.crypto,
      clockProvider: clientClock as any,
      nonceCacheProvider: new MemoryNonceCacheProvider(),
      fetchProvider: (config.fetch ?? createClientFetchProvider()) as any,
      timestampSkewSeconds: config.timestampSkewSeconds ?? 300,
    };
    this.verifier = new ProofVerifier(verifierConfig);
  }

  /**
   * Perform MCP-I handshake with the server.
   * Calls the _mcpi tool with action: 'handshake'.
   */
  async handshake(): Promise<MCPIHandshakeResult> {
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);

    try {
      const result = await this.client.callTool({
        name: '_mcpi',
        arguments: {
          action: 'handshake',
          nonce,
          timestamp,
          audience: this.config.expectedServerDid ?? '*',
          ...(this.config.agentDid && { agentDid: this.config.agentDid }),
          ...(this.config.clientInfo && { clientInfo: this.config.clientInfo }),
        },
      });

      // Parse handshake response
      const textContent = result.content.find((c) => c.type === 'text');
      if (!textContent?.text) {
        return { success: false, error: 'No text content in handshake response' };
      }

      const response = JSON.parse(textContent.text);

      if (response.sessionId) {
        this.sessionId = response.sessionId;
        this.serverDid = response.serverDid;
        logger.info(`[MCPIClient] Handshake complete. Session: ${this.sessionId}, Server: ${this.serverDid}`);
        return {
          success: true,
          sessionId: response.sessionId,
          serverDid: response.serverDid,
          serverName: response.serverName,
        };
      }

      return {
        success: false,
        error: response.error?.message ?? 'Handshake failed',
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`[MCPIClient] Handshake error: ${msg}`);
      return { success: false, error: msg };
    }
  }

  /**
   * Call a tool and optionally verify the proof on the response.
   */
  async callTool(
    name: string,
    args?: Record<string, unknown>
  ): Promise<MCPIToolResult> {
    const result = await this.client.callTool({ name, arguments: args });

    const mcpiResult: MCPIToolResult = {
      content: result.content,
      isError: result.isError,
    };

    // Extract and verify proof from _meta if present
    if (this.config.verifyProofs !== false && result._meta?.proof) {
      const proof = result._meta.proof as Record<string, unknown>;
      try {
        const verification = await this.verifyResponseProof(proof);
        mcpiResult.proof = {
          valid: verification.valid,
          meta: proof.meta as Record<string, unknown>,
          verification,
        };

        if (!verification.valid) {
          logger.warn(`[MCPIClient] Proof verification failed for tool ${name}: ${verification.reason}`);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error(`[MCPIClient] Proof verification error for tool ${name}: ${msg}`);
        mcpiResult.proof = { valid: false, verification: { valid: false, reason: msg } };
      }
    }

    return mcpiResult;
  }

  /**
   * Verify a proof from a tool response.
   */
  private async verifyResponseProof(
    proof: Record<string, unknown>
  ): Promise<ProofVerificationResult> {
    const meta = proof.meta as Record<string, unknown> | undefined;
    if (!meta?.did) {
      return { valid: false, reason: 'Proof missing meta.did' };
    }

    const did = meta.did as string;

    // Validate server DID if we know it
    if (this.serverDid && did !== this.serverDid) {
      return {
        valid: false,
        reason: `Proof DID mismatch: expected ${this.serverDid}, got ${did}`,
      };
    }

    // Fetch public key from DID
    const publicKey = await this.verifier.fetchPublicKeyFromDID(did);
    if (!publicKey) {
      return { valid: false, reason: `Could not resolve public key for DID: ${did}` };
    }

    // Verify the proof signature
    return this.verifier.verifyProof(proof as any, publicKey);
  }

  /** Get the current session ID */
  getSessionId(): string | undefined {
    return this.sessionId;
  }

  /** Get the server's DID (known after handshake) */
  getServerDid(): string | undefined {
    return this.serverDid;
  }

  /** Check if handshake has been completed */
  isConnected(): boolean {
    return !!this.sessionId;
  }

  /**
   * Query server identity via _mcpi tool.
   */
  async getServerIdentity(): Promise<Record<string, unknown> | null> {
    try {
      const result = await this.client.callTool({
        name: '_mcpi',
        arguments: { action: 'identity' },
      });
      const textContent = result.content.find((c) => c.type === 'text');
      if (!textContent?.text) return null;
      return JSON.parse(textContent.text);
    } catch {
      return null;
    }
  }
}

/** Generate a cryptographically random nonce */
function generateNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
