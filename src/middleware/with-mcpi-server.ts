/**
 * McpServer Adapter for MCP-I
 *
 * Adds MCP-I identity, session management, and proof generation to a
 * standard McpServer instance with a single function call.
 *
 * Usage:
 *   import { withMCPI } from '@mcp-i/core/middleware';
 *   const mcpi = await withMCPI(server, { crypto: new NodeCryptoProvider() });
 *   // All tools registered on `server` now get proofs automatically.
 *   await server.connect(transport); // transport is transparently wrapped
 */

import type { CryptoProvider } from "../providers/base.js";
import { generateDidKeyFromBase64 } from "../utils/did-helpers.js";
import {
  createMCPIMiddleware,
  type MCPIIdentityConfig,
  type MCPIDelegationConfig,
  type MCPIMiddleware,
} from "./with-mcpi.js";
import { createMCPITransport, type Transport } from "./mcpi-transport.js";
import { z } from "zod";

export interface WithMCPIOptions {
  /** Platform-specific crypto implementation (required) */
  crypto: CryptoProvider;
  /** Identity config — auto-generated if omitted */
  identity?: MCPIIdentityConfig;
  /** Session configuration */
  session?: { sessionTtlMinutes?: number };
  /** Auto-create sessions for non-MCP-I clients (default: true) */
  autoSession?: boolean;
  /** Attach proofs to all tool responses (default: true) */
  proofAllTools?: boolean;
  /** Tools to skip proof generation for */
  excludeTools?: string[];
  /** Delegation verification config */
  delegation?: MCPIDelegationConfig;
}

/**
 * Generate a fresh Ed25519 identity for MCP-I.
 *
 * @param crypto - Platform-specific crypto provider
 * @returns Identity config with DID, kid, and key material
 */
export async function generateIdentity(
  crypto: CryptoProvider,
): Promise<MCPIIdentityConfig> {
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  return {
    did,
    kid: `${did}#keys-1`,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

/**
 * McpServer type — minimal interface to avoid hard dependency on the SDK.
 * Matches the public API of @modelcontextprotocol/sdk McpServer.
 */
interface McpServerLike {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  connect(transport: Transport): Promise<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  registerTool(...args: any[]): void;
}

/**
 * Add MCP-I to a McpServer instance.
 *
 * 1. Auto-generates Ed25519 identity (or uses provided one)
 * 2. Registers `_mcpi_handshake` tool
 * 3. Patches `server.connect()` to transparently wrap the transport with
 *    MCPITransport, which injects detached proofs into all `tools/call`
 *    responses using only the public Transport interface.
 *
 * The user-facing API is unchanged — register tools before or after this
 * call, then connect as normal:
 *
 * ```ts
 * const mcpi = await withMCPI(server, { crypto: new NodeCryptoProvider() });
 * await server.connect(transport); // MCPITransport wraps silently
 * ```
 *
 * @param server  - McpServer instance
 * @param options - Configuration
 * @returns The MCPIMiddleware instance for advanced usage (wrapWithDelegation, etc.)
 */
export async function withMCPI(
  server: McpServerLike,
  options: WithMCPIOptions,
): Promise<MCPIMiddleware> {
  const identity =
    options.identity ?? (await generateIdentity(options.crypto));

  const mcpi = createMCPIMiddleware(
    {
      identity,
      session: options.session,
      delegation: options.delegation,
      autoSession: options.autoSession ?? true,
    },
    options.crypto,
  );

  // Register _mcpi_handshake tool
  server.registerTool(
    "_mcpi_handshake",
    {
      description:
        "MCP-I identity handshake — establishes a cryptographic session",
      inputSchema: {
        nonce: z.string().describe("Client-generated unique nonce"),
        audience: z
          .string()
          .describe("Intended audience (server DID or URL)"),
        timestamp: z.number().describe("Unix epoch seconds"),
      },
    },
    async (args: unknown) => {
      const result = await mcpi.handleHandshake(
        args as Record<string, unknown>,
      );
      return {
        ...result,
        content: result.content.map((c) => ({ ...c, type: "text" as const })),
      };
    },
  );

  // Auto-proof interception via transport wrapper (public API only).
  //
  // We patch server.connect() so that whatever transport the caller passes
  // is silently wrapped with MCPITransport before McpServer sees it.
  // Tool registration order does not matter — proofs are injected at the
  // transport boundary, after McpServer has already dispatched the call.
  if (options.proofAllTools !== false) {
    const exclude = ["_mcpi_handshake", ...(options.excludeTools ?? [])];
    const originalConnect = server.connect.bind(server);

    server.connect = (transport: Transport) =>
      originalConnect(createMCPITransport(transport, mcpi, exclude));
  }

  return mcpi;
}
