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
 */

import type { CryptoProvider } from "../providers/base.js";
import { generateDidKeyFromBase64 } from "../utils/did-helpers.js";
import {
  createMCPIMiddleware,
  type MCPIIdentityConfig,
  type MCPIDelegationConfig,
  type MCPIMiddleware,
} from "./with-mcpi.js";
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
  server: {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [key: string]: any;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  registerTool(...args: any[]): void;
}

/**
 * Add MCP-I to a McpServer instance.
 *
 * 1. Auto-generates Ed25519 identity (or uses provided one)
 * 2. Registers `_mcpi_handshake` tool
 * 3. Intercepts the `tools/call` request handler to auto-attach proofs
 *
 * @param server - McpServer instance
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
      const result = await mcpi.handleHandshake(args as Record<string, unknown>);
      return {
        ...result,
        content: result.content.map((c) => ({ ...c, type: "text" as const })),
      };
    },
  );

  // Auto-proof interception: wrap the tools/call handler
  const proofAllTools = options.proofAllTools ?? true;

  if (proofAllTools) {
    const lowLevel = server.server;
    // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
    const handlers: Map<string, Function> = lowLevel._requestHandlers;
    const original = handlers.get("tools/call");

    if (original) {
      handlers.set(
        "tools/call",
        async (request: Record<string, unknown>, extra: unknown) => {
          const result = (await (
            original as (
              req: Record<string, unknown>,
              ext: unknown,
            ) => Promise<Record<string, unknown>>
          )(request, extra)) as {
            content?: Array<{
              type: string;
              text: string;
              [key: string]: unknown;
            }>;
            isError?: boolean;
            _meta?: Record<string, unknown>;
            [key: string]: unknown;
          };

          const params = request.params as
            | { name?: string; arguments?: Record<string, unknown> }
            | undefined;
          const toolName = params?.name;

          if (
            !toolName ||
            toolName === "_mcpi_handshake" ||
            result.isError
          ) {
            return result;
          }

          if (options.excludeTools?.includes(toolName)) {
            return result;
          }

          // Use wrapWithProof to add proof — it handles session management
          const addProof = mcpi.wrapWithProof(
            toolName,
            async () => result as {
              content: Array<{ type: string; text: string; [key: string]: unknown }>;
              isError?: boolean;
              [key: string]: unknown;
            },
          );
          return addProof(params?.arguments ?? {});
        },
      );
    }
  }

  return mcpi;
}
