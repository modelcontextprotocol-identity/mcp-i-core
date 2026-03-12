/**
 * MCP-I Middleware for @modelcontextprotocol/sdk Server
 *
 * Adds identity, session management, and proof generation to a standard
 * MCP SDK Server.
 *
 * Usage:
 *   const { handshakeTool, registerToolWithProof } = createMCPIMiddleware(config, crypto);
 *   server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: [handshakeTool, ...] }));
 *   registerToolWithProof(server, myToolDef, myHandler);
 */

import type { CryptoProvider } from "../providers/base.js";
import {
  SessionManager,
  type SessionConfig,
  type HandshakeResult,
} from "../session/manager.js";
import {
  ProofGenerator,
  type ProofAgentIdentity,
  type ToolRequest,
  type ToolResponse,
} from "../proof/generator.js";
import { validateHandshakeFormat } from "../session/manager.js";

export interface MCPIIdentityConfig {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

export interface MCPIConfig {
  /** Agent identity (did:key + key material) */
  identity: MCPIIdentityConfig;
  /** Session configuration overrides */
  session?: Omit<SessionConfig, "nonceCache">;
  /**
   * When true, automatically creates a session on the first tool call
   * if no session exists. Useful for demos and development where
   * MCP clients don't support the _mcpi_handshake flow.
   * In production, MCP-I-aware clients handle handshake automatically.
   */
  autoSession?: boolean;
}

export interface MCPIToolDefinition {
  name: string;
  description?: string;
  inputSchema: {
    type: "object";
    properties?: Record<string, unknown>;
    required?: string[];
    [key: string]: unknown;
  };
}

export interface MCPIToolHandler {
  (
    args: Record<string, unknown>,
    sessionId?: string,
  ): Promise<{
    content: Array<{ type: string; text: string; [key: string]: unknown }>;
    isError?: boolean;
    [key: string]: unknown;
  }>;
}

/**
 * Server interface — minimal subset of @modelcontextprotocol/sdk Server.
 * This avoids a hard dependency on the SDK at the type level.
 */
export interface MCPIServer {
  setRequestHandler(
    schema: unknown,
    handler: (...args: unknown[]) => unknown,
  ): void;
}

export interface MCPIMiddleware {
  /** The SessionManager instance for manual session operations */
  sessionManager: SessionManager;

  /** The ProofGenerator instance for manual proof operations */
  proofGenerator: ProofGenerator;

  /**
   * Tool definition for `_mcpi_handshake`.
   * Include this in your ListToolsRequest handler's tool list.
   */
  handshakeTool: MCPIToolDefinition;

  /**
   * Handle a handshake call. Use this in your CallToolRequest handler
   * when `request.params.name === '_mcpi_handshake'`.
   */
  handleHandshake(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;

  /**
   * Wrap a tool handler to automatically generate proofs.
   * Returns a new handler that appends proof metadata to the response.
   */
  wrapWithProof(toolName: string, handler: MCPIToolHandler): MCPIToolHandler;
}

/**
 * Create MCP-I middleware for a standard MCP SDK Server.
 *
 * @param config - Agent identity and session configuration
 * @param cryptoProvider - Platform-specific crypto implementation
 * @returns Middleware components for session management and proof generation
 */
export function createMCPIMiddleware(
  config: MCPIConfig,
  cryptoProvider: CryptoProvider,
): MCPIMiddleware {
  const identity: ProofAgentIdentity = {
    did: config.identity.did,
    kid: config.identity.kid,
    privateKey: config.identity.privateKey,
    publicKey: config.identity.publicKey,
  };

  const sessionManager = new SessionManager(cryptoProvider, {
    ...config.session,
    serverDid: identity.did,
  });

  const proofGenerator = new ProofGenerator(identity, cryptoProvider);

  // Session map: sessionId → last nonce (for proof generation)
  const sessionNonces = new Map<string, string>();

  // Active session tracking — set after handshake (manual or auto)
  let activeSessionId: string | undefined;

  const handshakeTool: MCPIToolDefinition = {
    name: "_mcpi_handshake",
    description:
      "MCP-I identity handshake — establishes a cryptographic session",
    inputSchema: {
      type: "object",
      properties: {
        nonce: { type: "string", description: "Client-generated unique nonce" },
        audience: {
          type: "string",
          description: "Intended audience (server DID or URL)",
        },
        timestamp: { type: "number", description: "Unix epoch seconds" },
        agentDid: {
          type: "string",
          description: "Client agent DID (optional)",
        },
      },
      required: ["nonce", "audience", "timestamp"],
    },
  };

  async function handleHandshake(args: Record<string, unknown>): Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }> {
    if (!validateHandshakeFormat(args)) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              success: false,
              error: {
                code: "MCPI_INVALID_HANDSHAKE",
                message:
                  "Invalid handshake format: requires nonce (string), audience (string), and timestamp (positive integer)",
              },
            }),
          },
        ],
        isError: true,
      };
    }

    const result: HandshakeResult =
      await sessionManager.validateHandshake(args);

    if (result.success && result.session) {
      sessionNonces.set(result.session.sessionId, result.session.nonce);
      activeSessionId = result.session.sessionId;
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.success,
            ...(result.session && {
              sessionId: result.session.sessionId,
              serverDid: identity.did,
              serverKid: identity.kid,
            }),
            ...(result.error && { error: result.error }),
          }),
        },
      ],
      ...(result.error && { isError: true }),
    };
  }

  /**
   * Auto-create a session for proof generation when no handshake has occurred.
   * In production, MCP-I-aware clients handle the handshake automatically.
   * This convenience mode allows non-MCP-I clients (like MCP Inspector) to
   * still see proofs without manual handshake.
   */
  async function ensureSession(): Promise<string | undefined> {
    if (activeSessionId) {
      const existing = await sessionManager.getSession(activeSessionId);
      if (existing) return activeSessionId;
    }

    if (!config.autoSession) return undefined;

    // Generate a server-side session with a random nonce
    const nonce = `auto-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const timestamp = Math.floor(Date.now() / 1000);

    const result = await sessionManager.validateHandshake({
      nonce,
      audience: identity.did,
      timestamp,
    });

    if (result.success && result.session) {
      activeSessionId = result.session.sessionId;
      sessionNonces.set(result.session.sessionId, result.session.nonce);
      return activeSessionId;
    }

    return undefined;
  }

  function wrapWithProof(
    toolName: string,
    handler: MCPIToolHandler,
  ): MCPIToolHandler {
    return async (args: Record<string, unknown>, sessionId?: string) => {
      const result = await handler(args, sessionId);

      if (result.isError) {
        return result;
      }

      // Resolve session: explicit param → active session → auto-create
      const resolvedSessionId = sessionId ?? await ensureSession();
      if (!resolvedSessionId) {
        return result;
      }

      const session = await sessionManager.getSession(resolvedSessionId);
      if (!session) {
        return result;
      }

      try {
        const request: ToolRequest = { method: toolName, params: args };
        const response: ToolResponse = { data: result.content };

        const proof = await proofGenerator.generateProof(
          request,
          response,
          session,
        );

        // Attach proof as _meta (rendered by MCP Inspector, invisible to LLMs)
        result._meta = { proof };
      } catch {
        // Proof generation failure is non-fatal — the tool result is still valid
      }

      return result;
    };
  }

  return {
    sessionManager,
    proofGenerator,
    handshakeTool,
    handleHandshake,
    wrapWithProof,
  };
}
