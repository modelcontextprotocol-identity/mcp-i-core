#!/usr/bin/env npx tsx
/**
 * MCP-I Example Server
 *
 * Demonstrates the MCP-I protocol:
 *   1. greet           — open tool with signed proof (via _meta)
 *   2. restricted_greet — protected tool requiring delegation
 *
 * Sessions are created automatically — no manual handshake needed.
 * In production, MCP-I-aware clients handle the handshake transparently.
 *
 * Start server:
 *   npx tsx examples/node-server/server.ts
 *
 * Then connect MCP Inspector (SSE) to http://localhost:3001/sse
 */

import http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createMCPIMiddleware } from '../../src/middleware/with-mcpi.js';
import { generateDidKeyFromBase64 } from '../../src/utils/did-helpers.js';
import { NodeCryptoProvider } from './node-crypto.js';

// ── Tool protection config ─────────────────────────────────────────
// In production this comes from AgentShield remote config.
// Here we hard-code it to demonstrate the architecture.
const TOOL_PROTECTION: Record<string, { scopeId: string; consentUrl: string }> = {
  restricted_greet: {
    scopeId: 'greeting:restricted',
    consentUrl: 'https://example.com/consent?scope=greeting:restricted',
  },
};

function createMcpServer(mcpi: ReturnType<typeof createMCPIMiddleware>) {
  const server = new Server(
    { name: 'mcpi-example', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  // ── Tool handlers ───────────────────────────────────────────────

  const greetHandler = mcpi.wrapWithProof('greet', async (args) => ({
    content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}!` }],
  }));

  // ── Request handlers ────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'greet',
        description: 'Returns a greeting with a signed Ed25519 proof',
        inputSchema: {
          type: 'object' as const,
          properties: {
            name: { type: 'string', description: 'Name to greet' },
          },
        },
      },
      {
        name: 'restricted_greet',
        description: 'A protected greeting that requires delegation (scope: greeting:restricted)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            name: { type: 'string', description: 'Name to greet' },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    // ── Handshake (still available for MCP-I-aware clients) ─────
    if (name === '_mcpi_handshake') {
      return mcpi.handleHandshake(args as Record<string, unknown>);
    }

    // ── Tool protection check ───────────────────────────────────
    const protection = TOOL_PROTECTION[name];
    if (protection) {
      // In production, MCP-I checks the delegation chain via the verifier.
      // Without a valid delegation credential, the server returns a consent
      // URL that the agent can present to the user for authorization.
      const consentLink = `[Authorize ${name}](${protection.consentUrl})`;
      return {
        content: [
          {
            type: 'text',
            text: `Authorization required.\n\n${consentLink}\n\nRetry after authorizing.`,
          },
        ],
      };
    }

    // ── Open tools ──────────────────────────────────────────────
    if (name === 'greet') {
      return greetHandler(args as Record<string, unknown>);
    }

    return {
      content: [{ type: 'text', text: `Unknown tool: ${name}` }],
      isError: true,
    };
  });

  return server;
}

async function main() {
  const useStdio = process.argv.includes('--stdio');

  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();

  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#key-1`;

  console.error(`[mcpi] Agent DID: ${did}`);

  const mcpi = createMCPIMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      autoSession: true,
    },
    crypto
  );

  if (useStdio) {
    const server = createMcpServer(mcpi);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('[mcpi] Server running on stdio');
  } else {
    const PORT = parseInt(process.env['PORT'] ?? '3001', 10);
    let sseTransport: SSEServerTransport | null = null;

    const httpServer = http.createServer(async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

      if (url.pathname === '/sse' && req.method === 'GET') {
        const server = createMcpServer(mcpi);
        sseTransport = new SSEServerTransport('/messages', res);
        await server.connect(sseTransport);
        console.error('[mcpi] SSE client connected');
        return;
      }

      if (url.pathname === '/messages' && req.method === 'POST') {
        if (!sseTransport) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No SSE connection. Connect to /sse first.' }));
          return;
        }
        await sseTransport.handlePostMessage(req, res);
        return;
      }

      if (url.pathname === '/' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          name: 'mcpi-example',
          did,
          transport: 'sse',
          connect: `http://localhost:${PORT}/sse`,
        }));
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    });

    httpServer.listen(PORT, () => {
      console.error(`[mcpi] SSE server: http://localhost:${PORT}`);
      console.error(`[mcpi] Connect Inspector to: http://localhost:${PORT}/sse`);
    });
  }
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
