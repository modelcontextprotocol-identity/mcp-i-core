#!/usr/bin/env npx tsx
/**
 * MCP-I Example Server (Low-Level Server API)
 *
 * This example uses the low-level `Server` API with `createMCPIMiddleware`
 * for manual request handler patterns. For most servers, prefer the
 * simpler `withMCPI()` adapter — see examples/context7-with-mcpi/ for
 * a 2-line integration with the high-level `McpServer` API.
 *
 * Demonstrates the MCP-I protocol:
 *   1. greet           — open tool with signed proof (via _meta)
 *   2. restricted_greet — protected tool requiring a W3C Delegation Credential
 *
 * Sessions are created automatically — no manual handshake needed.
 * In production, MCP-I-aware clients handle the handshake transparently.
 *
 * Full demo flow:
 *   1. Start server:
 *        npx tsx examples/node-server/server.ts
 *   2. Issue a delegation VC:
 *        npx tsx examples/node-server/issue-delegation.ts > delegation.json
 *   3. Connect MCP Inspector to http://localhost:3001/sse
 *   4. Call `restricted_greet` with `_mcpi_delegation` = contents of delegation.json
 *   5. Watch it verify the VC and return the greeting with a signed proof
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

function createMcpServer(mcpi: ReturnType<typeof createMCPIMiddleware>) {
  const server = new Server(
    { name: 'mcpi-example', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  // ── Tool handlers ───────────────────────────────────────────────

  const greetHandler = mcpi.wrapWithProof('greet', async (args) => ({
    content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}!` }],
  }));

  // restricted_greet: verify delegation VC, then attach proof on success
  const restrictedGreetHandler = mcpi.wrapWithDelegation(
    'restricted_greet',
    {
      scopeId: 'greeting:restricted',
      consentUrl: 'https://example.com/consent?scope=greeting:restricted',
    },
    mcpi.wrapWithProof('restricted_greet', async (args) => ({
      content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}! (delegation verified)` }],
    })),
  );

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
            _mcpi_delegation: {
              type: 'object',
              description: 'W3C Delegation Credential granting scope greeting:restricted',
            },
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

    // ── Open tools ──────────────────────────────────────────────
    if (name === 'greet') {
      return greetHandler(args as Record<string, unknown>);
    }

    // ── Protected tools (delegation required) ───────────────────
    if (name === 'restricted_greet') {
      return restrictedGreetHandler(args as Record<string, unknown>);
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
  const kid = `${did}#keys-1`;

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
