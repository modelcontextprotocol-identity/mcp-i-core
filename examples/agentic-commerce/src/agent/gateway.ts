#!/usr/bin/env npx tsx
/**
 * KYA-OS GATEWAY — the agent runtime Claude Desktop plugs into.
 *
 *   Claude Desktop (the brain — no keys)
 *     │  plain MCP (stdio)
 *     ▼
 *   THIS gateway (holds the agent's did:key + the delegation; signs every call)
 *     │  place_order + credential + Ed25519 holder proof   (streamable-http)
 *     ▼
 *   Merchant edge (withKyaOs verifier)
 *
 * Claude sees two tools, `browse_catalog` and `place_order`,
 * with no crypto arguments. The gateway injects the
 * credential and mints the per-request holder proof. The LLM never touches
 * key material: that is the point, and a talking point.
 *
 * Run:  npm run gateway        (stdio — see docs/claude_desktop_config.json)
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { loadAgentIdentity, merchantOrigin } from '../lib/wiring.js';
import { browseCatalog, runAgentOrder } from './agent.js';
import { responseBody } from './authorization.js';
import { isMainModule } from '../lib/main-module.js';

const MERCHANT = merchantOrigin();

export function createGatewayServer(): Server {
  const server = new Server({ name: 'kya-shopping-agent', version: '0.1.0' }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'browse_catalog',
        description: 'List the merchant\'s products (name, GS1 Digital Link URI, price). Open to any agent; no authority needed.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'place_order',
        description:
          'Place an order for a catalog product. If human consent is needed, returns a verified authorizationUrl to open and approve. After the human approves, retry with exactly the same product and quantity. The gateway attaches the new grant and holder proof. Returns an order receipt or a policy denial. This does not make a payment.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            product: { type: 'string', description: 'Catalog sku (e.g. "risotto") or a GS1 Digital Link URI' },
            quantity: { type: 'integer', minimum: 1, description: 'How many units (default 1)' },
          },
          required: ['product'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    try {
      if (name === 'browse_catalog') {
        const items = (await browseCatalog(`${MERCHANT}/mcp`)) as Array<{ sku: string; name: string; uri: string; unitPrice: string; currency: string }>;
        return { content: [{ type: 'text', text: items.map((i) => `- ${i.sku}: ${i.name} — ${i.currency} ${i.unitPrice} — ${i.uri}`).join('\n') }] };
      }
      if (name === 'place_order') {
        const product = String((args as Record<string, unknown>)['product'] ?? '');
        const quantity = Number((args as Record<string, unknown>)['quantity'] ?? 1);
        const outcome = await runAgentOrder({ product, quantity, serverUrl: `${MERCHANT}/mcp` });
        const text = outcome.result.content?.[0]?.text ?? '{}';
        const body = responseBody(outcome.result);
        if (body['error'] === 'needs_authorization') {
          // runAgentOrder has verified the merchant signature and every URL binding.
          return { content: [{ type: 'text', text: JSON.stringify(body, null, 2) }] };
        }
        if (outcome.result.isError || body['error']) {
          const code = String(body['error'] ?? 'refused');
          const reason = String(body['reason'] ?? body['message'] ?? text);
          const hint = /revoked/i.test(reason) ? 'Your authority has been revoked by your owner. Nothing was ordered; ask them for a new delegation.'
            : code === 'PRODUCT_OUT_OF_SCOPE' ? 'That product is outside the product class you were delegated. Nothing was ordered.'
            : code === 'SPEND_CAP_EXCEEDED' ? 'That total exceeds your per-order cap. Nothing was ordered; try a smaller quantity.'
            : 'Nothing was ordered.';
          return { isError: true, content: [{ type: 'text', text: `Order refused (${code}): ${reason}\n${hint}` }] };
        }
        const o = body['order'] as Record<string, unknown>;
        return { content: [{ type: 'text', text: `Order ${String(body['orderId'])} placed: ${String(o['quantity'])} × ${String(o['name'])} = ${String(o['total'])}.\nThe merchant verified your delegation (signature, revocation, holder key, product class, cap) and returned a signed receipt.` }] };
      }
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: `Gateway error reaching the merchant: ${err instanceof Error ? err.message : String(err)}` }] };
    }
    return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  });
  return server;
}

async function main() {
  const identity = loadAgentIdentity(); // fail fast if the agent has no keys
  const server = createGatewayServer();
  await server.connect(new StdioServerTransport());
  process.stderr.write(`[gateway] kya-shopping-agent ready on stdio · agent ${identity.did} · merchant ${MERCHANT}\n`);
}

if (isMainModule(import.meta.url)) {
  main().catch((err) => { process.stderr.write(`[gateway] fatal: ${err instanceof Error ? err.message : String(err)}\n`); process.exit(1); });
}
