/**
 * The agent runtime Claude connects to at /agent/mcp on the merchant listener.
 *
 *   Claude (the brain, no keys)
 *     │  stateless MCP (Streamable HTTP)
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
 * npm run demo mounts both HTTP endpoints; each request gets a fresh MCP server.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { merchantOrigin } from '../lib/wiring.js';
import { browseCatalog, runAgentOrder } from './agent.js';
import { responseBody } from './authorization.js';
import { isMainModule } from '../lib/main-module.js';
export function createGatewayServer(options: { merchantOrigin?: string; audience?: string } = {}): Server {
  const merchant = options.merchantOrigin ?? merchantOrigin();
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
          'Place an order for a catalog product. If human consent is needed, returns a verified authorizationUrl to open and approve. After the human approves, retry within the approved product scope and per-order cap. The gateway attaches the new grant and a fresh holder proof. Returns an order receipt or a policy denial. This does not make a payment.',
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
        const items = (await browseCatalog(`${merchant}/mcp`)) as Array<{ sku: string; name: string; uri: string; unitPrice: string; currency: string }>;
        return { content: [{ type: 'text', text: items.map((i) => `- ${i.sku}: ${i.name} — ${i.currency} ${i.unitPrice} — ${i.uri}`).join('\n') }] };
      }
      if (name === 'place_order') {
        const product = String((args as Record<string, unknown>)['product'] ?? '');
        const quantity = Number((args as Record<string, unknown>)['quantity'] ?? 1);
        const outcome = await runAgentOrder({ product, quantity, serverUrl: `${merchant}/mcp`, audience: options.audience });
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

if (isMainModule(import.meta.url)) {
  process.stderr.write(`This gateway uses Streamable HTTP. Run npm run demo, then connect to ${merchantOrigin()}/agent/mcp. See ${merchantOrigin()}/connect. Remove the old stdio client entry.\n`);
  process.exitCode = 1;
}
