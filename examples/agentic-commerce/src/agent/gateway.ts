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
 * Claude sees a clean tool surface — `browse_catalog`, `place_order`,
 * `my_authority` — with NO crypto arguments. The gateway injects the
 * credential and mints the per-request holder proof. The LLM never touches
 * key material: that is the point, and a talking point.
 *
 * Run:  npm run gateway        (stdio — see docs/claude_desktop_config.json)
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { env, loadAgentIdentity, merchantOrigin } from '../lib/wiring.js';
import { browseCatalog, discover, runAgentOrder } from './agent.js';
import { activeCredential } from '../rp/issue.js';
import { summarizeMandate } from '../merchant/place-order.js';

const MERCHANT = env('MERCHANT_ORIGIN', merchantOrigin());

function createGatewayServer(): Server {
  const server = new Server({ name: 'kya-shopping-agent', version: '0.1.0' }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'browse_catalog',
        description: 'List the merchant\'s products (name, GS1 Digital Link URI, price). Open to any agent; no authority needed.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'my_authority',
        description: 'Show what you are currently allowed to buy: the delegation your owner issued (product class, per-order cap, validity, and whether the merchant accepts it). Check this before ordering.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'place_order',
        description:
          'Order a product from the merchant under your delegated authority. You do not hold or handle any keys — the gateway presents your owner\'s signed delegation and signs the request on your behalf. Returns the signed receipt, or the exact reason the merchant refused (outside your product class, over your cap, or your authority was revoked).',
        inputSchema: {
          type: 'object' as const,
          properties: {
            product: { type: 'string', description: 'Catalog sku (e.g. "risotto") or a GS1 Digital Link URI' },
            quantity: { type: 'integer', description: 'How many units (default 1)' },
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
      if (name === 'my_authority') {
        const m = summarizeMandate(activeCredential());
        const d = await discover(MERCHANT).catch(() => null);
        return { content: [{ type: 'text', text:
          `Delegated by ${m.responsibleParty} to ${m.agent}\n` +
          `Product class: ${m.scope?.resource ?? '(none)'} (${m.scope?.matcher ?? ''}; lots and serials beneath it are included)\n` +
          `Cap: ${m.cap ? `${m.cap.currency} ${m.cap.maxAmount} per ${m.cap.per}` : '(none)'}\n` +
          `Valid until: ${m.validUntil ?? '(unspecified)'}\n` +
          `Merchant ${MERCHANT}: ${d ? (d.accepted ? `accepts ${d.scheme?.['id']} (clock skew ${d.clockSkewSeconds}s)` : `does not accept — ${d.reasons.join('; ')}`) : 'unreachable'}\n` +
          `Revocation is checked by the merchant on every order; if your owner revokes, the next order is refused.` }] };
      }
      if (name === 'place_order') {
        const product = String((args as Record<string, unknown>)['product'] ?? '');
        const quantity = Number((args as Record<string, unknown>)['quantity'] ?? 1);
        const outcome = await runAgentOrder({ product, quantity, serverUrl: `${MERCHANT}/mcp` });
        const text = outcome.result.content?.[0]?.text ?? '{}';
        let body: Record<string, unknown> = {};
        try { body = JSON.parse(text); } catch { body = { raw: text }; }
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

main().catch((err) => { process.stderr.write(`[gateway] fatal: ${err instanceof Error ? err.message : String(err)}\n`); process.exit(1); });
