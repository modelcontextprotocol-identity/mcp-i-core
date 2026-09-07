#!/usr/bin/env npx tsx
/**
 * THE AGENT — a real MCP client, the thing being governed.
 *
 * 1. DISCOVER: read the merchant's /.well-known/mcp and decide whether the
 *    merchant accepts the authority the agent holds (scheme, DID methods,
 *    algorithms, clock skew, audience) — BEFORE presenting anything.
 * 2. ACT: call `place_order` over Streamable HTTP, presenting
 *      - its Delegation Credential (`_kyaos_delegation`) from the Responsible
 *        Party, scoped to one GS1 Digital Link product class, and
 *      - a per-request holder proof (`_kyaos_proof`) signed by its OWN did:key
 *        (the shipped `generateRequestProof`). The merchant runs
 *        holderBinding: 'enforce', so a stolen credential without this key is
 *        refused before any handler runs.
 *
 * Runnable standalone:
 *   npm run agent -- discover
 *   npm run agent -- order --product risotto --quantity 2
 *   npm run agent -- order --product olive-oil          # outside the scope
 *   npm run agent -- order --product risotto --quantity 5   # over the cap
 *   npm run agent -- order --product risotto --forge    # stolen credential, wrong key
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { generateDidKeyFromBase64, generateRequestProof, type DelegationCredential } from '@kya-os/mcp';
import { cryptoProvider, loadAgentIdentity, merchantOrigin, type KeyedIdentity } from '../lib/wiring.js';
import { activeCredential } from '../rp/issue.js';
import type { DiscoveryDocument } from '../merchant/well-known.js';

export interface DiscoveryDecision {
  document: DiscoveryDocument;
  accepted: boolean;
  scheme: Record<string, unknown> | null;
  audience: string;
  clockSkewSeconds: number;
  reasons: string[];
  elapsedMs: number;
}

export const SCHEME_ID = 'org.kya-os/delegation';

/** Read the merchant's discovery document and decide whether to present. */
export async function discover(origin = merchantOrigin(), identity?: KeyedIdentity): Promise<DiscoveryDecision> {
  const started = Date.now();
  const res = await fetch(`${origin}/.well-known/mcp`, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`discovery failed: HTTP ${res.status}`);
  const document = (await res.json()) as DiscoveryDocument;
  const reasons: string[] = [];
  const scheme = (document.acceptedTrustSchemes ?? []).find((s) => s['id'] === SCHEME_ID) ?? null;
  if (!scheme) reasons.push(`merchant does not list ${SCHEME_ID} in acceptedTrustSchemes`);
  const myDid = identity?.did ?? safeAgentDid();
  const myMethod = myDid ? myDid.split(':').slice(0, 2).join(':') : 'did:key';
  if (!(document.supportedDidMethods ?? []).includes(myMethod)) reasons.push(`merchant does not resolve ${myMethod}`);
  if (!(document.proofAlgorithms ?? []).includes('EdDSA')) reasons.push('merchant does not accept EdDSA proofs');
  if (!document.serverDid) reasons.push('merchant publishes no DID to bind the audience to');
  return {
    document,
    accepted: reasons.length === 0,
    scheme,
    audience: document.serverDid,
    clockSkewSeconds: document.clockSkewSeconds ?? 120,
    reasons,
    elapsedMs: Date.now() - started,
  };
}

function safeAgentDid(): string | null {
  try { return loadAgentIdentity().did; } catch { return null; }
}

export interface AgentOrderOutcome {
  result: { content?: Array<{ type: string; text?: string }>; isError?: boolean; _meta?: Record<string, unknown> };
  elapsedMs: number;
  agentDid: string;
  presented: { product: string; quantity: number; credentialId: string | null; audience: string };
}

/**
 * One delegated order, over the wire: connect → tools/call place_order with
 * credential + fresh holder proof → disconnect.
 */
export async function runAgentOrder(options: {
  product: string;
  quantity?: number;
  serverUrl?: string;
  audience?: string;
  identity?: KeyedIdentity;
  credential?: DelegationCredential;
  /** Theft simulation: present the REAL credential, sign the proof with a fresh key. */
  forge?: boolean;
}): Promise<AgentOrderOutcome> {
  const serverUrl = options.serverUrl ?? `${merchantOrigin()}/mcp`;
  let identity = options.identity ?? loadAgentIdentity();
  if (options.forge) {
    const stolen = await cryptoProvider.generateKeyPair();
    const thiefDid = generateDidKeyFromBase64(stolen.publicKey);
    identity = { did: thiefDid, kid: `${thiefDid}#${thiefDid.replace('did:key:', '')}`, privateKeyBase64: stolen.privateKey, publicKeyBase64: stolen.publicKey };
  }
  const credential = options.credential ?? activeCredential();
  const quantity = options.quantity ?? 1;
  // The audience is the merchant's DID — learned from discovery, or from the
  // credential's own audience constraint (the grant already names the merchant).
  const audience = options.audience
    ?? (typeof credential.credentialSubject.delegation.constraints.audience === 'string'
      ? credential.credentialSubject.delegation.constraints.audience
      : (await discover(new URL(serverUrl).origin)).audience);

  const args: Record<string, unknown> = { product: options.product, quantity, _kyaos_delegation: credential };
  args['_kyaos_proof'] = await generateRequestProof({
    identity: { did: identity.did, kid: identity.kid, privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 },
    crypto: cryptoProvider,
    toolName: 'place_order',
    args,
    audience,
  });

  const client = new Client({ name: 'shopping-agent', version: '0.1.0' });
  const transport = new StreamableHTTPClientTransport(new URL(serverUrl));
  const started = Date.now();
  await client.connect(transport);
  try {
    const result = await client.callTool({ name: 'place_order', arguments: args });
    return {
      result: result as AgentOrderOutcome['result'],
      elapsedMs: Date.now() - started,
      agentDid: identity.did,
      presented: { product: options.product, quantity, credentialId: credential.id ?? null, audience },
    };
  } finally {
    await client.close();
  }
}

/** Unauthenticated read — the "agent-visible" half. */
export async function browseCatalog(serverUrl = `${merchantOrigin()}/mcp`): Promise<unknown> {
  const client = new Client({ name: 'shopping-agent', version: '0.1.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(serverUrl)));
  try {
    const r = await client.callTool({ name: 'get_catalog', arguments: {} });
    const text = (r as { content?: Array<{ text?: string }> }).content?.[0]?.text ?? '[]';
    return JSON.parse(text);
  } finally {
    await client.close();
  }
}

const isMain = process.argv[1]?.endsWith('agent/agent.ts');
if (isMain) {
  const [, , cmd = 'order', ...rest] = process.argv;
  const arg = (name: string, fallback?: string) => { const i = rest.indexOf(`--${name}`); return i > -1 ? rest[i + 1] : fallback; };
  const run = async () => {
    if (cmd === 'discover') {
      const d = await discover();
      console.log(JSON.stringify({ accepted: d.accepted, reasons: d.reasons, audience: d.audience, clockSkewSeconds: d.clockSkewSeconds, scheme: d.scheme }, null, 2));
      return;
    }
    if (cmd === 'browse') { console.log(JSON.stringify(await browseCatalog(), null, 2)); return; }
    const outcome = await runAgentOrder({
      product: arg('product', 'risotto')!,
      quantity: Number(arg('quantity', '1')),
      forge: rest.includes('--forge'),
    });
    const text = outcome.result.content?.[0]?.text ?? '';
    let body: Record<string, unknown> = {};
    try { body = JSON.parse(text); } catch { body = { raw: text }; }
    console.log(JSON.stringify({ agent: outcome.agentDid, tool: 'place_order', ...outcome.presented, elapsedMs: outcome.elapsedMs, verdict: outcome.result.isError ? 'DENIED' : 'ALLOWED', ...body }, null, 2));
    process.exit(outcome.result.isError ? 1 : 0);
  };
  run().catch((err) => { console.error('agent error:', err instanceof Error ? err.message : err); process.exit(2); });
}
