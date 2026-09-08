#!/usr/bin/env npx tsx
/**
 * The MERCHANT EDGE — one process, four surfaces:
 *
 *   1. /.well-known/mcp   the discovery document an agent reads first: the
 *                         merchant's DID, algorithms, clock-skew tolerance and
 *                         the trust schemes it accepts (`acceptedTrustSchemes`).
 *   2. POST /mcp          a REAL MCP server (Streamable HTTP). `get_catalog` is
 *                         open (agent-visible); `place_order` is gated by the
 *                         SHIPPED withKyaOs delegation middleware: signature →
 *                         revocation (fetched from the Responsible Party's list
 *                         on every call) → holder key → scope; then the handler
 *                         reads the product class and the cap out of the same
 *                         credential. Point mcp-inspector at it — nothing
 *                         demo-specific in the gate.
 *   3. /api/*             act routes the console uses. "Agent orders" drives a
 *                         real MCP client against our own /mcp.
 *   4. /                  the verifier console (web/).
 *   5. /api/audit/*       the SHIPPED audit protocol: every gate decision above
 *                         is a signed, hash-chained ledger entry; `A` anchors an
 *                         RFC 9162 checkpoint (witnessed by the RP), `T` shows
 *                         an insider's edit failing, `E` exports the replay
 *                         bundle for `npx kya-audit verify`.
 *
 * Low-level SDK `Server` (not McpServer.registerTool): delegation-protected
 * tools receive `_kyaos_delegation` as a tool argument, and registerTool's zod
 * validation would strip it.
 */
import http from 'node:http';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { spawn } from 'node:child_process';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import { getRequestListener } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import {
  createKyaOsMiddleware,
  didWebToUrl,
  KYA_OS_PROOF_META_KEY,
  type DelegationCredential,
  type KyaOsMiddleware,
} from '@kya-os/mcp';
import {
  EXAMPLE_ROOT,
  MERCHANT_PORT,
  RP_DID,
  RP_DID_MIRROR_URL,
  STATUS_LIST_URL,
  WEB_DIR,
  cryptoProvider,
  env,
  flag,
  gzipCompressor,
  gzipDecompressor,
  loadMerchantIdentity,
  rpOrigin,
  type KeyedIdentity,
} from '../lib/wiring.js';
import { DemoFetchProvider } from '../lib/mirror-fetch.js';
import { HttpStatusListResolver, ed25519PublicKeyBase64 } from '../lib/http-statuslist-resolver.js';
import { createMerchantAudit } from './audit.js';
import { CATALOG } from '../lib/product.js';
import { buildDiscoveryDocument } from './well-known.js';
import { decideOrder, summarizeMandate, type Mandate } from './place-order.js';
import { discover, runAgentOrder } from '../agent/agent.js';

export interface MerchantAppConfig {
  identity: KeyedIdentity;
  name: string;
  port: number;
  rpDid: string;
  rpDidMirrorUrl: string;
  statusListUrl: string;
  rpOrigin: string;
  offline: boolean;
  allowInsecureLocalhost: boolean;
  statusCacheTtlMs: number;
  pythonVerifier: string | null;
  /** Ask the Responsible Party to witness each audit checkpoint (AUDIT_WITNESS=0 to disable). */
  witness: boolean;
  /** Where exported replay bundles land (default var/audit). */
  auditDir?: string;
}

export function merchantConfigFromEnv(overrides: Partial<MerchantAppConfig> = {}): MerchantAppConfig {
  return {
    identity: loadMerchantIdentity(),
    name: env('MERCHANT_NAME', 'Dal Giardino Direct (demo merchant)'),
    port: MERCHANT_PORT,
    rpDid: RP_DID,
    rpDidMirrorUrl: RP_DID_MIRROR_URL,
    statusListUrl: STATUS_LIST_URL,
    rpOrigin: rpOrigin(),
    offline: flag('OFFLINE'),
    allowInsecureLocalhost: env('ALLOW_INSECURE_LOCALHOST', '1') === '1',
    statusCacheTtlMs: Number(env('STATUS_CACHE_TTL_MS', '0')),
    pythonVerifier: path.join(EXAMPLE_ROOT, 'scripts', 'verify-receipt.py'),
    witness: env('AUDIT_WITNESS', '1') === '1',
    ...overrides,
  };
}

type GateState = 'pass' | 'fail' | 'skip';
export interface GateChecks {
  signature: GateState; revocation: GateState; holder: GateState;
  product: GateState; cap: GateState; receipt: GateState;
}

/**
 * Map an outcome to the six gates, honestly following the middleware's ACTUAL
 * order: basic+signature (window, audience) → status (revocation) → holder
 * binding → flat scope → [handler] product class → spend cap → signed receipt.
 */
export function checksFromOutcome(verdict: 'allowed' | 'denied', code: string | undefined, reason: string): GateChecks {
  if (verdict === 'allowed') return { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'pass', receipt: 'pass' };
  if (code === 'holder_binding_failed') return { signature: 'pass', revocation: 'pass', holder: 'fail', product: 'skip', cap: 'skip', receipt: 'skip' };
  if (/revoked|status_unresolvable|status list/i.test(reason)) return { signature: 'pass', revocation: 'fail', holder: 'skip', product: 'skip', cap: 'skip', receipt: 'skip' };
  if (code === 'PRODUCT_OUT_OF_SCOPE') return { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'fail', cap: 'skip', receipt: 'skip' };
  if (code === 'SPEND_CAP_EXCEEDED' || code === 'CURRENCY_MISMATCH' || code === 'NO_CAP_IN_CREDENTIAL') return { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'fail', receipt: 'skip' };
  if (code === 'UNKNOWN_PRODUCT' || code === 'INVALID_PRODUCT_URI' || code === 'INVALID_QUANTITY') return { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'fail', cap: 'skip', receipt: 'skip' };
  // Any other delegation_invalid (expired, wrong audience, bad signature) → the first gate.
  return { signature: 'fail', revocation: 'skip', holder: 'skip', product: 'skip', cap: 'skip', receipt: 'skip' };
}

export async function createMerchant(config: MerchantAppConfig) {
  const { identity } = config;

  // ---- outbound trust: the RP's DID document + revocation list ----------------
  const rpDidUrl = didWebToUrl(config.rpDid);
  const fetchProvider = new DemoFetchProvider({
    allowInsecureLocalhost: config.allowInsecureLocalhost,
    mirrors: rpDidUrl ? { [rpDidUrl]: config.rpDidMirrorUrl } : {},
    offline: config.offline,
  });
  const didResolver = { resolve: (did: string) => fetchProvider.resolveDID(did) };
  const statusListResolver = new HttpStatusListResolver({
    fetchProvider,
    didResolver,
    cryptoProvider,
    expectedIssuerDid: config.rpDid,
    compressor: gzipCompressor,
    decompressor: gzipDecompressor,
    cacheTtlMs: config.statusCacheTtlMs,
    allowInsecureLocalhost: config.allowInsecureLocalhost,
  });

  // ---- the shipped audit trail ----------------------------------------------------
  // Every decision the gate makes below lands here as a signed, chained entry;
  // `delivery: 'required'` means a call that cannot be recorded is refused.
  const audit = await createMerchantAudit(identity, {
    witnessUrl: config.witness ? `${config.rpOrigin}/api/rp/audit/observe` : undefined,
    resolvePublicKeyBase64: async (signer) => {
      const doc = await didResolver.resolve(signer.did);
      const method = doc?.verificationMethod?.find((m) => m.id === signer.kid) ?? doc?.verificationMethod?.[0];
      return method ? ed25519PublicKeyBase64(method) : null;
    },
    ...(config.auditDir ? { auditDir: config.auditDir } : {}),
  });

  // ---- the shipped gate ---------------------------------------------------------
  const kyaos: KyaOsMiddleware = createKyaOsMiddleware(
    {
      identity: { did: identity.did, kid: identity.kid, privateKey: identity.privateKeyBase64, publicKey: identity.publicKeyBase64 },
      autoSession: true,
      delegation: {
        fetchProvider,
        didResolver,
        statusListResolver,
        // Subject-bound, not bearer: the caller must present a per-request
        // proof signed by the delegation SUBJECT's did:key.
        holderBinding: 'enforce',
      },
      audit: audit.middlewareAudit,
    },
    cryptoProvider,
  );

  // The gate strips the `_kyaos_*` control args before the handler runs, so the
  // verified credential reaches the handler through a per-call context: the
  // MCP dispatcher stashes the SAME object the gate verifies, and the handler
  // checks the gate's `authorization.delegationRef` names that credential.
  const callStore = new AsyncLocalStorage<{ vc: DelegationCredential }>();

  // Demo memory: what the merchant has SEEN (for the console), never for trust.
  let lastMandate: Mandate | null = null;
  let lastReceipt: { body: Record<string, unknown>; proof: unknown; at: string; request: { method: string; params: Record<string, unknown> }; content: unknown } | null = null;
  let orders = 0;

  const placeOrderHandler = kyaos.wrapWithDelegation(
    'place_order',
    { scopeId: 'commerce.order', consentUrl: env('CONSENT_URL', `${config.rpOrigin}/consent`) },
    kyaos.wrapWithProof('place_order', async (args: Record<string, unknown>, _sessionId?: string, context?: { authorization?: { delegationRef?: string } }) => {
      // The gate has verified signature, window, audience, revocation (fresh),
      // holder key and the flat scope of THIS credential by the time we are here.
      const vc = callStore.getStore()?.vc;
      const ref = context?.authorization?.delegationRef;
      if (!vc || (ref && ref !== (vc.id ?? vc.credentialSubject.delegation.id))) {
        return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'CREDENTIAL_CONTEXT_MISMATCH', message: 'Fail-closed: the verified credential is not the one in the call context' }) }] };
      }
      lastMandate = summarizeMandate(vc);
      const outcome = decideOrder({ product: String(args['product'] ?? ''), quantity: Number(args['quantity'] ?? 1) }, vc);

      // The handler's own two gates (product class, cap) go on the same ledger
      // as the middleware's, with the merchant's reason codes. delivery is
      // 'required': a decision the merchant cannot record is a sale it refuses.
      const issuer = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
      const recorded = await audit.record({
        eventType: outcome.ok ? 'authorization.approved' : 'authorization.denied',
        action: { category: 'authorization', name: 'place_order' },
        actor: { kind: 'pairwise_did', did: vc.credentialSubject.id },
        responsibleParty: { kind: 'public_did', did: issuer },
        resource: { kind: 'keyed_commitment', value: `sha256:${createHash('sha256').update(outcome.ok ? outcome.item.uri : String(args['product'] ?? '')).digest('hex')}`, keyId: 'gs1-digital-link' },
        outcome: outcome.ok ? 'succeeded' : 'denied',
        ...(outcome.ok ? {} : { reason: { code: outcome.error } }),
        authorization: { source: 'delegation', decision: outcome.ok ? 'allowed' : 'denied', scopeId: 'commerce.order', ...(ref ? { delegationRef: ref } : {}) },
        evidence: [],
        details: { family: 'authorization', phase: outcome.ok ? 'approved' : 'denied' },
      }).catch((err: unknown) => ({ status: 'failed' as const, error: err }));
      if (recorded.status !== 'recorded') {
        return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'AUDIT_UNAVAILABLE', message: 'Fail-closed: the merchant could not record this decision, so it will not act on it' }) }] };
      }

      if (!outcome.ok) {
        return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: outcome.error, message: outcome.message, detail: outcome.detail ?? null, mandate: outcome.mandate }) }] };
      }
      orders += 1;
      const evidence = {
        ok: true,
        orderId: outcome.orderId,
        merchant: { did: identity.did, name: config.name },
        order: { product: outcome.item.uri, gtin: outcome.item.gtin, name: outcome.item.name, quantity: outcome.quantity, unitPrice: `${outcome.currency} ${outcome.item.unitPrice}`, total: outcome.total },
        mandate: outcome.mandate,
        checks: outcome.checks,
        payment: { status: 'authorized-for-capture', note: 'Spend enforcement and settlement stay with the merchant/PSP; the trust layer never touched the rail.' },
        verifiedAt: new Date().toISOString(),
      };
      return { content: [{ type: 'text', text: JSON.stringify(evidence) }] };
    }),
  );

  const catalogHandler = kyaos.wrapWithProof('get_catalog', async () => ({
    content: [{ type: 'text', text: JSON.stringify(CATALOG) }],
  }));

  // ---- event bus: the console is a VERIFIER VIEW that observes this server -----
  type Subscriber = (data: string) => void;
  const subscribers = new Set<Subscriber>();
  function broadcast(event: Record<string, unknown>): void {
    const data = JSON.stringify({ ...event, at: new Date().toISOString() });
    for (const sub of subscribers) { try { sub(data); } catch { /* dead subscriber must not break the others */ } }
  }

  // ---- MCP surface ---------------------------------------------------------------
  function createMcpServer(): Server {
    const server = new Server({ name: 'agentic-commerce-merchant', version: '0.1.0' }, { capabilities: { tools: {} } });

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        kyaos.kyaOsTool,
        {
          name: 'get_catalog',
          description: 'List the merchant catalog (GS1 Digital Link product URIs and prices). Open to any agent; the response is signed.',
          inputSchema: { type: 'object' as const, properties: {} },
        },
        {
          name: 'place_order',
          description:
            'Place an order for a catalog product. Requires a KYA-OS delegation (scope commerce.order) whose crisp scope covers the product\'s GS1 Digital Link class and whose cap covers the total; revocation is checked against the Responsible Party\'s status list on every call.',
          inputSchema: {
            type: 'object' as const,
            properties: {
              product: { type: 'string', description: 'Catalog sku or GS1 Digital Link URI (https://id.gs1.org/01/<gtin>[/10/<lot>][/21/<serial>])' },
              quantity: { type: 'integer', description: 'Units to order (default 1)' },
            },
            required: ['product'],
          },
        },
      ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const { name, arguments: args = {} } = request.params;
      const sessionId = extra?.sessionId;
      if (name === '_kyaos') return kyaos.handleKyaOs(args as Record<string, unknown>);
      if (name === 'get_catalog') return catalogHandler({}, sessionId);
      if (name === 'place_order') {
        const a = args as Record<string, unknown>;
        const started = Date.now();
        broadcast({ type: 'request', tool: 'place_order', product: String(a['product'] ?? ''), quantity: Number(a['quantity'] ?? 1), agentDid: (a['_kyaos_delegation'] as DelegationCredential | undefined)?.credentialSubject?.id ?? null });

        const vc = a['_kyaos_delegation'] as DelegationCredential | undefined;
        const result = vc
          ? await callStore.run({ vc }, () => placeOrderHandler(a, sessionId))
          : await placeOrderHandler(a, sessionId);

        const r = result as { isError?: boolean; content?: Array<{ text?: string }>; _meta?: Record<string, unknown> };
        const text = r.content?.[0]?.text ?? '{}';
        let body: Record<string, unknown> = {};
        try { body = JSON.parse(text); } catch { body = {}; }
        const verdict: 'allowed' | 'denied' = r.isError || body['error'] ? 'denied' : 'allowed';
        const code = body['error'] as string | undefined;
        const reason = String(body['reason'] ?? body['message'] ?? '');
        const proof = r._meta?.[KYA_OS_PROOF_META_KEY] ?? r._meta?.['proof'] ?? null;
        if (verdict === 'allowed') {
          // Exactly what the proof binds: the request minus the `_kyaos_*` control
          // args (the gate strips them before the proof wrapper hashes the call)
          // and the response content array (body profile).
          const params: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(a)) if (!k.startsWith('_kyaos')) params[k] = v;
          lastReceipt = { body, proof, at: new Date().toISOString(), request: { method: 'place_order', params }, content: r.content ?? null };
        }

        broadcast({
          type: 'verdict',
          verdict,
          code: code ?? null,
          reason: reason || null,
          elapsedMs: Date.now() - started,
          checks: checksFromOutcome(verdict, code, reason),
          body,
          receipt: proof,
          statusList: statusListResolver.lastObservation,
          rpResolvedFrom: rpDidUrl ? (fetchProvider.resolvedFrom.get(rpDidUrl) ?? null) : null,
        });
        return result;
      }
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    });
    return server;
  }

  // ---- discovery + act API + static console (Hono) -------------------------------
  const app = new Hono();
  const discovery = buildDiscoveryDocument({ serverDid: identity.did, name: config.name, currency: 'CHF' });

  app.get('/.well-known/mcp', (c) => { c.header('Cache-Control', 'no-store'); return c.json(discovery); });
  app.get('/api/catalog', (c) => c.json(CATALOG));

  app.get('/api/events', (c) =>
    streamSSE(c, async (stream) => {
      const sub: Subscriber = (data) => { void stream.writeSSE({ data }); };
      subscribers.add(sub);
      await stream.writeSSE({ data: JSON.stringify({ type: 'hello', role: 'merchant', at: new Date().toISOString() }) });
      await new Promise<void>((resolve) => {
        const ping = setInterval(() => { void stream.writeSSE({ data: JSON.stringify({ type: 'ping' }) }).catch(() => {}); }, 15000);
        stream.onAbort(() => { clearInterval(ping); subscribers.delete(sub); resolve(); });
      });
    }),
  );

  app.get('/api/state', async (c) => {
    let rpDocument: { resolved: boolean; from: string | null; kid: string | null } = { resolved: false, from: null, kid: null };
    try {
      const doc = await didResolver.resolve(config.rpDid);
      rpDocument = { resolved: !!doc, from: rpDidUrl ? (fetchProvider.resolvedFrom.get(rpDidUrl) ?? null) : null, kid: doc?.verificationMethod?.[0]?.id ?? null };
    } catch { /* unresolved → fail-closed at verification time */ }
    return c.json({
      merchant: { did: identity.did, kid: identity.kid, name: config.name, port: config.port },
      discovery,
      responsibleParty: { did: config.rpDid, hubOrigin: config.rpOrigin, didDocumentUrl: rpDidUrl, mirror: config.rpDidMirrorUrl, offline: config.offline, ...rpDocument },
      statusList: { url: config.statusListUrl, checkedAt: 'every-call', onUnresolvable: 'fail-closed', last: statusListResolver.lastObservation },
      policy: { holderBinding: 'enforce', revocationCheck: 'fail-closed', spendEnforcement: 'merchant, from credential cap' },
      lastMandate,
      lastReceipt: lastReceipt ? { at: lastReceipt.at, orderId: lastReceipt.body['orderId'] ?? null } : null,
      orders,
      catalog: CATALOG,
      audit: { ledger: audit.ledger, recorder: audit.recorder, profile: audit.capabilities.profile, delivery: audit.capabilities.delivery, entries: (await audit.entries()).length, witness: config.witness ? `${config.rpOrigin}/api/rp/audit/observe` : null },
    });
  });

  // ---- the audit finale: ledger → checkpoint → witness → tamper → export ----------
  app.get('/api/audit/ledger', async (c) => c.json(await audit.report()));

  app.post('/api/act/audit', async (c) => {
    const started = Date.now();
    try {
      const a = await audit.anchor();
      const report = await audit.report();
      broadcast({ type: 'audit', created: a.created, treeSize: a.checkpoint.core.treeSize, rootDigest: a.checkpoint.core.rootDigest, checkpointDigest: a.checkpoint.checkpointDigest, witnessed: !!a.witness, witnessError: a.witnessError, entries: report.entries.length, allIncluded: report.allIncluded, chainIntact: report.chainIntact, elapsedMs: Date.now() - started });
      return c.json(report);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  app.post('/api/act/tamper', async (c) => {
    const started = Date.now();
    try {
      const t = await audit.tamper();
      broadcast({ type: 'tamper', target: t.target, rootsMatch: t.rootsMatch, chainBreaksAt: t.chainBreaksAt, forgedInclusion: t.forgedInclusion, forgedReceiptVerifies: t.forgedReceiptVerifies, verdicts: verdictsOf(t.reports.tampered), elapsedMs: Date.now() - started });
      return c.json(t);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  app.post('/api/act/export', async (c) => {
    const started = Date.now();
    try {
      const e = await audit.exportBundle();
      broadcast({ type: 'export', bundleId: e.bundleId, manifestDigest: e.manifestDigest, files: e.files, command: e.command, verdicts: { honest: verdictsOf(e.reports.honest), tampered: verdictsOf(e.reports.tampered) }, elapsedMs: Date.now() - started });
      return c.json(e);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  app.get('/api/audit/bundle', async (c) => {
    try {
      const b = await audit.bundle();
      c.header('Content-Disposition', `attachment; filename="kya-audit-bundle-${audit.ledger.ledgerEpochId}.json"`);
      return c.json(b);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 409);
    }
  });

  // The console is only a control plane: these drive THE AGENT — a real MCP
  // client that connects to our own /mcp and presents credential + holder proof.
  app.post('/api/act/discover', async (c) => {
    try {
      const d = await discover(`http://localhost:${config.port}`);
      broadcast({ type: 'discovered', accepted: d.accepted, reasons: d.reasons, audience: d.audience, clockSkewSeconds: d.clockSkewSeconds, scheme: d.scheme, elapsedMs: d.elapsedMs });
      return c.json(d);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : String(err) }, 500);
    }
  });

  app.post('/api/act/order', async (c) => {
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const product = String((body as Record<string, unknown>)['product'] ?? 'risotto');
    const quantity = Number((body as Record<string, unknown>)['quantity'] ?? 1);
    const forge = Boolean((body as Record<string, unknown>)['forge']);
    try {
      const outcome = await runAgentOrder({ product, quantity, forge, serverUrl: `http://localhost:${config.port}/mcp`, audience: identity.did });
      return c.json({ elapsedMs: outcome.elapsedMs, result: outcome.result, agentDid: outcome.agentDid, presented: outcome.presented, via: 'mcp/streamable-http' });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      broadcast({ type: 'agent_error', message });
      return c.json({ error: message }, 500);
    }
  });

  app.post('/api/act/reset', async (c) => {
    // Ask the Responsible Party for a fresh grant (next status-list index).
    const res = await fetch(`${config.rpOrigin}/api/rp/issue`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const issued = (await res.json()) as Record<string, unknown>;
    statusListResolver.invalidateCache();
    lastMandate = null;
    broadcast({ type: 'reset', index: issued['index'] ?? null });
    return c.json(issued, res.ok ? 200 : 502);
  });

  app.get('/api/receipt/last', (c) => (lastReceipt ? c.json(lastReceipt) : c.json({ error: 'no receipt yet — place an order first' }, 404)));

  /** Cross-language re-verification of the last receipt with the stdlib Python verifier. */
  app.post('/api/act/verify-receipt', async (c) => {
    if (!lastReceipt) return c.json({ error: 'no receipt yet — place an order first' }, 404);
    if (!config.pythonVerifier) return c.json({ error: 'python verifier not configured' }, 501);
    const input = JSON.stringify({ receipt: lastReceipt, merchant: { did: identity.did, kid: identity.kid, publicKeyBase64: identity.publicKeyBase64 } });
    const started = Date.now();
    const out = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn(env('PYTHON', 'python3'), [config.pythonVerifier!], { stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      child.stdout.on('data', (d) => { stdout += String(d); });
      child.stderr.on('data', (d) => { stderr += String(d); });
      child.on('error', (e) => resolve({ code: null, stdout, stderr: stderr + String(e) }));
      child.on('close', (code) => resolve({ code, stdout, stderr }));
      child.stdin.end(input);
    });
    let parsed: unknown = null;
    try { parsed = JSON.parse(out.stdout); } catch { parsed = null; }
    const result = { ok: out.code === 0, exitCode: out.code, elapsedMs: Date.now() - started, report: parsed, stdout: parsed ? undefined : out.stdout, stderr: out.stderr || undefined };
    broadcast({ type: 'crosscheck', ...result });
    return c.json(result);
  });

  app.use('/*', serveStatic({ root: path.relative(process.cwd(), WEB_DIR) || './web' }));

  // ---- one HTTP server: /mcp → MCP transport, everything else → Hono ----------
  const honoListener = getRequestListener(app.fetch);
  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${config.port}`);
    if (url.pathname === '/mcp' && req.method === 'POST') {
      const server = createMcpServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }
    await honoListener(req, res);
  });

  return { app, httpServer, kyaos, statusListResolver, fetchProvider, discovery, broadcast, audit };
}

/** The seven verdicts of an SDK verification report, compact for the event bus. */
function verdictsOf(report: object): Record<string, { verdict: string; reasonCodes: string[] }> {
  const out: Record<string, { verdict: string; reasonCodes: string[] }> = {};
  for (const [k, v] of Object.entries(report as Record<string, unknown>)) {
    if (v && typeof v === 'object' && 'verdict' in v) out[k] = v as { verdict: string; reasonCodes: string[] };
  }
  return out;
}

export async function startMerchantServer(overrides: Partial<MerchantAppConfig> = {}) {
  const config = merchantConfigFromEnv(overrides);
  const merchant = await createMerchant(config);
  await new Promise<void>((resolve) => merchant.httpServer.listen(config.port, '127.0.0.1', () => {
    console.log(`Merchant edge: http://localhost:${config.port}`);
    console.log(`  console:    http://localhost:${config.port}/`);
    console.log(`  discovery:  http://localhost:${config.port}/.well-known/mcp`);
    console.log(`  MCP:        http://localhost:${config.port}/mcp`);
    console.log(`  did:        ${config.identity.did}`);
    console.log(`  trusts RP:  ${config.rpDid} (list: ${config.statusListUrl}${config.offline ? ', OFFLINE mirror' : ''})`);
    console.log(`  audit:      ${merchant.audit.ledger.ledgerId} · ${merchant.audit.capabilities.profile} · delivery ${merchant.audit.capabilities.delivery}${config.witness ? ` · witness ${config.rpOrigin}` : ''}`);
    resolve();
  }));
  return { ...merchant, config };
}

const isMain = process.argv[1]?.endsWith('merchant/server.ts');
if (isMain) void startMerchantServer();
