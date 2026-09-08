#!/usr/bin/env npx tsx
/**
 * The Responsible Party's hub — the shopper's own identity host. Three jobs:
 *
 *   1. Publish the RP's DID document (did:web → /.well-known/did.json).
 *   2. Host the signed StatusList2021 credential the merchant verifies on
 *      every call (GET /status-list, Cache-Control: no-store).
 *   3. Issue and revoke the agent's delegation, the latter behind an
 *      authenticator touch when KEY_WEBAUTHN=1.
 *   4. Witness the merchant's audit ledger: countersign each RFC 9162
 *      checkpoint the merchant publishes (POST /api/rp/audit/observe), so the
 *      merchant's history is pinned by a party it does not control.
 *
 * It is a SEPARATE process/origin from the merchant on purpose: the merchant
 * trusts the RP's signature, resolved through the RP's DID, not this server.
 */
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { streamSSE } from 'hono/streaming';
import { buildDidWebDocument, type DIDDocument } from '@kya-os/mcp';
import {
  RP_PORT,
  STATUS_LIST_URL,
  env,
  flag,
  loadRpIdentity,
  makeVcSigningFunction,
  merchantOrigin,
  readJson,
  writeJson,
  type KeyedIdentity,
} from '../lib/wiring.js';
import path from 'node:path';
import { ensureStatusList, loadStatusList, loadStatusListMeta, readBit, RP_DIR } from './statuslist.js';
import { activeIndex, issueAndActivate, delegationFile } from './issue.js';
import { revokeIndex, type RevokePhase } from './revoke.js';
import { createKeyRoutes } from './key/webauthn-routes.js';
import { hasAuthenticator, listAuthenticators } from './key/credential-store.js';
import { createWitness, type Witness } from './witness.js';

export const DID_DOCUMENT_FILE = path.join(RP_DIR, 'did.json');

export interface RpAppConfig {
  identity: KeyedIdentity;
  statusListUrl: string;
  /** DIDs allowed to be issued to / for. Read from env at request time by default. */
  agentDid: () => string;
  merchantDid: () => string;
  corsOrigins: string[];
  keySetup: boolean;
  keyWebauthn: boolean;
  bypassWebauthn: boolean;
  rpID: string;
  origin: string;
}

export function buildRpDidDocument(identity: KeyedIdentity): DIDDocument {
  return buildDidWebDocument({
    did: identity.did,
    kid: identity.kid,
    publicKey: identity.publicKeyBase64,
    createdAt: new Date().toISOString(),
  });
}

/** The DID document the hub serves — written once by setup, regenerated if missing. */
export function ensureDidDocument(identity: KeyedIdentity): DIDDocument {
  const existing = readJson<DIDDocument>(DID_DOCUMENT_FILE);
  if (existing && existing.id === identity.did) return existing;
  const doc = buildRpDidDocument(identity);
  writeJson(DID_DOCUMENT_FILE, doc);
  return doc;
}

export function createRpApp(config: RpAppConfig): Hono {
  const app = new Hono();
  const { identity } = config;
  const signingFunction = makeVcSigningFunction(identity.privateKeyBase64);
  const keyRequired = () => config.keyWebauthn && !config.bypassWebauthn && hasAuthenticator();

  app.use('/api/*', cors({ origin: config.corsOrigins }));
  app.use('/status-list', cors({ origin: '*' }));
  app.use('/.well-known/*', cors({ origin: '*' }));

  // ---- SSE: revocation phases, for the console's RP pane ----------------------
  type Subscriber = (data: string) => void;
  const subscribers = new Set<Subscriber>();
  const broadcast = (event: Record<string, unknown>) => {
    const data = JSON.stringify({ ...event, at: new Date().toISOString() });
    for (const sub of subscribers) { try { sub(data); } catch { /* dead subscriber */ } }
  };
  app.get('/api/rp/events', (c) =>
    streamSSE(c, async (stream) => {
      const sub: Subscriber = (data) => { void stream.writeSSE({ data }); };
      subscribers.add(sub);
      await stream.writeSSE({ data: JSON.stringify({ type: 'hello', role: 'rp', at: new Date().toISOString() }) });
      await new Promise<void>((resolve) => {
        const ping = setInterval(() => { void stream.writeSSE({ data: JSON.stringify({ type: 'ping' }) }).catch(() => {}); }, 15000);
        stream.onAbort(() => { clearInterval(ping); subscribers.delete(sub); resolve(); });
      });
    }),
  );

  // ---- 1. identity ----------------------------------------------------------
  app.get('/.well-known/did.json', (c) => {
    c.header('Cache-Control', 'no-store');
    return c.json(ensureDidDocument(identity));
  });

  // ---- 2. the revocation list ----------------------------------------------
  app.get('/status-list', async (c) => {
    const list = loadStatusList() ?? (await ensureStatusList({ identity, signingFunction, url: config.statusListUrl }));
    c.header('Cache-Control', 'no-store');
    c.header('Content-Type', 'application/json');
    return c.body(JSON.stringify(list));
  });

  // ---- state for the console ------------------------------------------------
  app.get('/api/rp/state', async (c) => {
    const list = loadStatusList();
    const meta = loadStatusListMeta();
    const index = activeIndex();
    const bit = list ? await readBit(list, index) : null;
    return c.json({
      did: identity.did,
      kid: identity.kid,
      didDocumentUrl: new URL('/.well-known/did.json', c.req.url).toString(),
      statusListUrl: config.statusListUrl,
      statusList: { version: meta.version, updatedAt: meta.updatedAt, lastAction: meta.lastAction ?? null, issuanceDate: list?.issuanceDate ?? null },
      activeIndex: index,
      revoked: bit,
      keyRequired: keyRequired(),
      keySetup: config.keySetup,
      authenticators: listAuthenticators().map((a) => ({ label: a.label, idTail: a.id.slice(-6) })),
    });
  });

  // ---- 3a. issue -------------------------------------------------------------
  app.post('/api/rp/issue', async (c) => {
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const requested = Number((body as Record<string, unknown>)['index']);
    const index = Number.isInteger(requested) && requested >= 0 ? requested : activeIndex() + 1;
    await ensureStatusList({ identity, signingFunction, url: config.statusListUrl });
    const { file, vc } = await issueAndActivate({
      index,
      agentDid: config.agentDid(),
      audience: config.merchantDid(),
      identity,
      statusListUrl: config.statusListUrl,
    });
    const scope = vc.credentialSubject.delegation.constraints.crisp?.scopes?.[0];
    broadcast({ type: 'issued', index, subject: vc.credentialSubject.id, scope: scope?.resource ?? null });
    return c.json({
      index,
      file,
      issuer: vc.issuer,
      subject: vc.credentialSubject.id,
      audience: vc.credentialSubject.delegation.constraints.audience ?? null,
      scope: scope ? { resource: scope.resource, matcher: scope.matcher, constraints: scope.constraints ?? {} } : null,
      expirationDate: vc.expirationDate ?? null,
      credentialStatus: vc.credentialStatus ?? null,
    });
  });

  app.get('/api/rp/delegation', (c) => {
    const index = activeIndex();
    const vc = readJson(delegationFile(index));
    if (!vc) return c.json({ error: 'no active delegation' }, 404);
    return c.json({ index, credential: vc });
  });

  // ---- 3b. revoke --------------------------------------------------------------
  async function performRevoke(index: number) {
    broadcast({ type: 'revoke_start', index });
    const result = await revokeIndex(index, {
      identity,
      statusListUrl: config.statusListUrl,
      onPhase: (p: RevokePhase) => broadcast({ type: 'revoke_phase', index, ...p }),
    });
    broadcast({ type: 'revoke_done', ...result });
    return result;
  }

  // Software path — used when the key feature is off or bypassed. When a key IS
  // required, the console runs the two-phase /api/rp/revoke/* flow instead.
  app.post('/api/rp/revoke', async (c) => {
    if (keyRequired()) {
      return c.json({ error: 'key_required', message: 'Revocation requires an authenticator assertion (/api/rp/revoke/challenge).' }, 403);
    }
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const requested = Number((body as Record<string, unknown>)['index']);
    const index = Number.isInteger(requested) && requested >= 0 ? requested : activeIndex();
    const restore = Boolean((body as Record<string, unknown>)['restore']);
    if (restore) {
      const result = await revokeIndex(index, { restore: true, identity, statusListUrl: config.statusListUrl });
      broadcast({ type: 'restored', ...result });
      return c.json(result);
    }
    return c.json(await performRevoke(index));
  });

  app.route('/', createKeyRoutes({
    rpID: config.rpID,
    origin: config.origin,
    rpName: 'KYA-OS Responsible Party',
    setupEnabled: config.keySetup,
    statusListUrl: () => config.statusListUrl,
    currentIndex: () => activeIndex(),
    performRevoke,
  }));

  // ---- 4. witness the merchant's audit ledger ----------------------------------
  // The SDK observer, keyed with the RP's did:web key; created on first use.
  let witnessPromise: Promise<Witness> | null = null;
  const witness = () => (witnessPromise ??= createWitness(identity, { acceptIssuer: () => config.merchantDid() }));

  app.post('/api/rp/audit/observe', async (c) => {
    const body = (await c.req.json().catch(() => null)) as { checkpoint?: unknown; consistency?: unknown } | null;
    if (!body || typeof body !== 'object' || !body.checkpoint) return c.json({ error: 'expected { checkpoint, consistency? }' }, 400);
    try {
      const w = await witness();
      const receipt = await w.observe(body as never);
      const cp = (body.checkpoint as { core: { treeSize: string; rootDigest: string; ledgerId: string }; checkpointDigest: string });
      broadcast({ type: 'witnessed', ledgerId: cp.core.ledgerId, treeSize: cp.core.treeSize, rootDigest: cp.core.rootDigest, checkpointDigest: cp.checkpointDigest, observationDigest: receipt.observationDigest, observations: w.observations });
      return c.json({ receipt, observer: w.observer });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      broadcast({ type: 'witness_refused', message });
      return c.json({ error: message }, 409);
    }
  });

  app.get('/api/rp/audit/latest', async (c) => {
    const ledgerId = c.req.query('ledgerId') ?? '';
    const ledgerEpochId = c.req.query('ledgerEpochId') ?? '';
    const w = await witness();
    const latest = await w.latest(ledgerId, ledgerEpochId);
    return c.json({ observer: w.observer, observations: w.observations, latest });
  });

  app.get('/', (c) => c.json({
    role: 'responsible-party-hub',
    did: identity.did,
    didDocument: '/.well-known/did.json',
    statusList: '/status-list',
    api: ['/api/rp/state', '/api/rp/issue', '/api/rp/revoke', '/api/rp/revoke/challenge', '/api/rp/revoke/execute', '/api/rp/key/list', '/api/rp/events', '/api/rp/audit/observe', '/api/rp/audit/latest'],
  }));

  return app;
}

export function rpConfigFromEnv(overrides: Partial<RpAppConfig> = {}): RpAppConfig {
  return {
    identity: loadRpIdentity(),
    statusListUrl: STATUS_LIST_URL,
    agentDid: () => env('AGENT_DID', ''),
    merchantDid: () => env('MERCHANT_DID', ''),
    corsOrigins: [merchantOrigin(), `http://localhost:${RP_PORT}`, `http://127.0.0.1:${RP_PORT}`],
    keySetup: flag('KEY_SETUP'),
    keyWebauthn: flag('KEY_WEBAUTHN'),
    bypassWebauthn: flag('DEMO_BYPASS_WEBAUTHN'),
    rpID: env('WEBAUTHN_RP_ID', 'localhost'),
    origin: env('WEBAUTHN_ORIGIN', merchantOrigin()),
    ...overrides,
  };
}

export function startRpServer(port = RP_PORT, overrides: Partial<RpAppConfig> = {}) {
  const config = rpConfigFromEnv(overrides);
  const app = createRpApp(config);
  const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' }, () => {
    console.log(`Responsible Party hub: http://localhost:${port}`);
    console.log(`  did:          ${config.identity.did}`);
    console.log(`  did.json:     http://localhost:${port}/.well-known/did.json`);
    console.log(`  status list:  ${config.statusListUrl}`);
    console.log(`  revocation:   ${config.keyWebauthn && !config.bypassWebauthn ? (hasAuthenticator() ? 'authenticator touch REQUIRED' : 'KEY_WEBAUTHN=1 but no authenticator registered → software') : 'software-confirmed'}`);
  });
  return { app, server, config };
}

const isMain = process.argv[1]?.endsWith('rp/server.ts');
if (isMain) startRpServer();
