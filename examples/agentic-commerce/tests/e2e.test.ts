/**
 * Every stage beat, end to end, in-process: a Responsible Party hub and a
 * merchant edge on ephemeral ports with their own temp var/ and .data/, a real
 * MCP client presenting a real credential + holder proof, and the shipped
 * verifier deciding. Also the two things the stage never shows on purpose: the
 * hub going DOWN (fail-closed) and the offline DID-document mirror.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const crypto = new NodeCryptoProvider();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentic-commerce-'));
const RP_PORT = 14950 + Math.floor(Math.random() * 1000);
const MERCHANT_PORT = RP_PORT + 1;

let rp: { server: { close: (cb?: () => void) => void } };
let merchant: { httpServer: { close: (cb?: () => void) => void }; statusListResolver: { invalidateCache(): void } };
let agent: typeof import('../src/agent/agent.js');
let merchantMod: typeof import('../src/merchant/server.js');
let merchantDid: string;

async function order(product: string, quantity = 1, forge = false) {
  const outcome = await agent.runAgentOrder({ product, quantity, forge, serverUrl: `http://localhost:${MERCHANT_PORT}/mcp`, audience: merchantDid });
  const text = outcome.result.content?.[0]?.text ?? '{}';
  const body = JSON.parse(text) as Record<string, unknown>;
  return { denied: !!outcome.result.isError, code: body['error'] as string | undefined, reason: String(body['reason'] ?? body['message'] ?? ''), body, meta: outcome.result._meta };
}

beforeAll(async () => {
  // Environment BEFORE any example module is imported (wiring reads it at import).
  const rpKp = await crypto.generateKeyPair();
  const mKp = await crypto.generateKeyPair();
  const aKp = await crypto.generateKeyPair();
  merchantDid = generateDidKeyFromBase64(mKp.publicKey);
  Object.assign(process.env, {
    DEMO_VAR_DIR: path.join(tmp, 'var'),
    DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(RP_PORT),
    MERCHANT_PORT: String(MERCHANT_PORT),
    RP_DID: `did:web:localhost%3A${RP_PORT}`,
    RP_KID: `did:web:localhost%3A${RP_PORT}#key-1`,
    RP_PRIVATE_KEY_BASE64: rpKp.privateKey,
    RP_PUBLIC_KEY_BASE64: rpKp.publicKey,
    MERCHANT_DID: merchantDid,
    MERCHANT_PRIVATE_KEY_BASE64: mKp.privateKey,
    MERCHANT_PUBLIC_KEY_BASE64: mKp.publicKey,
    AGENT_DID: generateDidKeyFromBase64(aKp.publicKey),
    AGENT_ED25519_PRIVATE_KEY_BASE64: aKp.privateKey,
    AGENT_ED25519_PUBLIC_KEY_BASE64: aKp.publicKey,
    KEY_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0',
  });
  const rpMod = await import('../src/rp/server.js');
  merchantMod = await import('../src/merchant/server.js');
  agent = await import('../src/agent/agent.js');
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const { issueAndActivate } = await import('../src/rp/issue.js');
  const { loadRpIdentity, makeVcSigningFunction, STATUS_LIST_URL } = await import('../src/lib/wiring.js');

  const identity = loadRpIdentity();
  rpMod.ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: makeVcSigningFunction(identity.privateKeyBase64), url: STATUS_LIST_URL });
  await issueAndActivate({ index: 94, agentDid: process.env['AGENT_DID']!, audience: merchantDid, identity, statusListUrl: STATUS_LIST_URL });

  rp = rpMod.startRpServer(RP_PORT);
  merchant = merchantMod.startMerchantServer({ port: MERCHANT_PORT });
  await new Promise((r) => setTimeout(r, 300));
});

afterAll(async () => {
  await new Promise<void>((r) => merchant.httpServer.close(() => r()));
  await new Promise<void>((r) => rp.server.close(() => r()));
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('the stage, beat by beat', () => {
  it('0 · discovery: the agent reads acceptedTrustSchemes and decides to present', async () => {
    const d = await agent.discover(`http://localhost:${MERCHANT_PORT}`);
    expect(d.accepted).toBe(true);
    expect(d.scheme?.['id']).toBe('org.kya-os/delegation');
    expect(d.audience).toBe(merchantDid);
    expect(d.clockSkewSeconds).toBe(120);
  });

  it('1 · an authorized order inside the class and the cap, with a signed receipt', async () => {
    const r = await order('risotto', 2);
    expect(r.denied).toBe(false);
    expect(r.body['orderId']).toMatch(/^ORD-/);
    expect((r.body['order'] as Record<string, unknown>)['total']).toBe('CHF 39.80');
    expect((r.body['mandate'] as Record<string, unknown>)['responsibleParty']).toBe(process.env['RP_DID']);
    const proof = r.meta?.['org.kya-os/response-proof'] as { jws?: string } | undefined;
    expect(proof?.jws).toMatch(/^eyJ/);
  });

  it('1b · a lot-level Digital Link beneath the class is in scope', async () => {
    expect((await order('risotto-lot', 1)).denied).toBe(false);
  });

  it('2 · another GTIN is refused: PRODUCT_OUT_OF_SCOPE', async () => {
    const r = await order('olive-oil', 1);
    expect(r.denied).toBe(true);
    expect(r.code).toBe('PRODUCT_OUT_OF_SCOPE');
  });

  it('3 · over the cap is refused: SPEND_CAP_EXCEEDED', async () => {
    const r = await order('risotto', 5);
    expect(r.code).toBe('SPEND_CAP_EXCEEDED');
  });

  it('5 · a stolen credential with the wrong key is refused before the handler', async () => {
    const r = await order('risotto', 1, true);
    expect(r.code).toBe('holder_binding_failed');
  });

  it('V · the receipt re-verifies in stdlib Python with no SDK', async () => {
    const res = await fetch(`http://localhost:${MERCHANT_PORT}/api/act/verify-receipt`, { method: 'POST' });
    const j = (await res.json()) as { ok: boolean; report?: { checks: string[] } };
    expect(j.ok).toBe(true);
    expect(j.report?.checks.length).toBeGreaterThanOrEqual(6);

    // and a tampered content array is refused by the same script
    const last = (await (await fetch(`http://localhost:${MERCHANT_PORT}/api/receipt/last`)).json()) as { content: Array<{ text: string }> };
    const tampered = { receipt: { ...last, content: [{ type: 'text', text: last.content[0]!.text.replace('"ok":true', '"ok":false') }] }, merchant: { did: merchantDid, kid: `${merchantDid}#x`, publicKeyBase64: process.env['MERCHANT_PUBLIC_KEY_BASE64'] } };
    const py = spawnSync('python3', [path.join(process.cwd(), 'scripts', 'verify-receipt.py')], { input: JSON.stringify(tampered), encoding: 'utf8' });
    expect(py.status).toBe(1);
    expect(py.stdout).toMatch(/responseHash/);
  });

  it('K · the Responsible Party revokes; the next request is refused in one round trip', async () => {
    const res = await fetch(`http://localhost:${RP_PORT}/api/rp/revoke`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    const j = (await res.json()) as { revoked: boolean; version: number };
    expect(j.revoked).toBe(true);
    expect(j.version).toBe(2);
    const r = await order('risotto', 1);
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/revoked/i);
  });

  it('R · reset issues a fresh grant at the next index and orders work again', async () => {
    const res = await fetch(`http://localhost:${MERCHANT_PORT}/api/act/reset`, { method: 'POST' });
    const j = (await res.json()) as { index: number };
    expect(j.index).toBe(95);
    expect((await order('risotto', 1)).denied).toBe(false);
  });

  it('the hub going down fails CLOSED: status unresolvable → refused', async () => {
    await new Promise<void>((r) => rp.server.close(() => r()));
    merchant.statusListResolver.invalidateCache();
    const r = await order('risotto', 1);
    expect(r.denied).toBe(true);
    expect(r.reason).toMatch(/status|revocation|unresolvable/i);
    const rpMod = await import('../src/rp/server.js');
    rp = rpMod.startRpServer(RP_PORT);
    await new Promise((r) => setTimeout(r, 200));
    expect((await order('risotto', 1)).denied).toBe(false);
  });

  it('OFFLINE=1: the RP DID document is served from the mirror and verification still passes', async () => {
    const offline = merchantMod.startMerchantServer({ port: MERCHANT_PORT + 1, offline: true });
    await new Promise((r) => setTimeout(r, 200));
    try {
      const outcome = await agent.runAgentOrder({ product: 'risotto', quantity: 1, serverUrl: `http://localhost:${MERCHANT_PORT + 1}/mcp`, audience: merchantDid });
      expect(outcome.result.isError).toBeFalsy();
      const state = (await (await fetch(`http://localhost:${MERCHANT_PORT + 1}/api/state`)).json()) as { responsibleParty: { from: string } };
      expect(state.responsibleParty.from).toBe('mirror');
    } finally {
      await new Promise<void>((r) => offline.httpServer.close(() => r()));
    }
  });
});
