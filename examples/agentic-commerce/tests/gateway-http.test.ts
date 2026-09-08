/** Exercise the connector URL with a real HTTP MCP client and the published verifier. */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-http-'));
const crypto = new NodeCryptoProvider();
let demo: ChildProcess;
let merchantOrigin: string;
let rpOrigin: string;
let agentDid: string;
let merchantDid: string;
const scope = 'https://id.gs1.org/01/09506000134352';
const rpcHeaders = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
const initialize = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
  protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'claude-http-test', version: '1.0' },
} };

async function withClient<T>(run: (client: Client) => Promise<T>, endpoint = '/agent/mcp') {
  const transport = new StreamableHTTPClientTransport(new URL(`${merchantOrigin}${endpoint}`));
  const client = new Client({ name: 'claude-http-test', version: '1.0' });
  try {
    await client.connect(transport);
    expect(transport.sessionId).toBeUndefined();
    return await run(client);
  } finally { await client.close(); }
}

const callTool = (name: string, args: Record<string, unknown> = {}) =>
  withClient((client) => client.callTool({ name, arguments: args }));
const order = (product = 'risotto', quantity = 2) => callTool('place_order', { product, quantity });
const textOf = (result: Awaited<ReturnType<typeof callTool>>) =>
  (result.content as Array<{ text: string }>).map((item) => item.text).join('\n');
type Challenge = { authorizationUrl: string; resumeToken: string; scopes: string[] };
async function consent(challenge: Challenge, decision: 'approve' | 'deny', selectedScopes = challenge.scopes) {
  return fetch(new URL(`/consent/${decision}`, challenge.authorizationUrl), {
    method: 'POST',
    body: new URLSearchParams({
      tool: 'place_order', scopes: JSON.stringify(challenge.scopes), selected_scopes: JSON.stringify(selectedScopes),
      agent_did: agentDid, session_id: challenge.resumeToken,
    }),
  });
}
const state = async () => (await fetch(`${merchantOrigin}/api/state`)).json() as Promise<{ orders: number }>;

async function unusedPort() {
  const server = http.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

beforeAll(async () => {
  const [rpKeys, merchantKeys, agentKeys] = await Promise.all([
    crypto.generateKeyPair(), crypto.generateKeyPair(), crypto.generateKeyPair(),
  ]);
  const rpPort = await unusedPort();
  let merchantPort = await unusedPort();
  while (merchantPort === rpPort) merchantPort = await unusedPort();
  merchantOrigin = `http://127.0.0.1:${merchantPort}`;
  rpOrigin = `http://127.0.0.1:${rpPort}`;
  merchantDid = generateDidKeyFromBase64(merchantKeys.publicKey);
  agentDid = generateDidKeyFromBase64(agentKeys.publicKey);
  for (const [key, value] of Object.entries({
    DEMO_VAR_DIR: path.join(tmp, 'var'), DEMO_DATA_DIR: path.join(tmp, 'data'),
    RP_PORT: String(rpPort), MERCHANT_PORT: String(merchantPort), RP_ORIGIN: rpOrigin, MERCHANT_ORIGIN: merchantOrigin,
    RP_DID: `did:web:localhost%3A${rpPort}`, RP_KID: `did:web:localhost%3A${rpPort}#key-1`,
    STATUS_LIST_URL: `${rpOrigin}/status-list`, RP_DID_MIRROR_URL: `${rpOrigin}/.well-known/did.json`,
    RP_PRIVATE_KEY_BASE64: rpKeys.privateKey, RP_PUBLIC_KEY_BASE64: rpKeys.publicKey,
    MERCHANT_DID: merchantDid, MERCHANT_PRIVATE_KEY_BASE64: merchantKeys.privateKey, MERCHANT_PUBLIC_KEY_BASE64: merchantKeys.publicKey,
    AGENT_DID: agentDid, AGENT_ED25519_PRIVATE_KEY_BASE64: agentKeys.privateKey, AGENT_ED25519_PUBLIC_KEY_BASE64: agentKeys.publicKey,
    GOOGLE_CLIENT_ID: '', KEY_WEBAUTHN: '0', CONSENT_WEBAUTHN: '0', KEY_SETUP: '0', OFFLINE: '0', AUDIT_WITNESS: '0',
  })) vi.stubEnv(key, value);
  const rpModule = await import('../src/rp/server.js');
  const { ensureStatusList } = await import('../src/rp/statuslist.js');
  const { loadRpIdentity, makeVcSigningFunction, STATUS_LIST_URL } = await import('../src/lib/wiring.js');
  const identity = loadRpIdentity();
  rpModule.ensureDidDocument(identity);
  await ensureStatusList({ identity, signingFunction: makeVcSigningFunction(identity.privateKeyBase64), url: STATUS_LIST_URL });
  // Qualify the real user entrypoint, including path resolution when launched
  // from elsewhere. npm and its children form a separately owned process group.
  const exampleRoot = fileURLToPath(new URL('..', import.meta.url));
  demo = spawn('npm', ['--prefix', exampleRoot, 'run', 'demo'], {
    cwd: os.tmpdir(), env: process.env, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise<void>((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error(`Demo did not start: ${output}`)), 8000);
    const startupError = (error: Error) => { clearTimeout(timeout); reject(error); };
    const exited = (code: number | null) => startupError(new Error(`Demo exited ${code}: ${output}`));
    demo.once('error', startupError);
    demo.once('exit', exited);
    const read = (chunk: Buffer) => {
      output += chunk.toString();
      if (!output.includes('Merchant edge:')) return;
      clearTimeout(timeout);
      demo.off('exit', exited);
      demo.off('error', startupError);
      resolve();
    };
    demo.stdout!.on('data', read);
    demo.stderr!.on('data', read);
  });
});

afterAll(async () => {
  if (demo?.pid && demo.exitCode === null && demo.signalCode === null) {
    await new Promise<void>((resolve) => {
      demo.once('exit', () => resolve());
      process.kill(-demo.pid!, 'SIGTERM');
    });
  }
  fs.rmSync(tmp, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe('Claude connector at /agent/mcp', () => {
  it('initializes using Streamable HTTP without allocating an MCP session', async () => {
    const response = await fetch(`${merchantOrigin}/agent/mcp`, {
      method: 'POST',
      headers: rpcHeaders,
      body: JSON.stringify(initialize),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('mcp-session-id')).toBeNull();
    const body = await response.json();
    expect(body.result).toMatchObject({ serverInfo: { name: 'kya-shopping-agent' }, capabilities: { tools: {} } });
  });

  it('accepts tools/list independently of initialize and discloses only ordinary shopping arguments', async () => {
    const response = await fetch(`${merchantOrigin}/agent/mcp`, {
      method: 'POST', headers: rpcHeaders,
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('mcp-session-id')).toBeNull();
    const { result } = await response.json();
    expect(result.tools.map((tool: { name: string }) => tool.name)).toEqual(['browse_catalog', 'place_order']);
    const orderTool = result.tools.find((tool: { name: string }) => tool.name === 'place_order');
    expect(Object.keys(orderTool.inputSchema.properties).sort()).toEqual(['product', 'quantity']);
    expect(JSON.stringify(result)).not.toMatch(/_kyaos|privateKey|resumeToken/);
  });

  it.each(['GET', 'DELETE'])('returns an explicit method refusal for %s without a session', async (method) => {
    const response = await fetch(`${merchantOrigin}/agent/mcp`, { method, headers: rpcHeaders });
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('POST');
    expect(response.headers.get('mcp-session-id')).toBeNull();
  });

  it.each([{ Host: 'attacker.example' }, { Origin: 'https://attacker.example' }])('refuses a foreign HTTP authority: %j', async (headers) => {
    const before = await state();
    // node:http preserves a deliberate Host header; Node fetch replaces it.
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const request = http.request(`${merchantOrigin}/agent/mcp`, {
        method: 'POST', headers: { ...rpcHeaders, ...headers },
      }, (response) => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      });
      request.on('error', reject);
      request.end(JSON.stringify(initialize));
    });
    expect(status).toBe(403);
    expect((await state()).orders).toBe(before.orders);
  });

  it('serves fresh and parallel MCP clients without a server-side transport session', async () => {
    // These are the first merchant tool requests after startup. Initializing
    // response signing concurrently must never leave a consent URL unsigned.
    const [catalog, ...challenges] = await Promise.all([callTool('browse_catalog'), order(), order()]);
    challenges.push(await order());
    const tokens = [];
    for (const challenge of challenges) {
      expect(challenge.isError, textOf(challenge)).toBeFalsy();
      const body = JSON.parse(textOf(challenge));
      expect(body).toMatchObject({ error: 'needs_authorization', scopes: [scope] });
      tokens.push(body.resumeToken);
    }
    expect(new Set(tokens).size).toBe(3);
    for (const response of [catalog, await callTool('browse_catalog')]) {
      expect(response.isError).toBeFalsy();
      expect(textOf(response)).toMatch(/risotto/i);
      expect(textOf(response)).toContain(scope);
    }
  });

  it('keeps the direct merchant endpoint holder-bound', async () => {
    const result = await withClient((client) => client.callTool({ name: 'place_order', arguments: { product: 'risotto', quantity: 2 } }), '/mcp');
    expect(result.isError).toBe(true);
    expect(JSON.parse(textOf(result)).error).toBe('holder_binding_failed');
    expect((await state()).orders).toBe(0);
  });

  it('carries human consent, narrowed authority, order refusals, and live revocation across fresh HTTP connections', async () => {
    const declined = JSON.parse(textOf(await order())) as Challenge;
    expect(new URL(declined.authorizationUrl).origin).toBe(rpOrigin);
    expect(new URL(declined.authorizationUrl).pathname).toBe('/consent');
    expect((await consent(declined, 'deny')).ok).toBe(true);
    expect((await fetch(`${rpOrigin}/api/rp/delegation`)).status).toBe(404);
    expect((await consent(declined, 'approve')).ok).toBe(false);

    const challengeResult = await order();
    const challenge = JSON.parse(textOf(challengeResult)) as Challenge & { error: string };
    expect(challenge.error).toBe('needs_authorization');
    expect(challenge.scopes).toEqual([scope]);
    expect(challenge.resumeToken).not.toBe(declined.resumeToken);
    const consentPage = await fetch(challenge.authorizationUrl);
    expect(consentPage.status).toBe(200);
    expect(await consentPage.text()).toContain('mcp-consent');

    // An unchecked permission cannot be replaced with the original URL scopes.
    expect((await consent(challenge, 'approve', [])).ok).toBe(false);
    expect((await fetch(`${rpOrigin}/api/rp/delegation`)).status).toBe(404);
    expect((await state()).orders).toBe(0);
    const approved = await consent(challenge, 'approve');
    expect(approved.ok, await approved.text()).toBe(true);
    const { credential } = await (await fetch(`${rpOrigin}/api/rp/delegation`)).json();
    expect(credential.credentialSubject.id).toBe(agentDid);
    expect(credential.credentialSubject.delegation.constraints).toMatchObject({
      audience: merchantDid,
      crisp: { scopes: [{ resource: scope, constraints: { maxAmount: '50.00', currency: 'CHF' } }] },
    });

    // Reconnecting reloads the human-approved grant. Its first use may change
    // quantity within the grant; it is not tied to the original order request.
    const accepted = await order('risotto', 1);
    expect(accepted.isError, textOf(accepted)).toBeFalsy();
    expect(textOf(accepted)).toMatch(/Order ORD-.*placed/);
    expect(textOf(accepted)).toContain('CHF 19.90');
    expect((await state()).orders).toBe(1);

    for (const [product, quantity, code] of [
      ['olive-oil', 1, 'PRODUCT_OUT_OF_SCOPE'], ['risotto', 5, 'SPEND_CAP_EXCEEDED'],
    ] as const) {
      const refused = await order(product, quantity);
      expect(refused.isError).toBe(true);
      expect(textOf(refused)).toContain(code);
      expect((await state()).orders).toBe(1);
    }

    // These are separate intentional orders with fresh proofs, not retries of
    // one business effect. Concurrent calls must not cross-bind response hashes.
    const parallel = await Promise.all([order('risotto', 1), order('risotto', 2)]);
    for (const result of parallel) expect(result.isError, textOf(result)).toBeFalsy();
    expect(textOf(parallel[0]!)).toContain('CHF 19.90');
    expect(textOf(parallel[1]!)).toContain('CHF 39.80');
    expect((await state()).orders).toBe(3);

    const revoked = await fetch(`${rpOrigin}/api/rp/revoke`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    expect(revoked.status).toBe(200);
    expect((await revoked.json()).revoked).toBe(true);
    const refused = await order('risotto', 1);
    expect(refused.isError).toBe(true);
    expect(textOf(refused)).toMatch(/revoked/i);
    expect((await state()).orders).toBe(3);

    const ledger = await (await fetch(`${merchantOrigin}/api/audit/ledger`)).json();
    const types = ledger.entries.map((entry: { eventType: string }) => entry.eventType);
    expect(types).toEqual(expect.arrayContaining(['consent.denied', 'consent.approved', 'delegation.issued', 'authorization.approved', 'delegation.revoked', 'authorization.denied']));
    expect(types.indexOf('consent.approved')).toBeLessThan(types.indexOf('authorization.approved'));
    expect(types.slice(types.indexOf('delegation.revoked') + 1)).toContain('authorization.denied');
  });
});
