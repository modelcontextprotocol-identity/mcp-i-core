import fs from 'node:fs';
import vm from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import { renderConsent } from '../src/rp/consent-page.js';
import type { HumanAccount } from '../src/rp/human-identity.js';
import type { ConsentFlow } from '../src/rp/consent-store.js';

vi.mock('../src/rp/key/credential-store.js', () => ({
  hasAuthenticator: () => false,
  listAuthenticators: () => [],
}));

// Exercise the actual projector script through its public SSE and HTTP inputs.
// This tiny DOM only implements the primitives this framework-free page uses.
class Element {
  textContent = '';
  innerHTML = '';
  className = '';
  hidden = false;
  disabled = false;
  href = '';
  title = '';
  style: Record<string, string> = {};
  children: Element[] = [];
  onclick: (() => unknown) | null = null;
  classList = {
    add: (name: string) => { this.className += ` ${name}`; },
    remove: (name: string) => { this.className = this.className.split(' ').filter((n) => n !== name).join(' '); },
    contains: (name: string) => this.className.split(' ').includes(name),
    toggle: (name: string, force?: boolean) => {
      if (force ?? !this.classList.contains(name)) this.classList.add(name);
      else this.classList.remove(name);
    },
  };
  appendChild(child: Element) { this.children.push(child); }
  replaceChildren(...children: Element[]) { this.children = children; }
  prepend(child: Element) { this.children.unshift(child); }
  querySelector() { const child = new Element(); this.children.push(child); return child; }
  scrollIntoView() {}
  removeAttribute(name: string) { if (name === 'href') this.href = ''; }
  setAttribute(name: string, value: string) { if (name === 'href') this.href = value; }
}

// Extract the trusted local fixture script for VM execution, not HTML sanitization.
function inlinePageScript(html: string): string {
  const script = html.match(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/i)?.[1];
  if (script === undefined) throw new Error('The local page fixture has no inline script');
  return script;
}

async function projector(initialChallenge?: Record<string, unknown>, credential: unknown = null,
  html = fs.readFileSync(new URL('../web/index.html', import.meta.url), 'utf8')) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => [match[1]!, new Element()]));
  const streams = new Map<string, { onmessage?: (event: { data: string }) => void }>();
  const state = { credential, responses: {} as Record<string, unknown> };
  const get = (id: string) => {
    const element = elements.get(id);
    if (!element) throw new Error(`Missing projector element #${id}`);
    return element;
  };
  const context = vm.createContext({
    URL, Date, console, setTimeout, clearTimeout,
    document: {
      getElementById: get, createElement: () => new Element(),
      body: new Element(), querySelectorAll: () => [], addEventListener: () => {},
    },
    fetch: async (url: string) => ({ json: async () => Object.hasOwn(state.responses, url)
      ? state.responses[url] : url.endsWith('/api/state')
      ? { responsibleParty: { hubOrigin: 'http://localhost:4950' }, authorizationChallenge: initialChallenge }
      : url.endsWith('/api/rp/state')
        ? { statusList: { version: 1 }, activeIndex: null, revoked: false }
        : url.includes('/consent/status?') ? { state: 'pending' }
        : { credential: state.credential } }),
    EventSource: class { constructor(url: string) { streams.set(url, this); } },
  });
  vm.runInContext(inlinePageScript(html), context);
  await new Promise((resolve) => setTimeout(resolve, 0));
  const emit = (stream: string, data: Record<string, unknown>) => {
    const source = streams.get(stream);
    if (!source?.onmessage) throw new Error(`Missing SSE stream ${stream}`);
    source.onmessage({ data: JSON.stringify(data) });
  };
  return { get, emit, state };
}

const attributePayload = `\" onpointerenter=\"globalThis.projectorInjected=1\" data-injected=\"'&<>`;
const encodedPayload = '&quot; onpointerenter=&quot;globalThis.projectorInjected=1&quot; data-injected=&quot;&#39;&amp;&lt;&gt;';
const digestPayload = 'sha256:<b>bad</b>';

function auditFixture() {
  return {
    ledger: { ledgerId: 'test-ledger', ledgerEpochId: 'test-epoch' },
    entries: [{ seq: attributePayload, outcome: attributePayload, eventType: 'order', reason: attributePayload,
      at: '2026-09-08T12:00:00Z', anchored: true, entryDigest: digestPayload, previousEntryDigest: null }],
    checkpoint: { rootDigest: digestPayload, treeSize: 1, createdAt: Date.now() },
    witness: { observer: { did: 'did:key:witness' }, observedAt: Date.now(), observationDigest: digestPayload },
    profile: { advertised: 'AAP-2' }, tree: [{ hash: digestPayload }, { hash: digestPayload, leafIndex: 0, prefix: '└ ', label: '[0]' }],
    inclusions: [], allIncluded: true, chainIntact: true,
  };
}

describe('projector untrusted receipt and audit rendering', () => {
  it('keeps quote-bearing receipt fields literal through the actual merchant SSE handler', async () => {
    const p = await projector();
    p.emit('/api/events', {
      type: 'verdict', verdict: 'allowed', elapsedMs: 1,
      body: { ok: true, orderId: attributePayload,
        order: { name: 'Risotto', product: attributePayload, quantity: 2, unitPrice: '19.90', total: '39.80' },
        mandate: { responsibleParty: attributePayload } },
      receipt: { jws: attributePayload, meta: { kid: attributePayload } },
    });
    expect(p.get('receipt').innerHTML).toContain(`<div class="jws" id="jws">${encodedPayload}</div>`);
    expect(p.get('receipt').innerHTML).not.toContain('" onpointerenter="');
  });

  it('contains ledger identifiers, outcomes and reason text inside their intended attributes', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = auditFixture();
    await p.get('btn-audit').onclick!();
    const table = p.get('audit-table').innerHTML;
    expect(table).toContain(`class="o-${encodedPayload}"`);
    expect(table).toContain(`id="ledger-row-${encodedPayload}"`);
    expect(table).toContain(`title="${encodedPayload}"`);
    expect(table).not.toContain('" onpointerenter="');
  });

  it('contains verdict classes, dimension/reason titles and exported commands inside their attributes', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = auditFixture();
    p.state.responses['/api/act/export'] = {
      components: [{ path: attributePayload, size: 12 }], command: { honest: attributePayload }, manifestDigest: digestPayload,
      reports: { honest: { [attributePayload]: { verdict: attributePayload, reasonCodes: [attributePayload] } }, tampered: {} },
    };
    await p.get('btn-export').onclick!();
    expect(p.get('audit-export').innerHTML).toContain(`title="${encodedPayload}"`);
    expect(p.get('audit-export').innerHTML).toContain('manifest &lt;b&gt;bad&lt;/b&gt; signed');
    const verdicts = p.get('audit-verdicts').innerHTML;
    expect(verdicts).toContain(`class="verdict ${encodedPayload}"`);
    expect(verdicts).toContain(`title="${encodedPayload}: ${encodedPayload} ${encodedPayload}"`);
    expect(verdicts).not.toContain('" onpointerenter="');
  });

  it('escapes ledger, tree and witness digest prefixes without changing ordinary digest or text labels', async () => {
    const p = await projector();
    p.state.responses['/api/act/audit'] = auditFixture();
    await p.get('btn-audit').onclick!();
    for (const id of ['audit-table', 'audit-tree-root', 'audit-tree', 'audit-cp']) {
      expect(p.get(id).innerHTML, id).toContain('&lt;b&gt;bad&lt;/b&gt;');
      expect(p.get(id).innerHTML, id).not.toContain('<b>bad</b>');
    }
    p.emit('/api/events', { type: 'audit', entries: 1, rootDigest: digestPayload, treeSize: 1 });
    expect(p.get('audit-root').textContent).toBe('root <b>bad</b>… · 1 leaves');
    for (const digest of ['0123456789abcdef0123456789abcdef', 'Ab_C-deF0123456789_ab-CdeF0123456']) {
      const ordinary = auditFixture();
      ordinary.entries[0]!.entryDigest = 'sha256:' + digest;
      ordinary.tree[0]!.hash = 'sha256:' + digest;
      p.state.responses['/api/act/audit'] = ordinary;
      await p.get('btn-audit').onclick!();
      expect(p.get('audit-table').innerHTML).toContain(`<td class="digest">${digest.slice(0, 10)}</td>`);
      expect(p.get('audit-tree-root').innerHTML).toContain(`<span class="h">${digest.slice(0, 24)}</span>`);
      p.emit('/api/events', { type: 'audit', entries: 1, rootDigest: 'sha256:' + digest, treeSize: 1 });
      expect(p.get('audit-root').textContent).toBe(`root ${digest.slice(0, 16)}… · 1 leaves`);
    }
  });

  it('escapes RP revocation timing before sending it into the log HTML', async () => {
    const p = await projector();
    p.emit('http://localhost:4950/api/rp/events', { type: 'revoke_phase', elapsedMs: '<b>bad</b>', phase: 'test' });
    const markup = p.get('rp-log').children.flatMap(row => row.children.map(child => child.innerHTML)).join('');
    expect(markup).toContain('&lt;b&gt;bad&lt;/b&gt;');
    expect(markup).not.toContain('<b>bad</b>');
  });
});

const challenge = {
  type: 'verdict', verdict: 'needs_authorization', elapsedMs: 10,
  body: {
    error: 'needs_authorization', resumeToken: 'human-grant-session',
    authorizationUrl: 'http://127.0.0.1:4950/consent?session_id=human-grant-session',
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    scopes: ['https://id.gs1.org/01/09506000134352'],
  },
};

function namedGrant(displayName = 'Dylan Hobbs') {
  return {
    issuer: 'did:web:localhost%3A4950',
    credentialSubject: {
      id: 'did:key:shopping-agent',
      delegation: {
        constraints: { audience: 'did:key:merchant' },
        metadata: {
          demoConsent: {
            consentRef: 'sha256:consent-reference',
            human: { provider: 'google', issuer: 'https://accounts.google.com', accountRef: 'google-account-reference', identitySource: 'identity-provider', displayName },
            authentication: { method: 'webauthn', credentialRef: 'sha256:passkey-reference', intentHash: 'sha256:intent-reference', userVerified: true },
            approvedAt: '2026-09-08T12:00:00Z',
          },
        },
      },
    },
  };
}

describe('projector human-grant journey', () => {
  it('executes the actual projector page when HTML uses uppercase script tags', async () => {
    const html = fs.readFileSync(new URL('../web/index.html', import.meta.url), 'utf8')
      .replaceAll('<script>', '<SCRIPT>').replaceAll('</script>', '</SCRIPT>');
    const p = await projector(undefined, namedGrant(), html);
    expect(p.get('c-human').textContent).toBe('Dylan Hobbs');
    expect(p.get('verdict-code').textContent).toBe('GRANT ACTIVE · READY TO ORDER');
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('grant-pill').textContent).toBe('no grant');
  });

  it('renders consent as a separate gate and preserves proven holder identity while consent is pending', async () => {
    const p = await projector();
    p.emit('/api/events', { ...challenge, checks: { signature: 'skip', revocation: 'skip', holder: 'pass', product: 'skip', cap: 'skip', consent: 'pending', receipt: 'skip' } });
    const gates = p.get('gates').children;
    expect(gates).toHaveLength(7);
    expect(gates[0]!.className).toBe('gate skip');
    expect(gates[2]!.className).toBe('gate pass');
    expect(gates[5]!.innerHTML).toContain('Human consent');
    expect(gates[5]!.className).toBe('gate pending');
  });

  it('shows a consent binding refusal without repainting a verified signature as failed', async () => {
    const p = await projector();
    p.emit('/api/events', { type: 'verdict', verdict: 'denied', code: 'CONSENT_BINDING_MISMATCH', reason: 'Resume token binding differs from this credential.', checks: { signature: 'pass', revocation: 'pass', holder: 'pass', product: 'pass', cap: 'pass', consent: 'fail', receipt: 'skip' } });
    const gates = p.get('gates').children;
    expect(gates[0]!.className).toBe('gate pass');
    expect(gates[5]!.className).toBe('gate fail');
    expect(p.get('verdict-code').textContent).toBe('CONSENT_BINDING_MISMATCH');
  });

  it('shows the Google account, passkey, signed consent and agent relationship from grant metadata', async () => {
    const p = await projector(undefined, namedGrant());
    expect(p.get('human-grant').hidden).toBe(false);
    expect(p.get('c-human').textContent).toBe('Dylan Hobbs');
    expect(p.get('c-human-source').textContent).toContain('Google account');
    expect(p.get('c-human-authentication').textContent).toContain('Passkey confirmed');
    expect(p.get('c-human-consent').textContent).toContain('consent-reference');
    expect(p.get('c-agent').textContent).toBe('did:key:shopping-agent');
    expect(p.get('verdict-code').textContent).toBe('GRANT ACTIVE · READY TO ORDER');
  });

  it('renders provider profile text literally and clears the named relationship on reset', async () => {
    const profile = '<img src=x onerror=alert(1)>';
    const p = await projector(undefined, namedGrant(profile));
    expect(p.get('c-human').textContent).toBe(profile);
    expect(p.get('c-human').innerHTML).toBe('');
    p.state.credential = null;
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('human-grant').hidden).toBe(true);
    expect(p.get('c-human').textContent).toBe('');
  });

  it('makes no named-human claim for self-declared metadata', async () => {
    const grant = namedGrant();
    grant.credentialSubject.delegation.metadata.demoConsent.human.identitySource = 'self-declared';
    const p = await projector(undefined, grant);
    expect(p.get('human-grant').hidden).toBe(true);
    expect(p.get('c-human').textContent).toBe('');
  });

  it('keeps legacy grants readable without attributing them to a named Google account', async () => {
    const grant = namedGrant();
    const { metadata: _metadata, ...delegation } = grant.credentialSubject.delegation;
    const legacy = { ...grant, credentialSubject: { ...grant.credentialSubject, delegation } };
    const p = await projector(undefined, legacy);
    expect(p.get('grant-pill').textContent).toBe('active');
    expect(p.get('human-grant').hidden).toBe(true);
    expect(p.get('c-human').textContent).toBe('');
  });
  it('starts with an explicit missing grant and displays the live challenge link', async () => {
    const p = await projector();
    expect(p.get('grant-pill').textContent).toBe('no grant');
    p.emit('/api/events', challenge);
    expect(p.get('seal').textContent).toBe('CONSENT NEEDED');
    expect(p.get('authorization-panel').hidden).toBe(false);
    expect(p.get('authorization-link').href).toBe(challenge.body.authorizationUrl);
    expect(p.get('authorization-detail').textContent).toContain('09506000134352');
  });

  it('never makes an unrelated authorization origin clickable', async () => {
    const p = await projector();
    p.emit('/api/events', { ...challenge, body: { ...challenge.body, authorizationUrl: 'https://attacker.example/consent' } });
    expect(p.get('authorization-link').href).toBe('');
    expect(p.get('verdict-code').textContent).toBe('AUTHORIZATION_URL_REJECTED');
  });

  it('recovers a still-pending challenge when the operator opens the console late', async () => {
    const p = await projector(challenge.body);
    expect(p.get('authorization-panel').hidden).toBe(false);
    expect(p.get('authorization-link').href).toBe(challenge.body.authorizationUrl);
  });

  it('refuses expired consent URLs and ignores approvals of a different request', async () => {
    const p = await projector();
    p.emit('/api/events', { ...challenge, body: { ...challenge.body, expiresAt: 1 } });
    expect(p.get('verdict-code').textContent).toBe('AUTHORIZATION_EXPIRED');
    expect(p.get('authorization-link').href).toBe('');
    p.emit('/api/events', challenge);
    p.emit('http://localhost:4950/api/rp/events', { type: 'consent.approved', resumeToken: 'another-request', index: 95 });
    expect(p.get('seal').textContent).toBe('CONSENT NEEDED');
    expect(p.get('authorization-panel').hidden).toBe(false);
  });

  it('marks approval as ready for retry, and hides the single-use URL', async () => {
    const p = await projector();
    p.emit('/api/events', challenge);
    p.emit('http://localhost:4950/api/rp/events', { type: 'consent.approved', sessionId: 'human-grant-session', index: 94 });
    expect(p.get('seal').textContent).toBe('GRANT APPROVED');
    expect(p.get('authorization-panel').hidden).toBe(true);
    expect(p.get('verdict-code').textContent).toContain('RETRY');
  });

  it('shows human denial without inventing a grant and resets to no consent', async () => {
    const p = await projector();
    p.emit('/api/events', challenge);
    p.emit('http://localhost:4950/api/rp/events', { type: 'consent.denied', sessionId: 'human-grant-session' });
    expect(p.get('seal').textContent).toBe('DENIED');
    expect(p.get('verdict-code').textContent).toBe('CONSENT_DENIED');
    expect(p.get('authorization-panel').hidden).toBe(true);
    p.emit('/api/events', { type: 'reset' });
    expect(p.get('grant-pill').textContent).toBe('no grant');
    expect(p.get('verdict-code').textContent).toBe('NO GRANT · HUMAN CONSENT REQUIRED');
  });
});

async function registrationPage(signedIn: boolean, displayName = 'Dylan Hobbs', label = 'Platform passkey', identityEnabled = true,
  html = fs.readFileSync(new URL('../web/setup-key.html', import.meta.url), 'utf8')) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1]!, new Element()]));
  const requests: Array<{ url: string; credentials?: string }> = [];
  const get = (id: string) => {
    const element = elements.get(id);
    if (!element) throw new Error(`Missing registration element #${id}`);
    return element;
  };
  const context = vm.createContext({
    URL, console, location: { origin: identityEnabled ? 'http://localhost:4950' : 'http://localhost:4949', href: 'http://localhost:4950/setup-key.html' },
    document: { getElementById: get, createElement: () => new Element() },
    fetch: async (url: string, options?: { credentials?: string }) => {
      requests.push({ url, credentials: options?.credentials });
      const data = url.endsWith('/api/state') ? (identityEnabled ? {} : { responsibleParty: { hubOrigin: 'http://localhost:4950' } })
        : url.endsWith('/api/rp/state') ? { googleIdentityEnabled: identityEnabled }
          : url.endsWith('/auth/account') ? { enabled: true, signedIn, account: signedIn ? { provider: 'google', displayName, identitySource: 'identity-provider', accountRef: 'account-ref' } : null }
            : { authenticators: [{ label, idTail: 'abcd', registeredAt: '2026-09-08T12:00:00Z', transports: ['internal'] }] };
      return { ok: true, json: async () => data };
    },
  });
  vm.runInContext(inlinePageScript(html), context);
  await new Promise(resolve => setTimeout(resolve, 0));
  return { get, requests };
}

describe('account-bound passkey registration page', () => {
  it('executes the actual registration page when HTML uses uppercase script tags', async () => {
    const html = fs.readFileSync(new URL('../web/setup-key.html', import.meta.url), 'utf8')
      .replaceAll('<script>', '<SCRIPT>').replaceAll('</script>', '</SCRIPT>');
    const page = await registrationPage(true, 'Workshop Test Human', 'Platform passkey', true, html);
    expect(page.get('account-name').textContent).toBe('Workshop Test Human');
    expect(page.get('go').disabled).toBe(false);
    expect(page.requests.some(request => request.url.endsWith('/auth/account'))).toBe(true);
  });

  it('preserves noncredentialed cross-origin RP requests for legacy registration', async () => {
    const page = await registrationPage(false, '', 'Platform passkey', false);
    expect(page.get('go').disabled).toBe(false);
    expect(page.get('account-panel').hidden).toBe(true);
    expect(page.requests.filter(request => request.url.startsWith('http://localhost:4950')).every(request => request.credentials === 'same-origin')).toBe(true);
  });
  it('requires Google sign-in before offering passkey registration on the RP origin', async () => {
    const page = await registrationPage(false);
    expect(page.get('go').disabled).toBe(true);
    expect(page.get('sign-in').hidden).toBe(false);
    expect(page.get('sign-in').href).toBe('http://localhost:4950/auth/login?return_to=%2Fsetup-key.html');
  });

  it('uses provider profile text and renders authenticator labels without HTML injection', async () => {
    const unsafe = '<img src=x onerror=alert(1)>';
    const page = await registrationPage(true, unsafe, unsafe);
    expect(page.get('account-name').textContent).toBe(unsafe);
    expect(page.get('account-name').innerHTML).toBe('');
    expect(page.get('registered').children[0]?.textContent).toContain(unsafe);
    expect(page.get('registered').children[0]?.innerHTML).toBe('');
    expect(page.get('go').disabled).toBe(false);
    expect(page.requests.filter(request => request.url.endsWith('/auth/account') || request.url.includes('/api/rp/key')).every(request => request.credentials === 'include')).toBe(true);
  });
});

describe('named consent rendering', () => {
  it('escapes the provider name, omits private claims, and requires a passkey for an account without one', () => {
    const account: HumanAccount = {
      id: 'local-account-ref', provider: 'google', issuer: 'https://accounts.google.com',
      subject: 'private-google-subject', email: 'private-google-email@example.test', emailVerified: true,
      displayName: '<img src=x onerror=alert(1)>', authenticatedAt: '2026-09-08T12:00:00Z',
    };
    const flow: ConsentFlow = {
      challenge: {
        error: 'needs_authorization', message: 'Human consent required',
        authorizationUrl: 'http://localhost:4950/consent?resume_token=fixture',
        resumeToken: 'fixture-token-for-human-consent', expiresAt: 2_000_000_000,
        scopes: ['https://id.gs1.org/01/09506000134352'], display: { title: 'Approve grant', hint: ['link'] },
      },
      bindings: { agentDid: 'did:key:shopping-agent', audience: 'did:key:merchant', product: 'risotto', quantity: 2, productClass: 'https://id.gs1.org/01/09506000134352', cap: '50.00', currency: 'CHF', validHours: 48 },
      state: 'pending', createdAt: '2026-09-08T12:00:00Z',
    };
    const html = renderConsent(flow, {
      identity: { did: 'did:web:localhost%3A4950', kid: 'issuer-key', privateKeyBase64: '', publicKeyBase64: '' },
      agentDid: () => flow.bindings.agentDid, merchantDid: () => flow.bindings.audience,
      statusListUrl: 'http://localhost:4950/status-list', broadcast: () => {},
    }, 'http://localhost:4950', account);
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain(account.subject);
    expect(html).not.toContain(account.email);
    const bridge = JSON.parse(html.match(/<script id="consent-ui-data" type="application\/json">([^<]*)<\/script>/)![1]!);
    expect(bridge.capabilities).toHaveLength(1);
    expect(bridge.capabilities[0].scopes).toEqual([flow.bindings.productClass]);
    expect(bridge.capabilities[0].cedar).toBeUndefined();
    expect(html).toContain('slot="identity"');
    expect(html).toContain('slot="notice"');
    expect(html).toContain('data-valid-hours="48"');
    expect(bridge.webauthnRequired).toBe(true);
    expect(bridge.needsRegistration).toBe(true);
    expect(bridge.human.identitySource).toBe('identity-provider');
    expect(html).toContain('http://localhost:4950/setup-key.html');
    expect(html).toContain('Passkey approval required');
  });
});
