/**
 * Key-gated revocation over WebAuthn (FIDO2). Two phases:
 *
 *   POST /api/rp/revoke/challenge → build the revocation intent, return
 *                                   navigator.credentials.get() options whose
 *                                   challenge is sha256(intent).
 *   POST /api/rp/revoke/execute   → verify the assertion against ANY registered
 *                                   authenticator AND the intent hash, then (only
 *                                   on success) publish the revocation.
 *
 * Registration (/api/rp/key/register/*) is gated by KEY_SETUP=1 and accepts
 * both roaming keys (a security key, a conference badge) and platform
 * authenticators (Touch ID) — whichever is in the operator's hand on stage.
 *
 * Fail-safe: no valid touch → no assertion → 403 → nothing published.
 */
import { randomBytes } from 'node:crypto';
import { Hono } from 'hono';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { buildRevocationIntent } from './revocation-intent.js';
import {
  findAuthenticator,
  listAuthenticators,
  removeAuthenticator,
  saveAuthenticator,
  updateCounter,
  writeRevocationRecord,
} from './credential-store.js';
import type { RevokeOutcome } from '../revoke.js';

export interface KeyRoutesConfig {
  rpID: string;
  origin: string;
  rpName: string;
  setupEnabled: boolean;
  statusListUrl: () => string;
  currentIndex: () => number;
  performRevoke: (index: number) => Promise<RevokeOutcome>;
}

const OPERATOR_USER = new TextEncoder().encode('responsible-party');
const CHALLENGE_TTL_MS = 120_000;

export function createKeyRoutes(config: KeyRoutesConfig): Hono {
  const app = new Hono();
  let pendingRegistration: { challenge: string; label: string } | null = null;
  const pendingAuth = new Map<string, { challengeB64u: string; intent: unknown; index: number; expiresAt: number }>();

  // ---- registration (KEY_SETUP=1) -----------------------------------------

  app.get('/api/rp/key/list', (c) =>
    c.json({ authenticators: listAuthenticators().map((a) => ({ idTail: a.id.slice(-6), label: a.label, transports: a.transports ?? [], registeredAt: a.registeredAt })) }),
  );

  app.post('/api/rp/key/register/options', async (c) => {
    if (!config.setupEnabled) return c.json({ error: 'key setup disabled — start the hub with KEY_SETUP=1' }, 403);
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const label = String((body as Record<string, unknown>)['label'] ?? 'authenticator').slice(0, 40);
    const options = await generateRegistrationOptions({
      rpName: config.rpName,
      rpID: config.rpID,
      userID: OPERATOR_USER,
      userName: 'responsible-party',
      attestationType: 'none',
      // No attachment preference: a roaming key (badge, YubiKey) or the laptop's
      // platform authenticator (Touch ID) are both fine. Presence, not UV.
      authenticatorSelection: { userVerification: 'discouraged', residentKey: 'discouraged' },
      excludeCredentials: listAuthenticators().map((a) => ({ id: a.id, ...(a.transports ? { transports: a.transports as never } : {}) })),
    });
    pendingRegistration = { challenge: options.challenge, label };
    return c.json(options);
  });

  app.post('/api/rp/key/register/verify', async (c) => {
    if (!config.setupEnabled) return c.json({ error: 'key setup disabled' }, 403);
    if (!pendingRegistration) return c.json({ error: 'no registration in progress' }, 400);
    const response = await c.req.json();
    try {
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: pendingRegistration.challenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        requireUserVerification: false, // presence (touch), not UV (PIN/biometric)
      });
      if (!verification.verified || !verification.registrationInfo) return c.json({ verified: false }, 400);
      const { credential, aaguid } = verification.registrationInfo;
      saveAuthenticator({
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        ...(credential.transports ? { transports: credential.transports } : {}),
        ...(aaguid ? { aaguid } : {}),
        label: pendingRegistration.label,
        registeredAt: new Date().toISOString(),
      });
      pendingRegistration = null;
      return c.json({ verified: true, idTail: credential.id.slice(-6), aaguid: aaguid ?? null });
    } catch (err) {
      return c.json({ verified: false, error: err instanceof Error ? err.message : String(err) }, 400);
    }
  });

  app.post('/api/rp/key/remove', async (c) => {
    if (!config.setupEnabled) return c.json({ error: 'key setup disabled' }, 403);
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const idTail = String((body as Record<string, unknown>)['idTail'] ?? '');
    const match = listAuthenticators().find((a) => a.id.endsWith(idTail));
    if (!match) return c.json({ error: 'unknown authenticator' }, 404);
    removeAuthenticator(match.id);
    return c.json({ removed: idTail });
  });

  // ---- revocation, phase 1: challenge -------------------------------------

  app.post('/api/rp/revoke/challenge', async (c) => {
    const registered = listAuthenticators();
    if (registered.length === 0) return c.json({ error: 'no authenticator registered — open /setup-key.html with KEY_SETUP=1' }, 400);
    const index = config.currentIndex();
    const nonce = randomBytes(16).toString('base64url');
    const built = buildRevocationIntent({ statusListUrl: config.statusListUrl(), index, nonce, ts: Date.now() });
    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      allowCredentials: registered.map((a) => ({ id: a.id, ...(a.transports ? { transports: a.transports as never } : {}) })),
      challenge: built.digest, // the challenge IS sha256(intent)
      userVerification: 'discouraged',
      timeout: 60_000,
    });
    pendingAuth.set(nonce, { challengeB64u: built.challengeB64u, intent: built.intent, index, expiresAt: Date.now() + CHALLENGE_TTL_MS });
    return c.json({ nonce, options, intentPreview: { index, challengeHead: built.challengeB64u.slice(0, 8), statusListUrl: config.statusListUrl() } });
  });

  // ---- revocation, phase 2: execute (assertion required) ------------------

  app.post('/api/rp/revoke/execute', async (c) => {
    const body = await c.req.json().catch(() => ({} as Record<string, unknown>));
    const nonce = String(body['nonce'] ?? '');
    const pending = pendingAuth.get(nonce);
    if (!pending || Date.now() > pending.expiresAt) {
      pendingAuth.delete(nonce);
      return c.json({ error: 'challenge expired or unknown — nothing revoked' }, 400);
    }
    const response = body['response'] as { id?: string } | undefined;
    const cred = response?.id ? findAuthenticator(response.id) : undefined;
    if (!cred) return c.json({ error: 'assertion is not from a registered authenticator — nothing revoked' }, 403);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body['response'] as never,
        expectedChallenge: pending.challengeB64u,
        expectedOrigin: config.origin,
        expectedRPID: config.rpID,
        credential: {
          id: cred.id,
          publicKey: new Uint8Array(Buffer.from(cred.publicKey, 'base64url')),
          counter: cred.counter,
          ...(cred.transports ? { transports: cred.transports as never } : {}),
        },
        requireUserVerification: false,
      });
    } catch (err) {
      return c.json({ error: `assertion rejected: ${err instanceof Error ? err.message : String(err)}` }, 403);
    }
    if (!verification.verified) return c.json({ error: 'assertion did not verify — nothing revoked' }, 403);

    // Success: consume the nonce (single use), advance the counter, write the
    // hardware-attested record, THEN publish the revocation.
    pendingAuth.delete(nonce);
    updateCounter(cred.id, verification.authenticationInfo.newCounter);
    const recordFile = writeRevocationRecord({
      intent: pending.intent,
      verifiedAt: new Date().toISOString(),
      authenticator: { label: cred.label, idTail: cred.id.slice(-6), aaguid: cred.aaguid ?? null },
      newCounter: verification.authenticationInfo.newCounter,
      userVerified: verification.authenticationInfo.userVerified,
    });
    const result = await config.performRevoke(pending.index);
    return c.json({ ...result, hardwareAttested: true, authenticator: cred.label, idTail: cred.id.slice(-6), recordFile });
  });

  return app;
}
