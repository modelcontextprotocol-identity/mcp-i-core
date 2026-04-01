/**
 * ProofVerifier Integration Tests (Real Crypto)
 *
 * Companion to verifier.test.ts — these tests use real Ed25519 signing,
 * real nonce caching, and real clock providers instead of mocking.
 *
 * The mocked unit tests verify pipeline logic and error code propagation.
 * These integration tests verify that real proofs are correctly verified
 * and that security properties hold with actual cryptographic operations.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { ProofGenerator } from '../generator.js';
import { ProofVerifier } from '../verifier.js';
import type { AgentIdentity } from '../../providers/base.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../delegation/did-key-resolver.js';
import type { Ed25519JWK } from '../../utils/crypto-service.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  RealClockProvider,
  RealFetchProvider,
  MemoryNonceCacheProvider,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';

describe('ProofVerifier (real crypto)', () => {
  let crypto: NodeCryptoProvider;
  let agent: AgentIdentity;
  let otherAgent: AgentIdentity;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    agent = await createRealIdentity(crypto);
    otherAgent = await createRealIdentity(crypto);
  });

  function makeVerifier(): { verifier: ProofVerifier; nonceCache: MemoryNonceCacheProvider } {
    const nonceCache = new MemoryNonceCacheProvider();
    const verifier = new ProofVerifier({
      cryptoProvider: crypto,
      clockProvider: new RealClockProvider(),
      nonceCacheProvider: nonceCache,
      fetchProvider: new RealFetchProvider(),
      timestampSkewSeconds: 300,
    });
    return { verifier, nonceCache };
  }

  function getJwk(identity: AgentIdentity): Ed25519JWK {
    const raw = extractPublicKeyFromDidKey(identity.did);
    const jwk = publicKeyToJwk(raw!);
    jwk.kid = identity.kid;
    return jwk as Ed25519JWK;
  }

  async function generateProof(identity: AgentIdentity) {
    const gen = new ProofGenerator(
      { did: identity.did, kid: identity.kid, privateKey: identity.privateKey, publicKey: identity.publicKey },
      crypto
    );
    return gen.generateProof(
      { method: 'tools/call', params: { name: 'test-tool' } },
      { data: { output: 'result' } },
      {
        sessionId: 'sess_integration',
        audience: 'did:web:server.example.com',
        nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        timestamp: Math.floor(Date.now() / 1000),
        createdAt: Math.floor(Date.now() / 1000),
        lastActivity: Math.floor(Date.now() / 1000),
        ttlMinutes: 30,
        identityState: 'anonymous',
      }
    );
  }

  // ── Core Verification ─────────────────────────────────────────

  it('should verify a valid proof with real Ed25519 signature', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);

    const result = await verifier.verifyProof(proof, jwk);

    expect(result.valid).toBe(true);
  });

  it('should reject proof signed by a different key', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const wrongJwk = getJwk(otherAgent);

    const result = await verifier.verifyProof(proof, wrongJwk);

    expect(result.valid).toBe(false);
  });

  // ── Nonce Replay (real cache) ─────────────────────────────────

  it('should prevent nonce replay with real MemoryNonceCacheProvider', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);

    const first = await verifier.verifyProof(proof, jwk);
    expect(first.valid).toBe(true);

    const replay = await verifier.verifyProof(proof, jwk);
    expect(replay.valid).toBe(false);
    expect(replay.reason).toContain('replay');
  });

  it('should scope nonces per agent DID', async () => {
    const { verifier } = makeVerifier();

    const proofA = await generateProof(agent);
    const proofB = await generateProof(otherAgent);
    const jwkA = getJwk(agent);
    const jwkB = getJwk(otherAgent);

    const resultA = await verifier.verifyProof(proofA, jwkA);
    const resultB = await verifier.verifyProof(proofB, jwkB);

    expect(resultA.valid).toBe(true);
    expect(resultB.valid).toBe(true);
  });

  // ── Detached Verification ─────────────────────────────────────

  it('should verify proof via verifyProofDetached with string payload', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);
    const canonical = verifier.buildCanonicalPayload(proof.meta);

    const result = await verifier.verifyProofDetached(proof, canonical, jwk);

    expect(result.valid).toBe(true);
  });

  it('should verify proof via verifyProofDetached with Uint8Array payload', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);
    const canonical = new TextEncoder().encode(verifier.buildCanonicalPayload(proof.meta));

    const result = await verifier.verifyProofDetached(proof, canonical, jwk);

    expect(result.valid).toBe(true);
  });

  // ── Proof Structure Rejection ─────────────────────────────────

  it('should reject malformed proof structure', async () => {
    const { verifier } = makeVerifier();
    const jwk = getJwk(agent);

    const result = await verifier.verifyProof(
      { jws: 'not-valid', meta: { did: 'x' } } as any,
      jwk
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Invalid proof structure');
  });

  // ── fetchPublicKeyFromDID (real DID resolution) ───────────────

  it('should resolve a real did:key to a valid Ed25519 JWK', async () => {
    const { verifier } = makeVerifier();

    const jwk = await verifier.fetchPublicKeyFromDID(agent.did);

    expect(jwk).toBeDefined();
    expect(jwk!.kty).toBe('OKP');
    expect(jwk!.crv).toBe('Ed25519');
    expect(jwk!.x).toBeTruthy();
  });
});
