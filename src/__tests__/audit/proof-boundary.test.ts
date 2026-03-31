/**
 * Proof Boundary Audit Tests
 *
 * Tests the proof generation → verification pipeline at exact boundary
 * conditions: timestamp skew thresholds, nonce scoping, malformed proofs.
 * Uses ControllableClockProvider for deterministic timestamp testing.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { ProofGenerator } from '../../proof/generator.js';
import { ProofVerifier } from '../../proof/verifier.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DetachedProof } from '../../types/protocol.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../delegation/did-key-resolver.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  ControllableClockProvider,
  RealFetchProvider,
  MemoryNonceCacheProvider,
} from './helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';
import type { Ed25519JWK } from '../../utils/crypto-service.js';

describe('Proof Boundary Audit', () => {
  let crypto: NodeCryptoProvider;
  let agentA: AgentIdentity;
  let agentB: AgentIdentity;
  const SKEW_SECONDS = 300; // default 5 minutes

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    agentA = await createRealIdentity(crypto);
    agentB = await createRealIdentity(crypto);
  });

  function makeGenerator(identity: AgentIdentity): ProofGenerator {
    return new ProofGenerator(
      { did: identity.did, kid: identity.kid, privateKey: identity.privateKey, publicKey: identity.publicKey },
      crypto
    );
  }

  function makeVerifier(clock: ControllableClockProvider): {
    verifier: ProofVerifier;
    nonceCache: MemoryNonceCacheProvider;
  } {
    const nonceCache = new MemoryNonceCacheProvider();
    const verifier = new ProofVerifier({
      cryptoProvider: crypto,
      clockProvider: clock,
      nonceCacheProvider: nonceCache,
      fetchProvider: new RealFetchProvider(),
      timestampSkewSeconds: SKEW_SECONDS,
    });
    return { verifier, nonceCache };
  }

  function getPublicKeyJwk(identity: AgentIdentity): Ed25519JWK {
    const rawPublicKey = extractPublicKeyFromDidKey(identity.did);
    const jwk = publicKeyToJwk(rawPublicKey!);
    jwk.kid = identity.kid;
    return jwk as Ed25519JWK;
  }

  async function generateProof(identity: AgentIdentity): Promise<DetachedProof> {
    const gen = makeGenerator(identity);
    return gen.generateProof(
      { method: 'tools/call', params: { name: 'test-tool', arguments: { input: 'hello' } } },
      { data: { output: 'world' } },
      {
        sessionId: 'sess_test_boundary',
        audience: 'did:web:test-server.example.com',
        nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        timestamp: Math.floor(Date.now() / 1000),
        createdAt: Math.floor(Date.now() / 1000),
        lastActivity: Math.floor(Date.now() / 1000),
        ttlMinutes: 30,
        identityState: 'anonymous',
      }
    );
  }

  // ── Timestamp Skew Boundary Tests ─────────────────────────────

  describe('timestamp skew boundaries', () => {
    it('should accept proof at exactly the skew boundary (300s)', async () => {
      // Generate proof first, then use its actual meta.ts to set the clock.
      // This avoids a race where a second boundary is crossed between
      // capturing the timestamp and generating the proof (which would
      // cause a JWS signature mismatch).
      const proof = await generateProof(agentA);
      const proofTimestampMs = proof.meta.ts * 1000;

      // Clock is exactly SKEW_SECONDS * 1000 ms ahead of the proof timestamp
      const clock = new ControllableClockProvider(proofTimestampMs + SKEW_SECONDS * 1000);
      const { verifier } = makeVerifier(clock);

      const jwk = getPublicKeyJwk(agentA);
      const result = await verifier.verifyProof(proof, jwk);

      expect(result.valid).toBe(true);
    });

    it('should reject proof 1ms beyond the skew boundary', async () => {
      const proof = await generateProof(agentA);
      const proofTimestampMs = proof.meta.ts * 1000;

      // Clock is 1ms beyond the skew window
      const clock = new ControllableClockProvider(proofTimestampMs + SKEW_SECONDS * 1000 + 1);
      const { verifier } = makeVerifier(clock);

      const jwk = getPublicKeyJwk(agentA);
      const result = await verifier.verifyProof(proof, jwk);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('skew');
    });

    it('should accept proof when verifier clock is behind by exactly the skew boundary', async () => {
      // Generate proof with real timestamp (meta.ts ≈ now)
      const proof = await generateProof(agentA);
      const proofTimestampMs = proof.meta.ts * 1000;

      // Set verifier clock to be exactly SKEW_SECONDS behind the proof
      // This simulates verifying a proof from a clock-ahead agent
      const clock = new ControllableClockProvider(proofTimestampMs - SKEW_SECONDS * 1000);
      const { verifier } = makeVerifier(clock);

      const jwk = getPublicKeyJwk(agentA);
      const result = await verifier.verifyProof(proof, jwk);

      expect(result.valid).toBe(true);
    });

    it('should reject proof when verifier clock is behind beyond the skew boundary', async () => {
      const proof = await generateProof(agentA);
      const proofTimestampMs = proof.meta.ts * 1000;

      // Set verifier clock 1ms further than the boundary
      const clock = new ControllableClockProvider(proofTimestampMs - SKEW_SECONDS * 1000 - 1);
      const { verifier } = makeVerifier(clock);

      const jwk = getPublicKeyJwk(agentA);
      const result = await verifier.verifyProof(proof, jwk);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('skew');
    });
  });

  // ── Nonce Scoping Tests ───────────────────────────────────────

  describe('nonce scoping', () => {
    it('should allow same nonce value from different agents (no cross-agent collision)', async () => {
      const sharedNonce = 'shared-nonce-value-12345';
      const clock = new ControllableClockProvider(Date.now());
      const { verifier } = makeVerifier(clock);

      // Generate proofs for both agents with the same nonce
      const genA = makeGenerator(agentA);
      const genB = makeGenerator(agentB);

      const session = {
        sessionId: 'sess_nonce_test',
        audience: 'did:web:server.example.com',
        nonce: sharedNonce,
        timestamp: Math.floor(Date.now() / 1000),
        createdAt: Math.floor(Date.now() / 1000),
        lastActivity: Math.floor(Date.now() / 1000),
        ttlMinutes: 30,
        identityState: 'anonymous' as const,
      };

      const request = { method: 'tools/call', params: { name: 'test' } };
      const response = { data: { result: 'ok' } };

      const proofA = await genA.generateProof(request, response, session);
      const proofB = await genB.generateProof(request, response, session);

      const jwkA = getPublicKeyJwk(agentA);
      const jwkB = getPublicKeyJwk(agentB);

      const resultA = await verifier.verifyProof(proofA, jwkA);
      expect(resultA.valid).toBe(true);

      // Same nonce, different agent — should also succeed
      const resultB = await verifier.verifyProof(proofB, jwkB);
      expect(resultB.valid).toBe(true);
    });

    it('should reject replay of same nonce from same agent', async () => {
      const clock = new ControllableClockProvider(Date.now());
      const { verifier } = makeVerifier(clock);

      const proof = await generateProof(agentA);
      const jwk = getPublicKeyJwk(agentA);

      const result1 = await verifier.verifyProof(proof, jwk);
      expect(result1.valid).toBe(true);

      // Same exact proof (same nonce, same agent) — should be rejected as replay
      const result2 = await verifier.verifyProof(proof, jwk);
      expect(result2.valid).toBe(false);
      expect(result2.reason).toContain('replay');
    });
  });

  // ── Wrong Key Tests ───────────────────────────────────────────

  describe('signature verification with wrong key', () => {
    it('should reject proof verified with wrong public key', async () => {
      const clock = new ControllableClockProvider(Date.now());
      const { verifier } = makeVerifier(clock);

      // Generate proof with agent A
      const proof = await generateProof(agentA);

      // Try to verify with agent B's public key
      const wrongJwk = getPublicKeyJwk(agentB);

      const result = await verifier.verifyProof(proof, wrongJwk);
      expect(result.valid).toBe(false);
    });
  });

  // ── Malformed Proof Tests ─────────────────────────────────────

  describe('malformed proof rejection', () => {
    it('should reject proof with empty nonce', async () => {
      const clock = new ControllableClockProvider(Date.now());
      const { verifier } = makeVerifier(clock);

      const proof = await generateProof(agentA);
      proof.meta.nonce = '';

      const jwk = getPublicKeyJwk(agentA);
      const result = await verifier.verifyProof(proof, jwk);

      expect(result.valid).toBe(false);
    });

    it('should reject proof with malformed requestHash', async () => {
      const clock = new ControllableClockProvider(Date.now());
      const { verifier } = makeVerifier(clock);

      const proof = await generateProof(agentA);
      proof.meta.requestHash = 'md5:abc123';

      const jwk = getPublicKeyJwk(agentA);
      const result = await verifier.verifyProof(proof, jwk);

      expect(result.valid).toBe(false);
    });

    it('should reject proof with ts=0', async () => {
      const clock = new ControllableClockProvider(Date.now());
      const { verifier } = makeVerifier(clock);

      const proof = await generateProof(agentA);
      proof.meta.ts = 0;

      const jwk = getPublicKeyJwk(agentA);
      const result = await verifier.verifyProof(proof, jwk);

      expect(result.valid).toBe(false);
    });
  });
});
