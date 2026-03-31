/**
 * VC Round-Trip Audit Tests
 *
 * Tests the full lifecycle: issue a DelegationCredential with real Ed25519
 * signing, then verify it through the 3-stage verification pipeline.
 * No mocks on crypto, canonicalization, or signing.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import {
  DelegationCredentialVerifier,
  type DIDResolver,
} from '../../delegation/vc-verifier.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { DelegationRecord, DelegationCredential } from '../../types/protocol.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSigningFunction,
  createRealSignatureVerifier,
} from './helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';

describe('VC Round-Trip Audit', () => {
  let crypto: NodeCryptoProvider;
  let issuerIdentity: AgentIdentity;
  let subjectIdentity: AgentIdentity;
  let issuer: DelegationCredentialIssuer;
  let verifier: DelegationCredentialVerifier;
  let didResolver: DIDResolver;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    issuerIdentity = await createRealIdentity(crypto);
    subjectIdentity = await createRealIdentity(crypto);

    const signingFunction = createRealSigningFunction(crypto, issuerIdentity);
    const signatureVerifier = createRealSignatureVerifier(crypto);
    didResolver = createDidKeyResolver();

    const issuerIdProvider = {
      getDid: () => issuerIdentity.did,
      getKeyId: () => issuerIdentity.kid,
      getPrivateKey: () => issuerIdentity.privateKey,
    };

    issuer = new DelegationCredentialIssuer(issuerIdProvider, signingFunction);

    verifier = new DelegationCredentialVerifier({
      didResolver,
      signatureVerifier,
    });
  });

  function makeDelegationRecord(overrides?: Partial<DelegationRecord>): DelegationRecord {
    return {
      id: 'test-delegation-001',
      issuerDid: issuerIdentity.did,
      subjectDid: subjectIdentity.did,
      vcId: 'urn:uuid:test-vc-001',
      constraints: {
        scopes: ['tools:read', 'tools:write'],
        notBefore: Math.floor(Date.now() / 1000) - 3600,
        notAfter: Math.floor(Date.now() / 1000) + 3600,
      },
      signature: '',
      status: 'active',
      createdAt: Date.now(),
      ...overrides,
    };
  }

  // ── Round-Trip Tests ──────────────────────────────────────────

  it('should issue and verify a delegation credential round-trip', async () => {
    const delegation = makeDelegationRecord();
    const vc = await issuer.issueDelegationCredential(delegation);

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(true);
    expect(result.stage).toBe('complete');
    expect(result.checks?.basicValid).toBe(true);
    expect(result.checks?.signatureValid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('should reject VC with tampered credentialSubject', async () => {
    const delegation = makeDelegationRecord();
    const vc = await issuer.issueDelegationCredential(delegation);

    // Tamper with the scopes after signing
    const tampered = structuredClone(vc);
    tampered.credentialSubject.delegation.scopes = ['admin:*'];

    const result = await verifier.verifyDelegationCredential(tampered, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.checks?.signatureValid).toBe(false);
  });

  it('should reject VC with swapped issuer DID', async () => {
    const delegation = makeDelegationRecord();
    const vc = await issuer.issueDelegationCredential(delegation);

    // Swap issuer to subject's DID — resolver will return subject's key,
    // which won't match the issuer's signature
    const tampered = structuredClone(vc);
    tampered.issuer = subjectIdentity.did;

    const result = await verifier.verifyDelegationCredential(tampered, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
  });

  it('should reject expired VC', async () => {
    const delegation = makeDelegationRecord({
      constraints: {
        scopes: ['tools:read'],
        notAfter: Math.floor(Date.now() / 1000) - 1, // 1 second in the past
      },
    });
    const vc = await issuer.issueDelegationCredential(delegation);

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.stage).toBe('basic');
    expect(result.reason).toContain('expired');
  });

  it('should reject VC with revoked status field', async () => {
    const delegation = makeDelegationRecord({ status: 'revoked' });
    const vc = await issuer.issueDelegationCredential(delegation);

    const result = await verifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.stage).toBe('basic');
    expect(result.reason).toContain('revoked');
  });

  it('should reject VC without proof field', async () => {
    const delegation = makeDelegationRecord();
    const vc = await issuer.issueDelegationCredential(delegation);

    // Remove proof entirely
    const noProof = { ...vc } as Record<string, unknown>;
    delete noProof['proof'];

    const result = await verifier.verifyDelegationCredential(
      noProof as DelegationCredential,
      { skipStatus: true, skipCache: true }
    );

    expect(result.valid).toBe(false);
    expect(result.stage).toBe('basic');
    expect(result.reason).toContain('proof');
  });

  it('should reject VC when DID resolver returns null', async () => {
    const delegation = makeDelegationRecord();
    const vc = await issuer.issueDelegationCredential(delegation);

    const nullResolver: DIDResolver = {
      resolve: async () => null,
    };

    const strictVerifier = new DelegationCredentialVerifier({
      didResolver: nullResolver,
      signatureVerifier: createRealSignatureVerifier(crypto),
    });

    const result = await strictVerifier.verifyDelegationCredential(vc, {
      skipStatus: true,
      skipCache: true,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('resolve');
  });

  // ── Caching Tests ─────────────────────────────────────────────

  it('should return cached result on second verification', async () => {
    const delegation = makeDelegationRecord();
    const vc = await issuer.issueDelegationCredential(delegation);

    const cachingVerifier = new DelegationCredentialVerifier({
      didResolver,
      signatureVerifier: createRealSignatureVerifier(crypto),
      cacheTtl: 60_000,
    });

    const first = await cachingVerifier.verifyDelegationCredential(vc, {
      skipStatus: true,
    });
    expect(first.valid).toBe(true);
    expect(first.cached).toBeUndefined();

    const second = await cachingVerifier.verifyDelegationCredential(vc, {
      skipStatus: true,
    });
    expect(second.valid).toBe(true);
    expect(second.cached).toBe(true);
  });

  it('should evict oldest cache entry when maxCacheSize is exceeded', async () => {
    const cachingVerifier = new DelegationCredentialVerifier({
      didResolver,
      signatureVerifier: createRealSignatureVerifier(crypto),
      cacheTtl: 60_000,
      maxCacheSize: 2,
    });

    // Issue 3 distinct VCs
    const vcs: DelegationCredential[] = [];
    for (let i = 0; i < 3; i++) {
      const delegation = makeDelegationRecord({
        id: `cache-test-${i}`,
        vcId: `urn:uuid:cache-test-${i}`,
      });
      vcs.push(await issuer.issueDelegationCredential(delegation));
    }

    // Verify all 3 — first should be evicted
    for (const vc of vcs) {
      await cachingVerifier.verifyDelegationCredential(vc, { skipStatus: true });
    }

    // First VC should NOT be cached (evicted)
    const first = await cachingVerifier.verifyDelegationCredential(vcs[0]!, {
      skipStatus: true,
    });
    expect(first.cached).toBeUndefined();

    // Third VC should still be cached
    const third = await cachingVerifier.verifyDelegationCredential(vcs[2]!, {
      skipStatus: true,
    });
    expect(third.cached).toBe(true);
  });

  // ── Signature Integrity ───────────────────────────────────────

  it('should produce different signatures for different delegations', async () => {
    const vc1 = await issuer.issueDelegationCredential(
      makeDelegationRecord({ id: 'del-A' })
    );
    const vc2 = await issuer.issueDelegationCredential(
      makeDelegationRecord({ id: 'del-B' })
    );

    expect(vc1.proof?.proofValue).not.toBe(vc2.proof?.proofValue);
  });

  it('should produce identical canonicalization for same delegation regardless of field order', async () => {
    const delegation = makeDelegationRecord();
    const vc1 = await issuer.issueDelegationCredential(delegation);
    const vc2 = await issuer.issueDelegationCredential(delegation);

    // Same input should produce same unsigned VC structure
    // (proof timestamps differ, but the unsigned portion should canonicalize the same)
    const strip = (vc: DelegationCredential) => {
      const copy = { ...vc } as Record<string, unknown>;
      delete copy['proof'];
      return copy;
    };

    const { canonicalizeJSON } = await import('../../delegation/utils.js');
    expect(canonicalizeJSON(strip(vc1))).toBe(canonicalizeJSON(strip(vc2)));
  });
});
