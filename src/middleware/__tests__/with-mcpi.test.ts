import { describe, it, expect } from 'vitest';
import { createMCPIMiddleware } from '../with-mcpi.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { DelegationCredentialIssuer } from '../../delegation/vc-issuer.js';
import type { Proof } from '../../types/protocol.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';

async function createTestMiddleware(options?: { autoSession?: boolean }) {
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#keys-1`;

  return createMCPIMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      autoSession: options?.autoSession,
    },
    crypto,
  );
}

describe('createMCPIMiddleware', () => {
  describe('handleHandshake', () => {
    it('should establish a session with valid handshake', async () => {
      const mcpi = await createTestMiddleware();
      const result = await mcpi.handleHandshake({
        nonce: 'test-nonce',
        audience: 'did:web:example.com',
        timestamp: Math.floor(Date.now() / 1000),
      });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(true);
      expect(parsed.sessionId).toMatch(/^mcpi_/);
      expect(parsed.serverDid).toMatch(/^did:key:/);
    });

    it('should reject invalid handshake', async () => {
      const mcpi = await createTestMiddleware();
      const result = await mcpi.handleHandshake({ nonce: 'test' });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.success).toBe(false);
      expect(parsed.error.code).toBe('MCPI_INVALID_HANDSHAKE');
    });
  });

  describe('wrapWithProof', () => {
    it('should attach proof in _meta after handshake', async () => {
      const mcpi = await createTestMiddleware();

      // Handshake first
      const hs = await mcpi.handleHandshake({
        nonce: 'test-nonce',
        audience: 'did:web:example.com',
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      // Call wrapped tool
      const handler = mcpi.wrapWithProof('greet', async (args) => ({
        content: [{ type: 'text', text: `Hello, ${args['name']}!` }],
      }));

      const result = await handler({ name: 'DIF' }, sessionId);

      // Tool result in content (single block)
      expect(result.content).toHaveLength(1);
      expect(result.content[0].text).toBe('Hello, DIF!');

      // Proof in _meta, not in content
      expect(result._meta).toBeDefined();
      expect(result._meta!.proof).toBeDefined();
      const proof = result._meta!.proof as { jws: string; meta: Record<string, unknown> };
      expect(proof.jws).toBeDefined();
      expect(proof.meta.did).toMatch(/^did:key:/);
      expect(proof.meta.sessionId).toBe(sessionId);
      expect(proof.meta.requestHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(proof.meta.responseHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('should not attach proof when result is an error', async () => {
      const mcpi = await createTestMiddleware();

      const hs = await mcpi.handleHandshake({
        nonce: 'test-nonce',
        audience: 'did:web:example.com',
        timestamp: Math.floor(Date.now() / 1000),
      });
      const sessionId = JSON.parse(hs.content[0].text).sessionId;

      const handler = mcpi.wrapWithProof('fail-tool', async () => ({
        content: [{ type: 'text', text: 'error' }],
        isError: true,
      }));

      const result = await handler({}, sessionId);
      expect(result.isError).toBe(true);
      expect(result._meta).toBeUndefined();
    });

    it('should return result without proof when no session exists and autoSession is off', async () => {
      const mcpi = await createTestMiddleware({ autoSession: false });

      const handler = mcpi.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));

      const result = await handler({});
      expect(result.content[0].text).toBe('Hello!');
      expect(result._meta).toBeUndefined();
    });
  });

  describe('wrapWithDelegation', () => {
    async function issueDelegationVC(scopes: string[]) {
      const crypto = new NodeCryptoProvider();
      const keyPair = await crypto.generateKeyPair();
      const did = generateDidKeyFromBase64(keyPair.publicKey);
      const kid = `${did}#keys-1`;

      const signingFn = async (
        canonicalVC: string,
        _issuerDid: string,
        kidArg: string,
      ): Promise<Proof> => {
        const data = new TextEncoder().encode(canonicalVC);
        const sigBytes = await crypto.sign(data, keyPair.privateKey);
        const proofValue = base64urlEncodeFromBytes(sigBytes);
        return {
          type: 'Ed25519Signature2020',
          created: new Date().toISOString(),
          verificationMethod: kidArg,
          proofPurpose: 'assertionMethod',
          proofValue,
        };
      };

      const issuer = new DelegationCredentialIssuer(
        {
          getDid: () => did,
          getKeyId: () => kid,
          getPrivateKey: () => keyPair.privateKey,
        },
        signingFn,
      );

      return issuer.createAndIssueDelegation({
        id: `test-delegation-${Date.now()}`,
        issuerDid: did,
        subjectDid: did,
        constraints: {
          scopes,
          notAfter: Math.floor(Date.now() / 1000) + 3600,
        },
      });
    }

    it('should return needs_authorization when no _mcpi_delegation arg is provided', async () => {
      const mcpi = await createTestMiddleware();

      const handler = mcpi.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ name: 'world' });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('needs_authorization');
      expect(parsed.authorizationUrl).toBe('https://example.com/consent');
      expect(parsed.scopes).toContain('test:scope');
      expect(typeof parsed.resumeToken).toBe('string');
      expect(typeof parsed.expiresAt).toBe('number');
    });

    it('should reject when VC has wrong scope', async () => {
      const mcpi = await createTestMiddleware();
      const vc = await issueDelegationVC(['wrong:scope']);

      const handler = mcpi.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
      );

      const result = await handler({ _mcpi_delegation: vc });

      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe('delegation_scope_missing');
    });

    it('should accept and call handler when VC has correct scope and valid signature', async () => {
      const mcpi = await createTestMiddleware();
      const vc = await issueDelegationVC(['test:scope', 'other:scope']);

      const handler = mcpi.wrapWithDelegation(
        'my-tool',
        { scopeId: 'test:scope', consentUrl: 'https://example.com/consent' },
        async (args) => ({
          content: [{ type: 'text', text: `Called: ${JSON.stringify(args)}` }],
        }),
      );

      const result = await handler({ _mcpi_delegation: vc, name: 'DIF' });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text.replace('Called: ', ''));
      // _mcpi_delegation should be stripped from args
      expect(parsed['_mcpi_delegation']).toBeUndefined();
      expect(parsed['name']).toBe('DIF');
    });
  });

  describe('autoSession', () => {
    it('should auto-create session and attach proof without handshake', async () => {
      const mcpi = await createTestMiddleware({ autoSession: true });

      const handler = mcpi.wrapWithProof('greet', async (args) => ({
        content: [{ type: 'text', text: `Hello, ${args['name']}!` }],
      }));

      // No handshake — call tool directly
      const result = await handler({ name: 'DIF' });

      expect(result.content).toHaveLength(1);
      expect(result.content[0].text).toBe('Hello, DIF!');

      // Proof should still be generated via auto-session
      expect(result._meta).toBeDefined();
      const proof = result._meta!.proof as { jws: string; meta: Record<string, unknown> };
      expect(proof.jws).toBeDefined();
      expect(proof.meta.did).toMatch(/^did:key:/);
      expect(proof.meta.sessionId).toMatch(/^mcpi_/);
      // Nonce is now a base64url-encoded 16-byte random value
      expect(proof.meta.nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should reuse auto-created session across multiple calls', async () => {
      const mcpi = await createTestMiddleware({ autoSession: true });

      const handler = mcpi.wrapWithProof('greet', async () => ({
        content: [{ type: 'text', text: 'Hello!' }],
      }));

      const result1 = await handler({});
      const result2 = await handler({});

      const proof1 = result1._meta!.proof as { meta: Record<string, unknown> };
      const proof2 = result2._meta!.proof as { meta: Record<string, unknown> };

      expect(proof1.meta.sessionId).toBe(proof2.meta.sessionId);
    });
  });
});
