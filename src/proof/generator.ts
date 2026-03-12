/**
 * Proof Generation — Platform-agnostic Protocol Reference
 *
 * Handles JCS canonicalization, SHA-256 digest generation, and Ed25519 JWS
 * signing (compact format) according to MCP-I requirements 5.1, 5.2, 5.3, 5.6.
 *
 * This module is the authoritative proof implementation. All platform adapters
 * (Node.js, Cloudflare Workers) inject a CryptoProvider and delegate here.
 */

import { CompactSign, importPKCS8 } from 'jose';
import { canonicalize } from 'json-canonicalize';
import type {
  DetachedProof,
  ProofMeta,
  CanonicalHashes,
  SessionContext,
} from '../types/protocol.js';
import type { CryptoProvider } from '../providers/base.js';
import { CryptoService, type Ed25519JWK } from '../utils/crypto-service.js';

export interface ProofAgentIdentity {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
}

export interface ToolRequest {
  method: string;
  params?: unknown;
}

export interface ToolResponse {
  data: unknown;
  meta?: {
    proof?: DetachedProof;
    [key: string]: unknown;
  };
}

export interface ProofOptions {
  scopeId?: string;
  delegationRef?: string;
  clientDid?: string;
}

export class ProofGenerator {
  private identity: ProofAgentIdentity;
  private cryptoProvider: CryptoProvider;

  constructor(identity: ProofAgentIdentity, cryptoProvider: CryptoProvider) {
    this.identity = identity;
    this.cryptoProvider = cryptoProvider;
  }

  async generateProof(
    request: ToolRequest,
    response: ToolResponse,
    session: SessionContext,
    options: ProofOptions = {}
  ): Promise<DetachedProof> {
    const hashes = await this.generateCanonicalHashes(request, response);

    const meta: ProofMeta = {
      did: this.identity.did,
      kid: this.identity.kid,
      ts: Math.floor(Date.now() / 1000),
      nonce: session.nonce,
      audience: session.audience,
      sessionId: session.sessionId,
      requestHash: hashes.requestHash,
      responseHash: hashes.responseHash,
      ...options,
    };

    const jws = await this.generateJWS(meta);

    return { jws, meta };
  }

  private async generateCanonicalHashes(
    request: ToolRequest,
    response: ToolResponse
  ): Promise<CanonicalHashes> {
    const canonicalRequest = {
      method: request.method,
      ...(request.params ? { params: request.params } : {}),
    };
    const canonicalResponse = response.data;

    const requestHash = await this.generateSHA256Hash(canonicalRequest);
    const responseHash = await this.generateSHA256Hash(canonicalResponse);

    return { requestHash, responseHash };
  }

  private async generateSHA256Hash(data: unknown): Promise<string> {
    const canonicalJson = this.canonicalizeJSON(data);
    const encoded = new TextEncoder().encode(canonicalJson);
    return this.cryptoProvider.hash(encoded);
  }

  private canonicalizeJSON(obj: unknown): string {
    return canonicalize(obj as Parameters<typeof canonicalize>[0]);
  }

  private async generateJWS(meta: ProofMeta): Promise<string> {
    try {
      const privateKeyPem = this.formatPrivateKeyAsPEM(this.identity.privateKey);
      const privateKey = await importPKCS8(privateKeyPem, 'EdDSA');

      const payload = {
        aud: meta.audience,
        sub: meta.did,
        iss: meta.did,
        requestHash: meta.requestHash,
        responseHash: meta.responseHash,
        ts: meta.ts,
        nonce: meta.nonce,
        sessionId: meta.sessionId,
        ...(meta.scopeId && { scopeId: meta.scopeId }),
        ...(meta.delegationRef && { delegationRef: meta.delegationRef }),
        ...(meta.clientDid && { clientDid: meta.clientDid }),
      };

      // Use canonicalized JSON (RFC 8785) for deterministic payload serialization.
      // This ensures signature verification succeeds regardless of JSON key ordering.
      const canonicalPayload = canonicalize(payload as Parameters<typeof canonicalize>[0]);
      const payloadBytes = new TextEncoder().encode(canonicalPayload);

      const jws = await new CompactSign(payloadBytes)
        .setProtectedHeader({
          alg: 'EdDSA',
          kid: this.identity.kid,
        })
        .sign(privateKey);

      return jws;
    } catch (error) {
      throw new Error(
        `Failed to generate JWS: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  private formatPrivateKeyAsPEM(base64PrivateKey: string): string {
    const binaryStr = atob(base64PrivateKey);
    const keyData = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      keyData[i] = binaryStr.charCodeAt(i);
    }

    const pkcs8Header = new Uint8Array([
      0x30, 0x2e,
      0x02, 0x01, 0x00,
      0x30, 0x05,
      0x06, 0x03, 0x2b, 0x65, 0x70,
      0x04, 0x22,
      0x04, 0x20,
    ]);

    const rawKey = keyData.subarray(0, 32);
    const fullKey = new Uint8Array(pkcs8Header.length + rawKey.length);
    fullKey.set(pkcs8Header);
    fullKey.set(rawKey, pkcs8Header.length);

    let binaryStrOut = '';
    for (let i = 0; i < fullKey.length; i++) {
      binaryStrOut += String.fromCharCode(fullKey[i]!);
    }
    const base64Key = btoa(binaryStrOut);

    const formattedKey = base64Key.match(/.{1,64}/g)?.join('\n') ?? base64Key;

    return (
      '-----BEGIN PRIVATE KEY-----\n' +
      formattedKey +
      '\n-----END PRIVATE KEY-----'
    );
  }

  async verifyProof(
    proof: DetachedProof,
    request: ToolRequest,
    response: ToolResponse
  ): Promise<boolean> {
    try {
      const expectedHashes = await this.generateCanonicalHashes(request, response);

      if (
        proof.meta.requestHash !== expectedHashes.requestHash ||
        proof.meta.responseHash !== expectedHashes.responseHash
      ) {
        return false;
      }

      const publicKeyJwk = this.base64PublicKeyToJWK(this.identity.publicKey);
      const cryptoService = new CryptoService(this.cryptoProvider);

      return cryptoService.verifyJWS(proof.jws, publicKeyJwk, {
        expectedKid: this.identity.kid,
        alg: 'EdDSA',
      });
    } catch {
      return false;
    }
  }

  private base64PublicKeyToJWK(publicKeyBase64: string): Ed25519JWK {
    const binaryStr = atob(publicKeyBase64);
    const publicKeyBytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      publicKeyBytes[i] = binaryStr.charCodeAt(i);
    }

    if (publicKeyBytes.length !== 32) {
      throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes.length}`);
    }

    let binaryStrOut = '';
    for (let i = 0; i < publicKeyBytes.length; i++) {
      binaryStrOut += String.fromCharCode(publicKeyBytes[i]!);
    }
    const base64url = btoa(binaryStrOut)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64url,
      kid: this.identity.kid,
    };
  }
}

export async function createProofResponse(
  request: ToolRequest,
  data: unknown,
  identity: ProofAgentIdentity,
  session: SessionContext,
  cryptoProvider: CryptoProvider,
  options: ProofOptions = {}
): Promise<ToolResponse> {
  const response: ToolResponse = { data };
  const proofGenerator = new ProofGenerator(identity, cryptoProvider);
  const proof = await proofGenerator.generateProof(request, response, session, options);
  response.meta = { proof };
  return response;
}

export function extractCanonicalData(
  request: ToolRequest,
  response: ToolResponse
): {
  request: unknown;
  response: unknown;
} {
  return {
    request: {
      method: request.method,
      ...(request.params ? { params: request.params } : {}),
    },
    response: response.data,
  };
}
